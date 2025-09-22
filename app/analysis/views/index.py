from datetime import datetime
import logging
from uuid import uuid4
from flask import flash, redirect, render_template, request, session, url_for
from flask_login import login_required
from app.analysis.views.session.alert import get_current_alert
from app.analysis.views.session.filters import filter_special_tags
from app.auth.permissions import require_permission
from app.blueprints import analysis
from saq.analysis.analysis import Analysis
from saq.analysis.observable import Observable
from saq.analysis.presenter import create_analysis_presenter, create_observable_presenter
from saq.analysis.root import RootAnalysis
from saq.configuration.config import get_config
from saq.constants import CLOSED_EVENT_LIMIT, F_FILE, VALID_OBSERVABLE_TYPES
from saq.database.model import Campaign, Comment, Company, Malware, User, Event
from saq.database.pool import get_db
from saq.database.util.observable_detection import get_all_observable_detections
from saq.disposition import get_dispositions
from saq.error.reporting import report_exception
from saq.util.ui import create_histogram_string
from saq.util.url import find_all_url_domains


class TreeNode:
    def __init__(self, obj, parent=None, prune_volatile=False):
        # unique ID that can be used in the GUI to track nodes
        self.uuid = str(uuid4())
        # Analysis or Observable object
        self.obj = obj
        self.parent = parent
        self.children = []
        # points to an already existing TreeNode for the analysis of this Observable
        self.reference_node = None
        # nodes are not visible unless something along the path has a "detection point"
        self.visible = False
        # a list of nodes that refer to this node
        self.referents = []
        # set to True if we are not showing volatile nodes
        self.prune_volatile = prune_volatile

        # set the analysis presenter
        if isinstance(obj, Analysis):
            self.presenter = create_analysis_presenter(obj)
        elif isinstance(obj, Observable):
            self.presenter = create_observable_presenter(obj)

    def add_child(self, child):
        assert isinstance(child, TreeNode)
        self.children.append(child)
        child.parent = self

    def remove_child(self, child):
        assert isinstance(child, TreeNode)
        self.children.remove(child)
        child.parent = self

    def refer_to(self, node):
        self.reference_node = node
        node.add_referent(self)

    def add_referent(self, node):
        self.referents.append(node)

    def walk(self, callback):
        callback(self)
        for node in self.children:
            node.walk(callback)

    @property
    def is_root_analysis(self):
        return isinstance(self.obj, RootAnalysis)

    @property
    def is_analysis(self):
        return isinstance(self.obj, Analysis)

    @property
    def volatile(self) -> bool:
        if isinstance(self.obj, Analysis):
            return False

        return self.obj.volatile

    def find_observable_node(self, ot, ov):
        # if obj is an observable, not sure what class that actually is but not analysis will be an observable
        if not self.is_analysis:
            if self.obj.type == ot and str(self.obj.value) == ov:
                return self

        # recurse through children
        for child in self.children:
            o = child.find_observable_node(ot, ov)
            if o is not None:
                return o
        return None

    def is_collapsible(self, prune):
        if self.is_analysis:
            if prune:
                for child in self.children:
                    if child.visible:
                        return True
                return False
            return len(self.children) > 0
        else:
            if self.reference_node is not None:
                return self.reference_node.is_collapsible(prune)
            for child in self.children:
                if child.presenter.should_render:
                    return True
            if self.obj.has_directive('preview'):
                return True
            if self.obj.type == F_FILE and self.obj.exists and self.obj.is_image:
                return True
            return False

    @property
    def should_render(self):
        if self.is_root_analysis:
            return True
        if self.is_analysis:
            return self.presenter.should_render
        # if we are pruning volatile nodes and this node is volatile AND does not lead to a detection point
        if self.prune_volatile and self.volatile and not self.visible:
            return False
        return True

    def __str__(self):
        return "TreeNode({}, {}, {})".format(self.obj, self.reference_node, self.visible)


def _recurse(current_node, node_tracker=None):
    assert isinstance(current_node, TreeNode)
    assert isinstance(current_node.obj, Analysis)
    assert node_tracker is None or isinstance(node_tracker, dict)

    analysis = current_node.obj
    if node_tracker is None:
        node_tracker = {}

    for observable in analysis.observables:
        child_node = TreeNode(observable, prune_volatile=current_node.prune_volatile)
        current_node.add_child(child_node)

        # if the observable is already in the current tree then we want to display a link to the existing analysis display
        if observable.uuid in node_tracker:
            child_node.refer_to(node_tracker[observable.uuid])
            continue

        node_tracker[observable.uuid] = child_node

        for observable_analysis in [a for a in observable.all_analysis if a]:
            observable_analysis_node = TreeNode(observable_analysis, prune_volatile=current_node.prune_volatile)
            child_node.add_child(observable_analysis_node)
            _recurse(observable_analysis_node, node_tracker)


def _sort(node):
    assert isinstance(node, TreeNode)

    node.children = sorted(node.children, key=lambda x: (x.obj.sort_order, x.obj))
    for node in node.children:
        _sort(node)


def _prune(node, current_path=None):
    assert isinstance(node, TreeNode)
    if current_path is None:
        current_path = []
    current_path.append(node)

    if node.children:
        for child in node.children:
            _prune(child, current_path)
    else:
        # all nodes are visible up to nodes that have "detection points" or tags
        # nodes tagged as "high_fp_frequency" are not visible
        update_index = 0
        index = 0
        while index < len(current_path):
            _has_detection_points = current_path[index].obj.has_detection_points()
            #_has_tags = len(current_path[index].obj.tags) > 0
            _always_visible = current_path[index].obj.always_visible()
            #_high_fp_freq = current_path[index].obj.has_tag('high_fp_frequency')
            _critical_analysis = current_path[index].obj.has_tag('critical_analysis')

            # 5/18/2020 - jdavison - changing how this works -- will refactor these out once these changes are approved
            _has_tags = False
            _high_fp_freq = False

            if _has_detection_points or _has_tags or _always_visible or _critical_analysis:
                # if we have tags but no detection points and we also have the high_fp_freq tag then we hide that
                if _high_fp_freq and not ( _has_detection_points or _always_visible ):
                    index += 1
                    continue

                while update_index <= index:
                    current_path[update_index].visible = True
                    update_index += 1

            index += 1

    current_path.pop()


def _resolve_references(node):
    # in the case were we have a visible node that is refering to a node that is NOT visible
    # then we need to use the data of the refering node
    def _resolve(node):
        if node.visible and node.reference_node and not node.reference_node.visible:
            node.children = node.reference_node.children
            for referent in node.reference_node.referents:
                referent.reference_node = node

            node.reference_node = None

    node.walk(_resolve)


@analysis.route('/analysis', methods=['GET', 'POST'])
@require_permission("alert", "read")
def index():
    alert = None

    # the "direct" parameter is used to specify a specific alert to load
    alert = get_current_alert()

    if alert is None:
        return redirect(url_for('analysis.manage'))

    #if alert.location != saq.SAQ_NODE:
        #target_node = node_translate_gui(alert.location)
        #target_url = translate_alert_redirect(url_for('analysis.index', direct=alert.uuid), saq.SAQ_NODE, target_node)
        #logging.info("redirecting %s for alert %s to %s", current_user, target_url)
        #return redirect(target_url)

    try:
        alert.load()
    except Exception as e:
        flash("unable to load alert {0}: {1}".format(alert, str(e)))
        report_exception()
        return redirect(url_for('analysis.manage'))

    observable_uuid = None
    module_path = None

    # by default we're looking at the initial alert
    # the user can navigate to look at the analysis performed on observables in the alert
    # did the user change their view?
    if 'observable_uuid' in request.values:
        observable_uuid = request.values['observable_uuid']

    if 'module_path' in request.values:
        module_path = request.values['module_path']

    # what observable are we currently looking at?
    observable = None
    if observable_uuid is not None:
        observable = alert.root_analysis.get_observable(observable_uuid)
        if observable is None:
            flash(f"observable {observable_uuid} not found")
            return redirect(url_for('analysis.index'))

    # get the analysis to view
    analysis = alert.root_analysis  # by default it's the alert

    if module_path is not None and observable is not None:
        analysis = observable.get_and_load_analysis(module_path)
        #analysis = observable.analysis[module_path]

    # load user comments for the alert
    try:
        alert.comments = get_db().query(Comment).filter(Comment.uuid == alert.uuid).all()
    except Exception as e: # pragma: no cover
        logging.error("could not load comments for alert: {}".format(e))

    # get all the tags for the alert
    all_tags = alert.root_analysis.all_tags

    # sort the tags by score
    alert_tags = filter_special_tags(sorted(all_tags, key=lambda x: (-x.score, x.name.lower())))
    # we don't show "special" tags in the display
    special_tag_names = [tag for tag in get_config()['tags'].keys() if get_config()['tags'][tag] == 'special']
    alert_tags = [tag for tag in alert_tags if tag.name not in special_tag_names]

    # XXX refactor this omg
    # get all of the current observable detection data 
    observable_detections = get_all_observable_detections(alert.root_analysis)

    # compute the display tree

    # are we viewing all analysis?
    if 'prune' not in session:
        session['prune'] = True
    elif not isinstance(session['prune'], bool):
        session['prune'] = True

    # are we viewing volatile analysis?
    if 'prune_volatile' not in session:
        session['prune_volatile'] = True
    elif not isinstance(session['prune_volatile'], bool):
        session['prune_volatile'] = True

    # we only display the tree if we're looking at the alert
    display_tree = None
    if alert.root_analysis is analysis:
        display_tree = TreeNode(analysis, prune_volatile=session['prune_volatile'])
        _recurse(display_tree)
        _sort(display_tree)
        if session['prune'] or session['prune_volatile']:
            _prune(display_tree)
            # root node is visible
            display_tree.visible = True

            # if the show_root_observables config option is True then
            # also all observables in the root node
            if get_config()['gui'].getboolean('show_root_observables'):
                for child in display_tree.children:
                    child.visible = True

            _resolve_references(display_tree)

    try:
        # go ahead and get the list of all the users, we'll end up using it
        all_users = get_db().query(User).order_by('username').all()
    except Exception as e:
        logging.error(f"idk why it breaks specifically right here {e}")
        get_db().rollback()
        all_users = get_db().query(User).order_by('username').all()

    open_events = []
    event_query_results = get_db().query(Event).filter(Event.status.has(value='OPEN')).order_by(Event.creation_date.desc()).all()
    if event_query_results:
        open_events = event_query_results
    internal_collection_events = []
    event_query_results = get_db().query(Event).filter(Event.status.has(value='INTERNAL COLLECTION')).order_by(Event.creation_date.desc())\
        .all()
    if event_query_results:
        internal_collection_events = event_query_results
    closed_events = []
    end_of_closed_events_list = True
    event_query_results = get_db().query(Event).filter(Event.status.has(value='CLOSED')).order_by(Event.creation_date.desc())\
        .limit(CLOSED_EVENT_LIMIT).all()
    if event_query_results:
        if len(event_query_results) == CLOSED_EVENT_LIMIT:
            end_of_closed_events_list = False
        closed_events = event_query_results

    malware = get_db().query(Malware).order_by(Malware.name.asc()).all()
    companies = get_db().query(Company).order_by(Company.name.asc()).all()
    campaigns = get_db().query(Campaign).order_by(Campaign.name.asc()).all()

    # get list of domains that appear in the alert
    domains = find_all_url_domains(analysis)
    #domain_list = list(domains)
    domain_list = sorted(domains, key=lambda k: domains[k])

    domain_summary_str = create_histogram_string(domains)

    # sort remediation targets
    target_types = {}
    for target in alert.remediation_targets:
        if target.type not in target_types:
            target_types[target.type] = []
        target_types[target.type].append(target)

    import saq.constants
    return render_template(
        'analysis/index.html',
        alert=alert,
        target_types=target_types,
        alert_tags=alert_tags,
        observable=observable,
        observable_presenter=create_observable_presenter(observable) if observable else None,
        analysis=analysis,
        analysis_presenter=create_analysis_presenter(analysis) if analysis else None,
        ace_config=get_config(),
        User=User,
        db=get_db(),
        current_time=datetime.now(),
        observable_types=VALID_OBSERVABLE_TYPES,
        display_tree=display_tree,
        prune_display_tree=session['prune'],
        prune_volatile=session['prune_volatile'],
        open_events=open_events,
        closed_events=closed_events,
        internal_collection_events=internal_collection_events,
        end_of_list=end_of_closed_events_list,
        malware=malware,
        companies=companies,
        campaigns=campaigns,
        all_users=all_users,
        dispositions=get_dispositions(),
        domains=domains,
        domain_list=domain_list,
        domain_summary_str=domain_summary_str,
        CONSTANTS=saq.constants,
        observable_open_event_counts=alert.observable_open_event_counts,
        # Skip file observables. The calculations will include their hash observables instead.
        num_observables_in_alert=len([o for o in alert.root_analysis.observable_store.values() if o.type != F_FILE]),
        observable_detections=observable_detections,
    )