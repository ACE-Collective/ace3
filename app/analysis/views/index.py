from datetime import datetime
import logging
from typing import NamedTuple
from uuid import uuid4
from flask import flash, redirect, render_template, request, session, url_for
from app.analysis.views.session.alert import get_current_alert
from app.analysis.views.session.filters import filter_special_tags
from app.auth.permissions import require_permission
from app.blueprints import analysis
from saq.analysis.analysis import Analysis
from saq.analysis.observable import Observable
from saq.analysis.presenter import create_analysis_presenter, create_observable_presenter
from saq.analysis.root import RootAnalysis
from saq.configuration.config import get_config
from saq.constants import CLOSED_EVENT_LIMIT, DIRECTIVE_DESCRIPTIONS, F_FILE, GUI_DIRECTIVES
from saq.database.model import Campaign, Comment, Company, Malware, User, Event
from saq.database.pool import get_db
from saq.analysis.detection_chain import (
    build_detection_chains,
    build_merged_detection_tree,
    module_display_name,
    observable_display_value,
)
from saq.database.database_observable import get_observable_disposition_histories
from saq.database.util.observable_detection import get_all_observable_detections
from aceapi_v2.observables.service import get_interesting_observables_by_hashes
from saq.disposition import get_dispositions
from saq.error.reporting import report_exception
from saq.remediation.coverage import get_remediation_coverage
from saq.remediation.external.database import get_external_checks_for_alert
from saq.remediation.external.events import summarize_alert_checks
from saq.remediation.timeline import gather_remediation_events
from saq.clicker_detection.timeline import gather_clicker_results
from saq.util.ui import create_histogram_string, get_tag_score
from saq.util.url import find_all_url_domains
from aceapi_v2.sync import run_async, run_async_with_session
from aceapi_v2.observable_comments.service import get_comments_for_observables, get_observable_db_ids
from aceapi_v2.observable_types.service import get_observable_types


# Key under root_analysis.details where correlated hunts record step provenance.
# Kept as a literal (mirroring how the template reads 'correlation_trace') to avoid
# importing the hunter collector into the web layer.
HUNT_PROVENANCE_DETAILS_KEY = "hunt_provenance"

# Accent palette for provenance group sections, mirroring the indent-rainbow colors
# in saq.css so the grouping reads as part of the same visual system. Indexed by step.
PROVENANCE_PALETTE = [
    "rgba(255, 99, 71, 0.55)",    # tomato
    "rgba(255, 165, 0, 0.55)",    # orange
    "rgba(230, 200, 0, 0.55)",    # gold
    "rgba(60, 179, 113, 0.55)",   # mediumseagreen
    "rgba(30, 144, 255, 0.55)",   # dodgerblue
    "rgba(138, 43, 226, 0.55)",   # blueviolet
    "rgba(199, 21, 133, 0.55)",   # violetred
]


def build_provenance_groups(root_analysis):
    """Build ordered Analysis-Overview groups from a correlated hunt's step provenance.

    Returns a list of group dicts (one per distinct set of contributing hunt steps),
    or None for alerts that carry no provenance (i.e. every non-correlated alert).
    Each group dict:
        key, anchor_id  -- stable identifiers derived from the step set
        label           -- heading ("Initial Query", "Correlated: <step>", or
                           "Found by Both Steps" for overlap groups)
        full_label      -- verbose join of all contributing step names (tooltip)
        sublabel        -- explanatory subtitle for overlap groups, else None
        colors          -- one accent color per contributing step (overlap groups
                           render these as a two-tone gradient)
        steps           -- sorted list of contributing step indices
        trace_steps     -- the correlate steps in this group (index>0 with a
                           property_name) for "View in Correlation Trace" links
        observable_uuids-- set of top-level observable uuids in this group

    Observables shared by multiple steps form their own truthful combined group rather
    than being assigned to one arbitrarily. Top-level observables with no provenance
    (e.g. the injected signature-id observable) are left out here and rendered by the
    template in a trailing "Other" section.
    """
    details = getattr(root_analysis, "details", None) or {}
    provenance = details.get(HUNT_PROVENANCE_DETAILS_KEY)
    if not provenance:
        return None

    steps = provenance.get("steps") or []
    obs_steps = provenance.get("observables") or {}
    if not steps:
        return None

    step_by_index = {s["index"]: s for s in steps}

    # bucket observable uuids by their full (sorted) step set
    buckets: dict[tuple, set] = {}
    for obs_uuid, step_list in obs_steps.items():
        key = tuple(sorted(step_list))
        buckets.setdefault(key, set()).add(obs_uuid)

    groups = []
    for key in sorted(buckets.keys()):
        step_objs = [step_by_index[i] for i in key if i in step_by_index]
        if not step_objs:
            continue

        label_parts = []
        for s in step_objs:
            if s["index"] == 0:
                label_parts.append(s["label"])
            else:
                label_parts.append(f"Correlated: {s['label']}")
        full_label = "  +  ".join(label_parts)

        # Overlap groups (observables returned by more than one step — typically the
        # pivot value the hunt correlated on) get a succinct heading + explanatory
        # subtitle; single-step groups keep the step name as the heading.
        if len(key) == 1:
            label = full_label
            sublabel = None
        else:
            label = "Found by Both Steps" if len(key) == 2 else "Found by Multiple Steps"
            if len(key) == 2 and key[0] == 0:
                sublabel = (
                    "returned by both the initial query and this correlated step — "
                    "typically the pivot value the hunt correlated on"
                )
            else:
                sublabel = "returned by multiple hunt steps: " + " + ".join(label_parts)

        # One color per contributing step. Single-step sections keep the exact color of
        # their Correlation Trace legend badge; overlap sections blend their members'
        # colors as a two-tone gradient in the template (so they never collide with a
        # single-step section's solid color).
        colors = [PROVENANCE_PALETTE[i % len(PROVENANCE_PALETTE)] for i in key]

        trace_steps = [
            {"index": s["index"], "label": s["label"], "property_name": s.get("property_name")}
            for s in step_objs
            if s["index"] != 0 and s.get("property_name")
        ]

        key_str = "-".join(str(i) for i in key)
        groups.append({
            "key": key_str,
            "anchor_id": f"provenance-group-{key_str}",
            "label": label,
            "full_label": full_label,
            "sublabel": sublabel,
            "colors": colors,
            "steps": list(key),
            "trace_steps": trace_steps,
            "observable_uuids": buckets[key],
        })

    return groups or None


class ObservablePresenterContext(NamedTuple):
    """The two per-observable database answers the action menu needs, looked up
    in bulk for the whole alert.

    Without this every ObservablePresenter re-queries for itself, and
    default_observable.html reads available_actions three times per observable
    node -- on a large alert that was thousands of round-trips per render, half
    of them going through run_async_with_session. The view already has both
    answers batched, so it hands them to the presenters instead.
    """
    detections: dict          # observable uuid -> ObservableDetectionSummary
    interesting: dict         # observable uuid -> True

    def presenter_kwargs(self, observable) -> dict:
        """The batched answers for one observable, as ObservablePresenter kwargs.

        Both dicts only carry the observables that *have* the flag set, matching
        observable_is_set_for_detection() / observable_is_interesting().
        """
        return {
            "detection_status": observable.uuid in self.detections,
            "is_interesting": observable.uuid in self.interesting,
        }


class TreeNode:
    def __init__(self, obj, parent=None, prune_volatile=False, presenter_context=None):
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
        # batched observable lookups shared by every node in this tree, or None
        # when the caller has none to give (the presenter then queries itself)
        self.presenter_context = presenter_context

        # set the analysis presenter
        if isinstance(obj, Analysis):
            self.presenter = create_analysis_presenter(obj)
        elif isinstance(obj, Observable):
            presenter_kwargs = presenter_context.presenter_kwargs(obj) if presenter_context else {}
            self.presenter = create_observable_presenter(obj, **presenter_kwargs)

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
    def default_collapsed(self):
        if not self.is_analysis or self.is_root_analysis:
            return False
        try:
            config = get_config().get_analysis_module_config_by_module_path(self.obj.module_path)
            if config is not None:
                return config.default_collapsed
        except Exception:
            pass
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
        if observable.ignored:
            continue
        child_node = TreeNode(
            observable,
            prune_volatile=current_node.prune_volatile,
            presenter_context=current_node.presenter_context)
        current_node.add_child(child_node)

        # if the observable is already in the current tree then we want to display a link to the existing analysis display
        if observable.uuid in node_tracker:
            child_node.refer_to(node_tracker[observable.uuid])
            continue

        node_tracker[observable.uuid] = child_node

        for observable_analysis in [a for a in observable.all_analysis if a]:
            observable_analysis_node = TreeNode(
                observable_analysis,
                prune_volatile=current_node.prune_volatile,
                presenter_context=current_node.presenter_context)
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
    alert_tags = filter_special_tags(sorted(all_tags, key=lambda x: (-get_tag_score(x), x.lower())))
    # we don't show "special" tags in the display
    special_tag_names = [tag for tag in get_config().tags.keys() if get_config().tags[tag] == 'special']
    alert_tags = [tag for tag in alert_tags if tag not in special_tag_names]

    # XXX refactor this omg
    # get all of the current observable detection data
    observable_detections = get_all_observable_detections(alert.root_analysis)

    detection_chain_merged_tree = build_merged_detection_tree(build_detection_chains(alert.root_analysis))

    # get all observable comments for the analysis tree
    all_observables = list(alert.root_analysis.all_observables)
    observable_comments = run_async_with_session(get_comments_for_observables, all_observables)
    observable_db_ids = run_async_with_session(get_observable_db_ids, all_observables)

    # map the usernames that manually added observables to their display names
    added_by_usernames = {obs.added_by for obs in all_observables if obs.added_by}
    observable_added_by_display = {}
    if added_by_usernames:
        for user in get_db().query(User).filter(User.username.in_(added_by_usernames)):
            observable_added_by_display[user.username] = user.gui_display

    # get all interesting observables for this alert
    sha256_list = [obs.sha256_bytes for obs in all_observables]
    db_interesting = run_async_with_session(get_interesting_observables_by_hashes, sha256_list)
    interesting_observables = {}
    for db_obs in db_interesting:
        for obs in all_observables:
            if obs.type == db_obs.type and obs.sha256_bytes == db_obs.sha256:
                interesting_observables[obs.uuid] = True
                break
    interesting_observable_list = [
        obs for obs in all_observables
        if obs.uuid in interesting_observables
    ]

    # the batched answers the observable action menus need, so that no presenter
    # in the display tree has to look them up for itself
    observable_presenter_context = ObservablePresenterContext(
        detections=observable_detections,
        interesting=interesting_observables)

    # disposition history for every observable in one query -- default_observable.html
    # reads it twice per rendered node, and the per-observable form is a 3-table
    # aggregate join
    observable_disposition_history = get_observable_disposition_histories(all_observables)

    # compute the display tree

    # are we viewing all analysis?
    # Always force prune to False to keep Detailed Analysis view (Critical Analysis is disabled)
    session['prune'] = False

    # are we viewing volatile analysis?
    if 'prune_volatile' not in session:
        session['prune_volatile'] = True
    elif not isinstance(session['prune_volatile'], bool):
        session['prune_volatile'] = True

    # we only display the tree if we're looking at the alert
    display_tree = None
    if alert.root_analysis is analysis:
        display_tree = TreeNode(
            analysis,
            prune_volatile=session['prune_volatile'],
            presenter_context=observable_presenter_context)
        _recurse(display_tree)
        _sort(display_tree)
        if session['prune_volatile']:
            _prune(display_tree)
            # root node is visible
            display_tree.visible = True

            # if the show_root_observables config option is True then
            # also all observables in the root node
            if get_config().gui.show_root_observables:
                for child in display_tree.children:
                    child.visible = True

            _resolve_references(display_tree)

    # For correlated-hunt alerts, group the Analysis Overview's top-level observables by
    # the hunt step that produced them. None for every other alert (renders flat as today).
    provenance_groups = None
    provenance_attributed_uuids = set()
    if alert.root_analysis is analysis:
        provenance_groups = build_provenance_groups(alert.root_analysis)
        if provenance_groups:
            for group in provenance_groups:
                provenance_attributed_uuids |= group["observable_uuids"]

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

    # Aggregate remediation events from any analysis in the tree that publishes them
    # plus ACE's own email_delivery remediation attempts from the DB
    # (see saq/remediation/timeline.py). ACE rows have no native received_time,
    # so we pass the alert's overall event_time as a fallback. The template
    # renders an alert-level timeline card when this list is non-empty.
    remediation_timeline_events = gather_remediation_events(
        alert.root_analysis,
        fallback_event_time=alert.root_analysis.event_time,
    )

    # Summarize in-flight / terminal external remediation probe activity for
    # this alert. The template renders a small footer under the timeline card
    # so analysts can see "we're still polling Defender" even when no events
    # have been confirmed yet. See saq/remediation/external/.
    external_check_footer = summarize_alert_checks(
        get_external_checks_for_alert(alert.uuid)
    )

    # the Remediation Timeline heading carries the same coverage badge as the alert list
    remediation_coverage = get_remediation_coverage([alert])

    # Aggregate URL-click state from any analysis in the tree that publishes it
    # (see saq/clicker_detection/timeline.py). The template renders an alert-level
    # "URL Clicks" card whenever detection ran (url_clicks.ran) — even with zero events —
    # so analysts can see the searches were performed and came back clean.
    url_clicks = gather_clicker_results(alert.root_analysis)

    import saq.constants

    # Phase 3 follow-up: precompute (module_path, observable_uuid) -> delta
    # for any module execution flagged as a cache hit. Lets the analysis-tree
    # macro answer "is this analysis a cache replay?" in O(1) per node.
    cache_hit_map = {
        (delta.module_path, delta.observable_uuid): delta
        for delta in alert.root_analysis.module_executions
        if delta.from_cache_hit
    }

    return render_template(
        'analysis/index.html',
        alert=alert,
        cache_hit_map=cache_hit_map,
        remediation_timeline_events=remediation_timeline_events,
        external_check_footer=external_check_footer,
        remediation_coverage=remediation_coverage,
        url_clicks_events=url_clicks.events,
        url_clicks_ran=url_clicks.ran,
        url_clicks_errors=url_clicks.errors,
        alert_tags=alert_tags,
        observable=observable,
        observable_presenter=create_observable_presenter(
            observable, **observable_presenter_context.presenter_kwargs(observable)) if observable else None,
        analysis=analysis,
        analysis_presenter=create_analysis_presenter(analysis) if analysis else None,
        ace_config=get_config(),
        User=User,
        db=get_db(),
        current_time=datetime.now(),
        directives={directive: DIRECTIVE_DESCRIPTIONS[directive] for directive in sorted(GUI_DIRECTIVES)},
        display_tree=display_tree,
        provenance_groups=provenance_groups,
        provenance_attributed_uuids=provenance_attributed_uuids,
        prune_display_tree=session['prune'],
        prune_volatile=session['prune_volatile'],
        open_events=open_events,
        closed_events=closed_events,
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
        observable_disposition_history=observable_disposition_history,
        observable_comments=observable_comments,
        observable_added_by_display=observable_added_by_display,
        observable_db_ids=observable_db_ids,
        interesting_observables=interesting_observables,
        interesting_observable_list=interesting_observable_list,
        observable_types=run_async(get_observable_types()),
        detection_chain_merged_tree=detection_chain_merged_tree,
        detection_chain_module_display_name=module_display_name,
        detection_chain_observable_display_value=observable_display_value,
    )