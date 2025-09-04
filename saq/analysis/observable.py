
from datetime import UTC, datetime
import hashlib
import importlib
import inspect
import logging
from typing import TYPE_CHECKING, Optional, Union
import uuid
from saq.analysis.detectable import DetectionManager
from saq.analysis.file_manager.file_manager_interface import FileManagerInterface
from saq.analysis.module_path import CLASS_STRING_REGEX, IS_MODULE_PATH, MODULE_PATH, SPLIT_MODULE_PATH
from saq.analysis.relationship import Relationship
from saq.analysis.search import search_down
from saq.analysis.serialize.observable_serializer import ObservableSerializer
from saq.analysis.sortable import SortManager
from saq.analysis.taggable import TagManager
from saq.analysis.event_source import EventSource
from saq.configuration import get_config_value
from saq.constants import CONFIG_OBSERVABLE_EXPIRATION_MAPPINGS, EVENT_ANALYSIS_ADDED, EVENT_DIRECTIVE_ADDED, EVENT_RELATIONSHIP_ADDED, EVENT_TIME_FORMAT_TZ, F_TEST, VALID_RELATIONSHIP_TYPES
from saq.environment import get_local_timezone
from saq.util import create_timedelta, parse_event_time

if TYPE_CHECKING:
    from saq.analysis.analysis import Analysis
    from saq.analysis.analysis_tree.analysis_tree_manager import AnalysisTreeManager
    from saq.remediation import RemediationTarget

class Observable(EventSource):
    """Represents a piece of information discovered in an analysis that can itself be analyzed."""

    def __init__(self, type: Optional[str]=None, value: Optional[str]=None, time: Union[str, datetime, None]=None, volatile: bool=False, sort_order: int=100, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._directives = []
        self._redirection = None
        self._links = []
        self._limited_analysis = []
        self._excluded_analysis = []
        self._relationships = []
        self._grouping_target = False
        self._volatile = volatile
        self._db = None

        self._id = str(uuid.uuid4())
        self._type = type
        self.value = value
        self._time = time
        self._analysis = {}
        self._directives = [] # of str
        self._redirection = None # (str)
        self._links = [] # [ str ]
        self._limited_analysis = [] # [ str ]
        self._excluded_analysis = [] # [ str ]
        self._relationships = [] # [ Relationship ]
        self._grouping_target = False
        self._volatile = volatile

        # reference to the AnalysisTreeManager object
        self._analysis_tree_manager: Optional["AnalysisTreeManager"] = None # injected
        self._file_manager: Optional[FileManagerInterface] = None # injected

        # composition-based component managers
        self._tag_manager = TagManager(event_source=self)
        self._detection_manager = DetectionManager(event_source=self)
        self._sort_manager = SortManager(sort_order=sort_order)

        self._cache_id = None
        self._faqueue_hits = None
        self._faqueue_search_url = None
        self._matching_events_by_status = None

        # runtime state 
        self._sha256_hasher = None

        # a list of documents that will be used to generate LLM context
        # each document becomes a vector embedding
        self.llm_context_documents: list[str] = []

    # temporary backwards compatibility
    # TODO this gets moved to some display layer we build when we refactor the gui
    @property
    def disposition_history(self):
        from saq.database.database_observable import get_observable_disposition_history
        return get_observable_disposition_history(self)

    # injection methods
    # ------------------------------------------------------------------------

    def inject_analysis_tree_manager(self, analysis_tree_manager: "AnalysisTreeManager"):
        self.analysis_tree_manager = analysis_tree_manager

    def inject_file_manager(self, file_manager: FileManagerInterface):
        self.file_manager = file_manager

    @property
    def analysis_tree_manager(self) -> "AnalysisTreeManager":
        if self._analysis_tree_manager is None:
            raise RuntimeError("analysis_tree_manager is not set")

        return self._analysis_tree_manager

    @analysis_tree_manager.setter
    def analysis_tree_manager(self, value: "AnalysisTreeManager"):
        self._analysis_tree_manager = value

    @property
    def file_manager(self) -> FileManagerInterface:
        if self._file_manager is None:
            raise RuntimeError("file_manager is not set")

        return self._file_manager
    
    @file_manager.setter
    def file_manager(self, value: FileManagerInterface):
        assert isinstance(value, FileManagerInterface)
        self._file_manager = value

    # JSON serialization methods
    # ------------------------------------------------------------------------

    @staticmethod
    def from_json(json_data) -> Optional["Observable"]:
        """Returns an object inheriting from Observable built from the given json."""
        from saq.observables import create_observable
        from saq.analysis.serialize.observable_serializer import KEY_TYPE, KEY_VALUE, KEY_VOLATILE
        result = create_observable(json_data[KEY_TYPE], json_data[KEY_VALUE], volatile=json_data.get(KEY_VOLATILE))
        if result:
            # XXX refactor this logic out
            # if the observable value was normalized, we don't want to overwrite that with the original JSON
            # exclude this for test values as they're a little different
            if result.value != json_data[KEY_VALUE] and json_data[KEY_TYPE] != F_TEST:
                json_data.pop(KEY_VALUE)

            result.json = json_data
            return result

        return None

    @property
    def json(self):
        return ObservableSerializer.serialize(self)

    @json.setter
    def json(self, value):
        ObservableSerializer.deserialize(self, value)

    # observable properties and methods
    # ------------------------------------------------------------------------

    @property
    def whitelisted(self) -> bool:
        """Returns True if this observable has been whitelisted."""
        return self.has_tag('whitelisted') or self.has_directive('whitelisted')

    def whitelist(self):
        """Utility function to mark this Observable as whitelisted by adding the tag 'whitelisted'."""
        self.add_tag('whitelisted')
        self.add_directive('whitelisted')

    def matches(self, value: str) -> bool:
        """Returns True if the given value matches this value of this observable.
        This can be overridden to provide more advanced matching such as CIDR for ipv4."""
        return self.value == value


    # tag management
    # ------------------------------------------------------------------------

    @property
    def tags(self):
        return self._tag_manager.tags

    @tags.setter
    def tags(self, value):
        self._tag_manager.tags = value

    def add_tag(self, *args, **kwargs):
        self._tag_manager.add_tag(*args, **kwargs)
        for target in self.links:
            target.add_tag(*args, **kwargs)

    def remove_tag(self, tag):
        self._tag_manager.remove_tag(tag)

    def clear_tags(self):
        self._tag_manager.clear_tags()

    def has_tag(self, tag_value):
        """Returns True if this object has this tag."""
        return self._tag_manager.has_tag(tag_value)

    # detection management
    # ------------------------------------------------------------------------

    @property
    def detections(self):
        return self._detection_manager.detections

    @detections.setter
    def detections(self, value):
        self._detection_manager.detections = value

    def has_detection_points(self):
        """Returns True if this object has at least one detection point, False otherwise."""
        return self._detection_manager.has_detection_points()

    def add_detection_point(self, description, details=None):
        """Adds the given detection point to this object."""
        self._detection_manager.add_detection_point(description, details)

    def clear_detection_points(self):
        self._detection_manager.clear_detection_points()

    # sort management
    # ------------------------------------------------------------------------

    @property
    def sort_order(self):
        return self._sort_manager.sort_order

    @sort_order.setter
    def sort_order(self, value):
        self._sort_manager.sort_order = value

    # observable properties and methods
    # ------------------------------------------------------------------------

    @property
    def id(self) -> str:
        """A unique ID for this Observable instance."""
        return self._id

    @id.setter
    def id(self, value: str):
        assert isinstance(value, str)
        self._id = value

    @property
    def volatile(self) -> bool:
        """Returns True if this node is a volatile node, False otherwise."""
        return self._volatile

    @volatile.setter
    def volatile(self, value: bool):
        assert isinstance(value, bool)
        self._volatile = value

    @property
    def type(self) -> str:
        return self._type

    @type.setter
    def type(self, value: str):
        self._type = value

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, value):
        self._value = value

    def _initialize_sha256_hasher(self) -> hashlib.sha256:
        if self._sha256_hasher is None:
            self._sha256_hasher = hashlib.sha256()
            self._sha256_hasher.update(self.value.encode('utf8', errors='ignore'))

        return self._sha256_hasher

    @property
    def sha256_hash(self) -> str:
        """Returns the hexidecimal SHA256 hash of the value of this observable."""
        return self._initialize_sha256_hasher().hexdigest()

    @property
    def sha256_bytes(self) -> bytes:
        """Returns the bytes of the SHA256 hash of the value of this observable."""
        return self._initialize_sha256_hasher().digest()

    @property
    def time(self):
        return self._time

    @time.setter
    def time(self, value):
        if value is None:
            self._time = None
        elif isinstance(value, datetime):
            # if we didn't specify a timezone then we use the timezone of the local system
            if value.tzinfo is None:
                value = get_local_timezone().localize(value)
            self._time = value
        elif isinstance(value, str):
            self._time = parse_event_time(value)
        else:
            raise ValueError("time must be a datetime object or a string in the format "
                             "%Y-%m-%d %H:%M:%S %z but you passed {}".format(type(value).__name__))

    @property
    def directives(self):
        return self._directives

    @directives.setter
    def directives(self, value):
        assert isinstance(value, list)
        self._directives = value

    @property
    def remediation_targets(self) -> list["RemediationTarget"]:
        """Returns a list of remediation targets for the observable, by default this is an empty list."""
        return []

    def add_directive(self, directive):
        """Adds a directive that analysis modules might use to change their behavior."""
        assert isinstance(self.directives, list)
        if directive not in self.directives:
            self.directives.append(directive)
            logging.debug("added directive {} to {}".format(directive, self))
            self.fire_event(self, EVENT_DIRECTIVE_ADDED, directive)

    def has_directive(self, directive):
        """Returns True if this Observable has this directive."""
        if self.directives:
            return directive in self.directives

        return False

    def remove_directive(self, directive):
        """Removes the given directive from this observable."""
        if directive in self.directives:
            self.directives.remove(directive)
            logging.debug("removed directive {} from {}".format(directive, self))

    def copy_directives_to(self, target):
        """Copies all directives applied to this Observable to another Observable."""
        assert isinstance(target, Observable)
        for directive in self.directives:
            target.add_directive(directive)

    @property
    def redirection(self):
        if not self._redirection:
            return None

        return self.analysis_tree_manager.get_observable_by_id(self._redirection)

    @redirection.setter
    def redirection(self, value):
        assert isinstance(value, Observable)
        self._redirection = value.id

    @property
    def links(self):
        if not self._links:
            return []

        return [self.analysis_tree_manager.get_observable_by_id(x) for x in self._links]

    @links.setter
    def links(self, value):
        assert isinstance(value, list)
        for v in value:
            assert isinstance(v, Observable)

        self._links = [x.id for x in value]

    def add_link(self, target):
        """Links this Observable object to another Observable object.  Any tags
           applied to this Observable are also applied to the target Observable."""

        assert isinstance(target, Observable)

        # two observables cannot link to each other
        # that would cause a recursive loop in add_tag override
        if self in target.links:
            logging.warning("{} already links to {}".format(target, self))
            return
        
        if target.id not in self._links:
            self._links.append(target.id)

        logging.debug("linked {} to {}".format(self, target))

    @property
    def limited_analysis(self):
        return self._limited_analysis

    @limited_analysis.setter
    def limited_analysis(self, value):
        assert isinstance(value, list)
        assert all([isinstance(x, str) for x in value])
        self._limited_analysis = value

    def limit_analysis(self, analysis_module):
        """Limit the analysis of this observable to the analysis module specified by configuration section name.
           For example, if you have a section for a module called [analysis_module_something] then you would pass
           the value "something" as the analysis_module."""
        from saq.modules import AnalysisModule
        assert isinstance(analysis_module, str) or isinstance(analysis_module, AnalysisModule)

        if isinstance(analysis_module, AnalysisModule):
            self._limited_analysis.append(analysis_module.config_section_name)
        else:
            self._limited_analysis.append(analysis_module)

    @property
    def excluded_analysis(self):
        """Returns a list of analysis modules in the form of module:class that are excluded from analyzing this Observable."""
        return self._excluded_analysis

    @excluded_analysis.setter
    def excluded_analysis(self, value):
        assert isinstance(value, list)
        self._excluded_analysis = value

    def exclude_analysis(self, analysis_module, instance=None):
        """Directs the engine to avoid analyzing this Observabe with this AnalysisModule.
           analysis_module can be an instance of type AnalysisModule or the type of the AnalysisModule itself"""
        from saq.modules import AnalysisModule
        # TODO check that the type inherits from AnalysisModule
        assert isinstance(analysis_module, type) or isinstance(analysis_module, AnalysisModule)
        if isinstance(analysis_module, AnalysisModule):
            _type = type(analysis_module)
            instance = analysis_module.instance
        else:
            _type = analysis_module

        name = '{}:{}'.format(analysis_module.__module__, str(_type))
        if instance is not None:
            name += f'{instance}'

        if name not in self.excluded_analysis:
            self.excluded_analysis.append(name)

    def is_excluded(self, analysis_module):
        """Returns True if this Observable has been excluded from analysis by this AnalysisModule."""
        from saq.modules import AnalysisModule
        assert isinstance(analysis_module, AnalysisModule)
        name = '{}:{}'.format(analysis_module.__module__, str(type(analysis_module)))
        if analysis_module.instance is not None:
            name += f'{analysis_module.instance}'

        return name in self.excluded_analysis

    def remove_analysis_exclusion(self, analysis_module, instance=None):
        """Removes AnalysisModule exclusion added to this observable, allowing it to be run again.
            Example use case: AnalysisModule excluded automatically to prevent recursion, but removed manually by analyst via GUI.
             USE CAREFULLY!"""
        from saq.modules import AnalysisModule
        assert isinstance(analysis_module, type) or isinstance(analysis_module, AnalysisModule)
        if isinstance(analysis_module, AnalysisModule):
            _type = type(analysis_module)
            instance = analysis_module.instance
        else:
            _type = analysis_module

        name = f'{analysis_module.__module__}:{str(_type)}'
        if instance is not None:
            name += f'{instance}'

        while name in self.excluded_analysis:
            self.excluded_analysis.remove(name)

    @property
    def relationships(self):
        return self._relationships

    @relationships.setter
    def relationships(self, value):
        self._relationships = value

    def has_relationship(self, _type):
        for r in self.relationships:
            if r.r_type == _type:
                return True

        return False

    def _load_relationships(self):
        temp = []
        for value in self.relationships:
            if isinstance(value, dict):
                r = Relationship()
                r.json = value

                try:
                    # XXX very hacky
                    # find the observable this points to and reference that
                    r.target = self.analysis_tree_manager.get_observable_by_id(r.target)
                except KeyError:
                    logging.error("missing observable uuid {} in {}".format(r.target, self))
                    continue

                value = r

            temp.append(value)

        self._relationships = temp

    def add_relationship(self, r_type, target):
        """Adds a new Relationship to this Observable.
           Existing relationship is returned, other new Relationship object is added and returned."""
        assert r_type in VALID_RELATIONSHIP_TYPES
        assert isinstance(target, Observable)

        for r in self.relationships:
            if r.r_type == r_type and r.target == target:
                return r

        r = Relationship(r_type, target)
        self.relationships.append(r)
        self.fire_event(self, EVENT_RELATIONSHIP_ADDED, target, relationship=r)
        return r

    def get_relationships_by_type(self, r_type):
        """Returns the list of Relationship objects by type."""
        return [r for r in self.relationships if r.r_type == r_type]

    def get_relationship_by_type(self, r_type):
        """Returns the first Relationship found of a given type, or None if none exist."""
        result = self.get_relationships_by_type(r_type)
        if not result:
            return None

        return result[0]

    #
    # GROUPING TARGETS
    #
    # When an AnalysisModule uses the observation_grouping_time_range configuration option, ACE will select a 
    # single Observable to analyze that falls within that time range. ACE will then *also* set the grouping_target
    # property of that Observable to True.
    # Then the next time another AnalysisModule which also groups by time is looking for an Observable to analyze
    # out of a group of Observables, it will select the (first) one that has grouping_target set to True.
    # This is so that most of the Analysis for grouped targets go into the same Observable, so that they're not
    # all spread out in the graphical view.
    #

    @property
    def grouping_target(self):
        """Retruns True if this Observable has become a grouping target."""
        return self._grouping_target

    @grouping_target.setter
    def grouping_target(self, value):
        assert isinstance(value, bool)
        self._grouping_target = value

    @property
    def analysis(self):
        """The dict of Analysis objects executed against this Observable.
           key = Analysis.module_path, value = Analysis or False."""
        return self._analysis

    @analysis.setter
    def analysis(self, value):
        assert isinstance(value, dict)
        self._analysis = value

    @property
    def all_analysis(self):
        from saq.analysis.analysis import Analysis
        """Returns a list of an Analysis objects executed against this Observable."""
        # we skip over lookups that return False here
        return [a for a in self._analysis.values() if isinstance(a, Analysis)]

    @property
    def children(self):
        """Returns what is considered all of the "children" of this object (in this case it is the Analysis.)"""
        return [a for a in self.all_analysis if a]

    @property
    def parents(self):
        """Returns a list of Analysis objects that have this Observable."""
        return [a for a in self.analysis_tree_manager.all_analysis if a and a.has_observable(self)]

    @property
    def dependencies(self):
        """Returns the list of all AnalysisDependency objects targeting this Observable."""
        return self.analysis_tree_manager.dependency_manager.get_dependencies_for_observable(self.id)

    def add_dependency(self, source_analysis, source_analysis_instance, target_observable, target_analysis, target_analysis_instance):
        from saq.analysis.analysis import Analysis
        assert inspect.isclass(source_analysis) and issubclass(source_analysis, Analysis)
        assert source_analysis_instance is None or isinstance(source_analysis_instance, str)
        assert isinstance(target_observable, Observable)
        assert inspect.isclass(target_analysis) and issubclass(target_analysis, Analysis)
        assert target_analysis_instance is None or isinstance(target_analysis_instance, str)
        
        self.analysis_tree_manager.dependency_manager.add_dependency(self, source_analysis, source_analysis_instance, target_observable, target_analysis, target_analysis_instance)

    def get_dependency(self, _type):
        assert isinstance(_type, str)
        return self.analysis_tree_manager.dependency_manager.get_dependency_by_type(self.id, _type)

    # this should only be called from the AnalysisTreeManager
    def add_analysis_to_tree(self, analysis: "Analysis", parent: "Observable") -> "Analysis":
        """Adds the Analysis to this Observable.  Returns the Analysis object."""
        from saq.analysis.analysis import Analysis
        assert isinstance(analysis, Analysis)
        assert isinstance(parent, Observable)

        self._analysis[analysis.module_path] = analysis
        self.fire_event(self, EVENT_ANALYSIS_ADDED, analysis)

        return analysis

    def add_analysis(self, analysis: "Analysis") -> "Analysis":
        return self.analysis_tree_manager.add_analysis(self, analysis)

    def add_no_analysis(self, analysis: "Analysis", instance: Optional[str]=None):
        """Records the fact that the analysis module that generates this Analysis did not for this Observable."""
        self.analysis_tree_manager.add_no_analysis(self, analysis, instance)

    def get_analysis(self, obj, instance=None):
        """Returns the Analysis object for the given type of analysis, or None if it does not exist (yet).
           :param obj: Can be any of the following types of values.
           * (type) a literal :class:`Analysis` based type
           * (AnalysisModule) an object of type :class:`AnalysisModule`
           * (str) a string format of the Analysis based type (example: "<class 'saq.modules.email.EmailAnalysis'>")
           * (str) a string of the name of the Analysis class (example: EmailAnalysis)
           * (str) a string in the MODULE_PATH format (example: saq.modules.email.EmailAnalysis:instance1)
           :param instance: Optional instance value for instanced modules. This is ignored if analysis_type is already a type.
    
           :return: 
           * The :class:`Analysis` that was added for this :class:`Observable` or
           * False if the analysis was not performed (or was skipped) or
           * None if the analysis is not available (was not loaded at the time of analysis.)
        """
        from saq.analysis.analysis import Analysis
        from saq.modules import AnalysisModule
        assert isinstance(obj, str) or isinstance(obj, AnalysisModule) or (inspect.isclass(obj) and issubclass(obj, Analysis))
        assert instance is None or isinstance(instance, str)

        try:
            # did we pass an Analysis type?
            if inspect.isclass(obj) and issubclass(obj, Analysis):
                return self.analysis[MODULE_PATH(obj, instance=instance)]
            elif isinstance(obj, AnalysisModule):
                return self.analysis[MODULE_PATH(obj)]
        except KeyError:
            return None

        # did we pass a MODULE_PATH?
        if IS_MODULE_PATH(obj):
            try:
                return self.analysis[obj]
            except KeyError:
                #logging.error(f"reference to missing module {obj}")
                #import traceback
                #traceback.print_stack()
                #raise RuntimeError()
                return None

        # str(type(Analysis)) will end up looking like this: <class 'saq.modules.test.BasicTestAnalysis'>
        # where the keys in self.analysis look like this: saq.modules.test:BasicTestAnalysis[:instance]
        # (I do not remember why it's like that)
        # so we translate the first into the second
        #
        # 10/28/2019 -- at this point in time I believe nothing should be using this to reference modules

        m = CLASS_STRING_REGEX.match(obj)
        if m:
            class_path = m.group(1)
            class_path_rw = list(class_path)
            
            class_path_rw[class_path.rfind('.')] = ':'
            class_path = ''.join(class_path_rw)

            if instance is not None:
                class_path += f':{instance}'

            logging.warning(f"CLASS_STRING_REGEX was used for {obj}")

            try:
                return self.analysis[class_path]
            except KeyError:
                #logging.error("reference to missing module {class_path} reference via {obj}")
                return None

        # otherwise we passed the name of the class
        for analysis_key in self.analysis.keys():
            _module, _class, _instance = SPLIT_MODULE_PATH(analysis_key)
            if _class == obj:
                return self.analysis[analysis_key]

        #logging.debug(f"request for unknown obj {obj} instance {instance} for {self}")
        return None

    def get_and_load_analysis(self, obj, instance=None):
        result = self.get_analysis(obj, instance)
        if result:
            result.load_details()

        return result

    def get_and_load_analysis_by_type(self, analysis_type):
        """Returns a list of Analysis objects of the given type that were performed on this observable"""
        result = [analysis for analysis in self.all_analysis if isinstance(analysis, analysis_type)]
        for analysis in result:
            analysis.load_details()

        return result

    def get_analysis_by_type(self, analysis_type):
        """Returns a list of Analysis objects of the given type that were performed on this observable"""
        return [a for a in self.all_analysis if isinstance(a, analysis_type)]

    def _load_analysis(self):
        from saq.analysis.analysis import Analysis, UnknownAnalysis
        assert isinstance(self.analysis, dict)

        # see the module_path property of the Analysis object
        for module_path in self.analysis.keys():
            # was there Analysis generated?
            if isinstance(self.analysis[module_path], bool):
                continue
                
            # have we already translated this?
            if isinstance(self.analysis[module_path], Analysis):
                continue

            assert isinstance(self.analysis[module_path], dict)

            try:
                _module_name, _class_name, _instance = SPLIT_MODULE_PATH(module_path)
                _module = importlib.import_module(_module_name)
                _class = getattr(_module, _class_name)
                analysis = _class()

            except Exception as e:
                logging.warning(f'unable to load analysis: {e}')
                analysis = UnknownAnalysis(module_path)

            analysis.observable = self # set the source of the analysis
            # XXX this is a hack to get this working for now, revisit when serialization move out of these classes
            analysis.file_manager = self.file_manager
            analysis.json = self.analysis[module_path]

            # set up the EVENT_GLOBAL_* events
            #analysis.root.event_bus.setup_analysis_event_propagation(analysis)

            self.analysis[module_path] = analysis # replace the JSON dict with the actual object

    def clear_analysis(self):
        """Deletes all analysis records for this observable."""
        self.analysis = {}

    def is_on_detection_path(self) -> bool:
        """Returns True if this node or any node down to (but not including) the root has a detection point."""
        from saq.analysis.root import RootAnalysis
        if self.has_detection_points():
            return True

        return search_down(self, lambda obj: False if isinstance(obj, RootAnalysis) else obj.has_detection_points()) is not None

    def is_managed(self) -> bool:
        """Returns True if this observable is considered to be managed. The definition of that is likely to change
        based on the company using this."""
        return False

    # TODO: display stuff needs to come out

    # LLM context management
    # ------------------------------------------------------------------------

    def add_llm_context_document(self, document: str):
        """Add a document to this observable."""
        self.llm_context_documents.append(document)

    @property
    def display_preview(self) -> Optional[str]:
        """Returns a value that can be used by a display to preview the observation."""
        return None 

    @property
    def display_type(self):
        for directive in self.directives:
            if directive.startswith('display_type_'):
                return directive[len('display_type_'):]
        return self.type

    @property
    def display_value(self):
        for directive in self.directives:
            if directive.startswith('display_value_'):
                return directive[len('display_value_'):]

        if isinstance(self.value, str):
            try:
                return self.value.encode('utf-8', errors='ignore').decode()
            except Exception as e:
                logging.warning("unable to decode value: {}".format(e))
        else:
            return self.value

    @display_value.setter
    def display_value(self, value: str):
        # remove any existing display value setting
        self.directives = [_ for _ in self.directives if not _.startswith('display_value_')]
        self.add_directive(f"display_value_{value}")

    @property
    def display_time(self):
        if self.time is None:
            return ''

        return self.time.strftime(EVENT_TIME_FORMAT_TZ)

    def always_visible(self) -> bool:
        """If this returns True then this Analysis is always visible in the GUI."""
        return False


    def __str__(self):
        if self.time is not None:
            return u'{}({}@{})'.format(self.type, self.value, self.time)
        else:
            return u'{}({})'.format(self.type, self.value)

    def _compare_value(self, other_value):
        """Default implementation to compare the value of this observable to the value of another observable.
           By default does == comparison, can be overridden."""
        return self.value == other_value

    def __eq__(self, other):
        if not isinstance(other, Observable):
            return False

        # exactly the same?
        if other.id == self.id:
            return True

        if other.type != self.type:
            return False

        if self.time is not None or other.time is not None:
            return self.time == other.time and self._compare_value(other.value)
        else:
            return self._compare_value(other.value)

    def __lt__(self, other):
        if not isinstance(other, Observable):
            return False

        if other.type == self.type:
            return self.value < other.value

        return self.type < other.type

    def __hash__(self):
        """Returns the hash of type:value."""
        return str(self).__hash__() # XXX this isn't right, is it?

def get_observable_type_expiration_time(observable_type: str) -> Union[datetime, None]:
    """Calculates the observable expiration datetime based on now + the configured time delta for this observable type."""
    delta = get_config_value(CONFIG_OBSERVABLE_EXPIRATION_MAPPINGS, observable_type)

    if delta:
        try:
            return datetime.now(UTC) + create_timedelta(delta)
        except:
            logging.error(f'Observable type {observable_type} has an invalid expiration mapping: {delta}')

    return None
