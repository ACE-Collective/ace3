# vim: ts=4:sw=4:et

import csv
import fnmatch
import logging
import os.path
import re
import ipaddress
from typing import Optional, Type, Union
from pydantic import Field, ConfigDict

from saq.analysis import Analysis
from saq.configuration.config import get_config
from saq.constants import CONFIG_TAGS
from saq.database.model import Observable
from saq.database.pool import get_db_connection
from saq.environment import get_base_dir
from saq.modules import AnalysisModule
from saq.modules.base_module import AnalysisExecutionResult
from saq.modules.config import AnalysisModuleConfig
from saq.util import is_subdomain

KEY_TAGS_ADDED = "tags_added"
KEY_TAGS_DETECTABLE = "tags_detectable"

class SiteTagAnalyzerConfig(AnalysisModuleConfig):
    csv_file: str = Field(..., description="The CSV file that contains the tagging definitions.")

class CorrelatedTagAnalyzerConfig(AnalysisModuleConfig):
    # Dynamic keys like definition_001_rule, definition_001_text are allowed via extra fields
    model_config = ConfigDict(extra='allow')

class ConfigurationDefinedTaggingAnalysis(Analysis):
    """Tags observables defined in the configuration"""
    pass

class ConfigurationDefinedTaggingAnalyzer(AnalysisModule):
    """Tags observables defined in the configuration"""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.tag_mapping = self.load_config_tag_mapping()

    def load_config_tag_mapping(self) -> dict[str, str]:
        tag_mapping = {}
        for tag_name, tag_value in get_config().tags.items():
            tag_mapping[tag_name] = tag_value

        return tag_mapping

    def get_tag_mapping_value(self, tag_name: str) -> Optional[str]:
        return self.tag_mapping.get(tag_name)

    def is_alertable_tag(self, tag_name: str) -> bool:
        return self.get_tag_mapping_value(tag_name) in ['alert', 'critical', 'warning']

    @property
    def generated_analysis_type(self) -> Optional[Type[Analysis]]:
        return ConfigurationDefinedTaggingAnalysis

    def execute_analysis(self, observable: Observable) -> AnalysisExecutionResult:
        return AnalysisExecutionResult.COMPLETED
    
    def execute_post_analysis(self) -> AnalysisExecutionResult:
        alerted_tags = set()
        for obj in self.get_root().all:
            for tag in obj.tags:
                if self.is_alertable_tag(tag) and tag not in alerted_tags:
                    self.get_root().add_detection_point(f"tag {tag} is configured to be alertable")
                    alerted_tags.add(tag)

        return AnalysisExecutionResult.COMPLETED

class UserDefinedTaggingAnalysis(Analysis):
    """Tags observables defined in the database"""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_TAGS_ADDED: [],
        }

    @property
    def tags_added(self) -> list[str]:
        return self.details[KEY_TAGS_ADDED]
    
    @tags_added.setter
    def tags_added(self, value: list[str]):
        self.details[KEY_TAGS_ADDED] = value

    def generate_summary(self) -> Optional[str]:
        if not self.tags_added:
            return None
        
        return f"User Defined Tagging: added {len(self.tags_added)} tags"

class UserDefinedTaggingAnalyzer(AnalysisModule):
    """Tags observables defined in the database"""
    @property
    def generated_analysis_type(self) -> Optional[Type[Analysis]]:
        return UserDefinedTaggingAnalysis

    @property
    def valid_observable_types(self) -> Optional[Union[str, list[str], None]]:
        return None

    def execute_analysis(self, observable: Observable) -> AnalysisExecutionResult:
        analysis = self.create_analysis(observable)
        assert isinstance(analysis, UserDefinedTaggingAnalysis)

        try:
            with get_db_connection() as db:
                cursor = db.cursor()
                cursor.execute("""
                SELECT 
                    `tags`.`name`
                FROM 
                    observables
                JOIN 
                    observable_tag_mapping ON observables.id = observable_tag_mapping.observable_id
                    JOIN tags ON observable_tag_mapping.tag_id = tags.id
                WHERE 
                    `observables`.`type` = %s AND `observables`.`sha256` = UNHEX(%s)
                """, 
                (observable.type, observable.sha256_hash))

                for row in cursor:
                    if row[0]:
                        observable.add_tag(row[0])
                        analysis.tags_added.append(row[0])

        except Exception as e:
            logging.error(f"unable to fetch tags for {observable}: {e}")
            raise e

        return AnalysisExecutionResult.COMPLETED

class SiteTagAnalysis(Analysis):
    """Tags observables defined in etc/tags.csv"""
    pass

class _tag_mapping:

    MATCH_TYPE_DEFAULT = 'default'
    MATCH_TYPE_GLOB = 'glob'
    MATCH_TYPE_REGEX= 'regex'
    MATCH_TYPE_CIDR = 'cidr'
    MATCH_TYPE_SUBDOMAIN = 'subdomain'

    def __init__(self, match_type, ignore_case, value, tags):
        assert match_type in [ _tag_mapping.MATCH_TYPE_DEFAULT,
                               _tag_mapping.MATCH_TYPE_GLOB,
                               _tag_mapping.MATCH_TYPE_REGEX,
                               _tag_mapping.MATCH_TYPE_SUBDOMAIN,
                               _tag_mapping.MATCH_TYPE_CIDR ]
        assert isinstance(ignore_case, bool)
        assert value is not None
        assert isinstance(tags, list)
        assert all([isinstance(t, str) for t in tags])

        self.match_type = match_type
        self.ignore_case = ignore_case
        self.value = value
        self.tags = tags

        # if we have a regex go ahead and compile it
        if self.match_type == _tag_mapping.MATCH_TYPE_REGEX:
            self.compiled_regex = re.compile(self.value, flags=re.I if ignore_case else 0)

        # if we have a cidr go ahead and create the object used to match it
        if self.match_type == _tag_mapping.MATCH_TYPE_CIDR:
            self.compiled_cidr = ipaddress.ip_network(value)

    def __str__(self):
        return 'tag_mapping({} --> {})'.format(self.value, ','.join(self.tags))

    def matches(self, value):
        if self.match_type == _tag_mapping.MATCH_TYPE_DEFAULT:
            return self._matches_default(value)
        elif self.match_type == _tag_mapping.MATCH_TYPE_GLOB:
            return self._matches_glob(value)
        elif self.match_type == _tag_mapping.MATCH_TYPE_REGEX:
            return self._matches_regex(value)
        elif self.match_type == _tag_mapping.MATCH_TYPE_CIDR:
            return self._matches_cidr(value)
        elif self.match_type == _tag_mapping.MATCH_TYPE_SUBDOMAIN:
            return self._matches_subdomain(value)
        else:
            raise RuntimeError("invalid match type: {}".format(self.match_type))

    def _matches_default(self, value):
        if self.ignore_case:
            return self.value.lower() == value.lower()

        return self.value == value

    def _matches_glob(self, value):
        if self.ignore_case:
            return fnmatch.fnmatch(value, self.value)

        return fnmatch.fnmatchcase(value, self.value)

    def _matches_regex(self, value):
        return self.compiled_regex.search(value) is not None

    def _matches_cidr(self, value):
        try:
            return ipaddress.ip_address(value) in self.compiled_cidr
        except ValueError as e:
            logging.debug("{} did not parse out to be an ip/cidr: {}".format(value, e))
            return False

    def _matches_subdomain(self, value):
        # is value equal to or a subdomain of self.value?
        return is_subdomain(value, self.value)

class SiteTagAnalyzer(AnalysisModule):
    @classmethod
    def get_config_class(cls) -> Type[AnalysisModuleConfig]:
        return SiteTagAnalyzerConfig

    def load_exclusions(self):
        pass

    def is_excluded(self, observable):
        return False 

    def verify_environment(self):
        self.verify_path_exists(self.csv_file)

    @property
    def csv_file(self):
        path = self.config.csv_file
        if os.path.isabs(path):
            return path

        return os.path.join(get_base_dir(), path)

    @property
    def generated_analysis_type(self):
        return SiteTagAnalysis

    @property
    def valid_observable_types(self):
        return None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.tag_mapping = {} # key = type, value = [_tag_mapping]
        self.watch_file(self.csv_file, self.load_csv_file)

    def load_csv_file(self):
        # load the configuration
        with open(self.csv_file, 'r') as fp:
            for row in csv.reader(fp):
                try:
                    o_types, match_type, ignore_case, value, tags = row
                except Exception as e:
                    logging.error("invalid tag specification: {}: {}".format(','.join(row), e))
                    continue

                o_types = o_types.split('|')
                ignore_case = bool(ignore_case)
                tags = tags.split('|')

                mapper = _tag_mapping(match_type, ignore_case, value, tags)
                #logging.debug("created mapping {}".format(mapper))

                for o_type in o_types:
                    if o_type not in self.tag_mapping:
                        self.tag_mapping[o_type] = []

                    self.tag_mapping[o_type].append(mapper)

    def execute_analysis(self, observable) -> AnalysisExecutionResult:

        if observable.type not in self.tag_mapping:
            return AnalysisExecutionResult.COMPLETED

        analysis = self.create_analysis(observable)

        for mapper in self.tag_mapping[observable.type]:
            if mapper.matches(observable.value):
                logging.debug("{} matches {}".format(observable, mapper))
                for tag in mapper.tags:
                    observable.add_tag(tag)

        return AnalysisExecutionResult.COMPLETED

#
# NOTE - understanding how this logic works
# (A) --> (C) --> (alert)
# (B) --> (C)
# (B) --> (D) --> (alert)
# where (A) has tag t1 and (B) has tag t2

# (A) has t1 so tag_map[A] = (t1) and tag_map[C] = (t1)
# (B) has t2 so tag_map[B] = (t2) and tag_map[C] = (t1, t2)
# (t1, t2) matches the definition so C gets the detection point

class CorrelatedTagDefinition(object):
    def __init__(self, text, tags):
        # the textual description of the alert
        self.text = text
        # the list of tags we expect to see in the children of a target object
        self.tags = set(tags)

class CorrelatedTagAnalyzer(AnalysisModule):
    """Does this combination of tagging exist on objects with a common ancestry?"""
    @classmethod
    def get_config_class(cls) -> Type[AnalysisModuleConfig]:
        return CorrelatedTagAnalyzerConfig

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.definitions = []
        
        # Access config as dict for dynamic keys (definition_*_rule, definition_*_text)
        config_dict = self.config.model_dump()
        for config_item in config_dict.keys():
            if config_item.startswith('definition_') and config_item.endswith('_rule'):
                config_rule = config_item
                config_text = config_item.replace('_rule', '_text')
                if config_text not in config_dict:
                    logging.error("missing text description for config rule {}".format(config_item))
                    continue

                self.definitions.append(CorrelatedTagDefinition(config_dict[config_text], 
                                         [x.strip() for x in config_dict[config_rule].split(',')]))
                logging.debug("loaded definition for {}".format(config_rule))

    def execute_post_analysis(self) -> AnalysisExecutionResult:
        for d in self.definitions:
            tag_map = {} # key = object_id, value = [tags]
            def callback(obj):
                if obj is self.get_root():
                    return

                if id(obj) not in tag_map:
                    tag_map[id(obj)] = set()

                tag_map[id(obj)].add(t)
                if tag_map[id(obj)] == d.tags:
                    o.add_detection_point("Correlated Tag Match: {}".format(d.text))

            for t in d.tags:
                for o in self.get_root().all:
                    # exclude looking at the RootAnalysis object itself
                    if o is self.get_root():
                        continue

                    # if this object has the tag we're looking for...
                    if o.has_tag(t):
                        # then "apply" the tag all the way down to (but not including) the root
                        o.recurse_down(callback)

        return AnalysisExecutionResult.COMPLETED
