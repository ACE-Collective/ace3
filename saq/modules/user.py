# vim: sw=4:ts=4:et

import os
import os.path
import logging
import json
from typing import Type

from pydantic import Field
from saq.analysis import Analysis
from saq.analysis.presenter import AnalysisPresenter, register_analysis_presenter
from saq.configuration.config import get_config
from saq.constants import F_EMAIL_ADDRESS, F_USER, AnalysisExecutionResult
from saq.environment import get_base_dir
from saq.ldap import lookup_email_address, lookup_user
from saq.modules import AnalysisModule
from saq.modules.config import AnalysisModuleConfig
from saq.email import is_local_email_domain, normalize_email_address

# XXX this is stupid, we just need a global list of observable matching to tag
class UserTagAnalysis(Analysis):
    pass

class UserTaggingAnalyzerConfig(AnalysisModuleConfig):
    json_path: str = Field(..., description="Location of the cache (use ace user update-organization to build this file).")

class UserTaggingAnalyzer(AnalysisModule):
    @classmethod
    def get_config_class(cls) -> Type[AnalysisModuleConfig]:
        return UserTaggingAnalyzerConfig

    @property
    def generated_analysis_type(self):
        return UserTagAnalysis

    @property
    def valid_observable_types(self):
        return F_USER

    @property
    def json_path(self):
        return os.path.join(get_base_dir(), self.config.json_path)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mapping = None # dict of key = username (lowercase), value = [ tags ]
        self.watch_file(self.json_path, self.load_tags)

    def load_tags(self):
        # if we haven't loaded it or if it has changed since the last time we loaded it
        logging.debug("loading {}".format(self.json_path))
        with open(self.json_path, 'r') as fp:
            self.mapping = json.load(fp)

    def execute_analysis(self, user) -> AnalysisExecutionResult:

        analysis = self.create_analysis(user)
        assert isinstance(analysis, UserTagAnalysis)

        # does this user ID exist in our list of userIDs to tag?
        if user.value.lower().strip() in self.mapping:
            for tag in self.mapping[user.value.lower().strip()]:
                user.add_tag(tag)

        return AnalysisExecutionResult.COMPLETED

class UserTagAnalysisPresenter(AnalysisPresenter):
    """Presenter for UserTagAnalysis - doesn't render in GUI."""

    @property
    def should_render(self) -> bool:
        return False

register_analysis_presenter(UserTagAnalysis, UserTagAnalysisPresenter)

class UserAnalysis(Analysis):
    @property
    def jinja_template_path(self):
        return "analysis/user.html"

    def generate_summary(self):
        name = self.details['ldap']['displayName'] if 'displayName' in self.details['ldap'] else 'None, None'
        location = self.details['ldap']['l'] if 'l' in self.details['ldap'] else 'None'
        division = self.details['ldap']['division'] if 'division' in self.details['ldap'] else 'None'
        title = self.details['ldap']['title'] if 'title' in self.details['ldap'] else 'None'
        return f'{name} - {location} - {division} - {title}'

class UserAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return UserAnalysis

    @property
    def valid_observable_types(self):
        return [F_EMAIL_ADDRESS, F_USER]

    def execute_analysis(self, observable) -> AnalysisExecutionResult:
        # skip if this observable was added by user analyzer
        if observable.has_directive('skip_user_analysis'):
            return AnalysisExecutionResult.COMPLETED

        # skip external email addresses
        if observable.type == F_EMAIL_ADDRESS and not is_local_email_domain(observable.value):
            return AnalysisExecutionResult.COMPLETED

        # lookup user details
        if observable.type == F_EMAIL_ADDRESS:
            details = lookup_email_address(observable.value)
        else:
            details = lookup_user(observable.value)

        # skip if user not found
        if details is None:
            return AnalysisExecutionResult.COMPLETED

        # create analysis
        analysis = self.create_analysis(observable)
        analysis.details['ldap'] = details

        # add user or email address observable depending on which we allready have
        new_observable = None
        if observable.type == F_EMAIL_ADDRESS:
            if 'cn' in analysis.details['ldap'] and analysis.details['ldap']['cn'] is not None:
                new_observable = analysis.add_observable_by_spec(F_USER, analysis.details['ldap']['cn'].lower())
        elif 'mail' in analysis.details['ldap'] and analysis.details['ldap']['mail'] is not None:
            new_observable = analysis.add_observable_by_spec(F_EMAIL_ADDRESS, normalize_email_address(analysis.details['ldap']['mail']))

        # add directive to new observale
        if new_observable is not None:
            # prevent redundant user analysis
            new_observable.add_directive('skip_user_analysis')

            # copy directives
            for directive in observable.directives:
                new_observable.add_directive(directive)

        # get manager info and determine if user is executive
        top_user = get_config().ldap.top_user
        if 'manager_cn' in analysis.details['ldap'] and analysis.details['ldap']['manager_cn'] is not None:
            analysis.details['manager_ldap'] = lookup_user(analysis.details['ldap']['manager_cn'])
            if analysis.details['manager_ldap'] is None:
                logging.error(f"Failed to fetch manger ldap info for {observable.value}")
            elif 'manager_cn' in analysis.details['manager_ldap'] and analysis.details['manager_ldap']['manager_cn'] is not None:
                if top_user in [observable.value.lower(), analysis.details['ldap']['manager_cn'].lower(), analysis.details['manager_ldap']['manager_cn'].lower()]:
                    observable.add_tag("executive")

        # check for privileged access
        analysis.details['ldap']['entitlements'] = []
        if 'memberOf' in analysis.details['ldap'] and analysis.details['ldap']['memberOf'] is not None:
            for group in analysis.details['ldap']['memberOf']:
                privileged = False # now used for any highlighting
                analysis.details['ldap']['entitlements'].append({'group':group, 'privileged':privileged})

        return AnalysisExecutionResult.COMPLETED

class UserAnalysisPresenter(AnalysisPresenter):
    """Presenter for UserAnalysis."""

    @property
    def template_path(self) -> str:
        return "analysis/user.html"

register_analysis_presenter(UserAnalysis, UserAnalysisPresenter)