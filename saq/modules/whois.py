"""Module for whois analysis of domain names.

A few outcomes can be expected and must be handled.

**Note that although some of these whois results do not tell an analyst
the 'creation time' of the domain, the lack of creation time might
say something to the analyst about that domain/zone. Some things to
consider:

    - The TLD is unknown/unsupported by the python-whois package.
    - All results are 'None' for a domain... it might not exist.
    - The whois whois_result for the TLD doesn't include
        a creation time.
    - There were actual whois_results.
"""

import logging
from datetime import datetime

from saq.analysis import Analysis
from saq.analysis.presenter.analysis_presenter import (
    AnalysisPresenter,
    register_analysis_presenter,
)
from saq.constants import F_FQDN, AnalysisExecutionResult
from saq.modules import AnalysisModule

import whois
from whois.exceptions import PywhoisError

from saq.util.strings import format_item_list_for_summary

KEY_ERROR = "error"

KEY_AGE_CREATED_IN_DAYS = "age_created_in_days"
KEY_AGE_LAST_UPDATED_IN_DAYS = "age_last_updated_in_days"
KEY_DATETIME_CREATED = "datetime_created"
KEY_DATETIME_EXPIRATION = "datetime_expiration"
KEY_DATETIME_OF_ANALYSIS = "datetime_of_analysis"
KEY_DATETIME_OF_LAST_UPDATE = "datetime_of_last_update"

example = {
    "domain_name": "BV.COM",
    "registrar": "Network Solutions, LLC",
    "registrar_url": "http://networksolutions.com",
    "reseller": None,
    "whois_server": "whois.networksolutions.com",
    "referral_url": None,
    "updated_date": [
        datetime(2023, 12, 2, 5, 6, 36),
        datetime(2025, 3, 21, 7, 55, 58),
    ],
    "creation_date": datetime(1993, 12, 2, 5, 0),
    "expiration_date": datetime(2033, 12, 1, 5, 0),
    "name_servers": ["NS4.BV.COM", "NS6.BV.COM", "NS7.BV.COM"],
    "status": "clientTransferProhibited https://icann.org/epp#clientTransferProhibited",
    "emails": [
        "domain.operations@web.com",
        "dm2zq2vv7vq@networksolutionsprivateregistration.com",
    ],
    "dnssec": "unsigned",
    "name": "PERFECT PRIVACY, LLC",
    "org": None,
    "address": "5335 Gate Parkway care of Network Solutions PO Box 459",
    "city": "Jacksonville",
    "state": "FL",
    "registrant_postal_code": "32256",
    "country": "US",
}

KEY_DOMAIN_NAME = "domain_name"
KEY_REGISTRAR = "registrar"
KEY_WHOIS_SERVER = "whois_server"
KEY_NAME_SERVERS = "name_servers"
KEY_EMAILS = "emails"
KEY_WHOIS_RAW_TEXT = "whois_raw_text"

KEY_WHOIS_DATA = "whois"

class WhoisAnalysis(Analysis):
    """How long ago was the domain registered?"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_ERROR: None,

            KEY_AGE_CREATED_IN_DAYS: None,
            KEY_AGE_LAST_UPDATED_IN_DAYS: None,
            KEY_DATETIME_CREATED: None,
            KEY_DATETIME_OF_ANALYSIS: None,
            KEY_DATETIME_OF_LAST_UPDATE: None,

            KEY_DOMAIN_NAME: None,
            KEY_REGISTRAR: None,
            KEY_WHOIS_SERVER: None,
            KEY_NAME_SERVERS: None,
            KEY_EMAILS: None,
            KEY_WHOIS_DATA: None,
            KEY_WHOIS_RAW_TEXT: None,
        }

    @property
    def error(self):
        return self.details[KEY_ERROR]

    @error.setter
    def error(self, value):
        self.details[KEY_ERROR] = value

    @property
    def whois_data(self):
        """The whois data associated with the domain."""
        return self.details[KEY_WHOIS_DATA]

    @whois_data.setter
    def whois_data(self, value):
        self.details[KEY_WHOIS_DATA] = value

    @property
    def whois_raw_text(self):
        """The raw whois text associated with the domain."""
        return self.details[KEY_WHOIS_RAW_TEXT]

    @whois_raw_text.setter
    def whois_raw_text(self, value):
        self.details[KEY_WHOIS_RAW_TEXT] = value

    @property
    def age_created_in_days(self):
        """How many days ago the domain was registered."""
        return self.details[KEY_AGE_CREATED_IN_DAYS]

    @age_created_in_days.setter
    def age_created_in_days(self, value):
        self.details[KEY_AGE_CREATED_IN_DAYS] = value

    @property
    def age_last_updated_in_days(self):
        """How many days ago the domain was updated."""
        return self.details[KEY_AGE_LAST_UPDATED_IN_DAYS]

    @age_last_updated_in_days.setter
    def age_last_updated_in_days(self, value):
        self.details[KEY_AGE_LAST_UPDATED_IN_DAYS] = value

    @property
    def datetime_created(self):
        """The date/time the domain was registered."""
        return self.details[KEY_DATETIME_CREATED]

    @datetime_created.setter
    def datetime_created(self, value):
        self.details[KEY_DATETIME_CREATED] = value

    @property
    def datetime_of_analysis(self):
        """The date/time the analysis was performed."""
        return self.details[KEY_DATETIME_OF_ANALYSIS]

    @datetime_of_analysis.setter
    def datetime_of_analysis(self, value):
        self.details[KEY_DATETIME_OF_ANALYSIS] = value

    @property
    def datetime_of_last_update(self):
        """The date/time the domain was last updated."""
        return self.details[KEY_DATETIME_OF_LAST_UPDATE]

    @datetime_of_last_update.setter
    def datetime_of_last_update(self, value):
        self.details[KEY_DATETIME_OF_LAST_UPDATE] = value

    @property
    def domain_name(self):
        """The root zone name."""
        return self.details[KEY_DOMAIN_NAME]

    @domain_name.setter
    def domain_name(self, value):
        self.details[KEY_DOMAIN_NAME] = value

    @property
    def registrar(self):
        """The registrar for the domain."""
        return self.details[KEY_REGISTRAR]

    @registrar.setter
    def registrar(self, value):
        self.details[KEY_REGISTRAR] = value

    @property
    def whois_server(self):
        """The whois server for the domain."""
        return self.details[KEY_WHOIS_SERVER]

    @whois_server.setter
    def whois_server(self, value):
        self.details[KEY_WHOIS_SERVER] = value

    @property
    def name_servers(self):
        """The name servers associated with the domain"""
        return self.details[KEY_NAME_SERVERS]

    @name_servers.setter
    def name_servers(self, value):
        self.details[KEY_NAME_SERVERS] = value

    @property
    def emails(self):
        """The emails associated with the domain."""
        return self.details[KEY_EMAILS]

    @emails.setter
    def emails(self, value):
        self.details[KEY_EMAILS] = value

    def generate_summary(self):
        """Return analysis whois_result string for alert analysis page."""

        parts = []

        if self.error:
            parts.append(f"error: {self.error}")
        else:
            if self.age_created_in_days:
                parts.append(f"created: {self.age_created_in_days} day(s) ago")
            if self.age_last_updated_in_days:
                parts.append(f"last updated: {self.age_last_updated_in_days} day(s) ago")
            if self.name_servers:
                parts.append(f"nameservers: ({format_item_list_for_summary(self.name_servers)})")
            if self.registrar:
                parts.append(f"registrar: {self.registrar}")
            if self.whois_server:
                parts.append(f"whois server: {self.whois_server}")
            if self.emails:
                parts.append(f"emails: ({format_item_list_for_summary(self.emails)})")

        if not parts:
            return None

        return "Whois Analysis: " + ", ".join(parts)

class WhoisAnalyzer(AnalysisModule):
    """AnalysisModule subclass for analyzing whois data about a domain."""

    @property
    def generated_analysis_type(self):
        return WhoisAnalysis

    @property
    def valid_observable_types(self):
        # python-whois module can pull domain from a URL and perform
        # whois query on it.
        return F_FQDN

    def execute_analysis(self, observable) -> AnalysisExecutionResult:
        """Executes analysis for Whois analysis of domains/zones."""

        analysis = self.create_analysis(observable)

        # Make the whois query.
        try:
            whois_result = whois.whois(observable.value)
        except PywhoisError as _error:
            error_message = str(_error)
            try:
                # error message is kind of free-form, so we'll try to parse it for a more helpful message
                error_message = error_message.split("\n")[0]
            except Exception:
                error_message = str(_error)[:50]

            analysis.error = error_message.strip()
            return AnalysisExecutionResult.COMPLETED

        analysis.whois_data = whois_result

        # Results could be lists or strings for some of the queries.
        _domain_name = whois_result.get("domain_name", None)
        if isinstance(_domain_name, list):
            _domain_name = _domain_name[0]

        analysis.domain_name = _domain_name
        analysis.registrar = whois_result.get("registrar", None)
        analysis.name_servers = whois_result.get("name_servers", [])

        # Get the full whois result
        analysis.whois_raw_text = whois_result.text

        # Creation date validation
        # First see if it's a single result or a list of results.
        #   Sometimes it includes both a tz-agnostic and tz-aware
        #   datetime object.
        _creation_date = whois_result.get("creation_date", None)
        if isinstance(_creation_date, list):
            _creation_date = _creation_date[0]

        # Now check to see it's an actual datetime object...
        if not isinstance(_creation_date, datetime):
            logging.warning(
                f"whois result for {observable} contains unexpected creation date format/contents."
            )

        # Last updated date validation
        _updated_date = whois_result.get("updated_date", None)
        if isinstance(_updated_date, list):
            _updated_date = _updated_date[0]

        if not isinstance(_updated_date, datetime):
            logging.warning(
                f"whois result for {observable} contains unexpected updated date format/contents."
            )

        _now = datetime.now()

        analysis.datetime_of_analysis = _now.isoformat(" ")

        def age_in_days_as_string(past, present):
            _delta = present - past
            # Days are negative if past is actually after the
            # present. Probably an indication of time zone issues so
            # assume it's less than a day.
            if _delta.days < 0:
                return "0"

            return str(_delta.days)

        if _creation_date:
            analysis.datetime_created = _creation_date.isoformat(" ")
            analysis.age_created_in_days = age_in_days_as_string(_creation_date, _now)

        if _updated_date:
            analysis.datetime_of_last_update = _updated_date.isoformat(" ")
            analysis.age_last_updated_in_days = age_in_days_as_string(
                _updated_date, _now
            )

        return AnalysisExecutionResult.COMPLETED


class WhoisAnalysisPresenter(AnalysisPresenter):
    """Presenter for WhoisAnalysis."""

    @property
    def template_path(self) -> str:
        return "analysis/whois.html"


register_analysis_presenter(WhoisAnalysis, WhoisAnalysisPresenter)
