import html
import logging
from typing import TYPE_CHECKING
from saq.analysis.observable import Observable
from saq.analysis.presenter.observable_presenter import ObservablePresenter, register_observable_presenter
from saq.constants import CONFIG_GLOBAL, CONFIG_GLOBAL_LOCAL_EMAIL_DOMAINS, F_EMAIL_ADDRESS, F_EMAIL_BODY, F_EMAIL_CONVERSATION, F_EMAIL_DELIVERY, F_EMAIL_HEADER, F_EMAIL_SUBJECT, F_EMAIL_X_MAILER, F_MESSAGE_ID, create_email_delivery, parse_email_conversation, parse_email_delivery
from saq.database.model import Remediation
from saq.database.pool import get_db, get_db_connection
from saq.email import is_local_email_domain, normalize_email_address, normalize_message_id
from saq.configuration.config import get_config
from saq.gui import ObservableActionAddLocalEmailDomain
from saq.observables.base import CaselessObservable, ObservableValueError
from saq.observables.generator import register_observable_type
from saq.util import is_subdomain


if TYPE_CHECKING:
    from saq.remediation import RemediationTarget

class EmailAddressObservable(CaselessObservable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_EMAIL_ADDRESS, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):

        # make sure this at least looks like a valid email address
        if '@' not in new_value:
            raise ObservableValueError("missing @ in email address")

        # normalize email addresses
        normalized = normalize_email_address(new_value)
        if not normalized:
            logging.warning(f"unable to normalize email address {new_value}")
            self._value = new_value
        else:
            self._value = normalized

    @property
    def jinja_available_actions(self):
        result = [
            ObservableActionAddLocalEmailDomain(),
        ]
        result.extend(super().jinja_available_actions)
        return result

    def is_managed(self):
        """Returns True if this email address uses a managed domain."""
        email_domain = self.value.split('@')[1]

        for fqdn in get_config().global_settings.local_email_domains:
            if is_subdomain(email_domain, fqdn):
                return True

        return False


class EmailAddressObservablePresenter(ObservablePresenter):
    """Presenter for EmailAddressObservable."""

    @property
    def template_path(self) -> str:
        return "analysis/default_observable.html"


register_observable_presenter(EmailAddressObservable, EmailAddressObservablePresenter)


class EmailDeliveryObservable(CaselessObservable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_EMAIL_DELIVERY, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()

        try:
            self.message_id, self.email_address = parse_email_delivery(self.value)
        except ValueError:
            raise ObservableValueError(f"invalid format for email_delivery: {new_value}")

        if not self.message_id or not self.email_address:
            raise ObservableValueError(f"invalid format for email_delivery: {new_value}")

        self.message_id = normalize_message_id(self.message_id)
        self.email_address = normalize_email_address(self.email_address)
        self._value = create_email_delivery(self.message_id, self.email_address)

    @property
    def jinja_template_path(self):
        return "analysis/email_delivery_observable.html"

    @property
    def remediation_targets(self) -> list["RemediationTarget"]:
        from saq.remediation import RemediationTarget

        if is_local_email_domain(self.email_address):
            return [RemediationTarget('email', self.value)]

        return []

class EmailSubjectObservable(Observable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_EMAIL_SUBJECT, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()


class EmailXMailerObservable(Observable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_EMAIL_X_MAILER, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()

class EmailConversationObservable(Observable):
    def __init__(self, *args, **kwargs):
        self._mail_from = None
        self._rcpt_to = None
        super().__init__(F_EMAIL_CONVERSATION, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()
        self._mail_from, self._rcpt_to = parse_email_conversation(self.value)

    @property
    def mail_from(self):
        return self._mail_from

    @property
    def rcpt_to(self):
        return self._rcpt_to

    @property
    def jinja_template_path(self):
        return "analysis/email_conversation_observable.html"


class EmailConversationObservablePresenter(ObservablePresenter):
    """Presenter for EmailConversationObservable."""

    @property
    def template_path(self) -> str:
        return "analysis/email_conversation_observable.html"


register_observable_presenter(EmailConversationObservable, EmailConversationObservablePresenter)


class MessageIDObservable(Observable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_MESSAGE_ID, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        # Make sure the message-id appears to be valid. What valid means in this case is defined in
        # RFC2822. There are some regex statements you can find to strictly validate against this RFC,
        # however, there are always exceptions. In general, the message-id should be in the format of
        # an email address. But instead of strictly validating it, we will start by simply making sure
        # that there is an "@" symbol in the value. We can always add stricter validation later if needed.
        if '@' not in new_value:
            raise ObservableValueError(f"{new_value} is not a valid message-id")

        self._value = normalize_message_id(new_value.strip())

    @property
    def remediation_targets(self) -> list["RemediationTarget"]:
        from saq.remediation import RemediationTarget

        message_id = html.unescape(self.value)

        # create targets from recipients of message_id in email archive
        targets = {}
        with get_db_connection("email_archive") as db:
            c = db.cursor()
            sql = "SELECT recipient FROM email_history WHERE message_id_hash = UNHEX(SHA2(%s, 256))"
            #sql = (
                #"SELECT as1.value FROM archive_search as1 "
                #"JOIN archive_search as2 ON as1.archive_id = as2.archive_id "
                #"WHERE as2.field = 'message_id' AND as2.value = %s AND as1.field IN ('env_to', 'body_to')"
            #)
            c.execute(sql, (message_id,))
            for row in c:
                mailbox = row[0]
                if is_local_email_domain(mailbox):
                    target = create_email_delivery(message_id, mailbox)
                    if target not in targets:
                        targets[target] = RemediationTarget('email', target)

        # also get targets from remediation history
        query = get_db().query(Remediation)
        query = query.filter(Remediation.type == 'email')
        query = query.filter(Remediation.key.like(f"{message_id}%"))
        history = query.all()
        for h in history:
            if h.key not in targets:
                targets[h.key] = RemediationTarget('email', h.key)

        return list(targets.values())

class EmailBodyObservable(Observable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_EMAIL_BODY, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value


class EmailHeaderObservable(Observable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_EMAIL_HEADER, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value

register_observable_type(F_EMAIL_ADDRESS, EmailAddressObservable)
register_observable_type(F_EMAIL_DELIVERY, EmailDeliveryObservable)
register_observable_type(F_EMAIL_SUBJECT, EmailSubjectObservable)
register_observable_type(F_EMAIL_X_MAILER, EmailXMailerObservable)
register_observable_type(F_EMAIL_CONVERSATION, EmailConversationObservable)
register_observable_type(F_MESSAGE_ID, MessageIDObservable)
register_observable_type(F_EMAIL_BODY, EmailBodyObservable)
register_observable_type(F_EMAIL_HEADER, EmailHeaderObservable)
