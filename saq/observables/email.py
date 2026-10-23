import logging
from saq.analysis.observable import Observable
from saq.analysis.presenter.observable_presenter import ObservablePresenter, register_observable_presenter
from saq.constants import F_EMAIL_ADDRESS, F_EMAIL_BODY, F_EMAIL_CONVERSATION, F_EMAIL_DELIVERY, F_EMAIL_FIRST_HOP_IP, F_EMAIL_HEADER, F_EMAIL_SUBJECT, F_EMAIL_X_MAILER, F_MESSAGE_ID, create_email_delivery, parse_email_conversation, parse_email_delivery
from saq.email import normalize_email_address, normalize_message_id
from saq.configuration.config import get_config
from saq.gui import ObservableActionAddLocalEmailDomain
from saq.observables.base import CaselessObservable, ObservableValueError
from saq.observables.generator import register_observable_type
from saq.observables.network.ip import IPObservable
from saq.util import is_subdomain

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

class EmailFirstHopIPObservable(IPObservable):
    """The sending IP of the first external hop of an email.

    Values come from Received: header parsing, so the inherited ip_address()
    validation is what keeps malformed hop tokens from becoming observables.
    """
    OBSERVABLE_TYPE = F_EMAIL_FIRST_HOP_IP


register_observable_type(F_EMAIL_ADDRESS, EmailAddressObservable)
register_observable_type(F_EMAIL_DELIVERY, EmailDeliveryObservable)
register_observable_type(F_EMAIL_SUBJECT, EmailSubjectObservable)
register_observable_type(F_EMAIL_X_MAILER, EmailXMailerObservable)
register_observable_type(F_EMAIL_CONVERSATION, EmailConversationObservable)
register_observable_type(F_MESSAGE_ID, MessageIDObservable)
register_observable_type(F_EMAIL_BODY, EmailBodyObservable)
register_observable_type(F_EMAIL_HEADER, EmailHeaderObservable)
register_observable_type(F_EMAIL_FIRST_HOP_IP, EmailFirstHopIPObservable)
