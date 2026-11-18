KEY_AUTHENTICATION_FAILED = 'authentication_failed'
KEY_CC = 'cc'
KEY_COMPAUTH_REASON = 'compauth_reason'
KEY_COMPAUTH_RESULT = 'compauth_result'
KEY_DECODED_SUBJECT = 'decoded_subject'
KEY_DELIVERIES = 'deliveries'
KEY_DKIM_RESULT = 'dkim_result'
KEY_DKIM_SIGNING_DOMAINS = 'dkim_signing_domains'
KEY_DMARC_RESULT = 'dmarc_result'
KEY_EMAIL = 'email'
KEY_EXTRACTION_ERRORS = 'extraction_errors'
KEY_ENV_MAIL_FROM = 'env_mail_from'
KEY_ENV_RCPT_TO = 'env_rcpt_to'
KEY_FIRST_HOP_FROM = 'first_hop_from'
KEY_FIRST_HOP_HELO = 'first_hop_helo'
KEY_FIRST_HOP_IP = 'first_hop_ip'
KEY_FROM = 'from'
KEY_FROM_ADDRESS = 'from_address'
KEY_INTERNAL_ORG_SENDER = 'internal_org_sender'
KEY_IS_ANONYMOUS_DIRECT_SEND = 'is_anonymous_direct_send'
KEY_MAIL_FROM_IS_LOCAL = 'mail_from_is_local'
KEY_MESSAGE_DIRECTIONALITY = 'message_directionality'
KEY_SPF_RESULT = 'spf_result'
KEY_SPOOFED_INTERNAL = 'spoofed_internal'
KEY_HEADERS = 'headers'
KEY_LOG_ENTRY = 'log_entry'
KEY_MESSAGE_ID = 'message-id'
KEY_O365_DETECTIONS = 'o365_detections'
KEY_ORIGINATING_IP = 'originating_ip'
KEY_PARSING_ERROR = 'parsing_error'
KEY_REPLY_TO = 'reply_to'
KEY_REPLY_TO_ADDRESS = 'reply_to_address'
KEY_RESULT = 'result'
KEY_SENDER = 'sender'
KEY_SENDER_TENANT_ID = 'sender_tenant_id'
KEY_SUBJECT = 'subject'
KEY_TIMED_OUT = 'timed_out'
KEY_TO = 'to'
KEY_TO_ADDRESSES = 'to_addresses'
KEY_UUIDS = 'uuids'
KEY_RETURN_PATH = 'return_path'
KEY_USER_AGENT = 'user-agent'
KEY_X_MAILER = 'x-mailer'
KEY_X_SENDER = 'x-sender'
KEY_X_SENDER_ID = 'x-sender-id'
KEY_X_AUTH_ID = 'x-auth-id'
KEY_X_ORIGINAL_SENDER = 'x-original-sender'
KEY_X_SENDER_IP = 'x-sender-ip'

# where a recipient's copy went, from an Office 365 journal report (EmailAnalysis.deliveries)
DELIVERY_DELIVERED = 'delivered'          # the address has its own Recipient: line
DELIVERY_FORWARDED = 'forwarded'          # a Forwarded: annotation links it to the mailbox that received it
DELIVERY_EXPANDED = 'expanded'            # an Expanded: annotation names it as a distribution list
DELIVERY_NOT_JOURNALED = 'not_journaled'  # in the headers, but no Recipient: line accounts for it

# the tag EmailAnalyzer puts on an email_delivery the journal did not deliver to under its own
# address; the observable tag index stores it per alert, so coverage reads it from the database
DELIVERY_TAGS = {
    DELIVERY_FORWARDED: 'delivery_forwarded',
    DELIVERY_EXPANDED: 'delivery_expanded',
    DELIVERY_NOT_JOURNALED: 'delivery_not_journaled',
}
DELIVERY_TAG_REASONS = {tag: reason for reason, tag in DELIVERY_TAGS.items()}
