# vim: sw=4:ts=4:et

#
# database section names
# these are used in calls to saq.database.get_db_connection
#

from enum import Enum

#
# environment variables
#

# path to the logging configuration file
ENV_ACE_LOG_CONFIG_PATH = "ACE_LOG_CONFIG_PATH"
ENV_FLUENT_BIT_TAG = "FLUENT_BIT_TAG"


DB_ACE = "ace"
DB_BROCESS = "brocess"
DB_EMAIL_ARCHIVE = "email_archive"
DB_COLLECTION = "collection"

# 
# instance types
#

INSTANCE_TYPE_PRODUCTION = 'PRODUCTION'
INSTANCE_TYPE_QA = 'QA'
INSTANCE_TYPE_DEV = 'DEV'
INSTANCE_TYPE_UNITTEST = 'UNITTEST'
INSTANCE_TYPE_LOCAL = 'LOCAL'
VALID_INSTANCE_TYPES = [INSTANCE_TYPE_PRODUCTION, INSTANCE_TYPE_QA, INSTANCE_TYPE_DEV, INSTANCE_TYPE_UNITTEST, INSTANCE_TYPE_LOCAL]

#
# required fields for every alert
#

F_UUID = 'uuid'
F_ID = 'id'
F_TOOL = 'tool'
F_TOOL_INSTANCE = 'tool_instance'
F_TYPE = 'type'
F_DESCRIPTION = 'description'
F_EVENT_TIME = 'event_time'
F_DETAILS = 'details'
F_DISPOSITION = 'disposition'
#F_COMMENTS = 'comments'

#
# observable types
#

#
# WARNING
# XXX NOTE
# when you add a new observable type you ALSO need to edit lib/saq/observables/__init__.py
# and add a matching entry to the _OBSERVABLE_TYPE_MAPPING dictionary

F_ASSET = 'asset'
F_AV_STREETNAME = 'av_streetname'
F_AWS_ACCESS_KEY_ID = 'aws_access_key_id'
F_AWS_ACCOUNT_ID = 'aws_account_id'
F_AWS_AMI_ID = 'aws_ami_id'
F_AWS_INSTANCE_ID = 'aws_instance_id'
F_AWS_NETWORK_INTERFACE_ID = 'aws_network_interface_id'
F_AWS_PRINCIPAL_ID = 'aws_principal_id'
F_AWS_PRIVATE_DNS_NAME = 'aws_private_dns_name'
F_AWS_SECURITY_GROUP_ID = 'aws_security_group_id'
F_AWS_SUBNET_ID = 'aws_subnet_id'
F_AWS_USERNAME = 'aws_username'
F_AWS_VPC_ID = 'aws_vpc_id'
F_CIDR = 'cidr'
F_COMMAND_LINE = 'command_line'
F_COMPROMISED_ACCOUNT = 'compromised_account'
F_COOKIE= 'cookie'
F_EMAIL_ADDRESS = 'email_address'
F_EMAIL_CONTACT = 'contact'
F_EMAIL_BODY = 'email_body'
F_EMAIL_CONVERSATION = 'email_conversation'
F_EMAIL_DELIVERY = 'email_delivery'
F_EMAIL_HEADER = 'email_header'
F_EMAIL_SUBJECT = 'email_subject'
F_EMAIL_X_MAILER = 'email_x_mailer'
F_EXTERNAL_UID = 'external_uid'
F_FILE = 'file'
F_FILE_LOCATION = 'file_location'
F_FILE_NAME = 'file_name'
F_FILE_PATH = 'file_path'
F_FIREEYE_UUID = 'fireeye_uuid'
F_FORUM_AUTHOR = 'forum_author'
F_FORUM_CHANNEL = 'forum_channel'
F_FORUM_CHAT_TYPE = 'forum_chat_type'
F_FQDN = 'fqdn'
F_HOSTNAME = 'hostname'
F_HTTP_REQUEST = 'http_request'
F_HUNT = 'hunt'
F_IDS_STREETNAME = 'ids_streetname'
F_IMPHASH = 'imphash'
F_INDICATOR = 'indicator'
F_IPV4 = 'ipv4'
F_IPV4_CONVERSATION = 'ipv4_conversation'
F_IPV4_FULL_CONVERSATION = 'ipv4_full_conversation'
F_JA3 = 'ja3'
F_JA3S = 'ja3s'
F_JARM_HASH = 'jarm_hash'
F_MAC_ADDRESS = 'mac_address'
F_MD5 = 'md5'
F_MESSAGE_ID = 'message_id'
F_MUTEX = 'mutex'
F_O365_FILE = 'o365_file'
F_O365_GROUP = 'o365_group'
F_O365_FILE_CONVERSATION = 'o365_file_conversation'
F_O365_SECURITY_ALERT = 'o365_security_alert'
F_PAN_PCAP_ID = 'pan_pcap_id'
F_PCAP = 'pcap'
F_PRINTER = 'printer'
F_PROCESS_GUID = 'process_guid'
F_PROOFPOINT_CAMPAIGN_ID = 'pp_campaign_id'
F_PROOFPOINT_GUID = 'pp_guid'
F_PROOFPOINT_THREAT_ID = 'pp_threat_id'
F_PROOFPOINT_TRAP_INCIDENT_ID = 'pp_trap_incident_id'
F_SCAN_ID = 'scan_id'
F_SHA1 = 'sha1'
F_SHA256 = 'sha256'
F_SHAREPOINT_FILE = 'sharepoint_file'
F_SNORT_SIGNATURE = 'snort_sig'
F_STRING_EPS = 'string_eps'
F_STRING_HTML = 'string_html'
F_STRING_JAVA = 'string_java'
F_STRING_JS = 'string_js'
F_STRING_OFFICE = 'string_office'
F_STRING_PDF = 'string_pdf'
F_STRING_PE = 'string_pe'
F_STRING_RTF = 'string_rtf'
F_STRING_SWF = 'string_swf'
F_STRING_UNIX_SHELL = 'string_unix_shell'
F_STRING_VBS = 'string_vbs'
F_STRING_WINDOWS_SHELL = 'string_windows_shell'
F_SUSPECT_FILE = 'suspect_file' # DEPRECATED
F_TEST = 'test'
F_URI_PATH = 'uri_path'
F_URL = 'url'
F_USER = 'user'
F_USER_AGENT = 'user_agent'
F_WINDOWS_REGISTRY = 'windows_registry'
F_WINDOWS_SERVICE = 'windows_service'
F_YARA = 'yara'
F_YARA_RULE = 'yara_rule'
F_YARA_STRING = 'yara_string'

OBSERVABLE_DESCRIPTIONS = {
    F_ASSET: 'a F_IPV4 identified to be a managed asset',
    F_AV_STREETNAME: 'anti-virus vendor name for a malware family',
    F_AWS_ACCESS_KEY_ID: 'an access key ID assigned to a user identity',
    F_AWS_ACCOUNT_ID: 'id of an AWS account',
    F_AWS_AMI_ID: 'id of an AWS AMI',
    F_AWS_INSTANCE_ID: 'id of an AWS instance',
    F_AWS_NETWORK_INTERFACE_ID: 'eni id',
    F_AWS_PRINCIPAL_ID: 'principal ID for an aws user',
    F_AWS_PRIVATE_DNS_NAME: 'private DNS Name for an AWS entity',
    F_AWS_SECURITY_GROUP_ID: 'id of an AWS security group',
    F_AWS_SUBNET_ID: 'AWS subnet id',
    F_AWS_USERNAME: 'username associated with an AWS account',
    F_AWS_VPC_ID: 'virtual private cloud (VPC) id',
    F_CIDR: 'IPv4 range in CIDR notation',
    F_COMMAND_LINE: 'command line options to a command that was executed',
    F_COMPROMISED_ACCOUNT: 'a username + password that may have been compromised',
    F_COOKIE: 'cookie',
    F_EMAIL_ADDRESS: 'email address',
    F_EMAIL_CONTACT: 'email contact e.g. "Last, First <email@domain.com>"',
    F_EMAIL_BODY: 'string from an email body',
    F_EMAIL_CONVERSATION: 'a conversation between a source email address (MAIL FROM) and a destination email address (RCPT TO)',
    F_EMAIL_DELIVERY: 'a delivery of a an email to a target mailbox',
    F_EMAIL_HEADER: 'string from an email header',
    F_EMAIL_SUBJECT: 'the subject of an email',
    F_EMAIL_X_MAILER: 'email x-mailer',
    F_EXTERNAL_UID: 'unique identifier for something that is stored in an external tool. Format: tool_name:uid',
    F_FILE: 'path to an attached file',
    F_FILE_LOCATION: 'the location of file with format hostname@full_path',
    F_FILE_NAME: 'a file name (no directory path)',
    F_FILE_PATH: 'a file path',
    F_FIREEYE_UUID: 'UUID used to identify a FireEye alert',
    F_FORUM_AUTHOR: 'author of forum post (used for intel tracking)',
    F_FORUM_CHANNEL: 'channel of forum post (used for intel tracking)',
    F_FORUM_CHAT_TYPE: 'type of forum post (used for intel tracking)',
    F_FQDN: 'fully qualified domain name',
    F_HOSTNAME: 'host or workstation name',
    F_HTTP_REQUEST: 'a single HTTP request',
    F_HUNT: 'the name of a hunt',
    F_IDS_STREETNAME: 'ids vendor name for a network attack or vulnerability',
    F_IMPHASH: 'hash of the imported functions of a PE file',
    F_INDICATOR: 'indicator id',
    F_IPV4: 'IP address (version 4)',
    F_IPV4_CONVERSATION: 'two F_IPV4 that were communicating formatted as aaa.bbb.ccc.ddd_aaa.bbb.ccc.ddd',
    F_IPV4_FULL_CONVERSATION: 'two F_IPV4 that were communicating formatted as src_ipv4:src_port:dest_ipv4:dest_port',
    F_MAC_ADDRESS: 'network card mac address',
    F_MD5: 'MD5 hash',
    F_MESSAGE_ID: 'email Message-ID',
    F_MUTEX: 'mutex created during sample execution',
    F_O365_FILE: 'graph api path to a file in o365',
    F_O365_GROUP: 'graph api id of a group in o365',
    F_O365_FILE_CONVERSATION: 'two users sharing o365 files',
    F_O365_SECURITY_ALERT: 'The alert uuID',
    F_PAN_PCAP_ID: 'PaloAlto PCAP identification',
    F_PCAP: 'path to a pcap formatted file *** DEPRECATED (use F_FILE instead)',
    F_PRINTER: 'name of a printer',
    F_PROOFPOINT_CAMPAIGN_ID: 'Proofpoint Campaign ID',
    F_PROOFPOINT_GUID: 'Proofpoint Email GUID',
    F_PROOFPOINT_THREAT_ID: 'Proofpoint Threat ID',
    F_PROOFPOINT_TRAP_INCIDENT_ID: 'Proofpoint TRAP Incident ID',
    F_SCAN_ID: 'an identifer for a scan by some remote system',
    F_SHA1: 'SHA1 hash',
    F_SHA256: 'SHA256 hash',
    F_SHAREPOINT_FILE: 'sharepoint file path',
    F_SNORT_SIGNATURE: 'snort signature ID',
    F_STRING_EPS: 'string in an eps file',
    F_STRING_HTML: 'string in an html file',
    F_STRING_JAVA: 'string in java source code',
    F_STRING_JS: 'string in javascript code',
    F_STRING_OFFICE: 'string in a microsoft office file',
    F_STRING_PDF: 'string in a pdf file',
    F_STRING_PE: 'string in a portable executable file',
    F_STRING_RTF: 'string in an rtf file',
    F_STRING_SWF: 'string in a shockwave/flash file',
    F_STRING_UNIX_SHELL: 'string from unix command line',
    F_STRING_VBS: 'string in a vbs file',
    F_STRING_WINDOWS_SHELL: 'string from windows command line',
    F_SUSPECT_FILE: 'path to an attached file that might be malicious *** DEPRECATED (use directives instead)',
    F_TEST: 'unit testing observable',
    F_URI_PATH: 'URI path from a URL',
    F_URL: 'a URL',
    F_USER: 'an NT user ID identified to have used a given asset in the given period of time',
    F_USER_AGENT: 'user agent used in web requests',
    F_WINDOWS_REGISTRY: 'a windows registry key',
    F_WINDOWS_SERVICE: 'name of a windows service',
    F_YARA: 'yara scan result *** DEPRECATED (use F_YARA_RULE instead)',
    F_YARA_RULE: 'yara rule name',
    F_YARA_STRING: 'yara rule and string name',
}

VALID_OBSERVABLE_TYPES = sorted([
    F_ASSET,
    F_AV_STREETNAME,
    F_AWS_ACCESS_KEY_ID,
    F_AWS_ACCOUNT_ID,
    F_AWS_AMI_ID,
    F_AWS_INSTANCE_ID,
    F_AWS_NETWORK_INTERFACE_ID,
    F_AWS_PRINCIPAL_ID,
    F_AWS_PRIVATE_DNS_NAME,
    F_AWS_SECURITY_GROUP_ID,
    F_AWS_SUBNET_ID,
    F_AWS_USERNAME,
    F_AWS_VPC_ID,
    F_CIDR,
    F_COMMAND_LINE,
    F_COMPROMISED_ACCOUNT,
    F_COOKIE,
    F_EMAIL_ADDRESS,
    F_EMAIL_CONTACT,
    F_EMAIL_BODY,
    F_EMAIL_CONVERSATION,
    F_EMAIL_DELIVERY,
    F_EMAIL_HEADER,
    F_EMAIL_SUBJECT,
    F_EMAIL_X_MAILER,
    F_EXTERNAL_UID,
    F_FILE,
    F_FILE_LOCATION,
    F_FILE_NAME,
    F_FILE_PATH,
    F_FIREEYE_UUID,
    F_FORUM_AUTHOR,
    F_FORUM_CHANNEL,
    F_FORUM_CHAT_TYPE,
    F_FQDN,
    F_HOSTNAME,
    F_HTTP_REQUEST,
    F_HUNT,
    F_IMPHASH,
    F_INDICATOR,
    F_IPV4,
    F_IPV4_CONVERSATION,
    F_IPV4_FULL_CONVERSATION,
    F_MAC_ADDRESS,
    F_MD5,
    F_MESSAGE_ID,
    F_MUTEX,
    F_O365_FILE,
    F_O365_GROUP,
    F_O365_FILE_CONVERSATION,
    F_O365_SECURITY_ALERT,
    F_PAN_PCAP_ID,
    F_PCAP,
    F_PRINTER,
    F_PROOFPOINT_CAMPAIGN_ID,
    F_PROOFPOINT_GUID,
    F_PROOFPOINT_THREAT_ID,
    F_PROOFPOINT_TRAP_INCIDENT_ID,
    F_SCAN_ID,
    F_SHA1,
    F_SHA256,
    F_SHAREPOINT_FILE,
    F_SNORT_SIGNATURE,
    F_STRING_EPS,
    F_STRING_HTML,
    F_STRING_JAVA,
    F_STRING_JS,
    F_STRING_OFFICE,
    F_STRING_PDF,
    F_STRING_PE,
    F_STRING_RTF,
    F_STRING_SWF,
    F_STRING_UNIX_SHELL,
    F_STRING_VBS,
    F_STRING_WINDOWS_SHELL,
    F_SUSPECT_FILE,
    F_TEST,
    F_URI_PATH,
    F_URL,
    F_USER,
    F_USER_AGENT,
    F_WINDOWS_REGISTRY,
    F_WINDOWS_SERVICE,
    F_YARA,
    F_YARA_RULE,
    F_YARA_STRING,
])

DEPRECATED_OBSERVABLES = sorted([
    F_CIDR,
    F_PCAP,
    F_HTTP_REQUEST,
    F_SUSPECT_FILE,
    F_YARA
])

# see docs/files.txt TODO
HARDCOPY_SUBDIR = "hardcopies"
# files are stored in subdirectories of the root analysis
FILE_SUBDIR = "files"

# utility functions to work with F_IPV4_FULL_CONVERSATION types
def parse_ipv4_full_conversation(f_ipv4_fc):
    return f_ipv4_fc.split(':', 4)


def create_ipv4_full_conversation(src, src_port, dst, dst_port):
    return '{}:{}:{}:{}'.format(src.strip(), src_port, dst.strip(), dst_port)

# utility functions to work with F_IPV4_CONVERSATION types
def parse_ipv4_conversation(f_ipv4_c):
    return f_ipv4_c.split('_', 2)

def create_ipv4_conversation(src, dst):
    return '{}_{}'.format(src.strip(), dst.strip())

# utility functions to work with F_EMAIL_CONVERSATION types
def parse_email_conversation(f_ipv4_c):
    result = f_ipv4_c.split('|', 2)
    
    # did parsing fail?
    if len(result) != 2:
        return f_ipv4_c, ''

    return result

def create_email_conversation(mail_from, rcpt_to):
    return '{}|{}'.format(mail_from.strip(), rcpt_to.strip())

def parse_file_location(file_location):
    return file_location.split('@', 1)

def create_file_location(hostname, full_path):
    return '{}@{}'.format(hostname.strip(), full_path)

def parse_email_delivery(email_delivery):
    return email_delivery.rsplit('|', 1)

def create_email_delivery(message_id, mailbox):
    return '{}|{}'.format(message_id.strip(), mailbox.strip())

def create_yara_string(rule, string):
    return '{}:{}'.format(rule, string)

# the expected format of the event_time of an alert
EVENT_TIME_FORMAT_TZ = '%Y-%m-%d %H:%M:%S %z'
# the old time format before we started storing timezones
EVENT_TIME_FORMAT = '%Y-%m-%d %H:%M:%S'
# the "ISO 8601" format that ACE uses to store datetime objects in JSON with a timezone
# NOTE this is the preferred format
EVENT_TIME_FORMAT_JSON_TZ = '%Y-%m-%dT%H:%M:%S.%f%z'
# the "ISO 8601" format that ACE uses to store datetime objects in JSON without a timezone
EVENT_TIME_FORMAT_JSON = '%Y-%m-%dT%H:%M:%S.%f'

# alert dispositions
DISPOSITION_OPEN = 'OPEN'
DISPOSITION_FALSE_POSITIVE = 'FALSE_POSITIVE'
DISPOSITION_IGNORE = 'IGNORE'
DISPOSITION_UNKNOWN = 'UNKNOWN'
DISPOSITION_REVIEWED = 'REVIEWED'
DISPOSITION_GRAYWARE = 'GRAYWARE'
DISPOSITION_POLICY_VIOLATION = 'POLICY_VIOLATION'
DISPOSITION_RECONNAISSANCE = 'RECONNAISSANCE'
DISPOSITION_WEAPONIZATION = 'WEAPONIZATION'
DISPOSITION_DELIVERY = 'DELIVERY'
DISPOSITION_EXPLOITATION = 'EXPLOITATION'
DISPOSITION_INSTALLATION = 'INSTALLATION'
DISPOSITION_COMMAND_AND_CONTROL = 'COMMAND_AND_CONTROL'
DISPOSITION_EXFIL = 'EXFIL'
DISPOSITION_DAMAGE = 'DAMAGE'
DISPOSITION_INSIDER_DATA_CONTROL = 'INSIDER_DATA_CONTROL'
DISPOSITION_INSIDER_DATA_EXFIL = 'INSIDER_DATA_EXFIL'
DISPOSITION_APPROVED_BUSINESS = 'APPROVED_BUSINESS'
DISPOSITION_APPROVED_PERSONAL = 'APPROVED_PERSONAL'

VALID_DISPOSITIONS = [
    DISPOSITION_OPEN,
    DISPOSITION_FALSE_POSITIVE,
    DISPOSITION_IGNORE,
    DISPOSITION_UNKNOWN,
    DISPOSITION_REVIEWED,
    DISPOSITION_GRAYWARE,
    DISPOSITION_POLICY_VIOLATION,
    DISPOSITION_RECONNAISSANCE,
    DISPOSITION_WEAPONIZATION,
    DISPOSITION_DELIVERY,
    DISPOSITION_EXPLOITATION,
    DISPOSITION_INSTALLATION,
    DISPOSITION_COMMAND_AND_CONTROL,
    DISPOSITION_EXFIL,
    DISPOSITION_DAMAGE,
    DISPOSITION_INSIDER_DATA_CONTROL,
    DISPOSITION_INSIDER_DATA_EXFIL,
    DISPOSITION_APPROVED_BUSINESS,
    DISPOSITION_APPROVED_PERSONAL,
]

# --- DIRECTIVES
DIRECTIVE_ANALYZE_ACTIVITY = 'analyze_activity'
DIRECTIVE_ARCHIVE = 'archive'
DIRECTIVE_COLLECT_FILE = 'collect_file'
DIRECTIVE_CRAWL = 'crawl'
DIRECTIVE_CRAWL_EXTRACTED_URLS = 'crawl_extracted_urls'
DIRECTIVE_DELAY = 'delay'
DIRECTIVE_DHASH = 'dhash'
DIRECTIVE_EXCLUDE_ALL = 'exclude_all'
DIRECTIVE_EXTRACT_EMAIL = 'extract_email'
DIRECTIVE_EXTRACT_PCAP = 'extract_pcap'
DIRECTIVE_EXTRACT_URLS = 'extract_urls'
DIRECTIVE_EXTRACT_URLS_DOMAIN_AS_URL = 'extract_urls_domain_as_url'
DIRECTIVE_FORCE_DOWNLOAD = 'force_download'
DIRECTIVE_IGNORE_AUTOMATION_LIMITS = 'ignore_automation_limits'
DIRECTIVE_NO_CACHE = 'no_cache'
DIRECTIVE_NO_SANDBOX = 'no_sandbox'
DIRECTIVE_NO_SCAN = 'no_scan'
DIRECTIVE_ORIGINAL_EMAIL = 'original_email'
DIRECTIVE_ORIGINAL_SMTP = 'original_smtp'
DIRECTIVE_PHISHKIT = 'phishkit'
DIRECTIVE_PREVIEW = 'preview'
DIRECTIVE_RENDER = 'render'
DIRECTIVE_REMEDIATE = 'remediate'
DIRECTIVE_RENAME_ANALYSIS = 'rename_analysis'
DIRECTIVE_RESOLVE_ASSET = 'resolve_asset'
DIRECTIVE_SANDBOX = 'sandbox'
DIRECTIVE_SCAN_URLSCAN = 'scan_urlscan'
DIRECTIVE_SUBMIT_AS_NEW = 'submit_as_new'
DIRECTIVE_TRACKED = 'tracked'
DIRECTIVE_TRIAGE = 'triage'
DIRECTIVE_VIEW_IN_BROWSER = 'view_in_browser'
DIRECTIVE_VMRAY = 'vmray'
DIRECTIVE_WHITELISTED = 'whitelisted'

DIRECTIVE_DESCRIPTIONS = {
    DIRECTIVE_ANALYZE_ACTIVITY: 'analyze the activity of this for some time period around a certain event',
    DIRECTIVE_ARCHIVE: 'archive the file',
    DIRECTIVE_COLLECT_FILE: 'collect the file from the remote endpoint',
    DIRECTIVE_CRAWL: 'crawl the URL',
    DIRECTIVE_CRAWL_EXTRACTED_URLS: 'crawl all extracted URLs',
    DIRECTIVE_DELAY: 'instructs various analysis modules to delay the analysis',
    DIRECTIVE_DHASH: 'compare the dhash of the image against known images',
    DIRECTIVE_EXCLUDE_ALL: 'instructs ACE to NOT analyze this observable at all',
    DIRECTIVE_EXTRACT_EMAIL: 'extract email from exchange or o365',
    DIRECTIVE_EXTRACT_PCAP: 'extract PCAP for the given observable and given time',
    DIRECTIVE_EXTRACT_URLS: 'extract URLs from the given file',
    DIRECTIVE_EXTRACT_URLS_DOMAIN_AS_URL: 'extract URLs from the given file and treat domain names as URLs',
    DIRECTIVE_FORCE_DOWNLOAD: 'download the content of the URL no matter what',
    DIRECTIVE_IGNORE_AUTOMATION_LIMITS: 'ignores any automation limits when analyzing this observable',
    DIRECTIVE_NO_CACHE: 'do not use local cache',
    DIRECTIVE_NO_SANDBOX: 'do not run the observable through any sandboxes',
    DIRECTIVE_NO_SCAN: 'do not scan this file with yara',
    DIRECTIVE_ORIGINAL_EMAIL: 'treat this file as the original email file',
    DIRECTIVE_ORIGINAL_SMTP: 'treat this file as the original smtp stream',
    DIRECTIVE_PHISHKIT: 'analyze target for phishkit detection',
    DIRECTIVE_PREVIEW: 'show this content inline if possible',
    DIRECTIVE_RENDER: 'render an image of the target',
    DIRECTIVE_REMEDIATE: 'remediate the target',
    DIRECTIVE_RENAME_ANALYSIS: 'indicates that the description of the root analysis object should be updated with analysis results',
    DIRECTIVE_RESOLVE_ASSET: 'indicates that ACE should treat this IP address as an asset and try to figure out the details',
    DIRECTIVE_SANDBOX: 'run the observable through a sandbox',
    DIRECTIVE_SCAN_URLSCAN: 'scans the target with urlscan',
    DIRECTIVE_SUBMIT_AS_NEW: 'submit the observable as new with flag to bypass any existing analysis',
    DIRECTIVE_TRACKED: 'indicates this observable should be tracked across different analysis requests',
    DIRECTIVE_TRIAGE: 'send this observable to tria.ge for analysis',
    DIRECTIVE_VIEW_IN_BROWSER: 'allows a file observable to be opened inside the browser',
    DIRECTIVE_VMRAY: 'send this observable to vmray for analysis',
    DIRECTIVE_WHITELISTED: 'indicates this observable was whitelisted, causing the entire analysis to also become whitelisted',
}

VALID_DIRECTIVES = list(DIRECTIVE_DESCRIPTIONS.keys())

# directives that are available for selection from the GUI
GUI_DIRECTIVES = [
    DIRECTIVE_ANALYZE_ACTIVITY,
    DIRECTIVE_COLLECT_FILE,
    DIRECTIVE_CRAWL,
    DIRECTIVE_CRAWL_EXTRACTED_URLS,
    DIRECTIVE_EXTRACT_EMAIL,
    DIRECTIVE_EXTRACT_PCAP,
    DIRECTIVE_EXTRACT_URLS,
    DIRECTIVE_FORCE_DOWNLOAD,
    DIRECTIVE_NO_CACHE,
    DIRECTIVE_NO_SANDBOX,
    DIRECTIVE_PHISHKIT,
    DIRECTIVE_SANDBOX,
    DIRECTIVE_SCAN_URLSCAN,
    DIRECTIVE_TRIAGE,
    DIRECTIVE_VMRAY,
]

def register_directive(directive: str, description: str, gui: bool = False):
    global DIRECTIVE_DESCRIPTIONS
    global GUI_DIRECTIVES
    DIRECTIVE_DESCRIPTIONS[directive] = description
    if gui:
        GUI_DIRECTIVES.append(directive)

#
# GUI constants
#

# max number of closed events to load at a time in 'Add to Event' modal
CLOSED_EVENT_LIMIT = 15

# used to determine where to redirect to after doing something
REDIRECT_MAP = {
    'analysis': 'analysis.index',
    'management': 'analysis.manage'
}

# controls if we prune analysis by default or not
# could also be called DEFAULT_PRUNE_ALL
DEFAULT_PRUNE = True

# controls if we prune volatile observables or not
DEFAULT_PRUNE_VOLATILE = True

#
# END GUI constants
#

def is_valid_directive(directive):
    return directive in VALID_DIRECTIVES

# --- TAGS
TAG_LEVEL_FALSE_POSITIVE = 'fp'
TAG_LEVEL_INFO = 'info'
TAG_LEVEL_WARNING = 'warning'
TAG_LEVEL_ALERT = 'alert'
TAG_LEVEL_CRITICAL = 'critical'
TAG_LEVEL_HIDDEN = 'hidden'

TAG_DECRYPTED_EMAIL = "decrypted_email"

# --- EVENTS
# fired when we add a tag to something
EVENT_TAG_ADDED = 'tag_added'
# called when an Observable is added to the Analysis
EVENT_OBSERVABLE_ADDED = 'observable_added'
# called when the details of an Analysis have been updated
EVENT_DETAILS_UPDATED = 'details_updated'
# fired when we add a directive to an Observable
EVENT_DIRECTIVE_ADDED = 'directive_added'
# fired when we add an Analysis to an Observable
EVENT_ANALYSIS_ADDED = 'analysis_added'
# fired when we add a DetectionPoint ot an Analysis or Observable
EVENT_DETECTION_ADDED = 'detection_added'
# fired when an analysis is marked as completed manually
EVENT_ANALYSIS_MARKED_COMPLETED = 'analysis_marked_completed'
# fired when a relationship is added to an observable
EVENT_RELATIONSHIP_ADDED = 'relationship_added'
# fired when we add a context record to an Analysis or Observable
EVENT_CONTEXT_RECORD_ADDED = 'context_record_added'

# these next two events are intended to be used with the RootAnalysis object
# fired when we add a tag to any taggable object
EVENT_GLOBAL_TAG_ADDED = 'global_tag_added'
# fired when we add an observable to any analysis object
EVENT_GLOBAL_OBSERVABLE_ADDED = 'global_observable_added'
# fired when we add an analysis to any observable object
EVENT_GLOBAL_ANALYSIS_ADDED = 'global_analysis_added'

# list of all valid events
VALID_EVENTS = [ 
    EVENT_ANALYSIS_MARKED_COMPLETED,
    EVENT_TAG_ADDED,
    EVENT_OBSERVABLE_ADDED,
    EVENT_ANALYSIS_ADDED,
    EVENT_DETECTION_ADDED,
    EVENT_DIRECTIVE_ADDED,
    EVENT_RELATIONSHIP_ADDED,
    EVENT_DETAILS_UPDATED,
    EVENT_GLOBAL_TAG_ADDED,
    EVENT_GLOBAL_OBSERVABLE_ADDED,
    EVENT_GLOBAL_ANALYSIS_ADDED ]

# available actions for observables
ACTION_CLEAR_CLOUDPHISH_ALERT = 'clear_cloudphish_alert'
ACTION_COLLECT_FILE = 'collect_file'
ACTION_ADD_LOCAL_EMAIL_DOMAIN = 'add_local_email_domain'
ACTION_DLP_INCIDENT_VIEW_DLP = 'dlp_incident_view_dlp'
ACTION_O365_FILE_DOWNLOAD = 'o365_file_download'
ACTION_SYMANTEC_DLP_ALLOW_WEB_DOMAIN = 'symantec_dlp_allow_web_domain'
ACTION_SYMANTEC_DLP_ALLOW_SENDER = 'symantec_dlp_allow_sender'
ACTION_SYMANTEC_DLP_ALLOW_RECIPIENT = 'symantec_dlp_allow_recipient'
ACTION_SYMANTEC_DLP_ALLOW_RECIPIENT_DOMAIN = 'symantec_dlp_allow_recipient_domain'
ACTION_FILE_DOWNLOAD = 'file_download'
ACTION_FILE_DOWNLOAD_AS_ZIP = 'file_download_as_zip'
ACTION_FILE_SEND_TO = 'file_send_to'
ACTION_FILE_UPLOAD_VT = 'file_upload_vt'
ACTION_FILE_UPLOAD_FALCON_SANDBOX = 'file_upload_falcon_sandbox'
ACTION_FILE_UPLOAD_VX = 'file_upload_vx'
ACTION_FILE_VIEW_AS_HEX = 'file_view_as_hex'
ACTION_FILE_VIEW_AS_TEXT = 'file_view_as_text'
ACTION_FILE_VIEW_AS_HTML = 'file_view_as_html'
ACTION_FILE_VIEW_IN_BROWSER = 'file_view_in_browser'
ACTION_FILE_VIEW_VT = 'file_view_vt'
ACTION_FILE_VIEW_FALCON_SANDBOX = 'file_view_falcon_sandbox'
ACTION_FILE_VIEW_VX = 'file_view_vx'
ACTION_REMEDIATE = 'remediate'
ACTION_REMEDIATE_EMAIL = 'remediate_email'
ACTION_RESTORE = 'restore'
ACTION_SET_SIP_INDICATOR_STATUS_ANALYZED = 'sip_status_analyzed'
ACTION_SET_SIP_INDICATOR_STATUS_INFORMATIONAL = 'sip_status_informational'
ACTION_SET_SIP_INDICATOR_STATUS_NEW = 'sip_status_new'
ACTION_TAG_OBSERVABLE = 'tag_observable'
ACTION_VIEW_IN_TRIAGE = 'view_in_triage'
ACTION_TRIAGE = 'triage'
ACTION_VMRAY = 'vmray'
ACTION_UN_WHITELIST = 'un_whitelist'
ACTION_WHITELIST = 'whitelist'
ACTION_URL_CRAWL = 'crawl'
ACTION_URLSCAN = 'urlscan'
ACTION_FILE_RENDER = 'file'
ACTION_ADD_TAG = 'add_tag'
ACTION_ENABLE_DETECTION = 'enable_detection'
ACTION_DISABLE_DETECTION = 'disable_detection'
ACTION_ADJUST_EXPIRATION = 'adjust_expiration'
ACTION_REVIEW_USER = 'review_user'

# recorded metrics
METRIC_THREAD_COUNT = 'thread_count'

# relationships
R_RELATED_TO = 'related_to'
R_DOWNLOADED_FROM = 'downloaded_from'
R_EXECUTED_ON = 'executed_on'
R_EXTRACTED_FROM = 'extracted_from'
R_IS_HASH_OF = 'is_hash_of'
R_LOGGED_INTO = 'logged_into'
R_REDIRECTED_FROM = 'redirected_from'

VALID_RELATIONSHIP_TYPES = [
    R_RELATED_TO,
    R_DOWNLOADED_FROM,
    R_EXECUTED_ON,
    R_EXTRACTED_FROM,
    R_IS_HASH_OF,
    R_LOGGED_INTO,
    R_REDIRECTED_FROM,
]

TARGET_EMAIL_RECEIVED = 'email.received'
TARGET_EMAIL_XMAILER = 'email.x_mailer'
TARGET_EMAIL_BODY = 'email.body'
TARGET_EMAIL_MESSAGE_ID = 'email.message_id'
TARGET_EMAIL_RCPT_TO = 'email.rcpt_to'
TARGET_VX_IPDOMAINSTREAMS = 'vx.ip_domain_streams'
VALID_TARGETS = [
    TARGET_EMAIL_RECEIVED,
    TARGET_EMAIL_XMAILER,
    TARGET_EMAIL_BODY,
    TARGET_EMAIL_MESSAGE_ID,
    TARGET_EMAIL_RCPT_TO,
    TARGET_VX_IPDOMAINSTREAMS,
]

# constants defined for keys to dicts (typically in json files)
KEY_DESCRIPTION = 'description'
KEY_DETAILS = 'details'

# analysis modes (more can be added)
ANALYSIS_MODE_AWS_HUNT = "aws_hunt"
ANALYSIS_MODE_CORRELATION = "correlation"
ANALYSIS_MODE_CLI = "cli"
ANALYSIS_MODE_ANALYSIS = "analysis"
ANALYSIS_MODE_EMAIL = "email"
ANALYSIS_MODE_HTTP = "http"
ANALYSIS_MODE_FILE = "file"
ANALYSIS_MODE_CLOUDPHISH = "cloudphish"
ANALYSIS_MODE_BINARY = "binary"
ANALYSIS_MODE_DISPOSITIONED = "dispositioned"
ANALYSIS_MODE_EVENT = "event"
ANALYSIS_MODE_TEST = "test"

ANALYSIS_TYPE_BRO_HTTP = 'bro - http'
ANALYSIS_TYPE_BRO_SMTP = 'bro - smtp'
ANALYSIS_TYPE_CLOUDPHISH = 'cloudphish'
ANALYSIS_TYPE_EWS = 'ews'
ANALYSIS_TYPE_FAQUEUE = 'faqueue'
ANALYSIS_TYPE_FIREEYE = 'fireeye'
ANALYSIS_TYPE_GENERIC = 'generic'
ANALYSIS_TYPE_MAILBOX = 'mailbox'
ANALYSIS_TYPE_MANUAL = 'manual'
ANALYSIS_TYPE_O365 = 'o365'
ANALYSIS_TYPE_PASSIVETOTAL = 'passivetotal'
ANALYSIS_TYPE_PROOFPOINT_EMAIL = 'proofpoint - email'
ANALYSIS_TYPE_PROOFPOINT_URL = 'proofpoint - url'
ANALYSIS_TYPE_PROOFPOINT_TRAP = 'proofpoint - trap'
ANALYSIS_TYPE_QRADAR_OFFENSE = 'qradar_offense'
ANALYSIS_TYPE_VIRUSTOTAL_LIVEHUNT = 'vti_livehunt'

# supported intelligence databases
INTEL_DB_SIP = 'sip'

# alert queues
QUEUE_DEFAULT = 'default'

# redis databases
REDIS_DB_SNORT = 1
REDIS_DB_TIP_A = 2
REDIS_DB_TIP_B = 3
REDIS_DB_FOR_DETECTION_A = 4
REDIS_DB_FOR_DETECTION_B = 5
REDIS_DB_BG_TASKS = 6
REDIS_DB_CELERY = 7

# valid summary detail formats
SUMMARY_DETAIL_FORMAT_PRE = 'pre' # preformatted
SUMMARY_DETAIL_FORMAT_TXT = 'txt' # plain text display

# messaging (TODO FIX ME)
MESSAGE_TYPE_SLACK = "slack"

REMEDIATION_STATUS_GUI = {'True': 'Attempted', 'False': 'Failed'}

# the list of tabs available in the gui
# this is used in the navigation_tabs property of the [gui] configuration section
GUI_TABS = [
    "analyze",
    "alerts",
    "events",
]

#
# service constants
#

SERVICE_STATUS_RUNNING = 'running'
SERVICE_STATUS_STOPPED = 'stopped'
SERVICE_STATUS_STALE = 'stale'
SERVICE_STATUS_DISABLED = 'disabled'

#
# collector constants
#

WORK_SUBMITTED = "work_submitted"
NO_WORK_AVAILABLE = "no_work_available"
NO_NODES_AVAILABLE = "no_nodes_available"
NO_WORK_SUBMITTED = "no_work_submitted"

# test modes
TEST_MODE_STARTUP = 'startup'
TEST_MODE_SINGLE_SUBMISSION = 'single_submission'


#
# global environment settings
#

G_ANALYST_DATA_DIR = "G_ANALYST_DATA_DIR"
G_API_PREFIX = "G_API_PREFIX"
G_AUTOMATION_USER_ID = "G_AUTOMATION_USER_ID"
G_CA_CHAIN_PATH = "G_CA_CHAIN_PATH"
G_COMPANY_ID = "G_COMPANY_ID"
G_COMPANY_NAME = "G_COMPANY_NAME"
G_CONFIG = "G_CONFIG"
G_CONFIG_PATHS = "G_CONFIG_PATHS"
G_DAEMON_DIR = "G_DAEMON_DIR"
G_DAEMON_MODE = "G_DAEMON_MODE"
G_DATA_DIR = "G_DATA_DIR"
G_DEFAULT_ENCODING = "G_DEFAULT_ENCODING"
G_DIRECTIVES = "G_DIRECTIVES"
G_DUMP_TRACEBACKS = "G_DUMP_TRACEBACKS"
G_ECS_SOCKET_PATH = "G_ECS_SOCKET_PATH"
G_EMAIL_ARCHIVE_SERVER_ID = "G_EMAIL_ARCHIVE_SERVER_ID"
G_ENCRYPTION_INITIALIZED = "G_ENCRYPTION_INITIALIZED"
G_ENCRYPTION_KEY = "G_ENCRYPTION_KEY"
G_EXECUTION_THREAD_LONG_TIMEOUT = "G_EXECUTION_THREAD_LONG_TIMEOUT"
G_FORCED_ALERTS = "G_FORCED_ALERTS"
G_GUI_WHITELIST_EXCLUDED_OBSERVABLE_TYPES = "G_GUI_WHITELIST_EXCLUDED_OBSERVABLE_TYPES"
G_INSTANCE_TYPE = "G_INSTANCE_TYPE"
G_INTEGRATION_CONFIG_PATHS = "G_INTEGRATION_CONFIG_PATHS"
G_LOCAL_DOMAINS = "G_LOCAL_DOMAINS"
G_LOCAL_TIMEZONE = "G_LOCAL_TIMEZONE"
G_LOCK_TIMEOUT_SECONDS = "G_LOCK_TIMEOUT_SECONDS"
G_LOG_DIRECTORY = "G_LOG_DIRECTORY"
G_LOG_LEVEL = "G_LOG_LEVEL"
G_MANAGED_NETWORKS = "G_MANAGED_NETWORKS"
G_MODULE_STATS_DIR = "G_MODULE_STATS_DIR"
G_NODE_COMPANIES = "G_NODE_COMPANIES"
G_OBSERVABLE_LIMIT = "G_OBSERVABLE_LIMIT"
G_OTHER_PROXIES = "G_OTHER_PROXIES"
G_SAQ_HOME = "G_SAQ_HOME"
G_SAQ_NODE = "G_SAQ_NODE"
G_SAQ_NODE_ID = "G_SAQ_NODE_ID"
G_SEMAPHORES_ENABLED = "G_SEMAPHORES_ENABLED"
G_SERVICES_DIR = "G_SERVICES_DIR"
G_SQLITE3_TIMEOUT = "G_SQLITE3_TIMEOUT"
G_STATS_DIR = "G_STATS_DIR"
G_TEMP_DIR = "G_TEMP_DIR"
G_UNIT_TESTING = "G_UNIT_TESTING"

#
# tags
#

TAG_SPECIAL = "special"
TAG_HIDDEN = "hidden"

#
# env constants
#

SAQ_ENC = "SAQ_ENC"

#
# configuration constants
#

CONFIG_GLOBAL = "global"

# global names
CONFIG_GLOBAL_ANALYST_DATA_DIR = "analyst_data_dir"
CONFIG_GLOBAL_CHECK_WATCHED_FILES_FREQUENCY = "check_watched_files_frequency"
CONFIG_GLOBAL_COMPANY_ID = "company_id"
CONFIG_GLOBAL_COMPANY_NAME = "company_name"
CONFIG_GLOBAL_DATA_DIR = "data_dir"
CONFIG_GLOBAL_DISTRIBUTE_DAYS_OLD = "distribute_days_old"
CONFIG_GLOBAL_DISTRIBUTION_TARGET = "distribution_target"
CONFIG_GLOBAL_ENABLE_SEMAPHORES = "enable_semaphores"
CONFIG_GLOBAL_ENCRYPTED_PASSWORDS_DB = "encrypted_passwords_db"
CONFIG_GLOBAL_ERROR_REPORTING_DIR = "error_reporting_dir"
CONFIG_GLOBAL_EXECUTION_THREAD_LONG_TIMEOUT = "execution_thread_long_timeout"
CONFIG_GLOBAL_FP_DAYS = "fp_days"
CONFIG_GLOBAL_IGNORE_DAYS = "ignore_days"
CONFIG_GLOBAL_INSTANCE_NAME = "instance_name"
CONFIG_GLOBAL_INSTANCE_TYPE = "instance_type"
CONFIG_GLOBAL_LOCAL_DOMAINS = "local_domains"
CONFIG_GLOBAL_LOCAL_EMAIL_DOMAINS = "local_email_domains"
CONFIG_GLOBAL_LOCK_KEEPALIVE_FREQUENCY = "lock_keepalive_frequency"
CONFIG_GLOBAL_LOCK_TIMEOUT = "lock_timeout"
CONFIG_GLOBAL_LOG_SQL = "log_sql"
CONFIG_GLOBAL_LOG_SQL_EXEC_TIMES = "log_sql_exec_times"
CONFIG_GLOBAL_MAXIMUM_ANALYSIS_DISK_SIZE = "maximum_analysis_disk_size"
CONFIG_GLOBAL_MAXIMUM_ANALYSIS_TIME = "maximum_analysis_time"
CONFIG_GLOBAL_MAXIMUM_CUMULATIVE_ANALYSIS_FAIL_TIME = "maximum_cumulative_analysis_fail_time"
CONFIG_GLOBAL_MAXIMUM_CUMULATIVE_ANALYSIS_WARNING_TIME = "maximum_cumulative_analysis_warning_time"
CONFIG_GLOBAL_MAXIMUM_OBSERVABLE_COUNT = "maximum_observable_count"
CONFIG_GLOBAL_MEMORY_LIMIT_KILL = "memory_limit_kill"
CONFIG_GLOBAL_MEMORY_LIMIT_WARNING = "memory_limit_warning"
CONFIG_GLOBAL_NODE = "node"
CONFIG_GLOBAL_TEMP_DIR = "tmp_dir"

# service constants
CONFIG_SERVICE_MODULE = "module"
CONFIG_SERVICE_CLASS = "class"
CONFIG_SERVICE_INSTANCE_TYPES = "instance_types"
CONFIG_SERVICE_ENABLED = "enabled"

# LLM
CONFIG_LLM = "llm"
CONFIG_LLM_EMBEDDING_MODEL = "embedding_model"
CONFIG_SERVICE_LLM_EMBEDDING = "service_llm_embedding"
CONFIG_SERVICE_LLM_EMBEDDING_ENABLED = "enabled"

# Qdrant
CONFIG_QDRANT = "qdrant"
CONFIG_QDRANT_URL = "url"
CONFIG_QDRANT_USE_SSL = "use_ssl"
CONFIG_QDRANT_SSL_CA_PATH = "ssl_ca_path"
CONFIG_QDRANT_API_KEY = "api_key"
CONFIG_QDRANT_COLLECTION_ALERTS = "collection_alerts"

# monitoring
CONFIG_MONITOR = "monitor"
CONFIG_MONITOR_USE_STDOUT = "use_stdout"
CONFIG_MONITOR_USE_STDERR = "use_stderr"
CONFIG_MONITOR_USE_LOGGING = "use_logging"
CONFIG_MONITOR_USE_CACHE = "use_cache"

# services
CONFIG_SERVICE_DEFAULT = "service_default"
CONFIG_SERVICE_WORKLOAD_TYPE = "workload_type"
CONFIG_SERVICE_QUEUE = "queue"
CONFIG_SERVICE_PERSISTENCE_CLEAR_SECONDS = "persistence_clear_seconds"
CONFIG_SERVICE_PERSISTENCE_EXPIRATION_SECONDS = "persistence_expiration_seconds"
CONFIG_SERVICE_PERSISTENCE_UNMODIFIED_EXPIRATION_SECONDS = "persistence_unmodified_expiration_seconds"

# modules
CONFIG_MODULE_ENABLED = "enabled"

# gui
CONFIG_GUI = "gui"
CONFIG_GUI_AUTHENTICATION = "authentication" # XXX remove
CONFIG_GUI_DISPLAY_EVENTS = "display_events"
CONFIG_GUI_DISPLAY_METRICS = "display_metrics"
CONFIG_GUI_GOOGLE_ANALYTICS = "google_analytics" # XXX remove
CONFIG_GUI_FILE_PREVIEW_BYTES = "file_preview_bytes"
CONFIG_GUI_NAVIGATION_TABS = "navigation_tabs" # XXX remove
CONFIG_GUI_SECRET_KEY = "secret_key"
CONFIG_GUI_WHITELIST_EXCLUDED_OBSERVABLE_TYPES = "whitelist_excluded_observable_types"
CONFIG_GUI_LISTEN_ADDRESS = "listen_address"
CONFIG_GUI_LISTEN_PORT = "listen_port"

# api
CONFIG_API = "api"
CONFIG_API_PREFIX = "prefix"
CONFIG_API_KEY = "api_key"
CONFIG_API_SECRET_KEY = "secret_key"

# ssl
CONFIG_SSL = "SSL"
CONFIG_SSL_CA_CHAIN_PATH = "ca_chain_path"

# sqlite3
CONFIG_SQLITE3 = "sqlite3"
CONFIG_SQLITE3_TIMEOUT = "timeout"

# collection
CONFIG_COLLECTION = "collection"
CONFIG_COLLECTION_QUEUE = "queue"
CONFIG_COLLECTION_DELETE_FILES = "delete_files"
CONFIG_COLLECTION_COLLECTION_FREQUENCY = "collection_frequency"
CONFIG_COLLECTION_WORKLOAD_TYPE = "workload_type"
CONFIG_COLLECTION_PERSISTENCE_DIR = "persistence_dir"
CONFIG_COLLECTION_INCOMING_DIR = "incoming_dir"
CONFIG_COLLECTION_ERROR_DIR = "error_dir"
CONFIG_COLLECTION_FORCE_API = "force_api"
CONFIG_COLLECTION_TUNING_UPDATE_FREQUENCY = "tuning_update_frequency"
CONFIG_COLLECTION_TUNING_DIR_DEFAULT = "tuning_dir_default"
CONFIG_COLLECTION_PERSISTENCE_CLEAR_SECONDS = "persistence_clear_seconds"
CONFIG_COLLECTION_PERSISTENCE_EXPIRATION_SECONDS = "persistence_expiration_seconds"
CONFIG_COLLECTION_PERSISTENCE_UNMODIFIED_EXPIRATION_SECONDS = "persistence_unmodified_expiration_seconds"

# collection group
CONFIG_COLLECTION_GROUP_COVERAGE = "coverage"
CONFIG_COLLECTION_GROUP_FULL_DELIVERY = "full_delivery"
CONFIG_COLLECTION_GROUP_COMPANY_ID = "company_id"
CONFIG_COLLECTION_GROUP_DATABASE = "database"
CONFIG_COLLECTION_GROUP_BATCH_SIZE = "batch_size"
CONFIG_COLLECTION_GROUP_THREAD_COUNT = "thread_count"
CONFIG_COLLECTION_GROUP_TARGET_NODE_AS_COMPANY_ID = "target_node_as_company_id"
CONFIG_COLLECTION_GROUP_TARGET_NODES = "target_nodes"
CONFIG_COLLECTION_GROUP_ENABLED = "enabled"

# node translation
CONFIG_NODE_TRANSLATION = "node_translation"

# network configuration
CONFIG_NETWORK_CONFIGURATION = "network_configuration"
CONFIG_NETWORK_CONFIGURATION_MANAGED_NETWORKS = "managed_networks"

# disposition settings??? gross
CONFIG_VALID_DISPOSITIONS = "valid_dispositions"
CONFIG_DISPOSITION_RANK = "disposition_rank"
CONFIG_DISPOSITION_CSS = "disposition_css"
CONFIG_DISPOSITION_SHOW_SAVE_TO_EVENT = "show_save_to_event"
CONFIG_DISPOSITION_BENIGN = "benign_dispositions"
CONFIG_DISPOSITION_MALICIOUS = "malicious_dispositions"

# service engine
CONFIG_ENGINE = "service_engine"
CONFIG_ENGINE_ALERTING_ENABLED = "alerting_enabled"
CONFIG_ENGINE_ALERT_DISPOSITION_CHECK_FREQUENCY = "alert_disposition_check_frequency"
CONFIG_ENGINE_ANALYSIS_MODES_IGNORE_CUMULATIVE_TIMEOUT = "analysis_modes_ignore_cumulative_timeout"
CONFIG_ENGINE_AUTO_REFRESH_FREQUENCY = "auto_refresh_frequency"
CONFIG_ENGINE_COPY_ANALYSIS_ON_ERROR = "copy_analysis_on_error"
CONFIG_ENGINE_COPY_FILE_ON_ERROR = "copy_file_on_error"
CONFIG_ENGINE_COPY_TERMINATED_ANALYSIS_CAUSES = "copy_terminated_analysis_causes"
CONFIG_ENGINE_DEFAULT_ANALYSIS_MODE = "default_analysis_mode"
CONFIG_ENGINE_EXCLUDED_ANALYSIS_MODES = "excluded_analysis_modes"
CONFIG_ENGINE_LOCAL_ANALYSIS_MODES = "local_analysis_modes"
CONFIG_ENGINE_NODE_STATUS_UPDATE_FREQUENCY = "node_status_update_frequency"
CONFIG_ENGINE_NON_DETECTABLE_MODES = "non_detectable_modes"
CONFIG_ENGINE_POOL_SIZE_LIMT = "pool_size_limit"
CONFIG_ENGINE_STOP_ANALYSIS_ON_ANY_ALERT_DISPOSITION = "stop_analysis_on_any_alert_disposition"
CONFIG_ENGINE_STOP_ANALYSIS_ON_DISPOSITIONS = "stop_analysis_on_dispositions"
CONFIG_ENGINE_TARGET_NODES = "target_nodes"
CONFIG_ENGINE_WORK_DIR = "work_dir"

# database
CONFIG_DATABASE = "database"
CONFIG_DATABASE_DATABASE = "database"
CONFIG_DATABASE_HOSTNAME = "hostname"
CONFIG_DATABASE_MAX_ALLOWED_PACKET = "max_allowed_packet"
CONFIG_DATABASE_MAX_CONNECTION_LIFETIME = "max_connection_lifetime"
CONFIG_DATABASE_PASSWORD = "password"
CONFIG_DATABASE_PORT = "port"
CONFIG_DATABASE_SSL_CA = "ssl_ca"
CONFIG_DATABASE_SSL_CERT = "ssl_cert"
CONFIG_DATABASE_SSL_KEY = "ssl_key"
CONFIG_DATABASE_UNIX_SOCKET = "unix_socket"
CONFIG_DATABASE_USERNAME = "username"

# database (ace)
CONFIG_DATABASE_ACE = "database_ace"

# tags
CONFIG_TAGS = "tags"
CONFIG_TAG_CSS_CLASS = "tag_css_class"

# gui favicons
CONFIG_GUI_FAVICONS = "gui_favicons"

# gui stuff
CONFIG_NODE_TRANSLATION_GUI = "node_translation_gui"
CONFIG_CUSTOM_ALERTS_BACKWARDS_COMPAT = "custom_alerts_backward_compatibility"

# custom alerts
CONFIG_CUSTOM_ALERTS = "custom_alerts"
CONFIG_CUSTOM_ALERTS_TEMPLATE_DIR = "template_dir"
CONFIG_CUSTOM_ALERTS_DIR = "dir"

# network semaphore
CONFIG_NETWORK_SEMAPHORE = "service_network_semaphore"

# apikeys
CONFIG_APIKEYS = "apikeys"

# email archive (module)
CONFIG_EMAIL_ARCHIVE_MODULE = "analysis_module_email_archiver"
CONFIG_EMAIL_ARCHIVE_MODULE_DIR = "archive_dir"

# email archive
CONFIG_EMAIL_ARCHIVE = "email_archive"
CONFIG_EMAIL_ARCHIVE_TARGET = "target"
CONFIG_EMAIL_ARCHIVE_PRIMARY = "primary"
CONFIG_EMAIL_ARCHIVE_S3_CONFIG = "s3_config"
CONFIG_EMAIL_ARCHIVE_S3_REGION = "s3_region"
CONFIG_EMAIL_ARCHIVE_S3_BUCKET = "s3_bucket"

# timeline
CONFIG_TIMELINE = "timeline"
CONFIG_TIMELINE_TIMEZONE = "timezone"

# observables
CONFIG_OBSERVABLE_EXPIRATION_MAPPINGS = "observable_expiration_mappings"
CONFIG_OBSERVABLE_EXCLUSIONS = "observable_exclusions"

# elk
CONFIG_ELK = "elk"
CONFIG_ELK_ENABLED = "enabled"
CONFIG_ELK_URI = "uri"
CONFIG_ELK_MAX_RESULT_COUNT = "max_result_count"
CONFIG_ELK_CLUSTER = "cluster"
CONFIG_ELK_RELATIVE_DURATION_BEFORE = "relative_duration_before"
CONFIG_ELK_RELATIVE_DURATION_AFTER = "relative_duration_after"
CONFIG_ELK_USERNAME = "username"
CONFIG_ELK_PASSWORD = "password"

CONFIG_ELK_LOGGING = "elk_logging"
CONFIG_ELK_LOGGING_DIR = "elk_log_dir"

# hunter
CONFIG_HUNTER = "service_hunter"

# ldap
CONFIG_LDAP = "ldap"
CONFIG_LDAP_SERVER = "ldap_server"
CONFIG_LDAP_PORT = "ldap_port"
CONFIG_LDAP_BIND_USER = "ldap_bind_user"
CONFIG_LDAP_BIND_PASSWORD = "ldap_bind_password"
CONFIG_LDAP_BASE_DN = "ldap_base_dn"
CONFIG_LDAP_TOP_USER = "top_user"

# smtp
CONFIG_SMTP = "smtp"
CONFIG_SMTP_ENABLED = "enabled"
CONFIG_SMTP_MAIL_FROM = "mail_from"
CONFIG_SMTP_SERVER = "server"

# asset tracking
CONFIG_ASSET_TRACKING = "asset_tracking"
CONFIG_ASSET_TRACKING_REQUIRE_ALL_TOOLS = "require_all_tools"
CONFIG_ASSET_TRACKING_REQUIRE_ONE_OF_TOOLS = "require_one_of_tools"

# analysis modules
CONFIG_ANALYSIS_MODULE_ID = "id"
CONFIG_ANALYSIS_MODULE_MODULE = "module"
CONFIG_ANALYSIS_MODULE_MODULE_GROUPS = "module_groups"
CONFIG_ANALYSIS_MODULE_CLASS = "class"
CONFIG_ANALYSIS_MODULE_INSTANCE = "instance"
CONFIG_ANALYSIS_MODULE_ENABLED = "enabled"

CONFIG_DISABLED_MODULES = "disabled_modules"

# analysis mode
CONFIG_ANALYSIS_MODE_CLEANUP = "cleanup"

# common configuration prefixes
CONFIG_ANALYSIS_MODE_PREFIX = "analysis_mode_"
CONFIG_MODULE_GROUP_PREFIX = "module_group_"
CONFIG_ANALYSIS_MODULE_PREFIX = "analysis_module_"


# splunk
CONFIG_SPLUNK = "splunk"
CONFIG_SPLUNK_URI = "uri"
CONFIG_SPLUNK_TIMEZONE = "timezone"
CONFIG_SPLUNK_USER_CONTEXT = "user_context"
CONFIG_SPLUNK_APP_CONTEXT = "app_context"

CONFIG_SPLUNK_LOGGING = "splunk_logging"
CONFIG_SPLUNK_LOGGING_DIR = "splunk_log_dir"

# query hunter
CONFIG_QUERY_HUNTER = "query_hunter"
CONFIG_QUERY_HUNTER_MAX_RESULT_COUNT = "max_result_count"
CONFIG_QUERY_HUNTER_QUERY_TIMEOUT = "query_timeout"

# email scanning
CONFIG_EMAIL = "email"
CONFIG_EMAIL_DIR = "email_dir"
CONFIG_EMAIL_SUBDIR_FORMAT = "subdir_format"

CONFIG_EMAIL_COLLECTOR = "service_email_collector"
CONFIG_EMAIL_COLLECTOR_ASSIGNMENT_YARA_RULE_PATH = "assignment_yara_rule_path"
CONFIG_EMAIL_COLLECTOR_BLACKLIST_YARA_RULE_PATH = "blacklist_yara_rule_path"

# journal email collector
CONFIG_JOURNAL_EMAIL_COLLECTOR = "service_journal_email_collector"
CONFIG_JOURNAL_EMAIL_COLLECTOR_DELETE_S3_OBJECTS = "delete_s3_objects"
CONFIG_JOURNAL_EMAIL_COLLECTOR_BLACKLIST_YARA_RULE_PATH = "blacklist_yara_rule_path"
CONFIG_JOURNAL_EMAIL_COLLECTOR_BLACKLIST_YARA_RULE_CHECK_FREQUENCY = "blacklist_yara_rule_check_frequency"


# remote email scanner
CONFIG_REMOTE_EMAIL_COLLECTOR = "service_remote_email_collector"

# events
CONFIG_EVENTS = "events"
CONFIG_EVENTS_AUTO_CLOSE_PATH = "auto_close_path"

# celery
CONFIG_RABBITMQ = "rabbitmq"
CONFIG_RABBITMQ_USER = "username"
CONFIG_RABBITMQ_PASSWORD = "password"
CONFIG_RABBITMQ_HOST = "host"
CONFIG_RABBITMQ_PORT = "port"

# minio
CONFIG_MINIO = "minio"
CONFIG_MINIO_HOST = "host"
CONFIG_MINIO_PORT = "port"
CONFIG_MINIO_ACCESS_KEY = "access_key"
CONFIG_MINIO_SECRET_KEY = "secret_key"
CONFIG_MINIO_SECURE = "secure"
CONFIG_MINIO_CERT_CHECK = "cert_check"
CONFIG_MINIO_REGION = "region"
CONFIG_MINIO_USE_EC2_METADATA = "use_ec2_metadata"

# redis
CONFIG_REDIS = "redis"
CONFIG_REDIS_USERNAME = "username"
CONFIG_REDIS_PASSWORD = "password"
CONFIG_REDIS_LOCAL = "redis-local"
CONFIG_REDIS_HOST = "host"
CONFIG_REDIS_PORT = "port"
CONFIG_REDIS_USE_SSL = "use_ssl"
CONFIG_REDIS_SSL_CA_PATH = "ssl_ca_path"

# yara scanner
CONFIG_YARA_SCANNER = "service_yara"
CONFIG_YARA_SCANNER_SOCKET_DIR = "socket_dir"
CONFIG_YARA_SCANNER_SIGNATURE_DIR = "signature_dir"
CONFIG_YARA_SCANNER_SCAN_FAILURE_DIR = "scan_failure_dir"

# yara scanner module
CONFIG_YARA_SCANNER_MODULE = "analysis_module_yara_scanner_v3_4"

# encryption
CONFIG_ENCRYPTION = "encryption"
CONFIG_ENCRYPTION_SALT_SIZE = "salt_size"
CONFIG_ENCRYPTION_ITERATIONS = "iterations"

# proxy
CONFIG_PROXY = "proxy"

# git
CONFIG_GIT = "git"
CONFIG_GIT_REPOS = "repos"

# cron
CONFIG_SERVICE_CRON = "service_cron"
CONFIG_SERVICE_CRON_CONFIG = "cron_config_path"

# engine state flag that indicates pre-analysis has been executed on a RootAnalysis
STATE_PRE_ANALYSIS_EXECUTED = "pre_analysis_executed"
STATE_POST_ANALYSIS_EXECUTED = "post_analysis_executed"

# storage constants
BUCKET_ACE3 = "ace3"

# email archive constants
EMAIL_ARCHIVE_FIELD_MESSAGE_ID = "message_id"
EMAIL_ARCHIVE_FIELD_URL = "url"

class AnalysisExecutionResult(Enum):
    """Enum representing the possible results of an analysis execution."""
    COMPLETED = "completed"
    INCOMPLETE = "incomplete"

class LockManagerType(Enum):
    """Enum representing the type of lock manager to use."""
    LOCAL = "local"
    DISTRIBUTED = "distributed"

class WorkloadManagerType(Enum):
    """Enum representing the type of workload manager to use."""
    DATABASE = "database"
    MEMORY = "memory"

class ExecutionMode(Enum):
    """Enum representing the mode of execution of something that runs in a loop."""
    SINGLE_SHOT = "single_shot" # execute once and then exit, useful for testing and command line tools
    CONTINUOUS = "continuous" # execute continuously until stopped