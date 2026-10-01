import json
import re
from ldap3 import ALL, RESTARTABLE, SIMPLE, Server, Connection, SUBTREE, ALL_ATTRIBUTES
from ldap3.utils.ciDict import CaseInsensitiveDict
from saq.configuration.config import get_config
from saq.email import is_local_email_domain, normalize_email_address

connection = None
def connect():
    global connection
    connection = Connection(
        Server(
            get_config().ldap.ldap_server,
            port = get_config().ldap.ldap_port,
            get_info = ALL,
        ),
        auto_bind = True,
        client_strategy = RESTARTABLE,
        user = get_config().ldap.ldap_bind_user,
        password = get_config().ldap.ldap_bind_password,
        authentication = SIMPLE,
        check_names = True,
    )

def search(query, attributes=ALL_ATTRIBUTES):
    # replace memberOf wildcard queries with fullmatch
    query = re.sub(r'\(memberOf=([^\)]*\*[^\)]*)\)', member_of_wildcard_substitute, query)
    base_dn = get_config().ldap.ldap_base_dn
    if connection is None:
        connect()
    return [entry_to_dict(e) for e in list(connection.extend.standard.paged_search(base_dn, query, SUBTREE, attributes=attributes))]

# custom encoder for the annoying dict type that comes out of ldap3
class CaseInsensitiveDictEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, CaseInsensitiveDict):
            return dict(obj)
        if isinstance(obj, bytes):
            return str(obj)[2:-1]
        try:
            return json.JSONEncoder.default(self, obj)
        except:
            return str(obj)

# hack to make ldap3 paged_search results json serializable
def entry_to_dict(entry):
    return json.loads(json.dumps(entry, cls=CaseInsensitiveDictEncoder))

def get_user_attributes(query):
    entries = search(query)

    if len(entries) == 0:
        return None

    attributes = entries[0]['attributes']

    # get the id of the user's manager
    if 'manager' in attributes:
        m = re.match(r'CN=([^,]+)', attributes['manager'])
        attributes['manager_cn'] = m.group(1)

    # determine if this user's email is on prem or not
    attributes['on_prem'] = None
    if 'msExchRecipientTypeDetails' in attributes:
        attributes['on_prem'] = attributes['msExchRecipientTypeDetails'] < 1024 or attributes['msExchRecipientTypeDetails'] == 4096
    elif 'objectClass' in attributes and 'publicFolder' in attributes['objectClass']:
        attributes['on_prem'] = True

    # get the user's primary email address
    attributes['primary_email'] = None
    if 'proxyAddresses' in attributes:
        for address in attributes['proxyAddresses']:
            if address.startswith("SMTP:"):
                attributes['primary_email'] = address.split(':', 1)[1]
                break

    return attributes

# return list of entries that match a given email address
def lookup_email_address(email_address, force=False):
    # don't look up external emails
    if not force and not is_local_email_domain(email_address):
        return None

    # lookup the user for an email by name so that it will match various internal domains
    email = normalize_email_address(email_address)
    name, domain = email.split('@', 1)

    # we have to use this query here
    return get_user_attributes(f"(proxyAddresses=smtp:{email})")

# return the user id of the email address
def lookup_user_by_email(email_address):
    details = lookup_email_address(email_address)
    if details is None:
        return None
    if 'cn' not in details:
        return None
    if details['cn'] is None:
        return None
    return details['cn'].lower()

# lookup a user by cn and return the attributes including manager cn
def lookup_user(user):
    return get_user_attributes(f"(cn={user})")

def lookup_user_email_address(user):
    attributes = lookup_user(user)
    if attributes is None:
        return None
    if 'mail' not in attributes:
        return None
    if attributes['mail'] is None:
        return None
    return normalize_email_address(attributes['mail'])

def get_child_groups(groups):
    query = ""
    for group in groups:
        query += f"(memberOf={group['dn']})"
    child_groups = search(f"(&(objectCategory=group)(|{query}))")
    if len(child_groups) > 0:
        child_groups.extend(get_child_groups(child_groups))
    return child_groups

def member_of_wildcard_substitute(match):
    query = f"(&(objectCategory=group)(cn={match.group(1)}))"
    groups = search(query)
    groups.extend(get_child_groups(groups))
    query = ""
    for group in groups:
        query += f"(memberOf={group['dn']})"
    return query

def find_users(query):
    entries = search(query, attributes=['cn'])
    return [e['attributes']['cn'].lower() for e in entries]

# converts a list of user ids to email addresses
def lookup_emails(employees):
    if len(employees) == 0:
        return []
    emps = ''.join([ f'(mail={e})' for e in employees ])
    query = f'(&(objectCategory=user)(|{emps}))'
    entries = search(query, attributes=['cn'])
    return [e['attributes']['cn'].lower() for e in entries]
