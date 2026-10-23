import pytest
from datetime import datetime
import saq
import saq.ldap
from ldap3.utils.ciDict import CaseInsensitiveDict
import json
import os.path

def mock_ldap(monkeypatch, datadir, query_filename_map):
    class MockServer:
        def __init__(self, *args, **kwargs):
            return

    class MockConnection:
        def __init__(self, *args, **kwargs):
            return
            
        def search(self, base_dn, query, tree, attributes=[]):
            self.response = {'entries':[]}
            if query in query_filename_map:
                with open(datadir / query_filename_map[query]) as f:
                    self.response = json.load(f)

        def response_to_json(self):
            return json.dumps(self.response)

        @property
        def extend(self):
            return self

        @property
        def standard(self):
            return self

        def paged_search(self, *args, **kwargs):
            self.search(*args, **kwargs)
            return self.response['entries']

    saq.ldap.connection = None
    monkeypatch.setattr("saq.ldap.Connection", MockConnection)
    monkeypatch.setattr("saq.ldap.Server", MockServer)

@pytest.mark.parametrize('email_address, query_filename_map, expected_cn, on_prem, primary', [
    ('"Doe, John" <john.doe@company.com>', {'(proxyAddresses=smtp:john.doe@company.com)':'jdoe.json'}, 'jdoe', True, None),
    ('"Doe, John" <john.doe@company.com>', {'(proxyAddresses=smtp:john.doe@company.com)':'jdoe_with_proxies.json'}, 'jdoe', True, 'jdoe@company.com'),
    ('"Doe, John" <john.doe@company.com>', {'(proxyAddresses=smtp:john.doe@company.com)':'public_folder.json'}, 'jdoe', True, None),
    ('"Doe, John" <john.doe@company.com>', {'(proxyAddresses=smtp:john.doe@company.com)':'off_prem.json'}, 'jdoe', False, None),
    ('"Doe, John" <john.doe@company.com>', {'(proxyAddresses=smtp:john.doe@company.com)':'no_prem.json'}, 'jdoe', None, None),
])
@pytest.mark.integration
def test_lookup_email_address(monkeypatch, datadir, email_address, query_filename_map, expected_cn, on_prem, primary):
    mock_ldap(monkeypatch, datadir, query_filename_map)
    user = saq.ldap.lookup_email_address(email_address)
    assert user['cn'].lower() == expected_cn
    assert user['on_prem'] == on_prem
    assert user['primary_email'] == primary

@pytest.mark.parametrize('user, query_filename_map, expected_attributes', [
    ('jdoe', {'(cn=jdoe)':'jdoe.json'}, {'cn':'jdoe','manager_cn':'theboss'}),
    ('nobody', {'(cn=jdoe)':'jdoe.json'}, None),
])
@pytest.mark.integration
def test_lookup_user(monkeypatch, datadir, user, query_filename_map, expected_attributes):
    mock_ldap(monkeypatch, datadir, query_filename_map)
    attributes = saq.ldap.lookup_user(user)
    if expected_attributes is None:
        assert attributes is None
    else:
        for attribute in expected_attributes:
            assert attributes[attribute] == expected_attributes[attribute]

@pytest.mark.parametrize('lookup, value, expected_query', [
    # an inbound sender address is attacker controlled: unescaped, a * matches some other user
    ('lookup_email_address', 'a*@company.com', r'(proxyAddresses=smtp:a\2a@company.com)'),
    ('lookup_email_address', '"a)(cn=*"@company.com', r'(proxyAddresses=smtp:"a\29\28cn=\2a"@company.com)'),
    ('lookup_user', 'j*', r'(cn=j\2a)'),
    ('lookup_user', 'jdoe)(objectClass=*', r'(cn=jdoe\29\28objectClass=\2a)'),
])
@pytest.mark.unit
def test_lookup_escapes_filter_characters(monkeypatch, lookup, value, expected_query):
    queries = []
    monkeypatch.setattr(saq.ldap, "search", lambda query, **kwargs: queries.append(query) or [])

    assert getattr(saq.ldap, lookup)(value) is None
    assert queries == [expected_query]


@pytest.mark.unit
def test_entry_to_dict():
    entry = {
        'recursive': {
            'cid': CaseInsensitiveDict(),
            'num': 1.3,
            'None': None,
            'date': datetime.strptime('2012-02-10', '%Y-%m-%d'),
            'str': 'hello',
            'bytes': b'123',
         },
    }
    d = saq.ldap.entry_to_dict(entry)
    assert d['recursive']['cid'] == {}
    assert d['recursive']['num'] == 1.3
    assert d['recursive']['None'] is None
    assert d['recursive']['date'] == '2012-02-10 00:00:00'
    assert d['recursive']['str'] == 'hello'
    assert d['recursive']['bytes'] == '123'
