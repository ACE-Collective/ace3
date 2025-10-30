from datetime import UTC, datetime
import pytest
from requests.exceptions import HTTPError, Timeout, ProxyError, ConnectionError

from saq.configuration import get_config
from saq.splunk import SplunkClient, SplunkQueryObject, extract_event_timestamp
from tests.saq.mock_datetime import MOCK_NOW
from tests.saq.requests import mock_site 

@pytest.mark.unit
def test_queue(requests_mock, datadir):
    # mock
    mock_site(requests_mock, datadir, [{
        'method': 'POST',
        'url': f'http://test.com/servicesNS/o/o/search/jobs',
        'status_code': 200,
        'headers': {'Authorization': 'Basic dXNlcjpwYXNz'},
        'request_text': 'search=search+hello&max_count=1',
        'response_file': 'queue_response.xml',
    }])

    # test
    splunk = SplunkQueryObject('http://test.com', 'user', 'pass', user_context='o', app='o')
    sid = splunk.queue('hello', 1)

    # verify
    assert sid == 'the_search_id'


@pytest.mark.unit
def test_complete(requests_mock, datadir):
    # mock
    mock_site(requests_mock, datadir, [{
        'method': 'GET',
        'url': f'http://test.com/servicesNS/o/o/search/jobs/sid',
        'status_code': 200,
        'headers': {'Authorization': 'Basic dXNlcjpwYXNz'},
        'response_file': 'complete_response.xml',
    }])

    # test
    splunk = SplunkQueryObject('http://test.com', 'user', 'pass', user_context='o', app='o')
    complete = splunk.complete('sid')

    # verify
    assert complete == True


@pytest.mark.unit
def test_incomplete(requests_mock, datadir):
    # mock
    mock_site(requests_mock, datadir, [{
        'method': 'GET',
        'url': f'http://test.com/servicesNS/o/o/search/jobs/sid',
        'status_code': 200,
        'headers': {'Authorization': 'Basic dXNlcjpwYXNz'},
        'response_file': 'incomplete_response.xml',
    }])

    # test
    splunk = SplunkQueryObject('http://test.com', 'user', 'pass', user_context='o', app='o')
    complete = splunk.complete('sid')

    # verify
    assert complete == False


@pytest.mark.unit
def test_complete_204(requests_mock, datadir):
    # mock
    mock_site(requests_mock, datadir, [{
        'method': 'GET',
        'url': f'http://test.com/servicesNS/o/o/search/jobs/sid',
        'status_code': 204,
        'headers': {'Authorization': 'Basic dXNlcjpwYXNz'},
        'response_text': '',
    }])

    # test
    splunk = SplunkQueryObject('http://test.com', 'user', 'pass', user_context='o', app='o')
    with pytest.raises(HTTPError) as e:
        complete = splunk.complete('sid')

    # verify
    assert e.value.response.status_code == 204


@pytest.mark.unit
def test_results(requests_mock, datadir):
    # mock
    mock_site(requests_mock, datadir, [{
        'method': 'GET',
        'url': f'http://test.com/servicesNS/o/o/search/jobs/sid/results',
        'params':  {'count': "0", 'output_mode': 'json_rows'},
        'status_code': 200,
        'headers': {'Authorization': 'Basic dXNlcjpwYXNz'},
        'response_file': 'results.json',
    }])

    # test
    splunk = SplunkQueryObject('http://test.com', 'user', 'pass', user_context='o', app='o')
    results = splunk.results('sid')

    # verify
    assert results == [{'foo': 'bar', 'hello': 'world'}]


@pytest.mark.unit
def test_cancel(requests_mock, datadir):
    # mock
    mock_site(requests_mock, datadir, [{
        'method': 'DELETE',
        'url': f'http://test.com/servicesNS/o/o/search/jobs/sid',
        'status_code': 200,
        'headers': {'Authorization': 'Basic dXNlcjpwYXNz'},
        'response_file': 'complete_response.xml',
    }])

    # test
    splunk = SplunkQueryObject('http://test.com', 'user', 'pass', user_context='o', app='o')
    cancelled = splunk.cancel('sid')

    assert cancelled == True


@pytest.mark.unit
def test_cancel_error(requests_mock, datadir):
    # mock
    mock_site(requests_mock, datadir, [{
        'method': 'DELETE',
        'url': f'http://test.com/servicesNS/o/o/search/jobs/sid',
        'status_code': 500,
        'headers': {'Authorization': 'Basic dXNlcjpwYXNz'},
        'response_file': 'complete_response.xml',
    }])

    # test
    splunk = SplunkQueryObject('http://test.com', 'user', 'pass', user_context='o', app='o')
    cancelled = splunk.cancel('sid')

    assert cancelled == False


@pytest.mark.unit
def test_cancel_none():
    splunk = SplunkQueryObject('http://test.com', 'user', 'pass', user_context='o', app='o')
    cancelled = splunk.cancel(None)

    assert cancelled == True


@pytest.mark.unit
def test_get_all_from_kvstore(requests_mock, datadir):
    # mock
    mock_site(requests_mock, datadir, [{
        'method': 'GET',
        'url': f'http://test.com/servicesNS/o/o/storage/collections/data/hello',
        'status_code': 200,
        'headers': {'Authorization': 'Basic dXNlcjpwYXNz'},
        'response_json': [{'foo': 'bar', 'hello': 'world'}],
    }])

    # test
    splunk = SplunkQueryObject('http://test.com', 'user', 'pass', user_context='o', app='o')
    results = splunk.get_all_from_kvstore('hello')

    # verify
    assert results == [{'foo': 'bar', 'hello': 'world'}]


@pytest.mark.unit
def test_get_all_from_kvstore_error(requests_mock, datadir):
    # mock
    mock_site(requests_mock, datadir, [{
        'method': 'GET',
        'url': f'http://test.com/servicesNS/o/o/storage/collections/data/hello',
        'status_code': 500,
        'headers': {'Authorization': 'Basic dXNlcjpwYXNz'},
        'response_json': [{'foo': 'bar', 'hello': 'world'}],
    }])

    # test
    splunk = SplunkQueryObject('http://test.com', 'user', 'pass', user_context='o', app='o')
    results = splunk.get_all_from_kvstore('hello')

    # verify
    assert results == []


@pytest.mark.unit
def test_save_to_kvstore(requests_mock, datadir):
    # mock
    mock_site(requests_mock, datadir, [{
        'method': 'POST',
        'url': f'http://test.com/servicesNS/o/o/storage/collections/data/hello/batch_save',
        'status_code': 200,
        'headers': {'Authorization': 'Basic dXNlcjpwYXNz'},
        'request_json': [{'foo': 'bar', 'hello': 'world'}],
        'response_json': [{'foo': 'bar'}],
    }])

    # test
    splunk = SplunkQueryObject('http://test.com', 'user', 'pass', user_context='o', app='o')
    results = splunk.save_to_kvstore('hello', [{'foo': 'bar', 'hello': 'world'}])

    # verify
    assert results == True


@pytest.mark.unit
def test_save_to_kvstore_error(requests_mock, datadir):
    # mock
    mock_site(requests_mock, datadir, [{
        'method': 'POST',
        'url': f'http://test.com/servicesNS/o/o/storage/collections/data/hello/batch_save',
        'status_code': 500,
        'headers': {'Authorization': 'Basic dXNlcjpwYXNz'},
        'request_json': [{'foo': 'bar', 'hello': 'world'}],
        'response_json': [{'foo': 'bar'}],
    }])

    # test
    splunk = SplunkQueryObject('http://test.com', 'user', 'pass', user_context='o', app='o')
    results = splunk.save_to_kvstore('hello', [{'foo': 'bar', 'hello': 'world'}])

    # verify
    assert results == False


@pytest.mark.unit
def test_delete_from_kvstore_by_id(requests_mock, datadir):
    # mock
    mock_site(requests_mock, datadir, [{
        'method': 'DELETE',
        'url': f'http://test.com/servicesNS/o/o/storage/collections/data/hello/123',
        'status_code': 200,
        'headers': {'Authorization': 'Basic dXNlcjpwYXNz'},
        'response_text': '',
    }])

    # test
    splunk = SplunkQueryObject('http://test.com', 'user', 'pass', user_context='o', app='o')
    results = splunk.delete_from_kvstore_by_id('hello', '123')

    # verify
    assert results == True


@pytest.mark.unit
def test_delete_from_kvstore_by_id_error(requests_mock, datadir):
    # mock
    mock_site(requests_mock, datadir, [{
        'method': 'DELETE',
        'url': f'http://test.com/servicesNS/o/o/storage/collections/data/hello/123',
        'status_code': 500,
        'headers': {'Authorization': 'Basic dXNlcjpwYXNz'},
        'response_text': '',
    }])

    # test
    splunk = SplunkQueryObject('http://test.com', 'user', 'pass', user_context='o', app='o')
    results = splunk.delete_from_kvstore_by_id('hello', '123')

    # verify
    assert results == False


@pytest.mark.unit
def test_delete_all_from_kvstore(requests_mock, datadir):
    # mock
    mock_site(requests_mock, datadir, [{
        'method': 'DELETE',
        'url': f'http://test.com/servicesNS/o/o/storage/collections/data/hello',
        'status_code': 200,
        'headers': {'Authorization': 'Basic dXNlcjpwYXNz'},
        'response_text': '',
    }])

    # test
    splunk = SplunkQueryObject('http://test.com', 'user', 'pass', user_context='o', app='o')
    results = splunk.delete_all_from_kvstore('hello')

    # verify
    assert results == True


@pytest.mark.unit
def test_delete_all_from_kvstore_error(requests_mock, datadir):
    # mock
    mock_site(requests_mock, datadir, [{
        'method': 'DELETE',
        'url': f'http://test.com/servicesNS/o/o/storage/collections/data/hello',
        'status_code': 500,
        'headers': {'Authorization': 'Basic dXNlcjpwYXNz'},
        'response_text': '',
    }])

    # test
    splunk = SplunkQueryObject('http://test.com', 'user', 'pass', user_context='o', app='o')
    results = splunk.delete_all_from_kvstore('hello')

    # verify
    assert results == False


@pytest.mark.unit
def test_link():
    # init splunk
    splunk = SplunkQueryObject('http://test.com:8089', 'test', 'test')

    # make sure special chars get encoded
    link = splunk.encoded_query_link('search index=test field!=":&+*" | table field')
    assert link == 'http://test.com/en-US/app/search/search?q=search+index%3Dtest+field%21%3D%22%3A%26%2B%2A%22+%7C+table+field'

    # make sure search is prepended when missing
    link = splunk.encoded_query_link('index=test field!=":&+*" | table field')
    assert link == 'http://test.com/en-US/app/search/search?q=search+index%3Dtest+field%21%3D%22%3A%26%2B%2A%22+%7C+table+field'

    # test optional time range
    link = splunk.encoded_query_link('index=test', start_time=MOCK_NOW, end_time=MOCK_NOW)
    assert link == 'http://test.com/en-US/app/search/search?q=search+index%3Dtest&earliest=1510385761&latest=1510385761'

    # test app namespace
    splunk = SplunkQueryObject('http://test.com:8089', 'test', 'test', app='myapp')
    link = splunk.encoded_query_link('search index=test field!=":&+*" | table field')
    assert link == 'http://test.com/en-US/app/myapp/search?q=search+index%3Dtest+field%21%3D%22%3A%26%2B%2A%22+%7C+table+field'


@pytest.mark.unit
def test_get_event_time(monkeypatch):
    def mock_local_time():
        return 'blorp'
    monkeypatch.setattr('saq.splunk.local_time', mock_local_time)
    assert extract_event_timestamp({}) == 'blorp'
    assert extract_event_timestamp({'_time': '2021-03-04'}) == 'blorp'
    assert extract_event_timestamp({'_time': '2021-03-04T01:01:01.001+00:00'}) == datetime(2021, 3, 4, 1, 1, 1, tzinfo=UTC)


@pytest.mark.unit
def test_query(monkeypatch):
    search_results = None
    class MockSplunk(SplunkQueryObject):
        def query_async(self, query, sid=None, limit=1000, start=None, end=None, use_index_time=False, timeout=None):
            self.cancelled = False
            return sid, search_results

        def cancel(self, sid):
            self.cancelled = True

        def delete_search_job(self, sid):
            self.cancelled = True
            return True

        def get_search_log(self, *args, **kwargs):
            return True

    def mock_sleep(t):
        nonlocal search_results
        search_results = 'yada'

    monkeypatch.setattr('saq.splunk.time.sleep', mock_sleep)

    # test no longer valid since timeout check moved into query_async
    #splunk = MockSplunk('http://test.com:8089', 'test', 'test')
    #splunk.running_start_time = local_time()
    #result = splunk.query('whatever', timeout='00:00:00')
    #assert result == []
    #assert splunk.cancelled == True

    splunk = MockSplunk('http://test.com:8089', 'test', 'test')
    result = splunk.query('whatever', timeout='05:00:00')
    assert splunk.cancelled == False
    assert result == 'yada'


@pytest.mark.unit
def test_query_async(monkeypatch):
    queue_result = '123'
    complete = False

    class MockSplunk(SplunkQueryObject):
        def queue(self, query, limit, start=None, end=None, use_index_time=False):
            return queue_result

        def complete(self, sid):
            assert sid == '123'
            return complete

        def results(self, sid):
            return 'blorp' if sid == '123' else None

        def delete_search_job(self, sid):
            return True

        def get_search_log(self, *args, **kwargs):
            return True

    splunk = MockSplunk('http://test.com:8089', 'test', 'test')

    # first call should just queue
    sid, result = splunk.query_async('whatever', sid=None)
    assert sid == '123'
    assert result == None

    # second call should be incomplete
    queue_result = '456'
    sid, result = splunk.query_async('whatever', sid=sid)
    assert sid == '123'
    assert result == None

    # third call should return results
    complete = True
    sid, result = splunk.query_async('whatever', sid=sid)
    assert sid == '123'
    assert result == 'blorp'


class MockResponse:
    def __init__(self, status_code):
        self.status_code = status_code
@pytest.mark.parametrize('exception, expected_result', [
    (HTTPError('error', response=MockResponse(204)), None),
    (HTTPError('error', response=MockResponse(404)), []),
    (ConnectionError(), []),
    (Timeout(), []),
    (ProxyError(), []),
    (Exception(), []),
])
@pytest.mark.unit
def test_query_async_error(exception, expected_result):
    class MockSplunk(SplunkQueryObject):
        def complete(self, sid):
            self.cancelled = False
            raise exception
        def cancel(self, sid):
            assert sid == '123'
            self.cancelled = True
        def delete_search_job(self, sid):
            self.cancelled = True
            return True
        def get_search_log(self, *args, **kwargs):
            return True

    splunk = MockSplunk('http://test.com:8089', 'test', 'test')

    sid, result = splunk.query_async('whatever', sid='123')
    assert sid == None
    assert result == expected_result
    assert splunk.cancelled == (expected_result is not None)


@pytest.mark.unit
def test_splunk_client_init(monkeypatch):
    monkeypatch.setattr('saq.OTHER_PROXIES', { 'zorp': { 'http': 'http://whatever' } })
    get_config()['splunk_test'] = {
        'uri': 'https://test.com:443',
        'username': 'hello',
        'password': 'world',
        'proxy': 'zorp',
    }

    client = SplunkClient('splunk_test', user_context='foo', app='bar')

    assert client.search_session.base_url == 'https://test.com:443/servicesNS/foo/bar'
    assert client.search_session.proxies == { 'http': 'http://whatever' }
    assert client.search_session.auth == ('hello', 'world')
    assert client.search_session.trust_env == False
    assert client.search_session.verify == False
    assert client.gui_path == 'en-US/app/bar/search'


@pytest.mark.unit
def test_splunk_client_init(monkeypatch):
    get_config()['splunk_test'] = {
        'uri': 'https://test.com:443',
        'username': 'hello',
        'password': 'world',
    }

    client = SplunkClient('splunk_test')

    assert client.search_session.base_url == 'https://test.com:443/servicesNS/-/-'
    assert client.search_session.proxies == {}
    assert client.search_session.auth == ('hello', 'world')
    assert client.search_session.trust_env == False
    assert client.search_session.verify == False
    assert client.gui_path == 'en-US/app/search/search'
