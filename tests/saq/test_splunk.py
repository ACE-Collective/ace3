from datetime import UTC, datetime
from unittest.mock import Mock, patch

import pytest
from requests.exceptions import ConnectionError, HTTPError, ProxyError, Timeout
from splunklib.binding import HTTPError as SplunkHTTPError
from splunklib.client import AuthenticationError

from saq.configuration import get_config
from saq.configuration.schema import ProxyConfig, SplunkConfig
from saq.splunk import (
    SplunkClient,
    SplunkQueryObject,
    _proxy_handler,
    extract_event_timestamp,
)
from tests.saq.mock_datetime import MOCK_NOW


@pytest.mark.unit
def test_queue():
    # create mock job
    mock_job = Mock()
    mock_job.name = "the_search_id"

    # create mock client with jobs collection
    mock_client = Mock()
    mock_client.jobs.create.return_value = mock_job

    # test
    with patch("saq.splunk.client.connect", return_value=mock_client):
        splunk = SplunkQueryObject(host="test.com", port=8089, username="user", password="pass", user_context="o", app="o")
        job = splunk.queue("hello", 1)

    # verify
    assert job.name == "the_search_id"
    mock_client.jobs.create.assert_called_once()


@pytest.mark.unit
def test_complete():
    # create mock job
    mock_job = Mock()
    mock_job.name = "sid"
    mock_job.is_ready.return_value = True
    mock_job.__getitem__ = Mock(side_effect=lambda x: {
        "isDone": "1",
        "doneProgress": "1.0",
        "dispatchState": "DONE",
        "isFailed": "0",
        "eventCount": "100",
        "runDuration": "1.234"
    }[x])

    # create mock client
    mock_client = Mock()

    # test
    with patch("saq.splunk.client.connect", return_value=mock_client):
        splunk = SplunkQueryObject(host="test.com", port=8089, username="user", password="pass", user_context="o", app="o")
        complete = splunk.complete(mock_job)

    # verify
    assert complete is True
    mock_job.refresh.assert_called_once()


@pytest.mark.unit
def test_incomplete():
    # create mock job
    mock_job = Mock()
    mock_job.name = "sid"
    mock_job.is_ready.return_value = True
    mock_job.__getitem__ = Mock(side_effect=lambda x: {
        "isDone": "0",
        "doneProgress": "0.5",
        "dispatchState": "RUNNING",
        "isFailed": "0",
        "eventCount": "50",
        "runDuration": "0.5"
    }[x])

    # create mock client
    mock_client = Mock()

    # test
    with patch("saq.splunk.client.connect", return_value=mock_client):
        splunk = SplunkQueryObject(host="test.com", port=8089, username="user", password="pass", user_context="o", app="o")
        complete = splunk.complete(mock_job)

    # verify
    assert complete is False
    mock_job.refresh.assert_called_once()


@pytest.mark.unit
def test_complete_not_ready():
    # create mock job that is not ready
    mock_job = Mock()
    mock_job.name = "sid"
    mock_job.is_ready.return_value = False

    # create mock client
    mock_client = Mock()

    # test
    with patch("saq.splunk.client.connect", return_value=mock_client):
        splunk = SplunkQueryObject(host="test.com", port=8089, username="user", password="pass", user_context="o", app="o")
        complete = splunk.complete(mock_job)

    # verify
    assert not complete
    mock_job.refresh.assert_not_called()


@pytest.mark.unit
def test_results():
    # create mock job that is complete
    mock_job = Mock()
    mock_job.name = "sid"
    mock_job.is_ready.return_value = True
    mock_job.__getitem__ = Mock(side_effect=lambda x: {
        "isDone": "1",
        "doneProgress": "1.0",
        "dispatchState": "DONE",
        "isFailed": "0",
        "eventCount": "100",
        "runDuration": "1.234"
    }[x])
    mock_job.results.return_value = '{"fields":["foo","hello"],"rows":[["bar","world"]]}'

    # create mock client
    mock_client = Mock()

    # mock the JSONResultsReader to return expected results
    with patch("saq.splunk.client.connect", return_value=mock_client):
        with patch("saq.splunk.JSONResultsReader") as mock_reader:
            mock_reader.return_value = [{"foo": "bar", "hello": "world"}]

            splunk = SplunkQueryObject(host="test.com", port=8089, username="user", password="pass", user_context="o", app="o")

            # simulate query_async completing
            job, results = splunk.query_async("test", job=mock_job, limit=1000)

            # verify
            assert results == [{"foo": "bar", "hello": "world"}]
            mock_job.results.assert_called_once_with(count="0", output_mode="json")


@pytest.mark.unit
def test_cancel():
    # create mock job
    mock_job = Mock()
    mock_job.name = "sid"
    mock_job.cancel.return_value = None

    # create mock client
    mock_client = Mock()

    # test
    with patch("saq.splunk.client.connect", return_value=mock_client):
        splunk = SplunkQueryObject(host="test.com", port=8089, username="user", password="pass", user_context="o", app="o")
        cancelled = splunk.cancel(mock_job)

    assert cancelled is True
    mock_job.cancel.assert_called_once()


@pytest.mark.unit
def test_cancel_error():
    # create mock job that raises exception
    mock_job = Mock()
    mock_job.name = "sid"
    mock_job.cancel.side_effect = Exception("cancel failed")

    # create mock client
    mock_client = Mock()

    # test
    with patch("saq.splunk.client.connect", return_value=mock_client):
        splunk = SplunkQueryObject(host="test.com", port=8089, username="user", password="pass", user_context="o", app="o")
        cancelled = splunk.cancel(mock_job)

    assert cancelled is False


@pytest.mark.unit
def test_cancel_none():
    # create mock client
    mock_client = Mock()

    with patch("saq.splunk.client.connect", return_value=mock_client):
        splunk = SplunkQueryObject(host="test.com", port=8089, username="user", password="pass", user_context="o", app="o")
        cancelled = splunk.cancel(None)

    assert cancelled is True


@pytest.mark.unit
def test_delete_search_job():
    # create mock job
    mock_job = Mock()
    mock_job.name = "sid"
    mock_job.delete.return_value = None

    # create mock client
    mock_client = Mock()

    # test
    with patch("saq.splunk.client.connect", return_value=mock_client):
        splunk = SplunkQueryObject(host="test.com", port=8089, username="user", password="pass", user_context="o", app="o")
        deleted = splunk.delete_search_job(mock_job)

    assert deleted
    mock_job.delete.assert_called_once()


@pytest.mark.unit
def test_delete_search_job_error():
    # create mock job that raises exception
    mock_job = Mock()
    mock_job.name = "sid"
    mock_job.delete.side_effect = Exception("delete failed")

    # create mock client
    mock_client = Mock()

    # test
    with patch("saq.splunk.client.connect", return_value=mock_client):
        splunk = SplunkQueryObject(host="test.com", port=8089, username="user", password="pass", user_context="o", app="o")
        deleted = splunk.delete_search_job(mock_job)

    assert not deleted


@pytest.mark.unit
def test_link():
    # create mock client
    mock_client = Mock()

    with patch("saq.splunk.client.connect", return_value=mock_client):
        # init splunk
        splunk = SplunkQueryObject(host="test.com", port=8089, username="test", password="test")

        # make sure special chars get encoded
        link = splunk.encoded_query_link('search index=test field!=":&+*" | table field')
        assert link == 'https://test.com/en-US/app/search/search?q=search+index%3Dtest+field%21%3D%22%3A%26%2B%2A%22+%7C+table+field'

        # make sure search is prepended when missing
        link = splunk.encoded_query_link('index=test field!=":&+*" | table field')
        assert link == 'https://test.com/en-US/app/search/search?q=search+index%3Dtest+field%21%3D%22%3A%26%2B%2A%22+%7C+table+field'

        # test optional time range
        link = splunk.encoded_query_link('index=test', start_time=MOCK_NOW, end_time=MOCK_NOW)
        assert link == 'https://test.com/en-US/app/search/search?q=search+index%3Dtest&earliest=1510385761&latest=1510385761'

        # test app namespace
        splunk = SplunkQueryObject(host="test.com", port=8089, username="test", password="test", app="myapp")
        link = splunk.encoded_query_link('search index=test field!=":&+*" | table field')
        assert link == 'https://test.com/en-US/app/myapp/search?q=search+index%3Dtest+field%21%3D%22%3A%26%2B%2A%22+%7C+table+field'


@pytest.mark.unit
def test_link_with_use_index_time():
    # create mock client
    mock_client = Mock()

    with patch("saq.splunk.client.connect", return_value=mock_client):
        # init splunk
        splunk = SplunkQueryObject(host="test.com", port=8089, username="test", password="test")

        # test use_index_time with both start and end times
        link = splunk.encoded_query_link('index=test', start_time=MOCK_NOW, end_time=MOCK_NOW, use_index_time=True)
        # verify the query includes _index_earliest and _index_latest
        assert '_index_earliest%3D11%2F11%2F2017%3A07%3A36%3A01' in link
        assert '_index_latest%3D11%2F11%2F2017%3A07%3A36%3A01' in link
        # verify the earliest and latest params are extended by 30 days
        # MOCK_NOW - 30 days = 1507793761, MOCK_NOW + 30 days = 1512977761
        assert 'earliest=1507793761' in link
        assert 'latest=1512977761' in link

        # test use_index_time with only start time
        link = splunk.encoded_query_link('index=test', start_time=MOCK_NOW, use_index_time=True)
        assert '_index_earliest%3D11%2F11%2F2017%3A07%3A36%3A01' in link
        assert '_index_latest%3D' in link
        assert '&earliest=1507793761' in link
        assert '&latest=' not in link

        # test use_index_time with only end time
        link = splunk.encoded_query_link('index=test', end_time=MOCK_NOW, use_index_time=True)
        assert '_index_earliest%3D' in link
        assert '_index_latest%3D11%2F11%2F2017%3A07%3A36%3A01' in link
        assert '&earliest=' not in link
        assert '&latest=1512977761' in link

        # test use_index_time without any times
        link = splunk.encoded_query_link('index=test', use_index_time=True)
        assert '_index_earliest%3D' in link
        assert '_index_latest%3D' in link
        assert '&earliest=' not in link
        assert '&latest=' not in link

        # test use_index_time with 'search' already in query
        link = splunk.encoded_query_link('search index=test | stats count', start_time=MOCK_NOW, end_time=MOCK_NOW, use_index_time=True)
        assert '_index_earliest%3D11%2F11%2F2017%3A07%3A36%3A01' in link
        assert '_index_latest%3D11%2F11%2F2017%3A07%3A36%3A01' in link
        assert 'earliest=1507793761' in link
        assert 'latest=1512977761' in link

        # test use_index_time with special characters in query
        link = splunk.encoded_query_link('index=test field!=":&+*"', start_time=MOCK_NOW, end_time=MOCK_NOW, use_index_time=True)
        assert '_index_earliest%3D11%2F11%2F2017%3A07%3A36%3A01' in link
        assert '_index_latest%3D11%2F11%2F2017%3A07%3A36%3A01' in link
        assert 'field%21%3D%22%3A%26%2B%2A%22' in link


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
        def query_async(self, query, job=None, limit=1000, start=None, end=None, use_index_time=False, timeout=None):
            self.cancelled = False
            return job, search_results

        def cancel(self, job):
            self.cancelled = True

        def delete_search_job(self, job):
            self.cancelled = True
            return True

    def mock_sleep(t):
        nonlocal search_results
        search_results = 'yada'

    monkeypatch.setattr('saq.splunk.time.sleep', mock_sleep)

    # create mock client
    mock_client = Mock()

    with patch("saq.splunk.client.connect", return_value=mock_client):
        splunk = MockSplunk(host="test.com", port=8089, username="test", password="test")
        result = splunk.query('whatever', timeout='05:00:00')
        assert not splunk.cancelled
        assert result == 'yada'


@pytest.mark.unit
def test_query_async(monkeypatch):
    queue_result = Mock()
    queue_result.name = "123"
    queue_result.results.return_value = Mock()
    complete_status = False

    class MockSplunk(SplunkQueryObject):
        def queue(self, query, limit, start=None, end=None, use_index_time=False):
            return queue_result

        def complete(self, job):
            # only verify job name on the first job instance
            if job.name == "123":
                return complete_status
            # if we somehow got a different job, fail
            raise AssertionError(f"unexpected job name: {job.name}")

        def delete_search_job(self, job):
            return True

    # create mock client
    mock_client = Mock()

    with patch("saq.splunk.client.connect", return_value=mock_client):
        with patch("saq.splunk.JSONResultsReader") as mock_reader:
            mock_reader.return_value = ["blorp"]

            splunk = MockSplunk(host="test.com", port=8089, username="test", password="test")

            # first call should just queue
            job, result = splunk.query_async('whatever', job=None)
            assert job.name == "123"
            assert result is None

            # second call should be incomplete (job not complete yet)
            job, result = splunk.query_async('whatever', job=job)
            assert job.name == "123"
            assert result is None

            # third call should return results (job is now complete)
            complete_status = True
            job, result = splunk.query_async('whatever', job=job)
            assert job.name == "123"
            assert result == ["blorp"]


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
        def complete(self, job):
            self.cancelled = False
            raise exception
        def cancel(self, job):
            assert job.name == "123"
            self.cancelled = True
        def delete_search_job(self, job):
            self.cancelled = True
            return True

    # create mock job
    mock_job = Mock()
    mock_job.name = "123"

    # create mock client
    mock_client = Mock()

    with patch("saq.splunk.client.connect", return_value=mock_client):
        splunk = MockSplunk(host="test.com", port=8089, username="test", password="test")

        job, result = splunk.query_async('whatever', job=mock_job)
        assert job is None
        assert result == expected_result
        assert splunk.cancelled == (expected_result is not None)


@pytest.mark.unit
def test_query_async_authentication_error():
    class MockSplunk(SplunkQueryObject):
        def complete(self, job):
            self.cancelled = False
            # construct a valid AuthenticationError with mocked splunklib internals
            mock_response = Mock()
            mock_response.status = 401
            mock_response.reason = "Unauthorized"
            mock_response.body = Mock(read=lambda: b"Session expired")
            mock_response.headers = {}
            cause = SplunkHTTPError(mock_response)
            raise AuthenticationError("session expired", cause=cause)
        def cancel(self, job):
            self.cancelled = True
        def delete_search_job(self, job):
            self.cancelled = True
            return True

    # create mock job
    mock_job = Mock()
    mock_job.name = "123"

    # create mock client
    mock_client = Mock()

    with patch("saq.splunk.client.connect", return_value=mock_client):
        splunk = MockSplunk(host="test.com", port=8089, username="test", password="test")

        job, result = splunk.query_async("whatever", job=mock_job)
        assert job is mock_job
        assert result is None
        assert splunk.cancelled is False


@pytest.mark.unit
def test_splunk_client_init():
    get_config().clear_splunk_configs()
    get_config().add_splunk_config("splunk_test",
        SplunkConfig(
            name="splunk_test",
            enabled=True,
            host="test.com",
            port=443,
            username="hello",
            password="world",
            token=None,
            timezone="UTC",
            performance_logging_dir=".",
            user_context="foo",
            app_context="bar",
        )
    )
    # create mock client
    mock_client = Mock()

    with patch("saq.splunk.client.connect") as mock_connect:
        mock_connect.return_value = mock_client
        client = SplunkClient('splunk_test', user_context='foo', app='bar')

        # verify connection was called with correct parameters
        mock_connect.assert_called_once()
        call_kwargs = mock_connect.call_args[1]
        assert call_kwargs['host'] == 'test.com'
        assert call_kwargs['port'] == 443
        assert call_kwargs['username'] == 'hello'
        assert call_kwargs['password'] == 'world'
        assert call_kwargs['owner'] == 'foo'
        assert call_kwargs['app'] == 'bar'
        assert call_kwargs['autologin']

        assert client.gui_path == 'en-US/app/bar/search'


@pytest.mark.unit
def test_splunk_client_init_defaults():
    get_config().clear_splunk_configs()
    get_config().add_splunk_config("splunk_test",
        SplunkConfig(
            name="splunk_test",
            enabled=True,
            host="test.com",
            port=443,
            username="hello",
            password="world",
            timezone="UTC",
            performance_logging_dir=".",
        )
    )

    # create mock client
    mock_client = Mock()

    with patch("saq.splunk.client.connect") as mock_connect:
        mock_connect.return_value = mock_client
        client = SplunkClient('splunk_test')

        # verify connection was called with correct parameters
        mock_connect.assert_called_once()
        call_kwargs = mock_connect.call_args[1]
        assert call_kwargs['host'] == 'test.com'
        assert call_kwargs['port'] == 443
        assert call_kwargs['username'] == 'hello'
        assert call_kwargs['password'] == 'world'

        assert client.gui_path == 'en-US/app/search/search'


@pytest.mark.unit
def test_splunk_client_init_with_token():
    get_config().clear_splunk_configs()
    get_config().add_splunk_config("splunk_test",
        SplunkConfig(
            name="splunk_test",
            enabled=True,
            host="test.com",
            port=443,
            token="mytoken123",
            timezone="UTC",
            performance_logging_dir=".",
            user_context="foo",
            app_context="bar",
        )
    )

    # create mock client
    mock_client = Mock()

    with patch("saq.splunk.client.connect") as mock_connect:
        mock_connect.return_value = mock_client
        SplunkClient('splunk_test')

        # verify connection was called with correct parameters
        mock_connect.assert_called_once()
        call_kwargs = mock_connect.call_args[1]
        assert call_kwargs['host'] == 'test.com'
        assert call_kwargs['port'] == 443
        assert call_kwargs['token'] == 'mytoken123'
        assert 'username' not in call_kwargs
        assert 'password' not in call_kwargs


@pytest.mark.unit
def test_proxy_handler_creates_tunnel_for_https():
    """HTTPS targets use HTTPSConnection with set_tunnel for TLS after CONNECT."""
    handler = _proxy_handler(proxy_host="proxy.local", proxy_port=8080)

    mock_conn = Mock()
    mock_conn.getresponse.return_value = Mock(
        status=200, reason="OK", getheaders=lambda: [], read=lambda: b"ok",
    )

    with patch("saq.splunk.http_client.HTTPSConnection", return_value=mock_conn) as mock_cls:
        handler(
            "https://splunk.example.com:8089/services/auth/login",
            {"method": "GET", "headers": [], "body": ""},
        )

    mock_cls.assert_called_once()
    mock_conn.set_tunnel.assert_called_once_with("splunk.example.com", 8089)
    mock_conn.request.assert_called_once()
    mock_conn.close.assert_called_once()


@pytest.mark.unit
def test_proxy_handler_no_tunnel_for_http():
    """HTTP targets use HTTPConnection with no tunnel."""
    handler = _proxy_handler(proxy_host="proxy.local", proxy_port=8080)

    mock_conn = Mock()
    mock_conn.getresponse.return_value = Mock(
        status=200, reason="OK", getheaders=lambda: [], read=lambda: b"ok",
    )

    with patch("saq.splunk.http_client.HTTPConnection", return_value=mock_conn):
        handler(
            "http://splunk.example.com:8089/services/auth/login",
            {"method": "GET", "headers": [], "body": ""},
        )

    mock_conn.set_tunnel.assert_not_called()


@pytest.mark.unit
def test_proxy_handler_https_target_always_uses_https_connection():
    """HTTPS targets always use HTTPSConnection regardless of proxy_scheme."""
    handler = _proxy_handler(proxy_host="proxy.local", proxy_port=8080, proxy_scheme="http")

    mock_conn = Mock()
    mock_conn.getresponse.return_value = Mock(
        status=200, reason="OK", getheaders=lambda: [], read=lambda: b"ok",
    )

    with patch("saq.splunk.http_client.HTTPSConnection", return_value=mock_conn) as mock_https, \
         patch("saq.splunk.http_client.HTTPConnection") as mock_http:
        handler(
            "https://splunk.example.com:8089/services/auth/login",
            {"method": "GET", "headers": [], "body": ""},
        )

    mock_https.assert_called_once()
    mock_http.assert_not_called()


@pytest.mark.unit
def test_proxy_handler_http_target_uses_http_connection():
    """HTTP targets with HTTP proxy use HTTPConnection (no TLS needed)."""
    handler = _proxy_handler(proxy_host="proxy.local", proxy_port=8080, proxy_scheme="http")

    mock_conn = Mock()
    mock_conn.getresponse.return_value = Mock(
        status=200, reason="OK", getheaders=lambda: [], read=lambda: b"ok",
    )

    with patch("saq.splunk.http_client.HTTPSConnection") as mock_https, \
         patch("saq.splunk.http_client.HTTPConnection", return_value=mock_conn) as mock_http:
        handler(
            "http://splunk.example.com:8089/services/auth/login",
            {"method": "GET", "headers": [], "body": ""},
        )

    mock_http.assert_called_once()
    mock_https.assert_not_called()


@pytest.mark.unit
def test_proxy_handler_http_target_https_proxy():
    """HTTP targets with HTTPS proxy use HTTPSConnection (TLS to proxy)."""
    handler = _proxy_handler(proxy_host="proxy.local", proxy_port=443, proxy_scheme="https")

    mock_conn = Mock()
    mock_conn.getresponse.return_value = Mock(
        status=200, reason="OK", getheaders=lambda: [], read=lambda: b"ok",
    )

    with patch("saq.splunk.http_client.HTTPSConnection", return_value=mock_conn) as mock_https, \
         patch("saq.splunk.http_client.HTTPConnection") as mock_http:
        handler(
            "http://splunk.example.com:8089/services/auth/login",
            {"method": "GET", "headers": [], "body": ""},
        )

    mock_https.assert_called_once()
    mock_http.assert_not_called()
    mock_conn.set_tunnel.assert_not_called()


@pytest.mark.unit
def test_splunk_query_object_passes_handler_when_proxied():
    """When proxies is provided, a handler kwarg is passed to client.connect."""
    proxy = ProxyConfig(name="test", transport="http", host="proxy.local", port=8080)

    with patch("saq.splunk.client.connect", return_value=Mock()) as mock_connect:
        SplunkQueryObject(
            host="splunk.example.com",
            port=8089,
            username="user",
            password="pass",
            proxies=proxy,
        )

    mock_connect.assert_called_once()
    call_kwargs = mock_connect.call_args[1]
    assert "handler" in call_kwargs
    assert callable(call_kwargs["handler"])


@pytest.mark.unit
def test_splunk_query_object_no_handler_without_proxy():
    """When proxies is None, no handler kwarg is passed (backward compat)."""
    with patch("saq.splunk.client.connect", return_value=Mock()) as mock_connect:
        SplunkQueryObject(
            host="splunk.example.com",
            port=8089,
            username="user",
            password="pass",
        )

    mock_connect.assert_called_once()
    call_kwargs = mock_connect.call_args[1]
    assert "handler" not in call_kwargs
