from datetime import UTC, datetime
from unittest.mock import Mock, patch
import pytest
from requests.exceptions import HTTPError, Timeout, ProxyError, ConnectionError

from saq.configuration import get_config
from saq.splunk import SplunkClient, SplunkQueryObject, extract_event_timestamp
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
    assert complete == True
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
    assert complete == False
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

    assert cancelled == True
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

    assert cancelled == False


@pytest.mark.unit
def test_cancel_none():
    # create mock client
    mock_client = Mock()

    with patch("saq.splunk.client.connect", return_value=mock_client):
        splunk = SplunkQueryObject(host="test.com", port=8089, username="user", password="pass", user_context="o", app="o")
        cancelled = splunk.cancel(None)

    assert cancelled == True


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
        assert link == 'https://test.com:8089/en-US/app/search/search?q=search+index%3Dtest+field%21%3D%22%3A%26%2B%2A%22+%7C+table+field'

        # make sure search is prepended when missing
        link = splunk.encoded_query_link('index=test field!=":&+*" | table field')
        assert link == 'https://test.com:8089/en-US/app/search/search?q=search+index%3Dtest+field%21%3D%22%3A%26%2B%2A%22+%7C+table+field'

        # test optional time range
        link = splunk.encoded_query_link('index=test', start_time=MOCK_NOW, end_time=MOCK_NOW)
        assert link == 'https://test.com:8089/en-US/app/search/search?q=search+index%3Dtest&earliest=1510385761&latest=1510385761'

        # test app namespace
        splunk = SplunkQueryObject(host="test.com", port=8089, username="test", password="test", app="myapp")
        link = splunk.encoded_query_link('search index=test field!=":&+*" | table field')
        assert link == 'https://test.com:8089/en-US/app/myapp/search?q=search+index%3Dtest+field%21%3D%22%3A%26%2B%2A%22+%7C+table+field'


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
def test_splunk_client_init():
    get_config()['splunk_test'] = {
        'host': 'test.com',
        'port': '443',
        'username': 'hello',
        'password': 'world',
    }

    # create mock client
    mock_client = Mock()

    with patch("saq.splunk.client.connect") as mock_connect:
        mock_connect.return_value = mock_client
        client = SplunkClient('splunk_test', user_context='foo', app='bar')

        # verify connection was called with correct parameters
        mock_connect.assert_called_once()
        call_kwargs = mock_connect.call_args[1]
        assert call_kwargs['host'] == 'test.com'
        assert call_kwargs['port'] == '443'
        assert call_kwargs['username'] == 'hello'
        assert call_kwargs['password'] == 'world'
        assert call_kwargs['owner'] == 'foo'
        assert call_kwargs['app'] == 'bar'
        assert call_kwargs['autologin']

        assert client.gui_path == 'en-US/app/bar/search'


@pytest.mark.unit
def test_splunk_client_init_defaults():
    get_config()['splunk_test'] = {
        'host': 'test.com',
        'port': '443',
        'username': 'hello',
        'password': 'world',
    }

    # create mock client
    mock_client = Mock()

    with patch("saq.splunk.client.connect") as mock_connect:
        mock_connect.return_value = mock_client
        client = SplunkClient('splunk_test')

        # verify connection was called with correct parameters
        mock_connect.assert_called_once()
        call_kwargs = mock_connect.call_args[1]
        assert call_kwargs['host'] == 'test.com'
        assert call_kwargs['port'] == '443'
        assert call_kwargs['username'] == 'hello'
        assert call_kwargs['password'] == 'world'

        assert client.gui_path == 'en-US/app/search/search'


@pytest.mark.unit
def test_splunk_client_init_with_token():
    get_config()['splunk_test'] = {
        'host': 'test.com',
        'port': '443',
        'token': 'mytoken123',
    }

    # create mock client
    mock_client = Mock()

    with patch("saq.splunk.client.connect") as mock_connect:
        mock_connect.return_value = mock_client
        SplunkClient('splunk_test')

        # verify connection was called with correct parameters
        mock_connect.assert_called_once()
        call_kwargs = mock_connect.call_args[1]
        assert call_kwargs['host'] == 'test.com'
        assert call_kwargs['port'] == '443'
        assert call_kwargs['token'] == 'mytoken123'
        assert 'username' not in call_kwargs
        assert 'password' not in call_kwargs
