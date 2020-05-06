"""This module contains unit tests for the JoeSandbox class."""

import json
from pathlib import Path

from jbxapi import ApiError, ConnectionError
import pytest

from sandboxapi import JoeSandbox, SandboxError


APIKEY = '123456'


@pytest.fixture
def sandbox():
    """Provides a vanilla Joe sandbox for testing."""
    return JoeSandbox(APIKEY)


@pytest.fixture
def api_error():
    """Provides a reference Joe sandbox APIError."""
    raw = {
        'code': 4,
        'message': 'Invalid API key',
    }
    return ApiError(raw)


@pytest.fixture
def connection_error():
    """Provides a reference Joe sandbox ConnectionError."""
    return ConnectionError()


@pytest.fixture
def ref_report(ref_file_path):
    """Provides a reference report."""
    path = ref_file_path / 'files' / 'joe_sample_report.json'
    return path.read_bytes()


@pytest.fixture
def ref_status():
    """Provides a reference submission status."""
    return {
        "submission_id": "140",
        "name": "Sample.exe",
        "status": "finished",
        "time": "2019-04-15T08:05:05+00:00",

        "most_relevant_analysis": {
            "webid": "179",
            "detection": "suspect",
            "score": 30,
        },
        "analyses": [
            {
                "webid": "179",
                "time": "2019-04-15T08:05:08+00:00",
                "runs": [
                    {
                        "detection": "clean",
                        "error": None,
                        "system": "w7",
                        "yara": False,
                    },
                    {
                        "detection": "clean",
                        "error": None,
                        "system": "w7x64",
                        "yara": False,
                    },
                ],
                "tags": [],
                "analysisid": "127",
                "duration": 1,
                "md5": "098f6bcd4621d373cade4e832627b4f6",
                "sha1": "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3",
                "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
                "filename": "Sample.exe",
                "scriptname": "defaultwindowsofficecookbook.jbs",
                "status": "finished",
                "comments": ""
            },
        ]
    }


def test_base_url(sandbox):
    """Verify the base url is being set correctly."""
    assert sandbox.base_url == 'https://jbxcloud.joesecurity.org/api'
    sbx = JoeSandbox(APIKEY, host='dummyhost')
    assert sbx.base_url == 'https://dummyhost/api'
    sbx = JoeSandbox(APIKEY, host='http://dummyhost')
    assert sbx.base_url == 'https://dummyhost/api'


def test_arg_set():
    """Verify that constructor arguments passed to the super class constructor are set."""
    proxies = {
        'http': 'http://10.10.1.10:3128',
        'https': 'http://10.10.1.10:1080',
    }
    timeout = 3
    sandbox = JoeSandbox(APIKEY, proxies=proxies, timeout=timeout, verify_ssl=False, nada=True)
    assert sandbox.proxies == proxies
    assert sandbox.timeout_secs == timeout
    assert not sandbox.verify_ssl
    assert sandbox._request_opts == {'timeout': timeout, 'verify': False}
    assert not hasattr(sandbox, 'nada')


# def test_analyze_ok(mocker, ref_file_path, sandbox):
#     """Verify the analyze() method works correctly."""
#     ref_response = {
#         'submission_id': 22,
#     }
#     dummy_file = ref_file_path / 'files' / 'dummy.txt'
#     mocker.patch('jbxapi.JoeSandbox.submit_sample', return_value=ref_response)
#     with dummy_file.open('rb') as file:
#         eval_id = sandbox.analyze(file, 'dummy.txt')
#     assert eval_id == 22


# def test_analyze_api_error(api_error, mocker, ref_file_path, sandbox):
#     """Verify the case where jbxapi gives an api error and is wrapped by a SandboxError."""
#     dummy_file = ref_file_path / 'files' / 'dummy.txt'
#     mocker.patch('jbxapi.JoeSandbox.submit_sample', side_effect=api_error)
#     with pytest.raises(SandboxError):
#         with dummy_file.open('rb') as file:
#             sandbox.analyze(file, 'dummy.txt')


# def test_analyze_connection_error(connection_error, mocker, ref_file_path, sandbox):
#     """Verify the case where jbxapi gives a connection error is wrapped by a SandboxError."""
#     dummy_file = ref_file_path / 'files' / 'dummy.txt'
#     mocker.patch('jbxapi.JoeSandbox.submit_sample', side_effect=connection_error)
#     with pytest.raises(SandboxError):
#         with dummy_file.open('rb') as file:
#             sandbox.analyze(file, 'dummy.txt')


def test_submit_sample_ok(mocker, sandbox):
    """Verify the submit_sample() method works correctly."""
    ref_response = {
        'submission_id': 22,
    }
    mocker.patch('pathlib.Path.open')
    mocker.patch('jbxapi.JoeSandbox.submit_sample', return_value=ref_response)
    eval_id = sandbox.submit_sample('dummy')
    assert eval_id == 22


def test_submit_sample_api_error(api_error, mocker, sandbox):
    """Verify the case where jbxapi gives an api error and is wrapped by a SandboxError."""
    mocker.patch('pathlib.Path.open')
    mocker.patch('jbxapi.JoeSandbox.submit_sample', side_effect=api_error)
    with pytest.raises(SandboxError):
        sandbox.submit_sample('dummy')


def test_submit_sample_connection_error(connection_error, mocker, sandbox):
    """Verify the case where jbxapi gives a connection error is wrapped by a SandboxError."""
    mocker.patch('pathlib.Path.open')
    mocker.patch('jbxapi.JoeSandbox.submit_sample', side_effect=connection_error)
    with pytest.raises(SandboxError):
        sandbox.submit_sample('dummy')


def test_check_item_status_ok(mocker, ref_status, sandbox):
    """Verify the check_item_status() method works correctly."""
    mocker.patch('jbxapi.JoeSandbox.submission_info', return_value=ref_status)
    assert sandbox.check_item_status(22)
    assert sandbox.get_webid(22) == '179'


def test_check_item_status_not_finished(mocker, sandbox):
    """Verify the case where check_item_status() returns False."""
    ref_status = {
        'status': 'submitted',
    }
    mocker.patch('jbxapi.JoeSandbox.submission_info', return_value=ref_status)
    assert not sandbox.check_item_status(22)


def test_check_item_status_error(api_error, connection_error, mocker, sandbox):
    """Verify the case where check_item_status() encounters an error."""
    mocker.patch('jbxapi.JoeSandbox.submission_info', side_effect=(api_error, connection_error))
    with pytest.raises(SandboxError):
        sandbox.check_item_status(22)


def test_get_webid_ok(mocker, ref_status, sandbox):
    """Verify the get_webid() method works correctly."""
    mocker.patch('jbxapi.JoeSandbox.submission_info', return_value=ref_status)
    assert sandbox.get_webid(22) == '179'


def test_get_webid_error(api_error, connection_error, mocker, sandbox):
    """Verify the case where get_webid() encounters an error."""
    mocker.patch('jbxapi.JoeSandbox.submission_info', side_effect=(api_error, connection_error))
    with pytest.raises(SandboxError):
        sandbox.get_webid(22)


def test_available_ok(mocker, sandbox):
    """Verify the available property works correctly."""
    mocker.patch('jbxapi.JoeSandbox.server_online', return_value={'online': True})
    # assert sandbox.is_available() is True
    assert sandbox.available is True


def test_available_error(api_error, connection_error, mocker, sandbox):
    """Verify the case where available encounters an error."""
    mocker.patch('jbxapi.JoeSandbox.server_online', side_effect=(api_error, connection_error, KeyError))
    with pytest.raises(SandboxError):
        assert sandbox.available
    with pytest.raises(SandboxError):
        assert sandbox.available
    with pytest.raises(SandboxError):
        assert sandbox.available


def test_report_ok(mocker, ref_report, ref_status, sandbox):
    """Verify the report() method works correctly."""
    download = mocker.patch('jbxapi.JoeSandbox.analysis_download', return_value=(None, ref_report))
    mocker.patch('jbxapi.JoeSandbox.submission_info', return_value=ref_status)
    report = sandbox.report(22)
    assert 'detection' in report['analysis']
    assert download.call_args[0][0]


def test_report_error(api_error, connection_error, mocker, ref_status, sandbox):
    """Verify the case where report() encounters an error."""
    mocker.patch('jbxapi.JoeSandbox.analysis_download', side_effect=(api_error, connection_error))
    mocker.patch('jbxapi.JoeSandbox.submission_info', return_value=ref_status)
    with pytest.raises(SandboxError):
        sandbox.report(22)
        sandbox.report(23)


def test_pdf_report_ok(mocker, ref_report, ref_status, sandbox):
    """Verify the pdf_report() method works correctly."""
    mocker.patch('jbxapi.JoeSandbox.analysis_download', return_value=(None, ref_report))
    mocker.patch('jbxapi.JoeSandbox.submission_info', return_value=ref_status)
    report = sandbox.pdf_report(22)
    assert report


def test_pdf_report_error(api_error, connection_error, mocker, ref_status, sandbox):
    """Verify the case where pdf_report() encounters an error."""
    mocker.patch('jbxapi.JoeSandbox.analysis_download', side_effect=(api_error, connection_error))
    mocker.patch('jbxapi.JoeSandbox.submission_info', return_value=ref_status)
    with pytest.raises(SandboxError):
        sandbox.pdf_report(22)
        sandbox.pdf_report(23)


def test_xml_report_ok(mocker, ref_report, ref_status, sandbox):
    """Verify the xml_report() method works correctly."""
    mocker.patch('jbxapi.JoeSandbox.analysis_download', return_value=(None, ref_report))
    mocker.patch('jbxapi.JoeSandbox.submission_info', return_value=ref_status)
    report = sandbox.xml_report(22)
    assert report


def test_xml_report_error(api_error, connection_error, mocker, ref_status, sandbox):
    """Verify the case where xml_report() encounters an error."""
    mocker.patch('jbxapi.JoeSandbox.analysis_download', side_effect=(api_error, connection_error))
    mocker.patch('jbxapi.JoeSandbox.submission_info', return_value=ref_status)
    with pytest.raises(SandboxError):
        sandbox.xml_report(22)
        sandbox.xml_report(23)


def test_score_ok(ref_report, sandbox):
    """Verify the score() method works correctly."""
    report = json.loads(ref_report.decode('utf-8'))
    assert sandbox.score(report) == 10


def test_score_bad_format(sandbox):
    """Verify the case where score raises an error when the report format is bad."""
    ref_report = {
        'Boo': "I'm a ghost!"
    }
    with pytest.raises(KeyError):
        sandbox.score(ref_report)


def test_config(sandbox):
    """Verify that config is set by passing in the correct argument."""
    assert hasattr(sandbox, 'config')
    assert not sandbox.config
    box = JoeSandbox(
        config=Path(__file__).parent / 'files' / 'ref_config.json',
    )
    assert box.config
    assert not hasattr(box.config, 'api_key')
    assert not hasattr(box.config, 'host')
    assert box.base_url == 'https://jbxcloud.joesecurity.org/api'


# def test_joe_legacy_class():
#     """Verify the legacy class constructor is backwards compatible."""
#     sandbox = joe.JoeAPI(APIKEY, 'http://localhost/api2', True, 50, False, 5)
#     assert not sandbox.verify_ssl
#     assert sandbox.base_url == 'https://localhost/api2'
#     sandbox = joe.JoeAPI(APIKEY, 'localhost', True)
#     assert sandbox.verify_ssl
#     assert sandbox.base_url == 'https://localhost/api'
