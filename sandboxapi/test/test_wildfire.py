"""This module contains unit tests for the WildFireSandbox class."""

from unittest.mock import MagicMock

import pytest
from requests.exceptions import Timeout

from sandboxapi import WildFireSandbox, SandboxError
from sandboxapi.wildfire import BENIGN, GRAYWARE, MALWARE, PHISHING


APIKEY = '123456'


@pytest.fixture
def sandbox():
    """Provides a vanilla WildFireSandbox object."""
    return WildFireSandbox(APIKEY)


@pytest.fixture
def ref_submit_sample_ok():
    """Provides a valid response for submitting a sample."""
    return """<?xml version="1.0" encoding="UTF-8"?>
<wildfire>
    <upload-file-info>
        <url></url>
        <filetype>PE32 executable</filetype>
        <filename>wildfire-test-pe-file.exe</filename>
        <sha256>c58158f7bc2caef28a0bc5f10e0536daf841a32bf9ed05c52d7a0576346080e5</sha256>
        <md5>4e8c629221da743086cd0af905d6f6d2</md5>
        <size>55296</size>
    </upload-file-info>
</wildfire>"""


@pytest.fixture
def ref_submit_sample_no_sha256():
    """Provides a submit response with a missing sha256 hash."""
    return """<?xml version="1.0" encoding="UTF-8"?>
    <wildfire>
        <upload-file-info>
            <url></url>
            <filetype>PE32 executable</filetype>
            <filename>wildfire-test-pe-file.exe</filename>
            <md5>4e8c629221da743086cd0af905d6f6d2</md5>
            <size>55296</size>
        </upload-file-info>
    </wildfire>"""


@pytest.fixture
def ref_check_item():
    """Provides a factory fixture for reference check item responses."""
    def create_response(status):
        return """<?xml version="1.0" encoding="UTF-8"?>
<wildfire>
    <get-verdict-info>
        <sha256>c58158f7bc2caef28a0bc5f10e0536daf841a32bf9ed05c52d7a0576346080e5</sha256>
        <verdict>{}</verdict>
        <md5>4e8c629221da743086cd0af905d6f6d2</md5>
    </get-verdict-info>
</wildfire>""".format(status)
    return create_response


def test_base_url(sandbox):
    """Verify the base url is being set correctly."""
    assert sandbox.base_url == 'https://wildfire.paloaltonetworks.com/publicapi'
    sbx = WildFireSandbox(APIKEY, host='dummyhost')
    assert sbx.base_url == 'https://dummyhost/publicapi'
    sbx = WildFireSandbox(APIKEY, host='http://dummyhost')
    assert sbx.base_url == 'https://dummyhost/publicapi'
    sbx = WildFireSandbox(APIKEY, host='http://dummyhost')
    assert sbx.base_url == 'https://dummyhost/publicapi'


def test_arg_set():
    """Verify that constructor arguments passed to the super class constructor are set."""
    proxies = {
        'http': 'http://10.10.1.10:3128',
        'https': 'http://10.10.1.10:1080',
    }
    timeout = 3
    sandbox = WildFireSandbox(APIKEY, proxies=proxies, timeout=timeout, verify_ssl=False, nada=True)
    assert sandbox.proxies == proxies
    assert sandbox.timeout_secs == timeout
    assert not sandbox.verify_ssl
    assert sandbox._request_opts == {'timeout': timeout, 'verify': False}
    assert not hasattr(sandbox, 'nada')


# def test_analyze_ok(mocker, ref_file_path, ref_submit_sample_ok, sandbox):
#     """Verify the analyze() logic and parsing works correctly."""
#     mocker.patch(
#         'requests.post',
#         return_value=MagicMock(content=bytes(ref_submit_sample_ok, encoding='utf-8'), status_code=200),
#     )
#     dummy_file = ref_file_path / 'files' / 'dummy.txt'
#     with dummy_file.open('rb') as file:
#         res_hash = sandbox.analyze(file, 'dummy.txt')
#     assert res_hash == 'c58158f7bc2caef28a0bc5f10e0536daf841a32bf9ed05c52d7a0576346080e5'


# def test_analyze_not_found(mocker, ref_file_path, sandbox):
#     """Verify that a SandboxError is raised when a 404 is returned."""
#     mocker.patch(
#         'requests.post',
#         return_value=MagicMock(content=bytes('Not Found', encoding='utf-8'), status_code=404),
#     )
#     dummy_file = ref_file_path / 'files' / 'dummy.txt'
#     with pytest.raises(SandboxError):
#         with dummy_file.open('rb') as file:
#             sandbox.analyze(file, 'dummy.txt')


# def test_analyze_no_sha256(mocker, ref_file_path, ref_submit_sample_no_sha256, sandbox):
#     """Verify that a SandboxError is raised when a malformed XML is returned."""
#     mocker.patch(
#         'requests.post',
#         return_value=MagicMock(content=bytes(ref_submit_sample_no_sha256, encoding='utf-8'), status_code=200),
#     )
#     dummy_file = ref_file_path / 'files' / 'dummy.txt'
#     with pytest.raises(KeyError):
#         with dummy_file.open('rb') as file:
#             sandbox.analyze(file, 'dummy.txt')


def test_submit_sample_ok(mocker, ref_submit_sample_ok, sandbox):
    """Verify the submit_sample() logic and parsing works correctly."""
    mocker.patch('pathlib.Path.open')
    mocker.patch(
        'requests.post',
        return_value=MagicMock(content=bytes(ref_submit_sample_ok, encoding='utf-8'), status_code=200),
    )
    res_hash = sandbox.submit_sample('dummy')
    assert res_hash == 'c58158f7bc2caef28a0bc5f10e0536daf841a32bf9ed05c52d7a0576346080e5'


def test_submit_sample_not_found(mocker, sandbox):
    """Verify that a SandboxError is raised when a 404 is returned."""
    mocker.patch('pathlib.Path.open')
    mocker.patch(
        'requests.post',
        return_value=MagicMock(content=bytes('Not Found', encoding='utf-8'), status_code=404),
    )
    with pytest.raises(SandboxError):
        sandbox.submit_sample('dummy')


def test_submit_sample_no_sha256(mocker, ref_submit_sample_no_sha256, sandbox):
    """Verify that a SandboxError is raised when a malformed XML is returned."""
    mocker.patch('pathlib.Path.open')
    mocker.patch(
        'requests.post',
        return_value=MagicMock(content=bytes(ref_submit_sample_no_sha256, encoding='utf-8'), status_code=200),
    )
    with pytest.raises(KeyError):
        sandbox.submit_sample('dummy')


def test_check_item_status_ready(mocker, ref_check_item, sandbox):
    """Verify that check_item_status() logic and parsing works correctly."""
    ref_response = [ref_check_item(code) for code in (1, 2, 4)]
    mocker.patch(
        'requests.post',
        side_effect=[MagicMock(content=bytes(ref, encoding='utf-8'), status_code=200) for ref in ref_response],
    )
    for _ in range(len(ref_response)):
        assert sandbox.check_item_status('c58158f7bc2caef28a0bc5f10e0536daf841a32bf9ed05c52d7a0576346080e5')


def test_check_item_status_benign(mocker, ref_check_item, sandbox):
    """Verify that check_item_status() logic and parsing works for benign files."""
    ref_response = ref_check_item(0)
    mocker.patch(
        'requests.post',
        return_value=MagicMock(content=bytes(ref_response, encoding='utf-8'), status_code=200),
    )
    assert sandbox.check_item_status('c58158f7bc2caef28a0bc5f10e0536daf841a32bf9ed05c52d7a0576346080e5')
    assert not sandbox._get_verdict('c58158f7bc2caef28a0bc5f10e0536daf841a32bf9ed05c52d7a0576346080e5')


def test_check_item_status_not_ready(mocker, ref_check_item, sandbox):
    """Verify that check_item_status() logic and parsing works for the not ready status."""
    ref_response = ref_check_item(-100)
    mocker.patch(
        'requests.post',
        return_value=MagicMock(content=bytes(ref_response, encoding='utf-8'), status_code=200),
    )
    assert not sandbox.check_item_status('c58158f7bc2caef28a0bc5f10e0536daf841a32bf9ed05c52d7a0576346080e5')
    assert sandbox._get_verdict('c58158f7bc2caef28a0bc5f10e0536daf841a32bf9ed05c52d7a0576346080e5') == -100


def test_check_item_status_errors(mocker, ref_check_item, sandbox):
    """Verify that a SandboxError is raised when any other negative status is returned."""
    ref_response = [ref_check_item(code) for code in (-101, -102, -103, 99)]
    mocker.patch(
        'requests.post',
        side_effect=[MagicMock(content=bytes(ref, encoding='utf-8'), status_code=200) for ref in ref_response],
    )
    for _ in range(len(ref_response)):
        with pytest.raises(SandboxError):
            sandbox.check_item_status('c58158f7bc2caef28a0bc5f10e0536daf841a32bf9ed05c52d7a0576346080e5')


def test_check_item_status_not_a_code(mocker, ref_check_item, sandbox):
    """Verify that a SandboxError is raised if verdict is not a number."""
    ref_response = ref_check_item('blah')
    mocker.patch(
        'requests.post',
        return_value=MagicMock(content=bytes(ref_response, encoding='utf-8'), status_code=200),
    )
    with pytest.raises(ValueError):
        sandbox.check_item_status('c58158f7bc2caef28a0bc5f10e0536daf841a32bf9ed05c52d7a0576346080e5')


def test_check_item_status_missing_verdict(mocker, sandbox):
    """Verify that a SandboxError is raised if verdict is missing."""
    ref_response = """<?xml version="1.0" encoding="UTF-8"?>
        <wildfire>
            <get-verdict-info>
                <sha256>c58158f7bc2caef28a0bc5f10e0536daf841a32bf9ed05c52d7a0576346080e5</sha256>
                <md5>4e8c629221da743086cd0af905d6f6d2</md5>
            </get-verdict-info>
        </wildfire>"""
    mocker.patch(
        'requests.post',
        return_value=MagicMock(content=bytes(ref_response, encoding='utf-8'), status_code=200),
    )
    with pytest.raises(KeyError):
        sandbox.check_item_status('c58158f7bc2caef28a0bc5f10e0536daf841a32bf9ed05c52d7a0576346080e5')


def test_available_ok(mocker, sandbox):
    """Verify the case where available property works as expected."""
    mocker.patch(
        'requests.get',
        return_value=MagicMock(
            status_code=405,
        ),
    )
    # assert sandbox.is_available()
    assert sandbox.available


def test_available_unavailable(mocker, sandbox):
    """Verify the case where available returns False."""
    mocker.patch(
        'requests.get',
        return_value=MagicMock(
            status_code=500,
        ),
    )
    # assert not sandbox.is_available()
    assert not sandbox.available


def test_available_timeout(mocker, sandbox):
    """Verify the case where available returns False because of a timeout."""
    mocker.patch('requests.get', side_effect=Timeout)
    # assert not sandbox.is_available()
    assert not sandbox.available


def test_report_ok(mocker, ref_file_path, sandbox):
    """Verify the report() method parses the returned content correctly."""
    ref_hash = 'c58158f7bc2caef28a0bc5f10e0536daf841a32bf9ed05c52d7a0576346080e5'
    ref_response = (ref_file_path / 'files' / 'wildfire_sample_report.xml').read_text()
    mock_response = mocker.patch(
        'requests.post',
        return_value=MagicMock(content=bytes(ref_response, encoding='utf-8'), status_code=200),
    )
    report = sandbox.report(ref_hash)
    assert report['wildfire']['file_info']['sha256'] == ref_hash
    assert 'report' in report['wildfire']['task_info']
    assert mock_response.call_args[1]['data']['hash'] == ref_hash
    assert mock_response.call_args[1]['data']['format'] == 'xml'
    assert mock_response.call_args[1]['timeout'] == 30


def test_report_ok_pdf(mocker, ref_file_path, sandbox):
    """Verify the pdf_report() method returns the resulting pdf."""
    ref_hash = 'c58158f7bc2caef28a0bc5f10e0536daf841a32bf9ed05c52d7a0576346080e5'
    ref_response = (ref_file_path / 'files' / 'wildfire_sample_report.pdf').read_bytes()
    mock_response = mocker.patch(
        'requests.post',
        return_value=MagicMock(content=ref_response, status_code=200),
    )
    report = sandbox.pdf_report(ref_hash)
    assert isinstance(report, bytes)
    assert 'PDF' in str(report)[:6]
    assert mock_response.call_args[1]['data']['hash'] == ref_hash
    assert mock_response.call_args[1]['data']['format'] == 'pdf'
    assert mock_response.call_args[1]['timeout'] == 30


def test_report_ok_xml(mocker, ref_file_path, sandbox):
    """Verify the xml_report() method returns the resulting xml."""
    ref_hash = 'c58158f7bc2caef28a0bc5f10e0536daf841a32bf9ed05c52d7a0576346080e5'
    ref_response = (ref_file_path / 'files' / 'wildfire_sample_report.xml').read_bytes()
    mock_response = mocker.patch(
        'requests.post',
        return_value=MagicMock(content=ref_response, status_code=200),
    )
    report = sandbox.xml_report(ref_hash)
    assert isinstance(report, bytes)
    assert 'xml' in str(report)[:7]
    assert mock_response.call_args[1]['data']['hash'] == ref_hash
    assert mock_response.call_args[1]['data']['format'] == 'xml'
    assert mock_response.call_args[1]['timeout'] == 30


def test_report_error(mocker, sandbox):
    """Verify that a SandboxError is raised when an error is returned trying to get a report."""
    ref_response = """<?xml version="1.0" encoding="UTF-8"?>
<error>
    <error-message>'Invalid hash, has to be 32 or 64 bytes 0-9a-fA-F'</error-message>
</error>"""
    mocker.patch(
        'requests.post',
        return_value=MagicMock(content=bytes(ref_response, encoding='utf-8'), status_code=200),
    )
    with pytest.raises(SandboxError):
        sandbox.report('dummy')


def test_score(mocker, sandbox):
    """Verify the Wildfire score mapping."""
    ref_report = {
        'wildfire': {
            'file_info': {
                'malware': 'yes',
                'sha1': 'ad1585cc43ac22a0e9bc505da699efb1afdd6c12',
                'filetype': 'RTF',
                'sha256': '4b504e06bedebe7462f307d399e4f1ff1bb891195c476586aad2f632644a2634',
                'md5': '3f5e1b65dd9c767baebaa31498462fcd',
                'size': '1934558',
            }
        }
    }
    mocker.patch('sandboxapi.wildfire.WildFireSandbox._get_verdict', side_effect=(BENIGN, MALWARE, GRAYWARE, PHISHING))
    assert sandbox.score(ref_report) == 0
    assert sandbox.score(ref_report) == 8
    assert sandbox.score(ref_report) == 2
    assert sandbox.score(ref_report) == 5


def test_config(ref_file_path, sandbox):
    """Verify that config is set by passing in the correct argument."""
    assert hasattr(sandbox, 'config')
    assert not sandbox.config
    assert sandbox.timeout_secs == 30
    box = WildFireSandbox(
        config=ref_file_path / 'files' / 'ref_config.json',
        timeout=10,
    )
    assert hasattr(box, 'config')
    assert not hasattr(box.config, 'timeout')
    assert not box.api_key
    assert box.timeout_secs == 10
    assert box.base_url == 'https://wildfire.paloaltonetworks.com/publicapi'


# def test_wildfire_legacy_class():
#     """Verify the legacy class constructor is backwards compatible."""
#     sandbox = wildfire.WildFireAPI(APIKEY, 'http://localhost', verify_ssl=False)
#     assert not sandbox.verify_ssl
#     assert sandbox.api_key == APIKEY
#     assert sandbox.base_url == 'https://localhost/publicapi'
#     sandbox = wildfire.WildFireAPI(APIKEY, 'localhost', verify_ssl=False)
#     assert sandbox.base_url == 'https://localhost/publicapi'
#     sandbox = wildfire.WildFireAPI(APIKEY, 'https://localhost/api')
#     assert sandbox.base_url == 'https://localhost/api'
#     sandbox = wildfire.WildFireAPI(APIKEY)
#     assert sandbox.base_url == 'https://wildfire.paloaltonetworks.com/publicapi'
