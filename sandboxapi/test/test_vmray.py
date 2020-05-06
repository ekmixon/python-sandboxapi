"""The module contains unit tests for the VMRaySandbox class."""

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from sandboxapi import VMRaySandbox, SandboxError


APIKEY = '123456'


@pytest.fixture
def sandbox():
    """Provides a vanilla VMRaySandbox object."""
    return VMRaySandbox(APIKEY)


@pytest.fixture
def ref_submit_response(ref_file_path):
    """Provides a sample response after submitting a sample."""
    filepath = ref_file_path / 'files' / 'vmray_submit_sample_response.json'
    return json.loads(filepath.read_text())


@pytest.fixture
def ref_report_response(ref_file_path):
    """Provides a sample report."""
    filepath = ref_file_path / 'files' / 'vmray_report_response.json'
    return json.loads(filepath.read_text())


@pytest.fixture
def ref_report_mixed_response(ref_file_path):
    """Provdies a sample report with various scores."""
    filepath = ref_file_path / 'files' / 'vmray_ambiguous_report_response.json'
    return json.loads(filepath.read_text())


@pytest.fixture
def ref_detailed_report_response(ref_file_path):
    """Provides a sample detailed report."""
    filepath = ref_file_path / 'files' / 'vmray_detailed_report_response.json'
    return json.loads(filepath.read_text())


@pytest.fixture
def ref_item_status():
    """Provides a sample response after checking a submission's status."""
    return {
        'data': [
            {
                'submission_analyzer_mode_analyzer_mode': 'reputation_static_dynamic',
                'submission_analyzer_mode_enable_reputation': True,
                'submission_analyzer_mode_enable_triage': True,
                'submission_analyzer_mode_enable_whois': True,
                'submission_analyzer_mode_id': 498054,
                'submission_analyzer_mode_reanalyze': True,
                'submission_analyzer_mode_triage_error_handling': 'no_start_analysis',
                'submission_api_key_id': 286,
                'submission_billing_type': 'analyzer',
                'submission_comment': None,
                'submission_created': '2019-11-04T06:17:01',
                'submission_deletion_date': None,
                'submission_dll_call_mode': None,
                'submission_dll_calls': None,
                'submission_document_password': None,
                'submission_enable_local_av': False,
                'submission_filename': '57 Pax.doc.rtf',
                'submission_finish_time': None,
                'submission_finished': True,
                'submission_has_errors': None,
                'submission_id': 5303637,
                'submission_ip_id': 902337,
                'submission_ip_ip': '52.6.12.249',
                'submission_known_configuration': False,
                'submission_original_filename': '57 Pax.doc',
                'submission_original_url': None,
                'submission_prescript_force_admin': False,
                'submission_prescript_id': None,
                'submission_priority': 1,
                'submission_reputation_mode': 'triage',
                'submission_retention_period': 0,
                'submission_sample_id': 22,
                'submission_sample_md5': '3f5e1b65dd9c767baebaa31498462fcd',
                'submission_sample_sha1': 'ad1585cc43ac22a0e9bc505da699efb1afdd6c12',
                'submission_sample_sha256': '4b504e06bedebe7462f307d399e4f1ff1bb891195c476586aad2f632644a2634',
                'submission_sample_ssdeep': '24576:DAZ+PKJx5JGP33beix7U4km/NuTfPabFJgBaSCBW3jwkeZ5C4OzBojpJS4jBv7R2:g',
                'submission_score': None,
                'submission_severity': None,
                'submission_shareable': False,
                'submission_submission_metadata': '{}',
                'submission_system_time': None,
                'submission_tags': [],
                'submission_triage_error_handling': 'no_start_analysis',
                'submission_type': 'api',
                'submission_user_account_id': 99,
                'submission_user_account_name': 'InQuest',
                'submission_user_account_subscription_mode': 'free_account',
                'submission_user_email': 'xxxxxxx@inquest.net',
                'submission_user_id': 236,
                'submission_webif_url': 'https://cloud.vmray.com/user/sample/view?id=4423259',
                'submission_whois_mode': 'enabled'
            }
        ],
        'result': 'ok'
    }


bad_responses = (
    # No data key.
    {
        'Boo': "I'm a ghost!",
    },
    # No analysis_vti_score key.
    {
        'data': [
            {
                'Boo': "I'm a ghost!",
            },
        ],
    },
    # Empty report.
    {},
)


@pytest.fixture(params=bad_responses)
def ref_top_ranked_bad_responses(request):
    """Provides several different bad responses for testing top_ranked_analysis()."""
    yield request.param


def test_base_url(sandbox):
    """Verify the base url is being set correctly."""
    assert sandbox.base_url == 'https://cloud.vmray.com/rest'
    sbx = VMRaySandbox(APIKEY, host='dummyhost')
    assert sbx.base_url == 'https://dummyhost/rest'
    sbx = VMRaySandbox(APIKEY, host='http://dummyhost')
    assert sbx.base_url == 'https://dummyhost/rest'


def test_arg_set():
    """Verify that constructor arguments passed to the super class constructor are set."""
    proxies = {
        'http': 'http://10.10.1.10:3128',
        'https': 'http://10.10.1.10:1080',
    }
    timeout = 3
    sandbox = VMRaySandbox(APIKEY, proxies=proxies, timeout=timeout, verify_ssl=False, nada=True)
    assert sandbox.proxies == proxies
    assert sandbox.timeout_secs == timeout
    assert not sandbox.verify_ssl
    assert sandbox._request_opts == {'timeout': timeout, 'verify': False}
    assert not hasattr(sandbox, 'nada')


# def test_analyze_ok(mocker, ref_file_path, ref_submit_response, sandbox):
#     """Verify the analyze() method works correctly."""
#     dummy_file = ref_file_path / 'files' / 'dummy.txt'
#     mocker.patch(
#         'requests.post',
#         return_value=MagicMock(
#             content=bytes(json.dumps(ref_submit_response), encoding='utf-8'),
#             status_code=200,
#         ),
#     )
#     with dummy_file.open('rb') as file:
#         submission_id = sandbox.analyze(file, 'dummy.txt')
#     assert submission_id == 22


# def test_analyze_error(mocker, ref_file_path, sandbox):
#     """Verify the case where an error response is received."""
#     dummy_file = ref_file_path / 'files' / 'dummy.txt'
#     ref_response = {
#         'error_msg': 'Missing parameter',
#     }
#     mocker.patch('pathlib.Path.open')
#     mocker.patch(
#         'requests.post',
#         return_value=MagicMock(
#             content=bytes(json.dumps(ref_response), encoding='utf-8'),
#             status_code=400,
#         ),
#     )
#     with pytest.raises(SandboxError):
#         with dummy_file.open('rb') as file:
#             sandbox.analyze(file, 'dummy.txt')


# def test_analyze_bad_format(mocker, ref_file_path, sandbox):
#     """Verify the case where the response is structured differently."""
#     dummy_file = ref_file_path / 'files' / 'dummy.txt'
#     ref_response = {
#         'Boo': "I'm a ghost!"
#     }
#     mocker.patch('pathlib.Path.open')
#     mocker.patch(
#         'requests.post',
#         return_value=MagicMock(
#             content=bytes(json.dumps(ref_response), encoding='utf-8'),
#             status_code=200,
#         ),
#     )
#     with pytest.raises(KeyError):
#         with dummy_file.open('rb') as file:
#             sandbox.analyze(file, 'dummy.txt')


def test_submit_sample_ok(mocker, ref_submit_response, sandbox):
    """Verify the submit_sample() method works correctly."""
    mocker.patch('pathlib.Path.open')
    mocker.patch(
        'requests.post',
        return_value=MagicMock(
            content=bytes(json.dumps(ref_submit_response), encoding='utf-8'),
            status_code=200,
        ),
    )
    submission_id = sandbox.submit_sample('dummy')
    assert submission_id == 22


def test_submit_sample_error(mocker, sandbox):
    """Verify the case where an error response is received."""
    ref_response = {
        'error_msg': 'Missing parameter',
    }
    mocker.patch('pathlib.Path.open')
    mocker.patch(
        'requests.post',
        return_value=MagicMock(
            content=bytes(json.dumps(ref_response), encoding='utf-8'),
            status_code=400,
        ),
    )
    with pytest.raises(SandboxError):
        sandbox.submit_sample('dummy')


def test_submit_sample_bad_format(mocker, sandbox):
    """Verify the case where the response is structured differently."""
    ref_response = {
        'Boo': "I'm a ghost!"
    }
    mocker.patch('pathlib.Path.open')
    mocker.patch(
        'requests.post',
        return_value=MagicMock(
            content=bytes(json.dumps(ref_response), encoding='utf-8'),
            status_code=200,
        ),
    )
    with pytest.raises(KeyError):
        sandbox.submit_sample('dummy')


def test_check_item_status_ok(mocker, ref_item_status, sandbox):
    """Verify the check_item_status() method works correctly."""
    mocker.patch(
        'requests.get',
        return_value=MagicMock(
            content=bytes(json.dumps(ref_item_status), encoding='utf-8'),
            status_code=200,
        ),
    )
    assert sandbox.check_item_status(22)


def test_check_item_status_error(mocker, sandbox):
    """Verify the case where check_item_status() receives an error code."""
    ref_response = {
        'error_msg': 'Not authorized',
    }
    mocker.patch(
        'requests.get',
        return_value=MagicMock(
            content=bytes(json.dumps(ref_response), encoding='utf-8'),
            status_code=403,
        ),
    )
    with pytest.raises(SandboxError):
        sandbox.check_item_status(22)


def test_check_item_status_bad_format(mocker, sandbox):
    """Verify the case where the response from check_item_status() is structured differently."""
    ref_response = {
        'Boo': "I'm a ghost!"
    }
    mocker.patch(
        'requests.get',
        return_value=MagicMock(
            content=bytes(json.dumps(ref_response), encoding='utf-8'),
            status_code=200,
        ),
    )
    with pytest.raises(KeyError):
        sandbox.check_item_status(22)


def test_available_ok(mocker, sandbox):
    """Verify the available property works correctly."""
    mocker.patch(
        'requests.get',
        return_value=MagicMock(
            status_code=200,
        ),
    )
    # assert sandbox.is_available()
    assert sandbox.available


def test_available_fails(mocker, sandbox):
    """Verify the available property returns False when getting an error code."""
    mocker.patch(
        'requests.get',
        return_value=MagicMock(
            status_code=404,
        ),
    )
    # assert not sandbox.is_available()
    assert not sandbox.available


def test_report_ok(mocker, ref_report_response, sandbox):
    """Verify the report() method works correctly."""
    mocker.patch(
        'requests.get',
        return_value=MagicMock(
            content=bytes(json.dumps(ref_report_response), encoding='utf-8'),
            status_code=200,
        ),
    )
    report = sandbox.report(22)
    assert 'data' in report
    assert sandbox.top_ranked_analysis(report) == 4477057


def test_report_error(mocker, sandbox):
    """Verify the case where report() encounters an error."""
    ref_response = {
        'error_msg': 'Invalid authentication'
    }
    mocker.patch(
        'requests.get',
        return_value=MagicMock(
            content=bytes(json.dumps(ref_response), encoding='utf-8'),
            status_code=403,
        )
    )
    with pytest.raises(SandboxError):
        sandbox.report(22)


def test_top_ranked_analysis(ref_report_mixed_response, ref_top_ranked_bad_responses, sandbox):
    """Verify that top_ranked_analysis() method works correctly."""
    assert sandbox.top_ranked_analysis(ref_report_mixed_response) == 4477043

    # Badly formatted
    with pytest.raises(IndexError):
        sandbox.top_ranked_analysis(ref_top_ranked_bad_responses)


def test_detailed_report_ok(mocker, ref_detailed_report_response, sandbox):
    """Verify the detailed_report() method works correctly."""
    mocker.patch(
        'requests.get',
        return_value=MagicMock(
            content=bytes(json.dumps(ref_detailed_report_response), encoding='utf-8'),
            status_code=200,
        )
    )
    assert 'vti' in sandbox.detailed_report(4878656)


def test_detailed_report_error(mocker, sandbox):
    """Verify the case where detailed_report() encounters an error."""
    ref_response = {
        'error_msg': 'Invalid authentication'
    }
    mocker.patch(
        'requests.get',
        return_value=MagicMock(
            content=bytes(json.dumps(ref_response), encoding='utf-8'),
            status_code=403,
        )
    )
    with pytest.raises(SandboxError):
        sandbox.detailed_report(4878656)


def test_score_summary_report(ref_report_response, ref_report_mixed_response, sandbox):
    """Verify the case where a summary report is passed to score()."""
    assert sandbox.score(ref_report_response) == 10
    assert sandbox.score(ref_report_mixed_response) == 9


def test_score_detailed_report(ref_detailed_report_response, sandbox):
    """Verify the case where a detailed report is passed to score()."""
    assert sandbox.score(ref_detailed_report_response) == 10


def test_config(sandbox):
    """Verify that config is set by passing in the correct argument."""
    assert hasattr(sandbox, 'config')
    assert not sandbox.config
    assert not sandbox.verify_ssl
    assert not sandbox.proxies
    box = VMRaySandbox(
        config=Path(__file__).parent / 'files' / 'ref_config.json',
    )
    assert hasattr(box, 'config')
    assert box.config.proxies == {"https": "http://10.10.1.10:1080"}
    assert box.config.api_key == '12345678'
    assert box.config.verify_ssl
    assert box.verify_ssl
    assert box.base_url == 'https://cloud.vmray.com/rest'


# def test_vmray_legacy_class():
#     """Verify the legacy class constructor is backwards compatible."""
#     sandbox = vmray.VMRayAPI(APIKEY, 'http://localhost/rest/v2', False)
#     assert not sandbox.verify_ssl
#     assert sandbox.base_url == 'https://localhost/rest/v2'
#     sandbox = vmray.VMRayAPI(APIKEY, 'localhost')
#     assert sandbox.base_url == 'https://localhost/rest'
#     sandbox = vmray.VMRayAPI(APIKEY)
#     assert sandbox.base_url == 'https://cloud.vmray.com/rest'
