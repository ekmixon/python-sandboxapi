"""This module contains unit tests for the FalconSandbox class."""

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from sandboxapi import FalconSandbox, SandboxError


APIKEY = '123456'


@pytest.fixture
def sandbox():
    """Provides a vanilla FalconSandbox object."""
    return FalconSandbox(APIKEY)


@pytest.fixture
def ref_submit_sample_ok():
    """Provides a submit sample response."""
    return {
        'job_id': '22',
        'submission_id': 'dummy',
        'environment_id': 100,
        'sha256': 'f005541e58f6cbb7475a9a152a25420c2db929cef4c2c3640bf1432b93635d59',
    }


@pytest.fixture
def ref_report():
    """Provides a sample report."""
    return {
        'job_id': '22',
        'environment_id': 100,
        'environment_description': 'Windows 7 32-bit',
        'size': 4545,
        'md5': '4dac03026ee5374dddd61fd4d9cb5f98',
        'sha1': 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
        'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        'threat_level': 2,
        'verdict': 'null',
        'threat_score': 80,
    }


def test_base_url(sandbox):
    """Verify the base url is being set correctly."""
    assert sandbox.base_url == 'https://www.reverse.it/api/v2'
    sbx = FalconSandbox(APIKEY, host='dummyhost')
    assert sbx.base_url == 'https://dummyhost/api/v2'
    sbx = FalconSandbox(APIKEY, host='http://dummyhost')
    assert sbx.base_url == 'https://dummyhost/api/v2'
    sbx = FalconSandbox(APIKEY, host='https://dummyhost')
    assert sbx.base_url == 'https://dummyhost/api/v2'


def test_arg_set():
    """Verify that constructor arguments passed to the super class constructor are set."""
    proxies = {
        'http': 'http://10.10.1.10:3128',
        'https': 'http://10.10.1.10:1080',
    }
    timeout = 3
    sandbox = FalconSandbox(APIKEY, proxies=proxies, timeout=timeout, verify_ssl=False, nada=True)
    assert sandbox.proxies == proxies
    assert sandbox.timeout_secs == timeout
    assert not sandbox.verify_ssl
    assert sandbox._request_opts == {'timeout': timeout, 'verify': False}
    assert not hasattr(sandbox, 'nada')


def test_submit_sample_ok(mocker, ref_submit_sample_ok, sandbox):
    """Verify the submit_sample() method works correctly."""
    mocker.patch('pathlib.Path.open')
    ref_post = mocker.patch(
        'requests.post',
        return_value=MagicMock(
            content=bytes(json.dumps(ref_submit_sample_ok), encoding='utf-8'),
            status_code=201,
        ),
    )
    eval_id = sandbox.submit_sample('dummy')
    assert eval_id == '22'
    call_args, call_kwargs = ref_post.call_args
    assert call_args[0] == 'https://www.reverse.it/api/v2/submit/file'
    assert 'environment_id' in call_kwargs['data']
    assert 'api-key' in call_kwargs['headers']


def test_submit_sample_error(mocker, sandbox):
    """Verify the case where submit_sample() gets an error response from the server."""
    ref_response = {
        'message': "I'm an error."
    }
    mocker.patch('pathlib.Path.open')
    mocker.patch(
        'requests.post',
        return_value=MagicMock(
            content=bytes(json.dumps(ref_response), encoding='utf-8'),
            status_code=403,
        ),
    )
    with pytest.raises(SandboxError):
        sandbox.submit_sample('dummy')


def test_submit_sample_unknown(mocker, sandbox):
    """Verify the case where submit_sample() gets an unexpected response from the server."""
    mocker.patch('pathlib.Path.open')
    mocker.patch(
        'requests.post',
        return_value=MagicMock(
            content=bytes("Server error", encoding='utf-8'),
            status_code=500,
        ),
    )
    with pytest.raises(SandboxError):
        sandbox.submit_sample('dummy')


def test_check_item_status_success(mocker, sandbox):
    """Verify the check_item_status() method works correctly when a job is complete."""
    ref_response = {
        'state': 'SUCCESS',
        'error_type': 'null',
        'error_origin': 'null',
        'error': 'null',
    }
    mocker.patch(
        'requests.get',
        return_value=MagicMock(
            content=bytes(json.dumps(ref_response), encoding='utf-8'),
            status_code=200,
        ),
    )
    assert sandbox.check_item_status(22)


def test_check_item_status_not_done(mocker, sandbox):
    """Verify the check_item_status() method works correctly when a job is in progress."""
    ref_response = {
        'state': 'IN_PROGRESS',
        'error_type': 'null',
        'error_origin': 'null',
        'error': 'null',
    }
    mocker.patch(
        'requests.get',
        return_value=MagicMock(
            content=bytes(json.dumps(ref_response), encoding='utf-8'),
            status_code=200,
        ),
    )
    assert not sandbox.check_item_status(22)


def test_check_item_status_not_found(mocker, sandbox):
    """Verify the case where check_item_status() gets a not found response."""
    mocker.patch(
        'requests.get',
        return_value=MagicMock(
            status_code=404,
        ),
    )
    with pytest.raises(SandboxError):
        sandbox.check_item_status(22)


def test_check_item_status_too_many_requests(mocker, sandbox):
    """Verify the case where check_item_status() gets a too many requests response."""
    mocker.patch(
        'requests.get',
        return_value=MagicMock(
            status_code=429,
        ),
    )
    with pytest.raises(SandboxError):
        sandbox.check_item_status(22)


def test_check_item_status_unknown(mocker, sandbox):
    """Verify the case where check_item_status() gets an unknown response."""
    ref_response = {
        'message': 'forbidden',
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
    """Verify the case where check_item_status() gets a badly formatted request."""
    ref_response = {
        'Boo': "I'm a ghost!",
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


def test_queue_size_ok(mocker, sandbox):
    """Verify the queue_size() method works correctly."""
    ref_response = {
        'value': 44,
    }
    mocker.patch(
        'requests.get',
        return_value=MagicMock(
            content=bytes(json.dumps(ref_response), encoding='utf-8'),
            status_code=200,
        ),
    )
    assert sandbox.queue_size == 44


def test_queue_size_error(mocker, sandbox):
    """Verify the case where queue_size() gets an unknown response."""
    ref_response = {
        'message': 'forbidden',
    }
    mocker.patch(
        'requests.get',
        return_value=MagicMock(
            content=bytes(json.dumps(ref_response), encoding='utf-8'),
            status_code=403,
        ),
    )
    with pytest.raises(SandboxError):
        assert sandbox.queue_size


def test_available_ok(mocker, sandbox):
    """Verify the case where the available property works for an on-prem sandbox."""
    mocker.patch(
        'requests.get',
        return_value=MagicMock(
            status_code=200,
        ),
    )
    assert sandbox.available


def test_available_not_ok(mocker, sandbox):
    """Verify the case where an on-prem sandbox is unavailable."""
    mocker.patch(
        'requests.get',
        return_value=MagicMock(
            status_code=500,
        ),
    )
    assert not sandbox.available


def test_available_ok_cloud(mocker, sandbox):
    """Verify the case where the available property works for the cloud sandbox."""
    mocker.patch(
        'requests.get',
        side_effect=[
            MagicMock(
                status_code=403,
            ),
            MagicMock(
                status_code=200,
            ),
            MagicMock(
                status_code=403,
            ),
            MagicMock(
                status_code=200,
            ),
        ]
    )
    assert sandbox.available


def test_available_not_ok_cloud(mocker, sandbox):
    """Verify the case where the cloud sandbox is unavailable."""
    mocker.patch(
        'requests.get',
        side_effect=[
            MagicMock(
                status_code=403,
            ),
            MagicMock(
                status_code=401,
            ),
            MagicMock(
                status_code=403,
            ),
            MagicMock(
                status_code=401,
            ),
        ]
    )
    assert not sandbox.available


def test_report_ok(mocker, ref_report, sandbox):
    """Verify the report() method works correctly."""
    mocker.patch(
        'requests.get',
        return_value=MagicMock(
            content=bytes(json.dumps(ref_report), encoding='utf-8'),
            status_code=200,
        ),
    )
    assert ref_report == sandbox.report(22)


def test_report_error(mocker, sandbox):
    """Verify the case where report() gets an unknown response."""
    mocker.patch(
        'requests.get',
        return_value=MagicMock(
            content=bytes('Unauthorized', encoding='utf-8'),
            status_code=401,
        ),
    )
    with pytest.raises(SandboxError):
        sandbox.report(22)


def test_pdf_report_ok(mocker, ref_file_path, sandbox):
    """Verify the pdf_report() method works correctly."""
    ref_path = ref_file_path / 'files' / 'wildfire_sample_report.pdf'
    ref_response = ref_path.read_bytes()
    mocker.patch(
        'requests.get',
        return_value=MagicMock(
            content=ref_response,
            status_code=200,
        ),
    )
    assert 'PDF' in str(sandbox.pdf_report(22))[:6]


def test_pdf_report_error(mocker, sandbox):
    """Verify the case where pdf_report() gets an unknown response."""
    mocker.patch(
        'requests.get',
        return_value=MagicMock(
            content=bytes('Unauthorized', encoding='utf-8'),
            status_code=401,
        ),
    )
    with pytest.raises(SandboxError):
        sandbox.pdf_report(22)


def test_score(sandbox):
    """Verify the score() method works correctly."""
    scores = {
        (2, 90): 10,
        (2, 89): 9,
        (2, 75): 9,
        (2, 60): 8,
        (1, 90): 7,
        (1, 89): 6,
        (1, 75): 6,
        (1, 20): 5,
        (0, 300): 4,
        (0, 90): 4,
        (0, 75): 3,
        (0, 74): 1,
        (0, 0): 1,
    }
    for (level, score), ref_score in scores.items():
        ref_report = {
            'threat_level': level,
            'threat_score': score,
        }
        assert sandbox.score(ref_report) == ref_score


def test_config(sandbox):
    """Verify that config is set by passing in the correct argument."""
    assert hasattr(sandbox, 'config')
    assert not sandbox.config
    box = FalconSandbox(
        config=Path(__file__).parent / 'files' / 'ref_config.cfg',
    )
    assert box.config
    assert hasattr(box, 'timeout_secs')
    assert box.timeout_secs == 30
    assert not hasattr(box.config, 'api_key')
    assert not hasattr(box.config, 'host')
    assert hasattr(box, 'environment')
    assert box.environment == 120
    assert box.base_url == 'https://www.reverse.it/api/v2'
