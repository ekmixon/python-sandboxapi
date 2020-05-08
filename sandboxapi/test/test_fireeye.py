"""This module contains unit tests for the FireEyeSandbox class."""

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from sandboxapi import FireEyeSandbox, SandboxError


USERNAME = 'user'
PASSWORD = 'pass'


@pytest.fixture
def sandbox():
    """Provides a vanilla FireEyeSandbox object."""
    return FireEyeSandbox(username=USERNAME, password=PASSWORD)


@pytest.fixture
def mock_auth(mocker):
    """Provides a valid response for authentications."""
    return mocker.patch(
        'requests.post',
        return_value=MagicMock(
            status_code=200,
        ),
    )


@pytest.fixture
def ref_major_report():
    """Provides a sample report that mimics a FireEye major malware report output."""
    return {
        "msg": "concise",
        "alertsCount": 1,
        "version": "MAS (MAS) 7.7.7.777777",
        "appliance": "MAS",
        "alert": [
            {
                "src": {},
                "product": "MAS",
                "name": "MALWARE_OBJECT",
                "explanation": {
                    "osChanges": [],
                    "malwareDetected": {
                        "malware": [
                            {
                                "md5Sum": "670c81770eb7ca761c30320ac62f4035",
                                "name": "malware.txt",
                            },
                        ],
                    },
                },
                "occurred": 1000000000000,
                "alertUrl": "https://10.10.10.10/malware_analysis/analyses?maid=22",
                "id": 22,
                "action": "notified",
                "dst": {},
                "severity": "MAJR"
            },
        ],
    }


@pytest.fixture
def ref_minor_report():
    """Provides a sample report that mimics a FireEye minor malware report output."""
    return {
        "msg": "concise",
        "alertsCount": 1,
        "version": "MAS (MAS) 7.7.7.777777",
        "appliance": "MAS",
        "alert": [
            {
                "src": {},
                "product": "MAS",
                "name": "MALWARE_OBJECT",
                "explanation": {
                    "osChanges": [],
                    "malwareDetected": {
                        "malware": [
                            {
                                "md5Sum": "63e1ef802ab029562d0e90553105c79c",
                                "name": "malware.txt",
                            },
                        ],
                    },
                },
                "occurred": 1000000000000,
                "alertUrl": "https://10.10.10.10/malware_analysis/analyses?maid=507",
                "id": 507,
                "action": "notified",
                "dst": {},
                "severity": "MINR"
            },
        ],
    }


@pytest.fixture
def ref_xml_report():
    """Provides a sample report that mimics a FireEye XML report."""
    return b"""<?xml version="1.0" ENCODING="UTF-8" standalone="yes"?>
    <alerts appliance="MAS" version ="MAS (MAS) 7.7.0.406866" msg="concise" 
    xmlns:ns2="http://www.fireeye.com/alert/2013AlertSchema">
        <ns2:alert id="100" name="malware-object" severity="minr" product=MAS">
            <ns2:explanation>
                <ns2:malware-detected>
                    <ns2:malware2:malware name="Trojan.Flashback.MAC.E"/>
                </ns2:malware-detected>
            </ns2:explanation>
            <ns2:src>
                <ns2:ip>xxx.xxx.xxx.xxx</ns2:ip>
                <ns2:port>123</ns2:port>
            </ns2:src>
            <ns2:alert-url>https://juniper/botnets/events_for?bot?ma_id=969098</ns2:alert-url>
            <ns2:action>notified</ns2:action>
            <ns2:occurred>2015-05-03T23:47:14.185Z</ns2:occurred>
            <ns2:dst>
                <ns2:port>123</ns2:port>
                <ns2:ip>xxx.xxx.xxx.xxx</ns2:ip>
            </ns2:dst>
        </ns2:alert>
    </alerts>"""


def test_base_url(sandbox):
    """Verify the base url is being set correctly."""
    assert sandbox.base_url == 'https://localhost:443/wsapis/v1.2.0'
    sbx = FireEyeSandbox(USERNAME, PASSWORD, host='dummyhost', port=8080, legacy_api=True)
    assert sbx.base_url == 'https://dummyhost:8080/wsapis/v1.1.0'
    sbx = FireEyeSandbox(USERNAME, PASSWORD, host='http://dummyhost', port=8090, legacy_api=True)
    assert sbx.base_url == 'https://dummyhost:8090/wsapis/v1.1.0'
    sbx = FireEyeSandbox(USERNAME, PASSWORD, host='https://dummyhost', port=8090, legacy_api=True)
    assert sbx.base_url == 'https://dummyhost:8090/wsapis/v1.1.0'


def test_arg_set():
    """Verify that constructor arguments passed to the super class constructor are set."""
    proxies = {
        'http': 'http://10.10.1.10:3128',
        'https': 'http://10.10.1.10:1080',
    }
    timeout = 3
    sandbox = FireEyeSandbox(USERNAME, PASSWORD, proxies=proxies, timeout=timeout, verify_ssl=False, nada=True)
    assert sandbox.proxies == proxies
    assert sandbox.timeout_secs == timeout
    assert not sandbox.verify_ssl
    assert sandbox._request_opts == {'timeout': timeout, 'verify': False}
    assert not hasattr(sandbox, 'nada')


def test_authenticate_success(mock_auth, sandbox):
    """Verify that the _authenticate() method works as expected."""
    assert not sandbox.has_token
    sandbox._authenticate()
    assert sandbox.has_token
    call_kwargs = mock_auth.call_args[1]
    assert ['auth', 'timeout', 'verify'] == list(call_kwargs.keys())
    assert call_kwargs['auth'].username, call_kwargs['auth'].password == (USERNAME, PASSWORD)
    assert call_kwargs['timeout'] == sandbox.timeout_secs


def test_authentication_unauthorized(mocker):
    """Verify that an unauthorized user is handled properly."""
    ref_post = mocker.patch(
        'requests.post',
        return_value=MagicMock(
            status_code=401,
        ),
    )
    sandbox = FireEyeSandbox(username='u$er', password='pa$$')
    assert not sandbox.has_token
    with pytest.raises(SandboxError):
        sandbox._authenticate()
    assert not sandbox.has_token
    call_kwargs = ref_post.call_args[1]
    assert call_kwargs['auth'].username, call_kwargs['auth'].password == ('u$er', 'pa$$')


def test_authentication_not_available(mocker, sandbox):
    """Verify the case where authentication fails because the sandbox is unavailable."""
    mocker.patch(
        'requests.post',
        return_value=MagicMock(
            status_code=503,
        ),
    )
    assert not sandbox.has_token
    with pytest.raises(SandboxError):
        sandbox._authenticate()
    assert not sandbox.has_token


def test_submit_sample_ok(mocker, sandbox):
    """Verify the submit_sample() method works correctly."""
    mocker.patch('pathlib.Path.open')
    mocker.patch('sandboxapi.fireeye.FireEyeSandbox._authenticate')
    mocker.patch(
        'requests.post',
        side_effect=[
            MagicMock(content=bytes(json.dumps([{'ID': 222}]), encoding='utf-8'), status_code=200),
            MagicMock(content=bytes(json.dumps({'ID': 222}), encoding='utf-8'), status_code=200),
        ]
    )
    eval_id = sandbox.submit_sample('dummy')
    assert eval_id == 222
    eval_id = sandbox.submit_sample('dummy')
    assert eval_id == 222


def test_submit_sample_bad(mocker, sandbox):
    """Verify the case where submit_sample() raises an error because of a bad request."""
    mocker.patch('pathlib.Path.open')
    mocker.patch('sandboxapi.fireeye.FireEyeSandbox._authenticate')
    mocker.patch(
        'requests.post',
        return_value=MagicMock(
            content='Request unsuccessful because the filter value was invalid.',
            status_code=400,
        ),
    )
    with pytest.raises(SandboxError):
        sandbox.submit_sample('dummy')


def test_submit_sample_unknown(mocker, sandbox):
    """Verify the case where submit_sample() raises an error because of an unknown status code."""
    mocker.patch('pathlib.Path.open')
    mocker.patch('sandboxapi.fireeye.FireEyeSandbox._authenticate')
    mocker.patch(
        'requests.post',
        return_value=MagicMock(
            content='Request unsuccessful because the filter value was invalid.',
            status_code=500,
        ),
    )
    with pytest.raises(SandboxError):
        sandbox.submit_sample('dummy')


def test_check_item_status_done(mocker, sandbox):
    """Verify the check_item_status() method detects a complete job correctly."""
    ref_response = {'submissionStatus': 'Done'}
    mocker.patch(
        'requests.post',
        return_value=MagicMock(
            content=bytes(json.dumps(ref_response), encoding='utf-8'),
            status_code=200,
        ),
    )
    assert sandbox.check_item_status(1)


def test_check_item_status_in_progress(mocker, sandbox):
    """Verify the check_item_status() method detects an in progress job correctly."""
    ref_response = {'submissionStatus': 'In Progress'}
    mocker.patch(
        'requests.post',
        return_value=MagicMock(
            content=bytes(json.dumps(ref_response), encoding='utf-8'),
            status_code=200,
        ),
    )
    assert not sandbox.check_item_status(1)


def test_check_item_status_unknown(mocker, sandbox):
    """Verify the case where check_item_status() raises an error if the response is unknown."""
    ref_response = {'Boo': "I'm a ghost!"}
    mocker.patch(
        'requests.post',
        return_value=MagicMock(
            content=bytes(json.dumps(ref_response), encoding='utf-8'),
            status_code=200,
        ),
    )
    with pytest.raises(SandboxError):
        sandbox.check_item_status(1)


def test_check_item_status_unauthorized(mocker, sandbox):
    """Verify the case where check_item_status() gets an unauthorized response."""
    mocker.patch(
        'requests.post',
        return_value=MagicMock(
            status_code=401,
        ),
    )
    with pytest.raises(SandboxError):
        sandbox.check_item_status(1)


def test_check_item_status_not_found(mocker, sandbox):
    """Verify the case where check_item_status() gets a not found response."""
    mocker.patch(
        'requests.post',
        return_value=MagicMock(
            status_code=404,
        ),
    )
    with pytest.raises(SandboxError):
        sandbox.check_item_status(1)


def test_available_ok(mocker, mock_auth, sandbox):
    """Verify the case where available property works as expected."""
    mocker.patch(
        'requests.get',
        return_value=MagicMock(
            status_code=200,
        ),
    )
    assert sandbox.available


def test_available_unavailable(mocker, mock_auth, sandbox):
    """Verify the case where available returns False."""
    mocker.patch(
        'requests.get',
        return_value=MagicMock(
            status_code=500,
        ),
    )
    assert not sandbox.available


def test_available_unauthorized(mocker, mock_auth, sandbox):
    """Verify the case where available gets an unauthorized response."""
    mocker.patch(
        'requests.get',
        return_value=MagicMock(
            status_code=401,
        ),
    )
    with pytest.raises(SandboxError):
        assert sandbox.available


def test_report_ok(mocker, ref_major_report, sandbox):
    """Verify the report() method works correctly when major malware is detected."""
    mocker.patch(
        'requests.post',
        return_value=MagicMock(
            content=bytes(json.dumps(ref_major_report), encoding='utf-8'),
            status_code=200,
        ),
    )
    assert 'alert' in sandbox.report(1)


def test_report_unauthorized(mocker, sandbox):
    """Verify the case where report() receives an unauthorized response."""
    mocker.patch(
        'requests.post',
        return_value=MagicMock(
            status_code=401,
        ),
    )
    with pytest.raises(SandboxError):
        sandbox.report(1)


def test_report_not_found(mocker, sandbox):
    """Verify the case where report() receives a not found response."""
    mocker.patch(
        'requests.post',
        return_value=MagicMock(
            status_code=404,
        ),
    )
    with pytest.raises(SandboxError):
        sandbox.report(1)


def test_xml_report_ok(mocker, ref_xml_report, sandbox):
    """Verify the xml_report() method works correctly when major malware is detected."""
    mocker.patch(
        'requests.post',
        return_value=MagicMock(
            content=ref_xml_report,
            status_code=200,
        ),
    )
    assert sandbox.xml_report(22)[2:5] == b'xml'


def test_xml_report_unauthorized(mocker, sandbox):
    """Verify the case where xml_report() receives an unauthorized response."""
    mocker.patch(
        'requests.post',
        return_value=MagicMock(
            status_code=401,
        ),
    )
    with pytest.raises(SandboxError):
        sandbox.report(1)


def test_xml_report_not_found(mocker, sandbox):
    """Verify the case where xml_report() receives a not found response."""
    mocker.patch(
        'requests.post',
        return_value=MagicMock(
            status_code=404,
        ),
    )
    with pytest.raises(SandboxError):
        sandbox.report(1)


def test_score_major(mock_auth, ref_major_report, sandbox):
    """Verify the score() method works correctly for a major report."""
    assert sandbox.score(ref_major_report) == 8


def test_score_minor(mock_auth, ref_minor_report, sandbox):
    """Verify the score() method works correctly for a minor report."""
    assert sandbox.score(ref_minor_report) == 2


def test_score_no_severity(mock_auth, sandbox):
    """Verify the score() method returns 0 if serverity isn't found in the report."""
    ref_report = {
        'alert': {
            'Boo': "I'm a ghost!"
        }
    }
    assert sandbox.score(ref_report) == 0


def test_score_bad_format(mock_auth, sandbox):
    """Verify the score() method raises a KeyError if the alert key is not found."""
    ref_report = {
        'Boo': "I'm a ghost!"
    }
    with pytest.raises(KeyError):
        sandbox.score(ref_report)


def test_logout_ok(mocker, sandbox):
    """Verify the logout() method works correctly."""
    mocker.patch(
        'requests.post',
        return_value=MagicMock(
            status_code=204,
        ),
    )
    assert not sandbox.has_token
    sandbox._authenticate()
    assert sandbox.has_token
    sandbox.logout()
    assert not sandbox.has_token


def test_logout_failed(mocker, sandbox):
    """Verify the case where logout() fails."""
    mocker.patch(
        'requests.post',
        return_value=MagicMock(
            status_code=304,
        ),
    )
    with pytest.raises(SandboxError):
        sandbox.logout()


def test_config(sandbox):
    """Verify that config is set by passing in the correct argument."""
    assert hasattr(sandbox, 'config')
    assert not sandbox.config
    assert sandbox.timeout_secs == 30
    box = FireEyeSandbox(
        config=Path(__file__).parent / 'files' / 'ref_config.cfg',
        environment='win7x64-sp1',
    )
    assert hasattr(box, 'config')
    assert box.config.username == 'maurice_moss'
    assert box.config.password == 'tnetennba'
    assert box.config.host == 'friendface.com'
    assert box.config.timeout == '10'
    assert box.profile == 'win7x64-sp1'
    assert box.timeout_secs == 10
    assert isinstance(box.legacy_api, bool)
    assert box.legacy_api
    assert box.base_url == 'https://friendface.com:443/wsapis/v1.1.0'
    # Make sure that explicitly defined args in the constructor are used instead of what's in the config file.
    box = FireEyeSandbox(
        config=Path(__file__).parent / 'files' / 'ref_config.cfg',
        environment='win7x64-sp1',
        host='bluffball',
        legacy_api=False,
    )
    assert box.base_url == 'https://bluffball:443/wsapis/v1.2.0'
