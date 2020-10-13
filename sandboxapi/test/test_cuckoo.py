"""This module contains unit tests for the CuckooSandbox class."""

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from sandboxapi import CuckooSandbox, SandboxError


@pytest.fixture
def sandbox():
    """Provides a vanilla CuckooSandbox object."""
    return CuckooSandbox()


@pytest.fixture
def ref_tasks():
    """Provides a task list that mimics the Cuckoo tasks list output."""
    return {
        "tasks": [
            {
                "category": "url",
                "machine": None,
                "errors": [],
                "target": "http://www.malicious.site",
                "package": None,
                "sample_id": None,
                "guest": {},
                "custom": None,
                "owner": "",
                "priority": 1,
                "platform": None,
                "options": None,
                "status": "pending",
                "enforce_timeout": False,
                "timeout": 0,
                "memory": False,
                "tags": [],
                "id": 1,
                "added_on": "2012-12-19 14:18:25",
                "completed_on": None
            },
            {
                "category": "file",
                "machine": None,
                "errors": [],
                "target": "/tmp/malware.exe",
                "package": None,
                "sample_id": 1,
                "guest": {},
                "custom": None,
                "owner": "",
                "priority": 1,
                "platform": None,
                "options": None,
                "status": "pending",
                "enforce_timeout": False,
                "timeout": 0,
                "memory": False,
                "tags": [
                            "32bit",
                            "acrobat_6",
                        ],
                "id": 2,
                "added_on": "2012-12-19 14:18:25",
                "completed_on": None
            }
        ]
    }


@pytest.fixture
def ref_complete_task():
    """Provides a task that mimics a Cuckoo complete task output."""
    return {
        "task": {
            "category": "url",
            "machine": None,
            "errors": [],
            "target": "/tmp/malware.exe",
            "package": None,
            "sample_id": None,
            "guest": {},
            "custom": None,
            "owner": "",
            "priority": 1,
            "platform": None,
            "options": None,
            "status": "completed",
            "enforce_timeout": False,
            "timeout": 0,
            "memory": False,
            "tags": [],
            "id": 1,
            "added_on": "2012-12-19 14:18:25",
            "completed_on": None
        }
    }


@pytest.fixture
def ref_pending_task():
    """Provides a task that mimics a Cuckoo pending task output."""
    return {
        "task": {
            "category": "url",
            "machine": None,
            "errors": [],
            "target": "/tmp/malware.exe",
            "package": None,
            "sample_id": None,
            "guest": {},
            "custom": None,
            "owner": "",
            "priority": 1,
            "platform": None,
            "options": None,
            "status": "pending",
            "enforce_timeout": False,
            "timeout": 0,
            "memory": False,
            "tags": [],
            "id": 1,
            "added_on": "2012-12-19 14:18:25",
            "completed_on": None
        }
    }


@pytest.fixture
def ref_report():
    """Provides a sample report that mimics a Cuckoo report output."""
    return {
        "signatures": [],
        "virustotal": {},
        "static": {},
        "malscore": 10,
        "dropped": [],
        "network": {},
        "info": {
            "category": "file",
            "package": "",
            "started": "2016-08-26 15:24:51",
            "custom": "",
            "machine": {},
            "ended": "2016-08-26 15:28:08",
            "version": "1.1",
            "duration": 197,
            "id": 1,
        },
        "target": {
            "category": "file",
            "file": {},
        },
        "behavior": {},
        "memory": {},
        "debug": {},
        "strings": [
            "!This program cannot be run in DOS mode.",
            "`.rdata",
            "@.data",
        ],
    }


def test_base_url(sandbox):
    """Verify the base url is being set correctly."""
    assert sandbox.base_url == 'http://localhost:8090'
    sbx = CuckooSandbox(host='dummyhost', port=8080, use_https=True)
    assert sbx.base_url == 'https://dummyhost:8080'
    sbx = CuckooSandbox(host='http://dummyhost', port=8090, use_https=True)
    assert sbx.base_url == 'https://dummyhost:8090'
    sbx = CuckooSandbox(host='https://dummyhost', port=8090, use_https=True)
    assert sbx.base_url == 'https://dummyhost:8090'


def test_arg_set():
    """Verify that constructor arguments passed to the super class constructor are set."""
    proxies = {
        'http': 'http://10.10.1.10:3128',
        'https': 'http://10.10.1.10:1080',
    }
    timeout = 3
    sandbox = CuckooSandbox(proxies=proxies, timeout=timeout, verify_ssl=False, nada=True)
    assert sandbox.proxies == proxies
    assert sandbox.timeout_secs == timeout
    assert not sandbox.verify_ssl
    assert sandbox._request_opts == {'timeout': timeout, 'verify': False}
    assert not hasattr(sandbox, 'nada')


def test_submit_sample_ok(mocker, sandbox):
    """Verify the submit_sample() logic and parsing works correctly."""
    ref_response = {
        'task_id': 1
    }
    mocker.patch('pathlib.Path.open')
    mocker.patch(
        'requests.post',
        return_value=MagicMock(
            content=bytes(json.dumps(ref_response), encoding='utf-8'),
            status_code=200,
        ),
    )
    res_id = sandbox.submit_sample('dummy')
    assert res_id == 1


def test_submit_sample_duplicate(mocker, sandbox):
    """Verify the case where submit_sample() sends a duplicate file."""
    mocker.patch('pathlib.Path.open')
    mocker.patch(
        'requests.post',
        return_value=MagicMock(content=bytes('Nope!', encoding='utf-8'), status_code=400),
    )
    with pytest.raises(SandboxError):
        sandbox.submit_sample('dummy')


def test_submit_sample_bad_response(mocker, sandbox):
    """Verify the case where submit_sample() receives an unrecognized response."""
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


def test_enqueued_ok(mocker, sandbox, ref_tasks):
    """Verify the enqueued() method works correctly."""
    mocker.patch(
        'requests.get',
        return_value=MagicMock(
            content=bytes(json.dumps(ref_tasks), encoding='utf-8'),
            status_code=200,
        ),
    )
    eval_tasks = sandbox.enqueued()
    assert len(eval_tasks) == 2


def test_check_item_status_ready(ref_complete_task, mocker, sandbox):
    """Verify the check_item_status() method works as expected when complete."""
    mocker.patch(
        'requests.get',
        return_value=MagicMock(
            content=bytes(json.dumps(ref_complete_task), encoding='utf-8'),
            status_code=200,
        ),
    )
    status = sandbox.check_item_status(1)
    assert status


def test_check_item_status_pending(mocker, ref_pending_task, sandbox):
    """Verify the check_item_status() method works as expected when pending."""
    mocker.patch(
        'requests.get',
        return_value=MagicMock(
            content=bytes(json.dumps(ref_pending_task), encoding='utf-8'),
            status_code=200,
        ),
    )
    status = sandbox.check_item_status(1)
    assert not status


def test_check_item_status_id_not_found(mocker, sandbox):
    """Verify the check_item_status() method when the task ID is not found."""
    mocker.patch(
        'requests.get',
        MagicMock(
            content=bytes('Not found', encoding='utf-8'),
            status_code=404,
        ),
    )
    with pytest.raises(SandboxError):
        sandbox.check_item_status(33)


def test_check_item_status_unavailable(mocker, sandbox):
    """Verify the check_item_status() raises an error when an unknown status code is given."""
    mocker.patch(
        'requests.get',
        MagicMock(
            content=bytes('Not found', encoding='utf-8'),
            status_code=500,
        ),
    )
    with pytest.raises(SandboxError):
        sandbox.check_item_status(33)


def test_check_item_status_bad_response(mocker, sandbox):
    """Verify the case where check_item_status() receives an unknown response."""
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
        sandbox.check_item_status(1)


def test_delete_task_ok(mocker, sandbox):
    """Verify the delete_task() method works correctly."""
    mocker.patch(
        'requests.get',
        return_value=MagicMock(
            status_code=200,
        ),
    )
    assert sandbox.delete_item(1)


def test_delete_task_not_found(mocker, sandbox):
    """Verify the delete_task() method raises an error when the task ID is not found."""
    mocker.patch(
        'requests.get',
        return_value=MagicMock(
            status_code=404,
        ),
    )
    with pytest.raises(SandboxError):
        sandbox.delete_item(1)


def test_delete_task_fail(mocker, sandbox):
    """Verify the delete_task() method raises an error when the task cannot be deleted."""
    mocker.patch(
        'requests.get',
        return_value=MagicMock(
            status_code=500,
        ),
    )
    with pytest.raises(SandboxError):
        sandbox.delete_item(1)


def test_delete_task_unknown_fail(mocker, sandbox):
    """Verify the delete_task() method raises an error when an unknown status code is received."""
    mocker.patch(
        'requests.get',
        return_value=MagicMock(
            status_code=423,
        ),
    )
    with pytest.raises(SandboxError):
        sandbox.delete_item(1)


def test_available_ok(mocker, sandbox):
    """Verify the available property is working correctly."""
    mocker.patch(
        'requests.get',
        return_value=MagicMock(
            status_code=200,
        ),
    )
    assert sandbox.available


def test_available_fail(mocker, sandbox):
    """Verify the case where available indicates the sandbox is unavailable."""
    mocker.patch(
        'requests.get',
        return_value=MagicMock(
            status_code=404,
        ),
    )
    assert not sandbox.available


def test_check_queue_size(mocker, sandbox, ref_tasks):
    """Verify the queue_size() method works correctly."""
    mocker.patch(
        'requests.get',
        return_value=MagicMock(
            content=bytes(json.dumps(ref_tasks), encoding='utf-8'),
            status_code=200,
        ),
    )
    assert sandbox.queue_size == 2


def test_report_ok(mocker, ref_report, sandbox):
    """Verify the report() method works as expected."""
    mocker.patch(
        'requests.get',
        return_value=MagicMock(
            content=bytes(json.dumps(ref_report), encoding='utf-8'),
            status_code=200,
        ),
    )
    report = sandbox.report(1)
    assert report['malscore'] == 10
    assert report['info']['id'] == 1


def test_report_not_found(mocker, ref_report, sandbox):
    """Verify the case where the report() method indicates the task ID cannot be found."""
    mocker.patch(
        'requests.get',
        return_value=MagicMock(
            content=bytes(json.dumps(ref_report), encoding='utf-8'),
            status_code=404,
        ),
    )
    with pytest.raises(SandboxError):
        sandbox.report(1)


def test_score(mocker, ref_report, sandbox):
    """Verify the score() method works as expected."""
    mocker.patch(
        'requests.get',
        return_value=MagicMock(
            content=bytes(json.dumps(ref_report), encoding='utf-8'),
            status_code=200,
        ),
    )
    report = sandbox.report(1)
    assert sandbox.score(report) == 10


def test_score_bad_report(sandbox):
    """Verify the score() method works when a badly formatted report is given."""
    with pytest.raises(KeyError):
        sandbox.score({})


def test_config(ref_file_path, sandbox):
    """Verify that config is set by passing in the correct argument."""
    assert hasattr(sandbox, 'config')
    assert not sandbox.config
    box = CuckooSandbox(
        config=ref_file_path / 'files' / 'ref_config.cfg',
        port=8888,
    )
    assert hasattr(box, 'config')
    assert hasattr(box, 'timeout_secs')
    assert box.timeout_secs == 30
    assert hasattr(box, 'verify_ssl')
    assert box.verify_ssl is True
    assert not hasattr(box.config, 'port')
    assert box.config.use_https
    assert hasattr(box, 'use_https')
    assert box.use_https is True
    assert box.base_url == 'https://localhost:8888'
