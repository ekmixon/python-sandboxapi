"""This module contains unit tests for the JoeSandbox class."""

import json
from pathlib import Path

from jbxapi import ApiError, ConnectionError
import pytest

from sandboxapi import SandboxError
from sandboxapi.joe import JoeSandbox, JoeReport


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


@pytest.fixture
def ref_common_report():
    """Provides a reference common report."""
    return {
        "sandbox_report": {
            "sandbox_info": {
                "vendor": "Joe",
                "url": None,
                "id": 1130398,
                "start_time": "09/05/2020 02:01:43",
                "environment": "Windows 7 (<b>Office 2010 SP2</b>, Java 1.8.0_40 1.8.0_191, Flash 16.0.0.305, Acrobat R"
                               "eader 11.0.08, Internet Explorer 11, Chrome 55, Firefox 43)"
            },
            "classification": {
                "label": "SUSPICIOUS",
                "score": 2,
                "category": None
            },
            "files": {
                "submitted": [
                    {
                        "name": "57 Pax.doc",
                        "path": None,
                        "hashes": {
                            "md5": "3f5e1b65dd9c767baebaa31498462fcd",
                            "sha1": "ad1585cc43ac22a0e9bc505da699efb1afdd6c12",
                            "sha256": "4b504e06bedebe7462f307d399e4f1ff1bb891195c476586aad2f632644a2634",
                            "ssdeep": None
                        },
                        "mime": None,
                        "size": None,
                        "classification": {
                            "label": "SUSPICIOUS",
                            "score": 2,
                            "category": None
                        }
                    }
                ],
                "created": [
                    {
                        "name": "C:\\Users\\user\\AppData\\Local\\Microsoft\\Windows\\Temporary Internet Files\\Content"
                                ".Word\\~WRS{06F0A53C-FCDF-48D7-878C-5FC4DF3B1DD8}.tmp",
                        "path": None,
                        "hashes": {
                            "md5": "22A797615C1275856CAF45BC7E84A663",
                            "sha1": "4AAF84FCD8BBEA316FDCCF0220DB402AAA57A18F",
                            "sha256": "8BA98AF656B2937078D82D1571559A442D42341656A19A05D0D6F9D139785920",
                            "ssdeep": None
                        },
                        "mime": None,
                        "size": None,
                        "classification": {
                            "label": None,
                            "score": None,
                            "category": None
                        }
                    },
                    {
                        "name": "C:\\Users\\user\\AppData\\Local\\Microsoft\\Windows\\Temporary Internet Files\\Content"
                                ".Word\\~WRS{DDE5E628-90A4-4B5E-88AA-45B3C51F5622}.tmp",
                        "path": None,
                        "hashes": {
                            "md5": "5D4D94EE7E06BBB0AF9584119797B23A",
                            "sha1": "DBB111419C704F116EFA8E72471DD83E86E49677",
                            "sha256": "4826C0D860AF884D3343CA6460B0006A7A2CE7DBCCC4D743208585D997CC5FD1",
                            "ssdeep": None
                        },
                        "mime": None,
                        "size": None,
                        "classification": {
                            "label": None,
                            "score": None,
                            "category": None
                        }
                    },
                    {
                        "name": "C:\\Users\\user\\AppData\\Roaming\\Microsoft\\Office\\Recent\\57 Pax.LNK",
                        "path": None,
                        "hashes": {
                            "md5": "B9CE13F45F30C738BCBCE241855FA65A",
                            "sha1": "88A8D0E9926EE98DEB07288B9B7F5240816C57BE",
                            "sha256": "A808E273E843C883CFB550088B42E9413340E0D2253BDF665EEF7E7875339B24",
                            "ssdeep": None
                        },
                        "mime": None,
                        "size": None,
                        "classification": {
                            "label": None,
                            "score": None,
                            "category": None
                        }
                    },
                    {
                        "name": "C:\\Users\\user\\AppData\\Roaming\\Microsoft\\Office\\Recent\\index.dat",
                        "path": None,
                        "hashes": {
                            "md5": "3DCB49086E32DF09B4BE634EB931B894",
                            "sha1": "88F10DB465268ED960A14F949B7947F52C6BDE97",
                            "sha256": "5B73C5249422D5738001281B9F1C36C009FA8F4700B96A545A7CB82943096AE5",
                            "ssdeep": None
                        },
                        "mime": None,
                        "size": None,
                        "classification": {
                            "label": None,
                            "score": None,
                            "category": None
                        }
                    },
                    {
                        "name": "C:\\Users\\user\\AppData\\Roaming\\Microsoft\\Templates\\~$Normal.dotm",
                        "path": None,
                        "hashes": {
                            "md5": "97B12F4B156C7F8FFF12C62484BA9186",
                            "sha1": "0930C35451483F0010DD81CCD44CF666510931AF",
                            "sha256": "963EA98818FA05B3A1AE3F0BD51F3549B1E606FEECD9181B2E3F5C708DDCDBF1",
                            "ssdeep": None
                        },
                        "mime": None,
                        "size": None,
                        "classification": {
                            "label": None,
                            "score": None,
                            "category": None
                        }
                    },
                    {
                        "name": "C:\\Users\\user\\AppData\\Roaming\\Microsoft\\Templates\\~WRD0000.tmp",
                        "path": None,
                        "hashes": {
                            "md5": "3B65431CC8E25A0FC49A488985A2767C",
                            "sha1": "7C3640ADE08D1357A49FAA60902C36ECC82B8085",
                            "sha256": "75433221EAA54E9E501052DB756049EB052891178F599AAC993CD94702DC58AF",
                            "ssdeep": None
                        },
                        "mime": None,
                        "size": None,
                        "classification": {
                            "label": None,
                            "score": None,
                            "category": None
                        }
                    },
                    {
                        "name": "C:\\Users\\user\\AppData\\Roaming\\Microsoft\\UProof\\ExcludeDictionaryEN0409.lex",
                        "path": None,
                        "hashes": {
                            "md5": "F3B25701FE362EC84616A93A45CE9998",
                            "sha1": "D62636D8CAEC13F04E28442A0A6FA1AFEB024BBB",
                            "sha256": "B3D510EF04275CA8E698E5B3CBB0ECE3949EF9252F0CDC839E9EE347409A2209",
                            "ssdeep": None
                        },
                        "mime": None,
                        "size": None,
                        "classification": {
                            "label": None,
                            "score": None,
                            "category": None
                        }
                    },
                    {
                        "name": "C:\\Users\\user\\Desktop\\~$57 Pax.doc",
                        "path": None,
                        "hashes": {
                            "md5": "CBE488DE967679976399F0D9A039FDF4",
                            "sha1": "82F493F44457AA642C124F8068248DE6F2E87B6D",
                            "sha256": "EF0C8A32E3845C71C2DA1D203F0A178E385AC8DF3D97A7D335A7FF85D1A37BA0",
                            "ssdeep": None
                        },
                        "mime": None,
                        "size": None,
                        "classification": {
                            "label": None,
                            "score": None,
                            "category": None
                        }
                    }
                ],
                "modified": [],
                "deleted": []
            },
            "network": {
                "domains": [
                    {
                        "name": "jobmalawi.com",
                        "ip": "unknown",
                        "label": "UNKNOWN"
                    }
                ],
                "sessions": [
                    {
                        "label": "UNKNOWN",
                        "protocol": None,
                        "source_ip": "192.168.1.109",
                        "source_port": None,
                        "destination_ip": None,
                        "destination_port": None,
                        "pcap": None
                    }
                ]
            }
        }
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
        config=Path(__file__).parent / 'files' / 'ref_config.cfg',
    )
    assert box.config
    assert not hasattr(box.config, 'api_key')
    assert not hasattr(box.config, 'host')
    assert box.base_url == 'https://jbxcloud.joesecurity.org/api'


def test_joe_common_report(ref_common_report, sandbox):
    """Verify that the Joe common report works correctly."""
    ref = Path(__file__).parent / 'files' / 'joe_57pax.json'
    report = json.loads(ref.read_text())
    common = JoeReport()
    assert common(report) == ref_common_report
