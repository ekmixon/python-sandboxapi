"""Unit tests for the FireEye CLI."""

import json
import pytest
from unittest.mock import PropertyMock

from sandboxapi.cli.commands.fireeye import fireeye
from sandboxapi import SandboxError


@pytest.fixture
def mock_auth(mocker):
    """Provides a valid response for authentications."""
    return mocker.patch('sandboxapi.FireEyeSandbox.has_token', new_callable=PropertyMock, return_value=True)


@pytest.fixture
def mock_logout(mocker):
    """Provides a dummy response for the logout method."""
    return mocker.patch('sandboxapi.FireEyeSandbox.logout', return_value=None)


def test_help_output(runner):
    """Verify the output when printing the usage."""
    ref = """Usage: fireeye [OPTIONS] COMMAND [ARGS]...

  FireEye sandbox commands.

Options:
  --config TEXT                   The path to a config file to load sandbox
                                  settings from.

  --host TEXT                     The hostname of the FireEye server.
  --port INTEGER                  The port of the FireEye server.
  --username TEXT                 A valid username.
  --password TEXT                 The FireEye user's password.
  --environment [winxp-sp3|win7-sp1|win7x64-sp1]
                                  The sandbox runtime OS to use.
  --legacy / --current            Use the FireEye legacy API.
  --proxy TEXT                    The URI of a proxy server to connect through.
  --timeout INTEGER               The delay in seconds before a request times
                                  out.

  --ssl / --no-ssl                Enables SSL certificate validation.
  --help                          Show this message and exit.

Commands:
  available  Check to see if the FireEye sandbox is available.
  check      Check the completion status of a submission.
  report     Get the FireEye report for a submitted sample.
  submit     Submit a sample to the FireEye sandbox.
"""
    result = runner.invoke(fireeye, ['--help'])
    assert result.output == ref
    assert result.exit_code == 0


def test_fireeye_available(mocker, mock_auth, mock_logout, runner):
    """Verify that the available command works correctly."""
    mocker.patch('sandboxapi.fireeye.FireEyeSandbox.available', new_callable=PropertyMock, return_value=True)
    result = runner.invoke(fireeye, ['available'])
    assert 'FireEye sandbox https://localhost:443/wsapis/v1.2.0 is available.\n' == result.output
    assert result.exit_code == 0
    assert mock_logout.call_count == 1


def test_fireeye_unavailable(mocker, mock_auth, mock_logout, runner):
    """Test the case where available responds with an unavailable status."""
    mocker.patch('sandboxapi.fireeye.FireEyeSandbox.available', new_callable=PropertyMock, return_value=False)
    result = runner.invoke(fireeye, ['available'])
    assert 'FireEye sandbox https://localhost:443/wsapis/v1.2.0 is unavailable.\n' == result.output
    assert result.exit_code == 1
    assert mock_logout.call_count == 1


def test_fireeye_available_help(runner):
    """Verify the output when printing the available command usage."""
    ref = """Usage: fireeye available [OPTIONS]

  Check to see if the FireEye sandbox is up and available.

Options:
  --help  Show this message and exit.
"""
    result = runner.invoke(fireeye, ['available', '--help'])
    assert result.output == ref
    assert result.exit_code == 0


def test_fireeye_submit_ok(mocker, mock_auth, mock_logout, runner):
    """Verify the submit command works correctly."""
    mocker.patch('pathlib.Path.open')
    mocker.patch('sandboxapi.fireeye.FireEyeSandbox.submit_sample', return_value=22)
    result = runner.invoke(fireeye, ['submit', '--file', 'virus.xlsx'])
    assert 'Submitted successfully. Submission key: 22.\n' == result.output
    assert result.exit_code == 0
    assert mock_logout.call_count == 1


def test_fireeye_submit_file_not_found(mock_auth, mock_logout, runner):
    """Test the case where the file to submit is not found."""
    result = runner.invoke(fireeye, ['submit', '--file', 'virus.xlsx'], catch_exceptions=False)
    assert "[Errno 2] No such file or directory: 'virus.xlsx'\n" == result.output
    assert result.exit_code == 2
    assert mock_logout.call_count == 1


def test_fireeye_submit_file_fail(runner, mock_auth, mock_logout, mocker):
    """Test the case where a SandboxError occurs while submitting the sample."""
    mocker.patch('pathlib.Path.open')
    mocker.patch('sandboxapi.fireeye.FireEyeSandbox.submit_sample', side_effect=SandboxError('Boo!'))
    result = runner.invoke(fireeye, ['submit', '--file', 'virus.xlsx'], catch_exceptions=False)
    assert result.output == 'Boo!\n'
    assert result.exit_code == 1
    assert mock_logout.call_count == 1


def test_fireeye_submit_no_file(runner, mock_auth, mock_logout, mocker):
    """Test the case where a file path is prompted for."""
    mocker.patch('pathlib.Path.open')
    mocker.patch('sandboxapi.fireeye.FireEyeSandbox.submit_sample', return_value=22)
    result = runner.invoke(fireeye, ['submit'], input='22\n')
    assert 'File: 22\nSubmitted successfully. Submission key: 22.\n' == result.output
    assert result.exit_code == 0
    assert mock_logout.call_count == 1


def test_fireeye_submit_help(runner):
    """Verify the output when printing the submit command usage."""
    ref = """Usage: fireeye submit [OPTIONS]

  Submit a sample to the FireEye sandbox for analysis.

Options:
  -f, --file TEXT  The path to the file to submit.  [required]
  --help           Show this message and exit.
"""
    result = runner.invoke(fireeye, ['submit', '--help'])
    assert result.output == ref
    assert result.exit_code == 0


def test_fireeye_check_ok(mocker, mock_auth, mock_logout, runner):
    """Verify that the check command works correctly."""
    mocker.patch('sandboxapi.fireeye.FireEyeSandbox.check_item_status', return_value=True)
    result = runner.invoke(fireeye, ['check', '--id', 22], color=True)
    assert '\x1b[32mSubmission 22 is complete.\x1b[0m\n' == result.output
    assert result.exit_code == 0
    assert mock_logout.call_count == 1


def test_fireeye_check_no_id(mocker, mock_auth, mock_logout, runner):
    """Test the case where the check command prompts for the id."""
    mocker.patch('sandboxapi.fireeye.FireEyeSandbox.check_item_status', return_value=True)
    result = runner.invoke(fireeye, ['check'], color=True, input='22\n')
    assert 'Id : 22\n\x1b[32mSubmission 22 is complete.\x1b[0m\n' == result.output
    assert result.exit_code == 0
    assert mock_logout.call_count == 1


def test_fireeye_check_not_ready(mocker, mock_auth, mock_logout, runner):
    """Test the case where the check command responds with a not ready state."""
    mocker.patch('sandboxapi.fireeye.FireEyeSandbox.check_item_status', return_value=False)
    result = runner.invoke(fireeye, ['check', '--id', 22], color=True)
    assert '\x1b[33mSubmission 22 is in progress.\x1b[0m\n' == result.output
    assert result.exit_code == 0
    assert mock_logout.call_count == 1


def test_fireeye_check_fail(mocker, mock_auth, mock_logout, runner):
    """Test the case where a SandboxError is raised when running the check command."""
    mocker.patch('sandboxapi.fireeye.FireEyeSandbox.check_item_status', side_effect=SandboxError('Boo!'))
    result = runner.invoke(fireeye, ['check', '--id', 22])
    assert 'Boo!\n' == result.output
    assert result.exit_code == 1
    assert mock_logout.call_count == 1


def test_fireeye_check_help(runner):
    """Verify the output when printing the check command usage."""
    ref = """Usage: fireeye check [OPTIONS]

  Check the completion status of a job by submission key.

Options:
  --id TEXT  The submission key of the job to check.  [required]
  --help     Show this message and exit.
"""
    result = runner.invoke(fireeye, ['check', '--help'])
    assert result.output == ref
    assert result.exit_code == 0


def test_fireeye_report_ok(mocker, mock_auth, mock_logout, runner):
    """Verify the report command works correctly."""
    ref = {'dummy': 'report'}
    mocker.patch('sandboxapi.fireeye.FireEyeSandbox.report', return_value=ref)
    result = runner.invoke(fireeye, ['report', '--id', 22])
    assert result.output == json.dumps(ref, indent=4) + '\n'
    assert result.exit_code == 0
    assert mock_logout.call_count == 1


def test_fireeye_report_file(mocker, mock_auth, mock_logout, runner, tmp_path):
    """Verify that the report command saves a report to a file correctly."""
    ref = {'dummy': 'report'}
    tmp_dir = tmp_path / 'report'
    tmp_dir.mkdir()
    tmp_file = tmp_dir / 'test.json'
    mocker.patch('sandboxapi.fireeye.FireEyeSandbox.report', return_value=ref)
    result = runner.invoke(fireeye, ['report', '--id', 22, '--file', str(tmp_file)])
    assert result.output == 'The file was written successfully.\n'
    assert result.exit_code == 0
    assert tmp_file.read_text() == json.dumps(ref, indent=4)
    assert mock_logout.call_count == 1


def test_fireeye_report_fail(mocker, mock_auth, mock_logout, runner):
    """Test the case where a SandboxError is raised when running the report command."""
    mocker.patch('sandboxapi.fireeye.FireEyeSandbox.report', side_effect=SandboxError('Boo!'))
    result = runner.invoke(fireeye, ['report', '--id', 22])
    assert result.output == 'Boo!\n'
    assert result.exit_code == 1
    assert mock_logout.call_count == 1


def test_fireeye_report_no_id(mocker, mock_auth, mock_logout, runner, tmp_path):
    """Test the case where the report command prompts for an id."""
    ref = {'dummy': 'report'}
    tmp_dir = tmp_path / 'report'
    tmp_dir.mkdir()
    tmp_file = tmp_dir / 'test.json'
    mocker.patch('sandboxapi.fireeye.FireEyeSandbox.report', return_value=ref)
    result = runner.invoke(fireeye, ['report', '--file', str(tmp_file)], input='22\n')
    assert result.output == 'Id : 22\nThe file was written successfully.\n'
    assert result.exit_code == 0
    assert tmp_file.read_text() == json.dumps(ref, indent=4)
    assert mock_logout.call_count == 1


def test_fireeye_report_ioerror(mocker, mock_auth, mock_logout, runner, tmp_path):
    """Test the case where an IOError is raised when trying to write to a file."""
    ref = {'dummy': 'report'}
    tmp_dir = tmp_path / 'report'
    tmp_dir.mkdir()
    tmp_file = tmp_dir / 'test.json'
    mocker.patch('sandboxapi.fireeye.FireEyeSandbox.report', return_value=ref)
    mocker.patch('pathlib.Path.write_text', side_effect=IOError('Boo!'))
    result = runner.invoke(fireeye, ['report', '--id', 22, '--file', str(tmp_file)])
    assert result.output == 'Boo!\n'
    assert result.exit_code == 2
    assert mock_logout.call_count == 1


def test_fireeye_report_xml_format(mocker, mock_auth, mock_logout, runner):
    """Verify that the report command outputs in XML format correctly."""
    ref = b'<?xml version="1.0" ENCODING="UTF-8" standalone="yes"?><alerts><test>Test Report</test></alerts>'
    mocker.patch('sandboxapi.fireeye.FireEyeSandbox.xml_report', return_value=ref)
    result = runner.invoke(fireeye, ['report', '--id', 22, '--format', 'xml'])
    assert result.output == ref.decode('utf-8') + '\n'
    assert result.exit_code == 0
    assert mock_logout.call_count == 1


def test_fireeye_report_xml_format_file(mocker, mock_auth, mock_logout, runner, tmp_path):
    """Verify that the report command saves the XML format to file correctly."""
    ref = b'<?xml version="1.0" ENCODING="UTF-8" standalone="yes"?><alerts><test>Test Report</test></alerts>'
    tmp_dir = tmp_path / 'report'
    tmp_dir.mkdir()
    tmp_file = tmp_dir / 'test.json'
    mocker.patch('sandboxapi.fireeye.FireEyeSandbox.xml_report', return_value=ref)
    result = runner.invoke(fireeye, ['report', '--id', 22, '--format', 'xml', '--file', str(tmp_file)])
    assert result.output == 'The file was written successfully.\n'
    assert tmp_file.read_text() == ref.decode('utf-8')
    assert result.exit_code == 0
    assert mock_logout.call_count == 1


def test_fireeye_report_help(runner):
    """Verify the output when printing the report command usage."""
    ref = """Usage: fireeye report [OPTIONS]

  Fetch the analysis report for a sample.

Options:
  --id TEXT            The submission key of the job to check.  [required]
  --file TEXT          File path to save the report to. Only required for PDF
                       format

  --format [json|xml]  The report format.
  --help               Show this message and exit.
"""
    result = runner.invoke(fireeye, ['report', '--help'])
    assert result.output == ref
    assert result.exit_code == 0
