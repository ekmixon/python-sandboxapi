"""Unit tests for the VMRay CLI."""

import json
import pytest
from unittest.mock import PropertyMock

from sandboxapi.cli.commands.vmray import vmray
from sandboxapi import SandboxError


@pytest.fixture
def api_key():
    """Provides a fake API key."""
    return 123456


def test_help_output(runner):
    """Verify the output when printing the usage."""
    ref = """Usage: vmray [OPTIONS] COMMAND [ARGS]...

  VMRay sandbox commands.

Options:
  --apikey TEXT      The customer API key for accessing the VMRay sandbox.
  --config TEXT      The path to config file to load sandbox settings from.
  --host TEXT        The hostname of the VMRay server.
  --proxy TEXT       The URI of a proxy server to connect through.
  --timeout INTEGER  The delay in seconds before a request times out.
  --ssl / --no-ssl   Enables SSL certificate validation.
  --help             Show this message and exit.

Commands:
  available        Check to see if the VMRay sandbox is available.
  check            Check the completion status of a submission.
  detailed-report  Get the detailed report for a submission's analysis ID.
  report           Get the VMRay report for a submitted sample.
  submit           Submit a sample to the VMRay sandbox.
"""
    result = runner.invoke(vmray, ['--help'])
    assert result.output == ref
    assert result.exit_code == 0


def test_vmray_available(mocker, runner):
    """Verify that the available command works correctly."""
    mocker.patch('sandboxapi.vmray.VMRaySandbox.available', new_callable=PropertyMock, return_value=True)
    result = runner.invoke(vmray, ['available'])
    assert 'VMRay sandbox https://cloud.vmray.com/rest is available.\n' == result.output
    assert result.exit_code == 0


def test_vmray_unavailable(mocker, runner):
    """Test the case where available responds with an unavailable status."""
    mocker.patch('sandboxapi.vmray.VMRaySandbox.available', new_callable=PropertyMock, return_value=False)
    result = runner.invoke(vmray, ['available'])
    assert 'VMRay sandbox https://cloud.vmray.com/rest is unavailable.\n' == result.output
    assert result.exit_code == 1


def test_vmray_available_help(runner):
    """Verify the output when printing the available command usage."""
    ref = """Usage: vmray available [OPTIONS]

  Check to see if the VMRay sandbox is up and available.

Options:
  --help  Show this message and exit.
"""
    result = runner.invoke(vmray, ['available', '--help'])
    assert result.output == ref
    assert result.exit_code == 0


def test_vmray_submit_ok(api_key, mocker, runner):
    """Verify the submit command works correctly."""
    mocker.patch('pathlib.Path.open')
    mocker.patch('sandboxapi.vmray.VMRaySandbox.submit_sample', return_value=22)
    result = runner.invoke(vmray, ['--apikey', api_key, 'submit', '--file', 'virus.xlsx'])
    assert 'Submitted successfully. Submission id: 22.\n' == result.output
    assert result.exit_code == 0


def test_vmray_submit_file_not_found(api_key, runner):
    """Test the case where the file to submit is not found."""
    result = runner.invoke(vmray, ['--apikey', api_key, 'submit', '--file', 'virus.xlsx'], catch_exceptions=False)
    assert "[Errno 2] No such file or directory: 'virus.xlsx'\n" == result.output
    assert result.exit_code == 2


def test_vmray_submit_file_fail(api_key, runner, mocker):
    """Test the case where a SandboxError occurs while submitting the sample."""
    mocker.patch('pathlib.Path.open')
    mocker.patch('sandboxapi.vmray.VMRaySandbox.submit_sample', side_effect=SandboxError('Boo!'))
    result = runner.invoke(vmray, ['--apikey', api_key, 'submit', '--file', 'virus.xlsx'], catch_exceptions=False)
    assert result.output == 'Boo!\n'
    assert result.exit_code == 1


def test_vmray_submit_no_file(api_key, runner, mocker):
    """Test the case where a file path is prompted for."""
    mocker.patch('pathlib.Path.open')
    mocker.patch('sandboxapi.vmray.VMRaySandbox.submit_sample', return_value=22)
    result = runner.invoke(vmray, ['--apikey', api_key, 'submit'], input='22\n')
    assert 'File: 22\nSubmitted successfully. Submission id: 22.\n' == result.output
    assert result.exit_code == 0


def test_vmray_submit_no_apikey(runner):
    """Test the case where no API key is provided to the submit command."""
    ref = 'API key is required.\n'
    result = runner.invoke(vmray, ['submit', '--file', 'virus.xlsx'])
    assert result.output == ref
    assert result.exit_code == 5


def test_vmray_submit_help(runner):
    """Verify the output when printing the submit command usage."""
    ref = """Usage: vmray submit [OPTIONS]

  Submit a sample to the VMRay sandbox for analysis.

Options:
  -f, --file TEXT  The path to the file to submit.  [required]
  --help           Show this message and exit.
"""
    result = runner.invoke(vmray, ['submit', '--help'])
    assert result.output == ref
    assert result.exit_code == 0


def test_vmray_check_ok(api_key, mocker, runner):
    """Verify that the check command works correctly."""
    mocker.patch('sandboxapi.vmray.VMRaySandbox.check_item_status', return_value=True)
    result = runner.invoke(vmray, ['--apikey', api_key, 'check', '--id', 22], color=True)
    assert '\x1b[32mSubmission 22 is complete.\x1b[0m\n' == result.output
    assert result.exit_code == 0


def test_vmray_check_no_id(api_key, mocker, runner):
    """Test the case where the check command prompts for the id."""
    mocker.patch('sandboxapi.vmray.VMRaySandbox.check_item_status', return_value=True)
    result = runner.invoke(vmray, ['--apikey', api_key, 'check'], color=True, input='22\n')
    assert 'Id : 22\n\x1b[32mSubmission 22 is complete.\x1b[0m\n' == result.output
    assert result.exit_code == 0


def test_vmray_check_not_ready(api_key, mocker, runner):
    """Test the case where the check command responds with a not ready state."""
    mocker.patch('sandboxapi.vmray.VMRaySandbox.check_item_status', return_value=False)
    result = runner.invoke(vmray, ['--apikey', api_key, 'check', '--id', 22], color=True)
    assert '\x1b[33mSubmission 22 is in progress.\x1b[0m\n' == result.output
    assert result.exit_code == 0


def test_vmray_check_fail(api_key, mocker, runner):
    """Test the case where a SandboxError is raised when running the check command."""
    mocker.patch('sandboxapi.vmray.VMRaySandbox.check_item_status', side_effect=SandboxError('Boo!'))
    result = runner.invoke(vmray, ['--apikey', api_key, 'check', '--id', 22])
    assert 'Boo!\n' == result.output
    assert result.exit_code == 1


def test_vmray_check_no_apikey(runner):
    """Test the case where no API key is provided to the check command."""
    ref = 'API key is required.\n'
    result = runner.invoke(vmray, ['check', '--id', 22])
    assert result.output == ref
    assert result.exit_code == 5


def test_vmray_check_help(runner):
    """Verify the output when printing the check command usage."""
    ref = """Usage: vmray check [OPTIONS]

  Check the completion status of a task by ID.

Options:
  --id TEXT  The submission id of the job to check.  [required]
  --help     Show this message and exit.
"""
    result = runner.invoke(vmray, ['check', '--help'])
    assert result.output == ref
    assert result.exit_code == 0


def test_vmray_report_ok(api_key, mocker, runner):
    """Verify the report command works correctly."""
    ref = {'dummy': 'report'}
    mocker.patch('sandboxapi.vmray.VMRaySandbox.report', return_value=ref)
    result = runner.invoke(vmray, ['--apikey', api_key, 'report', '--id', 22])
    assert result.output == json.dumps(ref, indent=4) + '\n'
    assert result.exit_code == 0


def test_vmray_report_file(api_key, mocker, runner, tmp_path):
    """Verify that the report command saves a report to a file correctly."""
    ref = {'dummy': 'report'}
    tmp_dir = tmp_path / 'report'
    tmp_dir.mkdir()
    tmp_file = tmp_dir / 'test.json'
    mocker.patch('sandboxapi.vmray.VMRaySandbox.report', return_value=ref)
    result = runner.invoke(vmray, ['--apikey', api_key, 'report', '--id', 22, '--file', str(tmp_file)])
    assert result.output == 'The file was written successfully.\n'
    assert result.exit_code == 0
    assert tmp_file.read_text() == json.dumps(ref, indent=4)


def test_vmray_report_fail(api_key, mocker, runner):
    """Test the case where a SandboxError is raised when running the report command."""
    mocker.patch('sandboxapi.vmray.VMRaySandbox.report', side_effect=SandboxError('Boo!'))
    result = runner.invoke(vmray, ['--apikey', api_key, 'report', '--id', 22])
    assert result.output == 'Boo!\n'
    assert result.exit_code == 1


def test_vmray_report_no_id(api_key, mocker, runner, tmp_path):
    """Test the case where the report command prompts for an id."""
    ref = {'dummy': 'report'}
    tmp_dir = tmp_path / 'report'
    tmp_dir.mkdir()
    tmp_file = tmp_dir / 'test.json'
    mocker.patch('sandboxapi.vmray.VMRaySandbox.report', return_value=ref)
    result = runner.invoke(vmray, ['--apikey', api_key, 'report', '--file', str(tmp_file)], input='22\n')
    assert result.output == 'Id : 22\nThe file was written successfully.\n'
    assert result.exit_code == 0
    assert tmp_file.read_text() == json.dumps(ref, indent=4)


def test_vmray_report_ioerror(api_key, mocker, runner, tmp_path):
    """Test the case where an IOError is raised when trying to write to a file."""
    ref = {'dummy': 'report'}
    tmp_dir = tmp_path / 'report'
    tmp_dir.mkdir()
    tmp_file = tmp_dir / 'test.json'
    mocker.patch('sandboxapi.vmray.VMRaySandbox.report', return_value=ref)
    mocker.patch('pathlib.Path.write_text', side_effect=IOError('Boo!'))
    result = runner.invoke(vmray, ['--apikey', api_key, 'report', '--id', 22, '--file', str(tmp_file)])
    assert result.output == 'Boo!\n'
    assert result.exit_code == 2


def test_vmray_report_no_apikey(runner):
    """Test the case where no API key is provided to the report command."""
    ref = 'API key is required.\n'
    result = runner.invoke(vmray, ['report', '--id', 22])
    assert result.output == ref
    assert result.exit_code == 5


def test_vmray_report_help(runner):
    """Verify the output when printing the report command usage."""
    ref = """Usage: vmray report [OPTIONS]

  Fetch the analysis report for a sample.

Options:
  --id TEXT    The submission ID of the task to check.  [required]
  --file TEXT  Optional file path to save the report to.
  --help       Show this message and exit.
"""
    result = runner.invoke(vmray, ['report', '--help'])
    assert result.output == ref
    assert result.exit_code == 0


def test_vmray_detailed_report_ok(api_key, mocker, runner):
    """Verify the detailed-report command works correctly."""
    ref = {'dummy': 'report'}
    mocker.patch('sandboxapi.vmray.VMRaySandbox.detailed_report', return_value=ref)
    result = runner.invoke(vmray, ['--apikey', api_key, 'detailed-report', '--id', 22])
    assert result.output == json.dumps(ref, indent=4) + '\n'
    assert result.exit_code == 0


def test_vmray_detailed_report_file(api_key, mocker, runner, tmp_path):
    """Verify that the detailed-report command saves a report to a file correctly."""
    ref = {'dummy': 'report'}
    tmp_dir = tmp_path / 'detailed_report'
    tmp_dir.mkdir()
    tmp_file = tmp_dir / 'test.json'
    mocker.patch('sandboxapi.vmray.VMRaySandbox.detailed_report', return_value=ref)
    result = runner.invoke(vmray, ['--apikey', api_key, 'detailed-report', '--id', 22, '--file', str(tmp_file)])
    assert result.output == 'The file was written successfully.\n'
    assert result.exit_code == 0
    assert tmp_file.read_text() == json.dumps(ref, indent=4)


def test_vmray_detailed_report_fail(api_key, mocker, runner):
    """Test the case where a SandboxError is raised when running the detailed-report command."""
    mocker.patch('sandboxapi.vmray.VMRaySandbox.detailed_report', side_effect=SandboxError('Boo!'))
    result = runner.invoke(vmray, ['--apikey', api_key, 'detailed-report', '--id', 22])
    assert result.output == 'Boo!\n'
    assert result.exit_code == 1


def test_vmray_detailed_report_no_id(api_key, mocker, runner, tmp_path):
    """Test the case where the detailed-report command prompts for an id."""
    ref = {'dummy': 'report'}
    tmp_dir = tmp_path / 'detailed_report'
    tmp_dir.mkdir()
    tmp_file = tmp_dir / 'test.json'
    mocker.patch('sandboxapi.vmray.VMRaySandbox.detailed_report', return_value=ref)
    result = runner.invoke(vmray, ['--apikey', api_key, 'detailed-report', '--file', str(tmp_file)], input='22\n')
    assert result.output == 'Id : 22\nThe file was written successfully.\n'
    assert result.exit_code == 0
    assert tmp_file.read_text() == json.dumps(ref, indent=4)


def test_vmray_detailed_report_ioerror(api_key, mocker, runner, tmp_path):
    """Test the case where an IOError is raised when trying to write to a file."""
    ref = {'dummy': 'report'}
    tmp_dir = tmp_path / 'detailed_report'
    tmp_dir.mkdir()
    tmp_file = tmp_dir / 'test.json'
    mocker.patch('sandboxapi.vmray.VMRaySandbox.detailed_report', return_value=ref)
    mocker.patch('pathlib.Path.write_text', side_effect=IOError('Boo!'))
    result = runner.invoke(vmray, ['--apikey', api_key, 'detailed-report', '--id', 22, '--file', str(tmp_file)])
    assert result.output == 'Boo!\n'
    assert result.exit_code == 2


def test_vmray_detailed_report_no_apikey(runner):
    """Test the case where no API key is provided to the detailed-report command."""
    ref = 'API key is required.\n'
    result = runner.invoke(vmray, ['detailed-report', '--id', 22])
    assert result.output == ref
    assert result.exit_code == 5


def test_vmray_detailed_report_help(runner):
    """Verify the output when printing the detailed-report command usage."""
    ref = """Usage: vmray detailed-report [OPTIONS]

  Fetch the detailed report for an analysis.

Options:
  --id TEXT    The analysis ID of the analysis to check.  [required]
  --file TEXT  Optional file path to save the report to.
  --help       Show this message and exit.
"""
    result = runner.invoke(vmray, ['detailed-report', '--help'])
    assert result.output == ref
    assert result.exit_code == 0
