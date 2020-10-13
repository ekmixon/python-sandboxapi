"""Unit tests for the Falcon CLI."""

import json
from pathlib import Path
import pytest
from unittest.mock import PropertyMock

from sandboxapi.cli.commands.falcon import falcon
from sandboxapi import SandboxError


@pytest.fixture
def api_key():
    """Provides a fake API key."""
    return 123456


def test_help_output(runner):
    """Verify the output when printing the usage."""
    ref = """Usage: falcon [OPTIONS] COMMAND [ARGS]...

  Falcon sandbox commands.

Options:
  --apikey TEXT                   The customer API key for accessing the Falcon
                                  sandbox.

  --config TEXT                   The path to a config file to load sandbox
                                  settings from.

  --host TEXT                     The hostname of the Falcon server.
  --environment [ANDROID|WIN7|WIN7HWP|WIN7X64|XENIAL]
                                  The sandbox runtime OS to use.
  --proxy TEXT                    The URI of a proxy server to connect through.
  --timeout INTEGER               The delay in seconds before a request times
                                  out.

  --ssl / --no-ssl                Enables SSL certificate validation.
  --help                          Show this message and exit.

Commands:
  available  Check to see if the Falcon sandbox is available.
  check      Check the completion status of a job.
  queue      Check how many jobs are pending or running on the Falcon server.
  report     Get the Falcon report for a submitted sample.
  submit     Submit a sample to the Falcon sandbox.
"""
    result = runner.invoke(falcon, ['--help'])
    assert result.output == ref
    assert result.exit_code == 0


def test_falcon_config(mocker, runner):
    """Verify that loading parameters from a config file works correctly."""
    ref = 'Falcon sandbox https://blernsball/api/v2 is available.\n'
    config_file = Path(__file__).parent / 'files' / 'config.cfg'
    mocker.patch('sandboxapi.falcon.FalconSandbox.available', new_callable=PropertyMock, return_value=True)
    result = runner.invoke(falcon, ['--config', str(config_file), '--host', 'blernsball', 'available'])
    assert result.output == ref
    assert result.exit_code == 0


def test_falcon_available(mocker, runner):
    """Verify that the available command works correctly."""
    mocker.patch('sandboxapi.falcon.FalconSandbox.available', new_callable=PropertyMock, return_value=True)
    result = runner.invoke(falcon, ['available'])
    assert 'Falcon sandbox https://www.reverse.it/api/v2 is available.\n' == result.output
    assert result.exit_code == 0


def test_falcon_unavailable(mocker, runner):
    """Test the case where available responds with an unavailable status."""
    mocker.patch('sandboxapi.falcon.FalconSandbox.available', new_callable=PropertyMock, return_value=False)
    result = runner.invoke(falcon, ['available'])
    assert 'Falcon sandbox https://www.reverse.it/api/v2 is unavailable.\n' == result.output
    assert result.exit_code == 1


def test_falcon_available_help(runner):
    """Verify the output when printing the available command usage."""
    ref = """Usage: falcon available [OPTIONS]

  Check to see if the Falcon sandbox is up and available.

Options:
  --help  Show this message and exit.
"""
    result = runner.invoke(falcon, ['available', '--help'])
    assert result.output == ref
    assert result.exit_code == 0


def test_falcon_submit_ok(api_key, mocker, runner):
    """Verify the submit command works correctly."""
    mocker.patch('pathlib.Path.open')
    mocker.patch('sandboxapi.falcon.FalconSandbox.submit_sample', return_value=22)
    result = runner.invoke(falcon, ['--apikey', api_key, 'submit', '--file', 'virus.xlsx'])
    assert 'Submitted successfully. Job id: 22.\n' == result.output
    assert result.exit_code == 0


def test_falcon_submit_file_not_found(api_key, runner):
    """Test the case where the file to submit is not found."""
    result = runner.invoke(falcon, ['--apikey', api_key, 'submit', '--file', 'virus.xlsx'], catch_exceptions=False)
    assert "[Errno 2] No such file or directory: 'virus.xlsx'\n" == result.output
    assert result.exit_code == 2


def test_falcon_submit_file_fail(api_key, runner, mocker):
    """Test the case where a SandboxError occurs while submitting the sample."""
    mocker.patch('pathlib.Path.open')
    mocker.patch('sandboxapi.falcon.FalconSandbox.submit_sample', side_effect=SandboxError('Boo!'))
    result = runner.invoke(falcon, ['--apikey', api_key, 'submit', '--file', 'virus.xlsx'], catch_exceptions=False)
    assert result.output == 'Boo!\n'
    assert result.exit_code == 1


def test_falcon_submit_no_file(api_key, runner, mocker):
    """Test the case where a file path is prompted for."""
    mocker.patch('pathlib.Path.open')
    mocker.patch('sandboxapi.falcon.FalconSandbox.submit_sample', return_value=22)
    result = runner.invoke(falcon, ['--apikey', api_key, 'submit'], input='22\n')
    assert 'File: 22\nSubmitted successfully. Job id: 22.\n' == result.output
    assert result.exit_code == 0


def test_falcon_submit_no_apikey(runner):
    """Test the case where no API key is provided to the submit command."""
    ref = 'API key is required.\n'
    result = runner.invoke(falcon, ['submit', '--file', 'virus.xlsx'])
    assert result.output == ref
    assert result.exit_code == 5


def test_falcon_submit_help(runner):
    """Verify the output when printing the submit command usage."""
    ref = """Usage: falcon submit [OPTIONS]

  Submit a sample to the Falcon sandbox.

Options:
  -f, --file TEXT  The path to the file to submit.  [required]
  --help           Show this message and exit.
"""
    result = runner.invoke(falcon, ['submit', '--help'])
    assert result.output == ref
    assert result.exit_code == 0


def test_falcon_check_ok(api_key, mocker, runner):
    """Verify that the check command works correctly."""
    mocker.patch('sandboxapi.falcon.FalconSandbox.check_item_status', return_value=True)
    result = runner.invoke(falcon, ['--apikey', api_key, 'check', '--id', 22], color=True)
    assert '\x1b[32mJob 22 is complete.\x1b[0m\n' == result.output
    assert result.exit_code == 0


def test_falcon_check_no_id(api_key, mocker, runner):
    """Test the case where the check command prompts for the id."""
    mocker.patch('sandboxapi.falcon.FalconSandbox.check_item_status', return_value=True)
    result = runner.invoke(falcon, ['--apikey', api_key, 'check'], color=True, input='22\n')
    assert 'Id : 22\n\x1b[32mJob 22 is complete.\x1b[0m\n' == result.output
    assert result.exit_code == 0


def test_falcon_check_not_ready(api_key, mocker, runner):
    """Test the case where the check command responds with a not ready state."""
    mocker.patch('sandboxapi.falcon.FalconSandbox.check_item_status', return_value=False)
    result = runner.invoke(falcon, ['--apikey', api_key, 'check', '--id', 22], color=True)
    assert '\x1b[33mJob 22 is in progress.\x1b[0m\n' == result.output
    assert result.exit_code == 0


def test_falcon_check_fail(api_key, mocker, runner):
    """Test the case where a SandboxError is raised when running the check command."""
    mocker.patch('sandboxapi.falcon.FalconSandbox.check_item_status', side_effect=SandboxError('Boo!'))
    result = runner.invoke(falcon, ['--apikey', api_key, 'check', '--id', 22])
    assert 'Boo!\n' == result.output
    assert result.exit_code == 1


def test_falcon_check_no_apikey(runner):
    """Test the case where no API key is provided to the check command."""
    ref = 'API key is required.\n'
    result = runner.invoke(falcon, ['check', '--id', 22])
    assert result.output == ref
    assert result.exit_code == 5


def test_falcon_check_help(runner):
    """Verify the output when printing the check command usage."""
    ref = """Usage: falcon check [OPTIONS]

  Check the completion status of a job by ID.

Options:
  --id TEXT  The job ID of the job to check.  [required]
  --help     Show this message and exit.
"""
    result = runner.invoke(falcon, ['check', '--help'])
    assert result.output == ref
    assert result.exit_code == 0


def test_falcon_queue_ok(api_key, mocker, runner):
    """Verify that the queue command works correctly."""
    mocker.patch('sandboxapi.falcon.FalconSandbox.queue_size', new_callable=PropertyMock, return_value=6)
    result = runner.invoke(falcon, ['--apikey', api_key, 'queue'])
    assert result.output == 'There are currently 6 jobs to process.\n'
    assert result.exit_code == 0


def test_falcon_queue_empty(api_key, mocker, runner):
    """Test the case where the queue command reports the queue is empty."""
    mocker.patch('sandboxapi.falcon.FalconSandbox.queue_size', new_callable=PropertyMock, return_value=0)
    result = runner.invoke(falcon, ['--apikey', api_key, 'queue'])
    assert result.output == 'There are no pending jobs.\n'
    assert result.exit_code == 0


def test_falcon_queue_fail(api_key, mocker, runner):
    """Test the case where a SandboxError is raised by the queue command."""
    mocker.patch(
        'sandboxapi.falcon.FalconSandbox.queue_size',
        new_callable=PropertyMock,
        side_effect=SandboxError('Boo!'),
    )
    result = runner.invoke(falcon, ['--apikey', api_key, 'queue'])
    assert result.output == 'Boo!\n'
    assert result.exit_code == 1


def test_falcon_queue_no_apikey(runner):
    """Test the case where no API key is provided to the queue command."""
    ref = 'API key is required.\n'
    result = runner.invoke(falcon, ['check', '--id', 22])
    assert result.output == ref
    assert result.exit_code == 5


def test_falcon_queue_help(runner):
    """Verify the output when printing the queue command usage."""
    ref = """Usage: falcon queue [OPTIONS]

  Check the number of jobs currently in the sandbox work queue.

Options:
  --help  Show this message and exit.
"""
    result = runner.invoke(falcon, ['queue', '--help'])
    assert result.output == ref
    assert result.exit_code == 0


def test_falcon_report_ok(api_key, mocker, runner):
    """Verify the report command works correctly."""
    ref = {'dummy': 'report'}
    mocker.patch('sandboxapi.falcon.FalconSandbox.report', return_value=ref)
    result = runner.invoke(falcon, ['--apikey', api_key, 'report', '--id', 22])
    assert result.output == json.dumps(ref, indent=4) + '\n'
    assert result.exit_code == 0


def test_falcon_report_file(api_key, mocker, runner, tmp_path):
    """Verify that the report command saves a report to a file correctly."""
    ref = {'dummy': 'report'}
    tmp_dir = tmp_path / 'report'
    tmp_dir.mkdir()
    tmp_file = tmp_dir / 'test.json'
    mocker.patch('sandboxapi.falcon.FalconSandbox.report', return_value=ref)
    result = runner.invoke(falcon, ['--apikey', api_key, 'report', '--id', 22, '--file', str(tmp_file)])
    assert result.output == 'The file was written successfully.\n'
    assert result.exit_code == 0
    assert tmp_file.read_text() == json.dumps(ref, indent=4)


def test_falcon_report_fail(api_key, mocker, runner):
    """Test the case where a SandboxError is raised when running the report command."""
    mocker.patch('sandboxapi.falcon.FalconSandbox.report', side_effect=SandboxError('Boo!'))
    result = runner.invoke(falcon, ['--apikey', api_key, 'report', '--id', 22])
    assert result.output == 'Boo!\n'
    assert result.exit_code == 1


def test_falcon_report_no_id(api_key, mocker, runner, tmp_path):
    """Test the case where the report command prompts for an id."""
    ref = {'dummy': 'report'}
    tmp_dir = tmp_path / 'report'
    tmp_dir.mkdir()
    tmp_file = tmp_dir / 'test.json'
    mocker.patch('sandboxapi.falcon.FalconSandbox.report', return_value=ref)
    result = runner.invoke(falcon, ['--apikey', api_key, 'report', '--file', str(tmp_file)], input='22\n')
    assert result.output == 'Id : 22\nThe file was written successfully.\n'
    assert result.exit_code == 0
    assert tmp_file.read_text() == json.dumps(ref, indent=4)


def test_falcon_report_ioerror(api_key, mocker, runner, tmp_path):
    """Test the case where an IOError is raised when trying to write to a file."""
    ref = {'dummy': 'report'}
    tmp_dir = tmp_path / 'report'
    tmp_dir.mkdir()
    tmp_file = tmp_dir / 'test.json'
    mocker.patch('sandboxapi.falcon.FalconSandbox.report', return_value=ref)
    mocker.patch('pathlib.Path.write_text', side_effect=IOError('Boo!'))
    result = runner.invoke(falcon, ['--apikey', api_key, 'report', '--id', 22, '--file', str(tmp_file)])
    assert result.output == 'Boo!\n'
    assert result.exit_code == 2


def test_falcon_report_pdf_format(api_key, mocker, runner, tmp_path):
    """Verify that the report command outputs in PDF format correctly."""
    ref_path = Path(__file__).parent / 'files' / 'joe_test1234.pdf'
    tmp_dir = tmp_path / 'report'
    tmp_dir.mkdir()
    tmp_file = tmp_dir / 'test.pdf'
    mocker.patch('sandboxapi.falcon.FalconSandbox.pdf_report', return_value=ref_path.read_bytes())
    result = runner.invoke(
        falcon,
        ['--apikey', api_key, 'report', '--id', 22, '--format', 'pdf', '--file', str(tmp_file)],
    )
    assert result.output == 'The file was written successfully.\n'
    assert result.exit_code == 0
    assert ref_path.read_bytes()[:20] == tmp_file.read_bytes()[:20]


def test_falcon_report_pdf_no_file(api_key, runner):
    """Verify that the report command requires a file for the PDF format."""
    ref = "No file specified to save the PDF report.\n"
    result = runner.invoke(falcon, ['--apikey', api_key, 'report', '--id', 22, '--format', 'pdf'])
    assert result.output == ref
    assert result.exit_code == 3


def test_falcon_report_no_apikey(runner):
    """Test the case where no API key is provided to the report command."""
    ref = 'API key is required.\n'
    result = runner.invoke(falcon, ['report', '--id', 22])
    assert result.output == ref
    assert result.exit_code == 5


def test_falcon_report_help(runner):
    """Verify the output when printing the report command usage."""
    ref = """Usage: falcon report [OPTIONS]

  Fetch the analysis report for a sample.

Options:
  --id TEXT            The job ID of the sample.  [required]
  --file TEXT          Optional file path to save the report to. Only required
                       for PDF format

  --format [json|pdf]  The report format.
  --help               Show this message and exit.
"""
    result = runner.invoke(falcon, ['report', '--help'])
    assert result.output == ref
    assert result.exit_code == 0
