"""Unit tests for the Cuckoo CLI."""

import json
from pathlib import Path
from unittest.mock import PropertyMock

from sandboxapi.cli.commands.cuckoo import cuckoo
from sandboxapi import SandboxError


def test_help_output(runner):
    """Verify the output when printing the usage."""
    ref_output = """Usage: cuckoo [OPTIONS] COMMAND [ARGS]...

  Cuckoo sandbox commands.

Options:
  --config TEXT      The path to a config file to load sandbox settings from.
  --host TEXT        The hostname of the Cuckoo server.
  --port INTEGER     The port of the Cuckoo server.
  --username TEXT    A valid username if using authentication.
  --password TEXT    The Cuckoo user's password.
  --https / --http   Use https.
  --proxy TEXT       The URI of a proxy server to connect through.
  --timeout INTEGER  The delay in seconds before a request times out.
  --ssl / --no-ssl   Enables SSL certificate validation.
  --help             Show this message and exit.

Commands:
  available  Check to see if the Cuckoo sandbox is available.
  check      Check the completion status of a task.
  delete     Delete a task from the Cuckoo sandbox queue.
  queue      Check how many tasks are pending or running on the Cuckoo server.
  report     Get the Cuckoo report for a submitted sample.
  submit     Submit a sample to the Cuckoo sandbox.
"""
    result = runner.invoke(cuckoo, ['--help'])
    assert result.output == ref_output
    assert result.exit_code == 0


def test_cuckoo_config(mocker, runner):
    """Verify that loading parameters from a config file works correctly."""
    ref = 'Cuckoo sandbox https://example.com:5555 is available.\n'
    config_file = Path(__file__).parent / 'files' / 'config.cfg'
    mocker.patch('sandboxapi.cuckoo.CuckooSandbox.available', new_callable=PropertyMock, return_value=True)
    result = runner.invoke(cuckoo, ['--config', str(config_file), 'available'])
    assert result.output == ref
    assert result.exit_code == 0


def test_cuckoo_config_read_fail(mocker, runner):
    """Test the case where the config option is given, but the file doesn't exist."""
    ref = """[Errno 2] No such file or directory: 'unknown/test.cfg'\n"""
    config_file = Path('unknown') / 'test.cfg'
    mocker.patch('sandboxapi.cuckoo.CuckooSandbox.available', new_callable=PropertyMock, return_value=True)
    result = runner.invoke(cuckoo, ['--config', str(config_file), 'available'])
    assert result.output == ref
    assert result.exit_code == 20


def test_cuckoo_available(mocker, runner):
    """Verify that the available command works correctly."""
    mocker.patch('sandboxapi.cuckoo.CuckooSandbox.available', new_callable=PropertyMock, return_value=True)
    result = runner.invoke(cuckoo, ['available'])
    assert 'Cuckoo sandbox http://localhost:8090 is available.\n' == result.output
    assert result.exit_code == 0
    result = runner.invoke(cuckoo, ['--https', 'available'])
    assert 'Cuckoo sandbox https://localhost:8090 is available.\n' == result.output
    assert result.exit_code == 0


def test_cuckoo_unavailable(mocker, runner):
    """Test the case where available responds with an unavailable status."""
    mocker.patch('sandboxapi.cuckoo.CuckooSandbox.available', new_callable=PropertyMock, return_value=False)
    result = runner.invoke(cuckoo, ['available'])
    assert 'Cuckoo sandbox http://localhost:8090 is unavailable.\n' == result.output
    assert result.exit_code == 1


def test_cuckoo_available_help(runner):
    """Verify the output when printing the available command usage."""
    ref = """Usage: cuckoo available [OPTIONS]

  Check to see if the Cuckoo sandbox is up and available.

Options:
  --help  Show this message and exit.
"""
    result = runner.invoke(cuckoo, ['available', '--help'])
    assert result.output == ref
    assert result.exit_code == 0


def test_cuckoo_submit_ok(mocker, runner):
    """Verify the submit command works correctly."""
    mocker.patch('pathlib.Path.open')
    mocker.patch('sandboxapi.cuckoo.CuckooSandbox.submit_sample', return_value=22)
    result = runner.invoke(cuckoo, ['submit', '--file', 'virus.xlsx'])
    assert 'Submitted successfully. Task id: 22.\n' == result.output
    assert result.exit_code == 0


def test_cuckoo_submit_file_not_found(runner):
    """Test the case where the file to submit is not found."""
    result = runner.invoke(cuckoo, ['submit', '--file', 'virus.xlsx'], catch_exceptions=False)
    assert "[Errno 2] No such file or directory: 'virus.xlsx'\n" == result.output
    assert result.exit_code == 2


def test_cuckoo_submit_file_fail(runner, mocker):
    """Test the case where a SandboxError occurs while submitting the sample."""
    mocker.patch('pathlib.Path.open')
    mocker.patch('sandboxapi.cuckoo.CuckooSandbox.submit_sample', side_effect=SandboxError('Boo!'))
    result = runner.invoke(cuckoo, ['submit', '--file', 'virus.xlsx'], catch_exceptions=False)
    assert result.output == 'Boo!\n'
    assert result.exit_code == 1


def test_cuckoo_submit_no_file(runner, mocker):
    """Test the case where a file path is prompted for."""
    mocker.patch('pathlib.Path.open')
    mocker.patch('sandboxapi.cuckoo.CuckooSandbox.submit_sample', return_value=22)
    result = runner.invoke(cuckoo, ['submit'], input='22\n')
    assert 'File: 22\nSubmitted successfully. Task id: 22.\n' == result.output
    assert result.exit_code == 0


def test_cuckoo_submit_help(runner):
    """Verify the output when printing the submit command usage."""
    ref = """Usage: cuckoo submit [OPTIONS]

  Submit a sample to the Cuckoo sandbox for analysis.

Options:
  -f, --file TEXT  The path to the file to submit.  [required]
  --help           Show this message and exit.
"""
    result = runner.invoke(cuckoo, ['submit', '--help'])
    assert result.output == ref
    assert result.exit_code == 0


def test_cuckoo_check_ok(mocker, runner):
    """Verify that the check command works correctly."""
    mocker.patch('sandboxapi.cuckoo.CuckooSandbox.check_item_status', return_value=True)
    result = runner.invoke(cuckoo, ['check', '--id', 22], color=True)
    assert '\x1b[32mTask 22 is complete.\x1b[0m\n' == result.output
    assert result.exit_code == 0


def test_cuckoo_check_no_id(mocker, runner):
    """Test the case where the check command prompts for the id."""
    mocker.patch('sandboxapi.cuckoo.CuckooSandbox.check_item_status', return_value=True)
    result = runner.invoke(cuckoo, ['check'], color=True, input='22\n')
    assert 'Id : 22\n\x1b[32mTask 22 is complete.\x1b[0m\n' == result.output
    assert result.exit_code == 0


def test_cuckoo_check_not_ready(mocker, runner):
    """Test the case where the check command responds with a not ready state."""
    mocker.patch('sandboxapi.cuckoo.CuckooSandbox.check_item_status', return_value=False)
    result = runner.invoke(cuckoo, ['check', '--id', 22], color=True)
    assert '\x1b[33mTask 22 is in progress.\x1b[0m\n' == result.output
    assert result.exit_code == 0


def test_cuckoo_check_fail(mocker, runner):
    """Test the case where a SandboxError is raised when running the check command."""
    mocker.patch('sandboxapi.cuckoo.CuckooSandbox.check_item_status', side_effect=SandboxError('Boo!'))
    result = runner.invoke(cuckoo, ['check', '--id', 22])
    assert 'Boo!\n' == result.output
    assert result.exit_code == 1


def test_cuckoo_check_help(runner):
    """Verify the output when printing the check command usage."""
    ref = """Usage: cuckoo check [OPTIONS]

  Check the completion status of a task by ID.

Options:
  --id TEXT  The task ID of the task to check.  [required]
  --help     Show this message and exit.
"""
    result = runner.invoke(cuckoo, ['check', '--help'])
    assert result.output == ref
    assert result.exit_code == 0


def test_cuckoo_delete_ok(mocker, runner):
    """Verify that the delete command works correctly."""
    mocker.patch('sandboxapi.cuckoo.CuckooSandbox.delete_item', return_value=True)
    result = runner.invoke(cuckoo, ['delete', '--id', 22])
    assert result.output == 'Task 22 was deleted successfully.\n'
    assert result.exit_code == 0


def test_cuckoo_delete_no_id(mocker, runner):
    """Test the case where the delete command prompts for the id."""
    mocker.patch('sandboxapi.cuckoo.CuckooSandbox.delete_item', return_value=True)
    result = runner.invoke(cuckoo, ['delete'], input='22\n')
    assert result.output == 'Id : 22\nTask 22 was deleted successfully.\n'
    assert result.exit_code == 0


def test_cuckoo_delete_fail(mocker, runner):
    """Test the case where a SandboxError is raised when running the delete command."""
    mocker.patch('sandboxapi.cuckoo.CuckooSandbox.delete_item', side_effect=SandboxError('Boo!'))
    result = runner.invoke(cuckoo, ['delete', '--id', 22])
    assert result.output == 'Boo!\n'
    assert result.exit_code == 1


def test_cuckoo_delete_unknown_error(mocker, runner):
    """Test the case where the task could not be deleted for an unknown reason."""
    mocker.patch('sandboxapi.cuckoo.CuckooSandbox.delete_item', return_value=False)
    result = runner.invoke(cuckoo, ['delete', '--id', 22])
    assert result.output == 'Failed to delete task 22.\n'
    assert result.exit_code == 2


def test_cuckoo_delete_help(runner):
    """Verify the output when printing the delete command usage."""
    ref = """Usage: cuckoo delete [OPTIONS]

  Remove a task from the Cuckoo sandbox queue by ID.

Options:
  --id TEXT  The task ID of the task to delete.  [required]
  --help     Show this message and exit.
"""
    result = runner.invoke(cuckoo, ['delete', '--help'])
    assert result.output == ref
    assert result.exit_code == 0


def test_cuckoo_queue_ok(mocker, runner):
    """Verify that the queue command works correctly."""
    mocker.patch('sandboxapi.cuckoo.CuckooSandbox.queue_size', new_callable=PropertyMock, return_value=6)
    result = runner.invoke(cuckoo, ['queue'])
    assert result.output == 'There are currently 6 tasks to process.\n'
    assert result.exit_code == 0


def test_cuckoo_queue_empty(mocker, runner):
    """Test the case where the queue command reports the queue is empty."""
    mocker.patch('sandboxapi.cuckoo.CuckooSandbox.queue_size', new_callable=PropertyMock, return_value=0)
    result = runner.invoke(cuckoo, ['queue'])
    assert result.output == 'There are no pending tasks.\n'
    assert result.exit_code == 0


def test_cuckoo_queue_fail(mocker, runner):
    """Test the case where a SandboxError is raised by the queue command."""
    mocker.patch(
        'sandboxapi.cuckoo.CuckooSandbox.queue_size',
        new_callable=PropertyMock,
        side_effect=SandboxError('Boo!'),
    )
    result = runner.invoke(cuckoo, ['queue'])
    assert result.output == 'Boo!\n'
    assert result.exit_code == 1


def test_cuckoo_queue_help(runner):
    """Verify the output when printing the queue command usage."""
    ref = """Usage: cuckoo queue [OPTIONS]

  Check the number of tasks currently in the sandbox work queue.

Options:
  --help  Show this message and exit.
"""
    result = runner.invoke(cuckoo, ['queue', '--help'])
    assert result.output == ref
    assert result.exit_code == 0


def test_cuckoo_report_ok(mocker, runner):
    """Verify the report command works correctly."""
    ref = {'dummy': 'report'}
    mocker.patch('sandboxapi.cuckoo.CuckooSandbox.report', return_value=ref)
    result = runner.invoke(cuckoo, ['report', '--id', 22])
    assert result.output == json.dumps(ref, indent=4) + '\n'
    assert result.exit_code == 0


def test_cuckoo_report_file(mocker, runner, tmp_path):
    """Verify that the report command saves a report to a file correctly."""
    ref = {'dummy': 'report'}
    tmp_dir = tmp_path / 'report'
    tmp_dir.mkdir()
    tmp_file = tmp_dir / 'test.json'
    mocker.patch('sandboxapi.cuckoo.CuckooSandbox.report', return_value=ref)
    result = runner.invoke(cuckoo, ['report', '--id', 22, '--file', str(tmp_file)])
    assert result.output == 'The file was written successfully.\n'
    assert result.exit_code == 0
    assert tmp_file.read_text() == json.dumps(ref, indent=4)


def test_cuckoo_report_fail(mocker, runner):
    """Test the case where a SandboxError is raised when running the report command."""
    mocker.patch('sandboxapi.cuckoo.CuckooSandbox.report', side_effect=SandboxError('Boo!'))
    result = runner.invoke(cuckoo, ['report', '--id', 22])
    assert result.output == 'Boo!\n'
    assert result.exit_code == 1


def test_cuckoo_report_no_id(mocker, runner, tmp_path):
    """Test the case where the report command prompts for an id."""
    ref = {'dummy': 'report'}
    tmp_dir = tmp_path / 'report'
    tmp_dir.mkdir()
    tmp_file = tmp_dir / 'test.json'
    mocker.patch('sandboxapi.cuckoo.CuckooSandbox.report', return_value=ref)
    result = runner.invoke(cuckoo, ['report', '--file', str(tmp_file)], input='22\n')
    assert result.output == 'Id : 22\nThe file was written successfully.\n'
    assert result.exit_code == 0
    assert tmp_file.read_text() == json.dumps(ref, indent=4)


def test_cuckoo_report_ioerror(mocker, runner, tmp_path):
    """Test the case where an IOError is raised when trying to write to a file."""
    ref = {'dummy': 'report'}
    tmp_dir = tmp_path / 'report'
    tmp_dir.mkdir()
    tmp_file = tmp_dir / 'test.json'
    mocker.patch('sandboxapi.cuckoo.CuckooSandbox.report', return_value=ref)
    mocker.patch('pathlib.Path.write_text', side_effect=IOError('Boo!'))
    result = runner.invoke(cuckoo, ['report', '--id', 22, '--file', str(tmp_file)])
    assert result.output == 'Boo!\n'
    assert result.exit_code == 2


def test_cuckoo_report_help(runner):
    """Verify the output when printing the report command usage."""
    ref = """Usage: cuckoo report [OPTIONS]

  Fetch the analysis report for a sample.

Options:
  --id TEXT    The task ID of the sample.  [required]
  --file TEXT  Optional file path to save the report to.
  --help       Show this message and exit.
"""
    result = runner.invoke(cuckoo, ['report', '--help'])
    assert result.output == ref
    assert result.exit_code == 0
