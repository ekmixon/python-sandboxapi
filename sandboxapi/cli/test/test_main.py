"""Unit tests for the main CLI module."""

from pathlib import Path

from sandboxapi.cli.cli import main


def test_help_output(runner):
    """Verify the output when printing the usage."""
    ref = """Usage: main [OPTIONS] COMMAND [ARGS]...

  sandboxapi command line interface.

Options:
  --help  Show this message and exit.

Commands:
  generate-config  Generate a config file to use for sandbox setting
                   configuration.
"""
    result = runner.invoke(main, ['--help'])
    assert result.output == ref
    assert result.exit_code == 0


def test_generate_config(runner, tmp_path):
    """Verify that the generate-config command works correctly."""
    ref = 'The config file was created successfully.\n'
    ref_config_path = Path(__file__).parent.parent.parent / 'static' / 'template.cfg'
    tmp_dir = tmp_path / 'config'
    tmp_dir.mkdir()
    tmp_file = tmp_dir / 'test.cfg'
    result = runner.invoke(main, ['generate-config', '--output', str(tmp_file)])
    assert result.output == ref
    assert ref_config_path.read_text() == tmp_file.read_text()


def test_generate_config_fail(runner):
    """Test the case where generate-config fails to create a config file."""
    ref = """[Errno 2] No such file or directory: 'unknown/test.cfg'
Could not write the config file.
"""
    tmp_file = Path('unknown') / 'test.cfg'
    result = runner.invoke(main, ['generate-config', '--output', str(tmp_file)])
    assert result.output == ref
    assert result.exit_code == 1
