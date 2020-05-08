"""This module hosts common test fixtures."""

from click.testing import CliRunner
import pytest


@pytest.fixture
def runner():
    """Provides an object for running CLI commands."""
    return CliRunner(echo_stdin=True)
