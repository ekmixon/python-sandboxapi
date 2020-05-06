"""This module hosts common test fixtures."""

from pathlib import Path

import pytest


@pytest.fixture
def ref_file_path():
    """Fixture for getting the parent path."""
    return Path(__file__).parent
