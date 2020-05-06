"""This module contains unit tests for the Config class."""

import pytest

from sandboxapi import SandboxError
from sandboxapi.base import Config, Sandbox


@pytest.fixture
def ref_config_path(ref_file_path):
    """Fixture for getting the reference config file used for tests."""
    return ref_file_path / 'files' / 'ref_config.json'


# noinspection PyUnresolvedReferences
def test_config_attributes(ref_config_path):
    """Verify the Config class sets object attributes correctly."""
    config = Config(ref_config_path, 'vmray')
    assert hasattr(config, 'api_key')
    assert config.api_key == '12345678'
    config = Config(ref_config_path, 'fireeye')
    assert hasattr(config, 'username')
    assert config.username == 'maurice_moss'
    assert hasattr(config, 'password')
    assert config.password == 'tnetennba'
    assert hasattr(config, 'host')
    assert config.host == 'friendface.com'


def test_config_no_sandbox(ref_config_path):
    """Verify the Config class properly handles the case where an unknown sandbox names is given."""
    config = Config(ref_config_path, 'friendface')
    assert ['_Config__path'] == list(config.__dict__.keys())


def test_config_no_apis_key(mocker):
    """Verify the Config class raises a SandboxError when the config files isn't properly formatted."""
    mocker.patch('pathlib.Path.read_text', return_value='{"blah": []}')
    with pytest.raises(SandboxError):
        Config('dummy', 'vmray')


def test_config_file_doesnt_exist():
    """Verify the Config class raises an error if the config file isn't found."""
    with pytest.raises(FileNotFoundError):
        Config('dummy', 'vmray')


def test_config_generate_config_file(ref_file_path, tmp_path):
    """Verify the generate_config_file() method works as expected."""
    ref_template = ref_file_path.parent / 'static' / 'config_template.json'
    tmp_dir = tmp_path / 'config'
    tmp_dir.mkdir()
    tmp_file = tmp_dir / 'sandbox_config.json'
    sandbox = Sandbox(alias='joe')
    sandbox._generate_config_file(tmp_file)
    assert tmp_file.exists
    assert ref_template.read_text() == tmp_file.read_text()
