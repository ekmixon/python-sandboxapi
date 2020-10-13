"""This module contains unit tests for the Config class."""

import configparser
import pytest

from sandboxapi import SandboxError
from sandboxapi.base import Config, Sandbox


@pytest.fixture
def ref_config_path(ref_file_path):
    """Fixture for getting the reference config file used for tests."""
    return ref_file_path / 'files' / 'ref_config.cfg'


# noinspection PyUnresolvedReferences
def test_config_attributes(ref_config_path):
    """Verify the Config class sets object attributes correctly."""
    config = Config(ref_config_path, 'cuckoo')
    print(config.__dict__)
    assert hasattr(config, 'timeout')
    assert config.timeout == '30'
    assert hasattr(config, 'verify_ssl')
    assert config.verify_ssl
    assert hasattr(config, 'use_https')
    assert config.use_https
    config = Config(ref_config_path, 'vmray')
    assert hasattr(config, 'api_key')
    assert config.api_key == '12345678'
    assert hasattr(config, 'proxies')
    assert config.proxies == 'http://10.10.1.10:1080'
    assert hasattr(config, 'verify_ssl')
    assert config.verify_ssl
    config = Config(ref_config_path, 'fireeye')
    assert hasattr(config, 'username')
    assert config.username == 'maurice_moss'
    assert hasattr(config, 'password')
    assert config.password == 'tnetennba'
    assert hasattr(config, 'host')
    assert config.host == 'friendface.com'
    assert hasattr(config, 'timeout')
    assert config.timeout == '10'


def test_config_no_sandbox(ref_config_path):
    """Verify the Config class properly handles the case where an unknown sandbox names is given."""
    config = Config(ref_config_path, 'friendface')
    assert ['_Config__path'] == list(config.__dict__.keys())


def test_config_no_apis_key(mocker, ref_config_path):
    """Verify the Config class raises a SandboxError when the config files isn't properly formatted."""
    mocker.patch('configparser.ConfigParser.read_file', side_effect=configparser.ParsingError('Blah'))
    with pytest.raises(SandboxError):
        Config(ref_config_path, 'vmray')


def test_config_file_doesnt_exist():
    """Verify the Config class raises an error if the config file isn't found."""
    with pytest.raises(SandboxError):
        Config('dummy', 'vmray')


def test_config_generate_config_file(ref_file_path, tmp_path):
    """Verify the generate_config_file() method works as expected."""
    ref_template = ref_file_path.parent / 'static' / 'template.cfg'
    tmp_dir = tmp_path / 'config'
    tmp_dir.mkdir()
    tmp_file = tmp_dir / 'sandbox_config.cfg'
    sandbox = Sandbox(alias='joe')
    sandbox.generate_config_file(tmp_file)
    assert tmp_file.exists
    assert ref_template.read_text() == tmp_file.read_text()
