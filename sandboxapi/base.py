"""This module hosts the Sandbox super class."""

import configparser
import json
import re
from pathlib import Path
import random
import time
from typing import Any, IO, Optional, Union

import requests


class SandboxError(Exception):
    """Represents a generic Sandbox error."""


class Sandbox:
    """Super class for all sandbox vendor classes to inherit from.

    :param alias: The shorthand name of the sandbox, used for mapping to properties in a config file.
    :param base_url: The base url for the sandbox API being called.
    :param config: The path to a config file to load attributes from.
    :param proxies: The http or https proxy or proxies to connect through.
    :param timeout: The number of seconds to wait before raising a time out error.
    :param verify_ssl: Enable or disable checking SSL certificates.

    **proxies:**

    - A dictionary of one or more proxies to route HTTP or HTTPS requests.
    - The keys should be http, https, or a scheme and host.
    - The values should an IP address or FQDN followed by the port.
    - To use basic auth, the format should be *http://user:pass@host:port*.

    .. code-block:: python

       proxies = {
           'http': 'http://10.10.1.10:3128',
       }

       proxies = {
           'http': 'http://10.10.1.10:3128',
           'https': 'http://10.10.1.10:1080',
       }

       proxies = {'http': 'http://user:pass@10.10.1.10:3128/'}

       proxies = {'http://10.20.1.128': 'http://10.10.1.10:5323'}

    .. seealso:: https://requests.kennethreitz.org/en/master/user/advanced/#proxies

    **verify_ssl**

    - Default is True.
    - Set to False to ignore SSL certificate verification.
    - Can also be a path to a trusted certfile or directory of certificates.
    """

    def __init__(
            self,
            alias: str = Path(__file__).stem,
            base_url: str = '',
            config: Union[Path, str] = '',
            proxies: Optional[dict] = None,
            timeout: Optional[int] = None,
            verify_ssl: Optional[bool] = None,
            **kwargs,
    ) -> None:
        """Instantiates a new Sandbox object."""
        self.base_url = base_url
        self.config = Config(config, alias) if config else None
        self.proxies = self._set_attribute(proxies, None, 'proxies')
        self.timeout_secs = self._set_attribute(timeout, 30, 'timeout', float)
        self.verify_ssl = self._set_attribute(verify_ssl, True, 'verify_ssl', bool)
        self._request_opts = dict(
            timeout=self.timeout_secs,
            verify=self.verify_ssl,
        )

    def submit_sample(self, filepath: Union[str, Path]) -> str:
        """Submit a new sample to the sandbox for analysis.

        :param filepath: The path to the sample to submit.
        :return: The ID of the created item.
        """
        raise NotImplementedError

    def check_item_status(self, item_id: Union[int, str]) -> bool:
        """Check to see if the analysis for a particular sample is complete.

        :param item_id: The item ID of the sample to check.
        :return: True if the analysis for the sample is complete, otherwise False.
        """
        raise NotImplementedError

    def report(self, item_id: Union[int, str]) -> dict:
        """Pulls the threat report from the sandbox for the submitted sample.

        :param item_id: The item ID of analyzed sample.
        :return: The report of the analyzed sample.
        """
        raise NotImplementedError

    def xml_report(self, item_id: Union[int, str]) -> bytes:
        """Pulls the threat report from the sandbox for the submitted sample as a XML file.

        This method might not be supported by all sandboxes.

        :param item_id: The item ID of the analyzed sample.
        :return: The report of the analyzed sample as XML.
        """
        return bytes()

    def pdf_report(self, item_id: Union[int, str]) -> bytes:
        """Pulls the threat report from the sandbox for the submitted sample as a PDF file.

        This method might not be supported by all sandboxes.

        :param item_id: The item ID of the analyzed sample.
        :return: The report of the analyzed sample as a PDF file.
        """
        return bytes()

    def decode(self, response: requests.Response) -> dict:
        """Parse the HTTP response into a dictionary.

        :param response: The requests Response object from the sandbox.
        :return: The response formatted as a Python dictionary.
        """
        return json.loads(response.content.decode('utf-8'))

    def score(self, report: dict) -> int:
        """Get the threat score for the submitted sample.

        :return: The threat score.
        """
        raise NotImplementedError

    def delete_item(self, item_id: Union[str, int]) -> bool:
        """Remove an item from the sandbox.

        :param item_id: The item ID of the sample to remove.
        :return: True if the item was successfully removed.
        """
        del item_id
        return False

    @property
    def available(self) -> bool:
        """Designates if a sandbox is up and available.

        :return: True if the sandbox is available, else False.
        """
        return False

    @property
    def queue_size(self) -> int:
        """Checks to see how many jobs are currently pending on the server.

        :return: The number of pending jobs on the server.
        """
        return 0

    @staticmethod
    def _get_file(filepath: Union[str, Path]) -> IO[Any]:
        """Get a handle to an open file and create a formatted dictionary that requests can use for uploading the file.

        :param filepath: The absolute or relative path to the file to upload.
        :return: A File object that requests can use for uploading the file.
        """
        filepath = Path(filepath).expanduser()
        return filepath.open(mode='rb')

    @staticmethod
    def generate_config_file(filepath: Union[str, Path] = '.') -> None:
        """Creates a config file template at the specified path.

        :param filepath: The path to the config file.
        :return: None

        The default name for the config file is *sandbox_config.json*.
        """
        template = (Path(__file__).parent / 'static' / 'template.cfg').read_text()
        if str(filepath) == '.':
            filepath = Path('.') / 'sandbox_config.cfg'
        Path(filepath).write_text(template)

    @staticmethod
    def _format_host(host: str) -> str:
        """Strips the protocol from a URI and returns the host.

        :param host: The URI or URL to format.
        :return: The hostname portion of a URI or URL.
        """
        match = re.match('[a-z]*://(.*)', host)
        if match:
            host = match.group(1)
        return host

    def _set_attribute(self, value: Any, default: Any, name: str, data_type: type = str) -> Any:
        """Sets initialized arguments values based on priority.

        Attribute setting priority: explicit arg > config property > arg default

        :param value: The argument value to set.
        :param default: The default value of the argument in __init__.
        :param name: The name of the setting in the config file.
        :param data_type: The data type for interpreting the attribute.
        :return: If no config, returns value if different from default, otherwise the setting in config.
        """
        if value is not None:
            return value
        if self.config and hasattr(self.config, name):
            out = vars(self.config).get(name)
            if out is not None:
                out = data_type(out)
            return out
        else:
            return default


class Config:
    """Class with optional configuration properties for specific sandboxes.

    :param path: The path to the config file.
    :param sandbox_name: The name of the sandbox with configuration properties to load.

    - Config files are stored in ini format.
    - The object for each sandbox contains name/value pairs for each configuration.
    - The configuration name must match the Sandbox object attribute name.

    :Example:

        [cuckoo]
        host = localhost
        port = 8888

        [vmray]
        api_key = 123456

    """

    def __init__(self, path: Union[Path, str], sandbox_name: str) -> None:
        """Instantiate a new Config object."""
        self.__path = Path(path)
        config = configparser.ConfigParser(allow_no_value=True)
        try:
            config.read_file(open(self.__path.expanduser()))
            if sandbox_name in config.sections():
                for key, value in config.items(sandbox_name):
                    if value.lower() in ('true', 'false', 'yes', 'no', 'on', 'off', '1', '0'):
                        value = str(config.getboolean(sandbox_name, key))
                    setattr(self, key, value)
        except FileNotFoundError as err:
            raise SandboxError(err)
        except (configparser.Error, KeyError, AttributeError):
            raise SandboxError('The config file cannot be read because it is not properly formatted.')


class SandboxAPI(object):
    """Sandbox API wrapper base class."""

    def __init__(self, *args, **kwargs):
        """Initialize the interface to Sandbox API.

        :type  proxies: dict
        :param proxies: Optional proxies dict passed to requests calls.
        """

        self.api_url = None

        # assume is *not* available.
        self.server_available = False

        # turn SSL verify on by default
        self.verify_ssl = True

        # allow passing in requests options directly.
        # be careful using this!
        self.proxies = kwargs.get('proxies')

    def _request(self, uri, method='GET', params=None, files=None, headers=None, auth=None):
        """Robustness wrapper. Tries up to 3 times to dance with the Sandbox API.

        :type  uri:     str
        :param uri:     URI to append to base_url.
        :type  params:  dict
        :param params:  Optional parameters for API.
        :type  files:   dict
        :param files:   Optional dictionary of files for multipart post.
        :type  headers: dict
        :param headers: Optional headers to send to the API.
        :type  auth:    dict
        :param auth:    Optional authentication object to send to the API.

        :rtype:  requests.response.
        :return: Response object.

        :raises SandboxError: If all attempts failed.
        """

        # make up to three attempts to dance with the API, use a jittered
        # exponential back-off delay
        for i in range(3):
            try:
                full_url = '{b}{u}'.format(b=self.api_url, u=uri)

                response = None
                if method == 'POST':
                    response = requests.post(full_url, data=params, files=files, headers=headers,
                                             verify=self.verify_ssl, auth=auth, proxies=self.proxies)
                else:
                    response = requests.get(full_url, params=params, headers=headers,
                                            verify=self.verify_ssl, auth=auth, proxies=self.proxies)

                # if the status code is 503, is no longer available.
                if response.status_code >= 500:
                    # server error
                    self.server_available = False
                    raise SandboxError("server returned {c} status code on {u}, assuming unavailable...".format(
                        c=response.status_code, u=response.url))
                else:
                    return response

            # 0.4, 1.6, 6.4, 25.6, ...
            except requests.exceptions.RequestException:
                time.sleep(random.uniform(0, 4 ** i * 100 / 1000.0))

        # if we couldn't reach the API, we assume that the box is down and lower availability flag.
        self.server_available = False

        # raise an exception.
        msg = "exceeded 3 attempts with sandbox API: {u}, p:{p}, f:{f}".format(u=full_url, p=params, f=files)
        try:
            msg += "\n" + response.content.decode('utf-8')
        except AttributeError:
            pass

        raise SandboxError(msg)

    def analyze(self, handle, filename):
        """Submit a file for analysis.

        :type  handle:   File handle
        :param handle:   Handle to file to upload for analysis.
        :type  filename: str
        :param filename: File name.

        :rtype:  str
        :return: Item ID as a string
        """
        raise NotImplementedError

    def check(self, item_id):
        """Check if an analysis is complete

        :type  item_id: int | str
        :param item_id: item_id to check.

        :rtype:  bool
        :return: Boolean indicating if a report is done or not.
        """
        raise NotImplementedError

    def is_available(self):
        """Determine if the Sandbox API servers are alive or in maintenance mode.

        :rtype:  bool
        :return: True if service is available, False otherwise.
        """
        raise NotImplementedError

    def report(self, item_id, report_format="json"):
        """Retrieves the specified report for the analyzed item, referenced by item_id.

        :type  item_id: int | str
        :param item_id: Item ID
        :param report_format: str

        :rtype:  dict
        :return: Dictionary representing the JSON parsed data or raw, for other
                 formats / JSON parsing failure.
        """
        raise NotImplementedError
