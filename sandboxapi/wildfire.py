"""This module hosts the WildFire Sandbox class."""

import json
from pathlib import Path
from typing import Optional, Union

import requests

import xmltodict

from sandboxapi.base import Sandbox, SandboxAPI, SandboxError


# WildFire score values
BENIGN = 0
MALWARE = 1
GRAYWARE = 2
PHISHING = 4


class WildFireSandbox(Sandbox):
    """Sandbox subclass for the Palo Alto WildFire sandbox API.

    :param api_key: The customer API key.
    :param host: The IP address or hostname of the WildFire sandbox server.
    """

    __slots__ = ['api_key']

    def __init__(
            self,
            api_key: Optional[str] = None,
            host: Optional[str] = None,
            **kwargs,
    ) -> None:
        """Create a new WildFireSandbox object with default base url and score."""
        super().__init__(alias=Path(__file__).stem, **kwargs)
        host = self._set_attribute(host, 'wildfire.paloaltonetworks.com', 'host')
        host = self._format_host(host)
        self.api_key = self._set_attribute(api_key, '', 'api_key')
        self.base_url = 'https://{}/publicapi'.format(host)

    def submit_sample(self, filepath: Union[str, Path]) -> str:
        """Submit a new sample to the WildFire sandbox for analysis.

        :param filepath: The path to the sample to submit.
        :return: The sha256 hash of the uploaded sample.
        """
        with self._get_file(filepath) as file:
            response = requests.post(
                '{}/submit/file'.format(self.base_url),
                data={'apikey': self.api_key},
                files={'file': file},
                **self._request_opts,
            )
        if response.status_code == requests.codes.ok:
            output = self.decode(response)
            item_hash = output['wildfire']['upload-file-info']['sha256']
        else:
            raise SandboxError('{}: {}'.format(response.content.decode("utf-8"), response.status_code))
        return item_hash

    def _get_verdict(self, item_id: Union[int, str]) -> int:
        """Get the score or completion status from WildFire.

        :param item_id: The sha256 hash of the uploaded sample.
        :return: The status or score of the queued sample.
        """
        data = {
            'apikey': self.api_key,
            'hash': str(item_id),
        }
        response = requests.post(
            '{}/get/verdict'.format(self.base_url),
            data=data,
            **self._request_opts,
        )
        if response.status_code == requests.codes.unauthorized:
            raise SandboxError('No API key provided.')
        if not response.ok:
            raise SandboxError('{}: {}'.format(response.status_code, response.content))
        output = self.decode(response)
        status = output['wildfire']['get-verdict-info']['verdict']
        status = int(status)
        return status

    def check_item_status(self, item_id: Union[int, str]) -> bool:
        """Check to see if a particular sample analysis is complete.

        WildFire is different from the other sandbox APIs in that it combines the score and status checks.
        If the analysis is done, the score is grabbed and stored in the object's score attribute.

        :param item_id: The sha256 hash of the uploaded sample.
        :return: True if the score and report are ready, otherwise False.
        """
        status = self._get_verdict(item_id)
        if status in [BENIGN, MALWARE, GRAYWARE, PHISHING]:
            return True
        elif status == -100:
            return False
        elif status == -101:
            raise SandboxError('An error occurred while processing the sample.')
        elif status == -102:
            raise SandboxError('Unknown sample in the Wildfire database.')
        elif status == -103:
            raise SandboxError('Invalid hash value.')
        else:
            raise SandboxError('Unknown status.')

    @property
    def available(self) -> bool:
        """Checks to see if the WildFire sandbox is up and running.

        :return: True if the WildFire sandbox is responding, otherwise False.

        WildFire doesn't have an explicit endpoint for checking the sandbox status, so this is kind of a hack.
        """
        try:
            # Making a GET request to the API should always give a code 405 if the service is running.
            # Relying on this fact to get a reliable 405 if the service is up.
            response = requests.get(
                '{}/get/sample'.format(self.base_url),
                data={'apikey': self.api_key},
                **self._request_opts,
            )
            if response.status_code == requests.codes.not_allowed:
                return True
            else:
                return False
        except requests.exceptions.RequestException:
            return False

    def report(self, item_id: Union[int, str]) -> dict:
        """Pulls the threat report from WildFire for the submitted sample.

        :param item_id: The sha256 hash of the submitted sample.
        :return: The threat report.
        """
        data = {
            'apikey': self.api_key,
            'hash': str(item_id),
            'format': 'xml',
        }
        response = requests.post(
            '{}/get/report'.format(self.base_url),
            data=data,
            **self._request_opts,
        )
        return self.decode(response)

    def xml_report(self, item_id: Union[int, str]) -> bytes:
        """Pulls the threat report from WildFire for the submitted sample as a XML file.

        :param item_id: The sha256 hash of the submitted sample.
        :return: The threat report.
        """
        data = {
            'apikey': self.api_key,
            'hash': str(item_id),
            'format': 'xml',
        }
        response = requests.post(
            '{}/get/report'.format(self.base_url),
            data=data,
            **self._request_opts,
        )
        return response.content

    def pdf_report(self, item_id: Union[int, str]) -> bytes:
        """Pulls the threat report from WildFire for the submitted sample as a PDF file.

        :param item_id: The sha256 hash of the submitted sample.
        :return: The PDF version of the threat report.
        """
        data = {
            'apikey': self.api_key,
            'hash': str(item_id),
            'format': 'pdf',
        }
        response = requests.post(
            '{}/get/report'.format(self.base_url),
            data=data,
            **self._request_opts,
        )
        return response.content

    def score(self, report: dict) -> int:
        """Get the threat score for the submitted sample.

        :param report: Not used.
        :return: The assigned threat score.
        """
        item_id = report['wildfire']['file_info']['sha256']
        score = self._get_verdict(item_id)
        if score == MALWARE:
            return 8
        elif score == GRAYWARE:
            return 2
        elif score == PHISHING:
            return 5
        else:
            return score

    def decode(self, response: requests.Response) -> dict:
        """Parse the response XML from WildFire into a dictionary.

        :param response: The requests Response object from the WildFire API.
        :return: The parsed response content as a Python native data structure.
        """
        # This weird conversion to and from JSON is because the XML is being parsed as an Ordereddict.
        # TODO: See if there's a better way to do this without having to convert to JSON.
        output = json.loads(json.dumps(xmltodict.parse(response.content.decode('utf-8'))))
        if 'error' in output:
            raise SandboxError(output['error']['error-message'])
        return output


class WildFireAPI(SandboxAPI):
    """WildFire Sandbox API wrapper."""

    def __init__(self, api_key='', url='', verify_ssl=True, **kwargs):
        """Initialize the interface to the WildFire Sandbox API.

        :param str api_key: The customer API key.
        :param str url: The WildFire API URL.
        """
        super(WildFireAPI, self).__init__(**kwargs)
        self.base_url = url or 'https://wildfire.paloaltonetworks.com'
        self.api_url = self.base_url + '/publicapi'
        self._api_key = api_key
        self._score = BENIGN
        self.verify_ssl = verify_ssl

    def analyze(self, handle, filename):
        """Submit a file for analysis.

        :param BytesIO handle: File handle
        :param str filename: File name
        :rtype: str
        :return: File ID as a string
        """
        # multipart post files.
        files = {"file": (filename, handle)}

        # ensure the handle is at offset 0.
        handle.seek(0)

        data = {'apikey': self._api_key}

        response = self._request('/submit/file', method='POST', files=files, params=data)

        try:
            if response.status_code == 200:
                output = self.decode(response)
                return output['wildfire']['upload-file-info']['sha256']
            else:
                raise SandboxError("api error in analyze ({}): {}".format(response.url, response.content))
        except (ValueError, KeyError, IndexError) as e:
            raise SandboxError("error in analyze {}".format(e))

    @staticmethod
    def decode(response):
        """Convert a xml response to a python dictionary.

        :param requests.Response response: A Response object with xml content.
        :rtype: dict
        :return: The xml content converted to a dictionary.
        """
        # This weird conversion to and from JSON is because the XML is being parsed as an Ordereddict.
        # TODO: See if there's a better way to do this without having to convert to JSON.
        output = json.loads(json.dumps(xmltodict.parse(response.content.decode('utf-8'))))
        if 'error' in output:
            raise SandboxError(output['error']['error-message'])
        return output

    def check(self, item_id):
        """Check if an analysis is complete.

        :param str item_id: The hash of the file to check.
        :rtype: bool
        :return: True if the report is ready, otherwise False.
        """
        data = {
            'apikey': self._api_key,
            'hash': item_id,
        }
        response = self._request('/get/verdict', method='POST', params=data)

        if not response.ok:
            raise SandboxError("{}: {}".format(response.status_code, response.content))

        output = self.decode(response)
        try:
            status = int(output['wildfire']['get-verdict-info']['verdict'])
            if status >= 0:
                self._score = status
                return True
            elif status == -100:
                return False
            elif status == -101:
                raise SandboxError('An error occurred while processing the sample.')
            elif status == -102:
                raise SandboxError('Unknown sample in the Wildfire database.')
            elif status == -103:
                raise SandboxError('Invalid hash value.')
            else:
                raise SandboxError('Unknown status.')
        except (ValueError, IndexError) as e:
            raise SandboxError(e)

    def is_available(self):
        """Checks to see if the WildFire sandbox is up and running.

        :rtype: bool
        :return: True if the WildFire sandbox is responding, otherwise False.

        WildFire doesn't have an explicit endpoint for checking the sandbox status, so this is kind of a hack.
        """
        try:
            # Making a GET request to the API should always give a code 405 if the service is running.
            # Relying on this fact to get a reliable 405 if the service is up.
            response = self._request('/get/sample', params={'apikey': self._api_key})
            if response.status_code == 405:
                return True
            else:
                return False
        except SandboxError:
            return False

    def report(self, item_id, report_format='json'):
        """Retrieves the specified report for the analyzed item, referenced by item_id.

        :param str item_id: The hash of the file.
        :param str report_format: Return format.
        :rtype: dic
        :return: Dictionary representing the JSON parsed data.
        """
        data = {
            'apikey': self._api_key,
            'hash': item_id,
            'format': 'xml',
        }
        response = self._request('/get/report', method='POST', params=data)
        if not response.ok:
            raise SandboxError("{}: {}".format(response.status_code, response.content))
        return self.decode(response)

    def score(self):
        """Get the threat score for the submitted sample.

        :rtype: int
        :return: The assigned threat score.
        """
        if self._score == MALWARE:
            return 8
        elif self._score == GRAYWARE:
            return 2
        elif self._score == PHISHING:
            return 5
        else:
            return self._score
