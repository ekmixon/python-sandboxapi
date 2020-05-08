"""This module hosts the Falcon Sandbox class."""

import json
from json import JSONDecodeError
from pathlib import Path
from typing import Optional, Union

import requests

from sandboxapi.base import Sandbox, SandboxAPI, SandboxError


# Environments
WIN7 = 100
WIN7HWP = 110
WIN7X64 = 120
ANDROID = 200
XENIAL = 300


class FalconSandbox(Sandbox):
    """Represents the Falcon Sandbox API.

    :param api_key: The customer API key.
    :param host: The IP address or hostname of the Falcon sandbox server.
    :param environment: The sandbox runtime environment to use.
    """

    __slots__ = ['_api_key', 'environment', '_headers']

    def __init__(
            self,
            api_key: Optional[str] = None,
            host: Optional[str] = None,
            environment: Optional[int] = None,
            **kwargs,
    ) -> None:
        """Instantiate a new FalconSandbox object."""
        super().__init__(alias=Path(__file__).stem, **kwargs)
        host = self._set_attribute(host, 'www.reverse.it', 'host')
        host = self._format_host(host)
        self.environment = self._set_attribute(environment, WIN7X64, 'environment', int)
        self._api_key = self._set_attribute(api_key, '', 'api_key')
        self.base_url = 'https://{}/api/v2'.format(host)
        self._headers = {
            'api-key': self.api_key,
            'User-Agent': 'Falcon Sandbox',
            'Accept': 'application/json',
        }

    def submit_sample(self, filepath: Union[str, Path]) -> str:
        """Submit a new sample to the Falcon sandbox for analysis.

        :param filepath: The path to the sample to submit.
        :return: The job ID for the submitted sample.
        """
        with self._get_file(filepath) as file:
            response = requests.post(
                '{}/submit/file'.format(self.base_url),
                data={'environment_id': str(self.environment)},
                headers=self._headers,
                files={'file': file},
                **self._request_opts,
            )

        try:
            output = self.decode(response)
            if response.status_code == requests.codes.created:
                return output['job_id']
            else:
                raise SandboxError('Error: {}'.format(output["message"]))
        except JSONDecodeError:
            raise SandboxError('{}: {}'.format(response.content, response.status_code))

    def check_item_status(self, item_id: Union[int, str]) -> bool:
        """Check to see if a particular sample analysis is complete.

        :param item_id: The job ID.
        :return: True if the report is ready, otherwise False.
        """
        response = requests.get(
            '{}/report/{}/state'.format(self.base_url, item_id),
            headers=self._headers,
            params={'environment_id': str(self.environment)},
            **self._request_opts,
        )

        if response.status_code == requests.codes.not_found:
            raise SandboxError('Unknown job ID.')
        elif response.status_code == requests.codes.too_many_requests:
            raise SandboxError('API request limit exceeded.')

        output = self.decode(response)
        if response.status_code != requests.codes.ok:
            raise SandboxError('Error: {}'.format(output["message"]))
        status = output['state']
        if status and status in {'SUCCESS', 'ERROR'}:
            return True
        else:
            return False

    @property
    def api_key(self) -> str:
        """Getter for the api_key.

        :return: The object's API key.
        """
        return self._api_key

    @property
    def queue_size(self) -> int:
        """Checks to see how many tasks are currently pending on the Falcon server.

        :return: The number of pending jobs on the Falcon server.
        """
        response = requests.get(
            '{}/system/queue-size'.format(self.base_url),
            headers=self._headers,
            params={'environment_id': str(self.environment)},
            **self._request_opts,
        )

        output = self.decode(response)
        if response.status_code == requests.codes.ok:
            return int(output['value'])
        else:
            raise SandboxError('Error: {}'.format(output["message"]))

    @property
    def available(self) -> bool:
        """Checks to see if the Falcon sandbox is up and running.

        :return: True if the Falcon sandbox is responding, otherwise False.
        """
        response = requests.get(
            '{}/system/heartbeat'.format(self.base_url),
            **self._request_opts,
        )
        if response.status_code == requests.codes.forbidden:
            response = requests.get(
                '{}/system/version'.format(self.base_url),
                **self._request_opts,
            )
            if response.status_code == requests.codes.ok:
                return True
            else:
                return False
        elif response.status_code == requests.codes.ok:
            return True
        else:
            return False

    def report(self, item_id: Union[int, str]) -> dict:
        """Pulls the threat report from Falcon for the submitted sample.

        :param item_id: The job ID for the submitted sample.
        :return: The threat report.
        """
        response = requests.get(
            '{}/report/{}/summary'.format(self.base_url, item_id),
            headers=self._headers,
            params={'environment_id': str(self.environment)},
            **self._request_opts,
        )
        if response.status_code != requests.codes.ok:
            raise SandboxError('{}: {}'.format(response.content, response.status_code))
        return self.decode(response)

    def pdf_report(self, item_id: Union[int, str]) -> bytes:
        """Pulls the threat report from Falcon for the submitted sample as a PDF file.

        :param item_id: The job ID for the submitted sample.
        :return: The PDF version of the threat report.
        """
        headers = self._headers
        headers['Accept'] = 'application/pdf'
        response = requests.get(
            '{}/report/{}/report/pdf'.format(self.base_url, item_id),
            headers=headers,
            params={'environment_id': str(self.environment)},
            **self._request_opts,
        )
        if response.status_code != requests.codes.ok:
            raise SandboxError('{}: {}'.format(response.content, response.status_code))
        return response.content

    def score(self, report: dict) -> int:
        """Get the threat score for the submitted sample.

        :param report: The report returned from Falcon for the submitted sample.
        :return: The threat score.
        """
        threat_level = int(report['threat_level'])
        threat_score = int(report['threat_score'])

        if threat_level == 2 and threat_score >= 90:
            score = 10
        elif threat_level == 2 and threat_score >= 75:
            score = 9
        elif threat_level == 2:
            score = 8
        elif threat_level == 1 and threat_score >= 90:
            score = 7
        elif threat_level == 1 and threat_score >= 75:
            score = 6
        elif threat_level == 1:
            score = 5
        elif threat_level == 0 and threat_score >= 90:
            score = 4
        elif threat_level == 0 and threat_score >= 75:
            score = 3
        elif threat_level == 0 and threat_score < 75:
            score = 1
        else:
            score = 0

        return score


class FalconAPI(SandboxAPI):
    """Falcon Sandbox API wrapper."""

    def __init__(self, key, url=None, env=100,  **kwargs):
        """Initialize the interface to Falcon Sandbox API with key and secret."""
        SandboxAPI.__init__(self, **kwargs)

        self.api_url = url or 'https://www.reverse.it/api/v2'
        self.key = key
        self.env_id = str(env)

    def _request(self, uri, method='GET', params=None, files=None, headers=None, auth=None):
        """Override the parent _request method.

        We have to do this here because FireEye requires some extra
        authentication steps.
        """
        if params:
            params['environment_id'] = self.env_id
        else:
            params = {
                'environment_id': self.env_id,
            }

        if headers:
            headers['api-key'] = self.key
            headers['User-Agent'] = 'Falcon Sandbox'
            headers['Accept'] = 'application/json'
        else:
            headers = {
                'api-key': self.key,
                'User-Agent': 'Falcon Sandbox',
                'Accept': 'application/json',
            }

        return SandboxAPI._request(self, uri, method, params, files, headers)

    def analyze(self, handle, filename):
        """Submit a file for analysis.

        :type  handle:   File handle
        :param handle:   Handle to file to upload for analysis.
        :type  filename: str
        :param filename: File name.

        :rtype:  str
        :return: File hash as a string
        """
        # multipart post files.
        files = {"file": (filename, handle)}

        # ensure the handle is at offset 0.
        handle.seek(0)

        response = self._request("/submit/file", method='POST', files=files)

        try:
            if response.status_code == 201:
                # good response
                return response.json()['job_id']
            else:
                raise SandboxError("api error in analyze: {r}".format(r=response.content.decode('utf-8')))
        except (ValueError, KeyError) as e:
            raise SandboxError("error in analyze: {e}".format(e=e))

    def check(self, item_id):
        """Check if an analysis is complete.

        :type  item_id: str
        :param item_id: Job ID to check.

        :rtype:  bool
        :return: Boolean indicating if a report is done or not.
        """

        response = self._request("/report/{job_id}/state".format(job_id=item_id))

        if response.status_code in (404, 429):
            # unknown job id, api request limit exceeded
            return False

        try:
            content = json.loads(response.content.decode('utf-8'))
            status = content['state']
            if status == 'SUCCESS' or status == 'ERROR':
                return True

        except (ValueError, KeyError) as e:
            raise SandboxError(e)

        return False

    def is_available(self):
        """Determine if the Falcon API server is alive.

        :rtype:  bool
        :return: True if service is available, False otherwise.
        """
        # if the availability flag is raised, return True immediately.
        # NOTE: subsequent API failures will lower this flag. we do this here
        # to ensure we don't keep hitting Falcon with requests while
        # availability is there.
        if self.server_available:
            return True

        # otherwise, we have to check with the cloud.
        else:

            try:
                # Try the on-prem endpoint.
                response = self._request("/system/heartbeat")

                # we've got falcon.
                if response.status_code == 200:
                    self.server_available = True
                    return True
                elif response.status_code == 403:
                    # Try the public sandbox endpoint.
                    response = self._request("/system/version")
                    if response.status_code == 200:
                        self.server_available = True
                        return True

            except SandboxError:
                pass

        self.server_available = False
        return False

    def queue_size(self):
        """Determine Falcon sandbox queue length

        :rtype:  str
        :return: Details on the queue size.
        """
        response = self._request("/system/queue-size")

        return response.content.decode('utf-8')

    def report(self, item_id, report_format="json"):
        """Retrieves the specified report for the analyzed item, referenced by item_id.

        Available formats include: json, html.

        :type  item_id:     str
        :param item_id:     File ID number
        :type  report_format: str
        :param report_format: Return format

        :rtype:  dict
        :return: Dictionary representing the JSON parsed data or raw, for other
                 formats / JSON parsing failure.
        """
        report_format = report_format.lower()

        response = self._request("/report/{job_id}/summary".format(job_id=item_id))

        if response.status_code == 429:
            raise SandboxError('API rate limit exceeded while fetching report')

        # if response is JSON, return it as an object
        if report_format == "json":
            try:
                return json.loads(response.content.decode('utf-8'))
            except ValueError:
                pass

        # otherwise, return the raw content.
        return response.content.decode('utf-8')

    def full_report(self, item_id, report_format="json"):
        """Retrieves a more detailed report"""
        report_format = report_format.lower()

        response = self._request("/report/{job_id}/file/{report_format}".format(
            job_id=item_id,
            report_format=report_format,
        ))

        if response.status_code == 429:
            raise SandboxError('API rate limit exceeded while fetching report')

        # if response is JSON, return it as an object
        if report_format == "json":
            try:
                return json.loads(response.content.decode('utf-8'))
            except ValueError:
                pass

        # otherwise, return the raw content.
        return response.content.decode('utf-8')

    @staticmethod
    def score(report):
        """Pass in the report from self.report(), get back an int 0-10."""

        try:
            threatlevel = int(report['threat_level'])
            threatscore = int(report['threat_score'])
        except (KeyError, IndexError, ValueError, TypeError) as e:
            raise SandboxError(e)

        # from falcon docs:
        # threatlevel is the verdict field with values: 0 = no threat, 1 = suspicious, 2 = malicious
        # threascore  is the "heuristic" confidence value of Falcon Sandbox in the verdict and is a value between 0
        # and 100. A value above 75/100 is "pretty sure", a value above 90/100 is "very sure".

        # the scoring below converts these values to a scalar. modify as needed.
        score = 0
        if threatlevel == 2 and threatscore >= 90:
            score = 10
        elif threatlevel == 2 and threatscore >= 75:
            score = 9
        elif threatlevel == 2:
            score = 8
        elif threatlevel == 1 and threatscore >= 90:
            score = 7
        elif threatlevel == 1 and threatscore >= 75:
            score = 6
        elif threatlevel == 1:
            score = 5
        elif threatlevel == 0 and threatscore < 75:
            score = 1

        return score
