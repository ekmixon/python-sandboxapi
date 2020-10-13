"""This module hosts the FireEye Sandbox class."""

import json
from pathlib import Path
from typing import Optional, Union

import requests
from requests.auth import HTTPBasicAuth

from sandboxapi.base import Sandbox, SandboxAPI, SandboxError


# Environments
WINXP = 'winxp-sp3'
WIN7 = 'win7-sp1'
WIN7X64 = 'win7x64-sp1'


class FireEyeSandbox(Sandbox):
    """Represents the FireEye Sandbox API.

    :param username: A valid user.
    :param password: The user's password.
    :param host: The IP address or hostname of the FireEye appliance.
    :param port: The port the web service api is running on.
    :param environment: The sandbox environment to use.
    :param legacy_api: Use the older api if True, otherwise False.
    """

    def __init__(
            self,
            username: Optional[str] = None,
            password: Optional[str] = None,
            host: Optional[str] = None,
            port: Optional[int] = None,
            environment: Optional[str] = None,
            legacy_api: Optional[bool] = None,
            **kwargs,
    ) -> None:
        """Instantiate a new FireEyeSandbox object."""
        super().__init__(alias=Path(__file__).stem, **kwargs)
        username = self._set_attribute(username, '', 'username')
        password = self._set_attribute(password, '', 'password')
        host = self._set_attribute(host, 'localhost', 'host')
        host = self._format_host(host)
        port = self._set_attribute(port, 443, 'port', int)
        environment = self._set_attribute(environment, WINXP, 'environment')
        self._legacy_api = self._set_attribute(legacy_api, False, 'legacy_api', bool)

        if self._legacy_api:
            base_url = 'https://{}:{}/wsapis/v1.1.0'.format(host, port)
        else:
            base_url = 'https://{}:{}/wsapis/v1.2.0'.format(host, port)

        self.base_url = base_url
        self._api_token = ''
        self._auth = HTTPBasicAuth(username, password)
        self._headers = {
            'Accept': 'application/json',
        }
        self.profile = environment

    def _authenticate(self) -> None:
        """Authenticates the user credentials and sets the returned api token."""
        if self.has_token:
            return
        response = requests.post(
            '{}/auth/login'.format(self.base_url),
            auth=self._auth,
            **self._request_opts,
        )

        if response.status_code == requests.codes.unauthorized:
            raise SandboxError('Authentication failed - HTTP {}'.format(response.status_code))
        elif response.status_code == requests.codes.unavailable:
            raise SandboxError('Sandbox unavailable - HTTP {}'.format(response.status_code))

        self._api_token = response.headers.get('X-FeApi-Token')
        self._headers['X-FeApi-Token'] = self._api_token

    def submit_sample(self, filepath: Union[str, Path]) -> int:
        """Submit a new sample to the FireEye sandbox for analysis.

        :param filepath: The path to the sample to submit.
        :return: The submission key for the submitted sample.
        """
        self._authenticate()
        fireeye_options = {
            'application': 0,
            'timeout': 500,
            'priority': 0,
            'profiles': self.profile,
            'analysistype': 0,
            'force': True,
            'prefetch': 1,
        }
        with self._get_file(filepath) as file:
            response = requests.post(
                '{}/submissions'.format(self.base_url),
                headers=self._headers,
                data={'options': json.dumps(fireeye_options)},
                files={'file': file},
                **self._request_opts,
            )

        if response.status_code == requests.codes.bad_request:
            raise SandboxError('{}'.format(response.content))
        elif response.status_code != requests.codes.ok:
            raise SandboxError('{}: {}'.format(response.status_code, response.content))

        output = self.decode(response)
        if isinstance(output, list):
            item_id = int(output[0].get('ID', 0))
        else:
            item_id = int(output.get('ID', 0))
        return item_id

    def check_item_status(self, item_id: Union[int, str]) -> bool:
        """Check to see if a particular sample analysis is complete.

        :param item_id: The submission key.
        :return: True if the report is ready, otherwise False.
        """
        self._authenticate()
        response = requests.post(
            '{}/submissions/status/{}'.format(self.base_url, item_id),
            headers=self._headers,
            **self._request_opts,
        )

        if response.status_code == requests.codes.unauthorized:
            raise SandboxError('Action is unauthorized.')
        elif response.status_code == requests.codes.not_found:
            raise SandboxError('Invalid submission key.')

        output = self.decode(response)
        status = output.get('submissionStatus')
        if status and status == 'Done':
            return True
        elif status and status == 'In Progress':
            return False
        else:
            raise SandboxError('Submission not found.')

    @property
    def legacy_api(self) -> bool:
        """Getter for the protected _legacy_api attribute."""
        return self._legacy_api

    @property
    def available(self) -> bool:
        """Checks to see if the FireEye sandbox is up and running.

        :return: True if the FireEye sandbox is responding, otherwise False.
        """
        self._authenticate()
        response = requests.get(
            '{}/config'.format(self.base_url),
            headers=self._headers,
            **self._request_opts,
        )
        if response.status_code == requests.codes.unauthorized:
            raise SandboxError('Action is unauthorized.')
        return True if response.status_code == requests.codes.ok else False

    def report(self, item_id: Union[int, str]) -> dict:
        """Pulls the threat report from FireEye for the submitted sample.

        :param item_id: The submission key.
        :return: The threat report.
        """
        self._authenticate()
        info_level = {'info_level': 'extended'}
        response = requests.post(
            '{}/submissions/results/{}'.format(self.base_url, item_id),
            headers=self._headers,
            data=info_level,
            **self._request_opts,
        )

        if response.status_code == requests.codes.unauthorized:
            raise SandboxError('Action is unauthorized.')
        elif response.status_code == requests.codes.not_found:
            raise SandboxError('Invalid submission key.')

        return self.decode(response)

    def xml_report(self, item_id: Union[int, str]) -> bytes:
        """Pulls the threat report from FireEye for the submitted sample as an XML file.

        :param item_id: The submission key.
        :return: The XML threat report.
        """
        self._authenticate()
        headers = {
            'Accept': 'application/xml',
            'X-FeApi-Token': self._api_token,
        }
        info_level = {'info_level': 'extended'}
        response = requests.post(
            '{}/submissions/results/{}'.format(self.base_url, item_id),
            headers=headers,
            data=info_level,
            **self._request_opts,
        )

        if response.status_code == requests.codes.unauthorized:
            raise SandboxError('Action is unauthorized.')
        elif response.status_code == requests.codes.not_found:
            raise SandboxError('Invalid submission key.')

        return response.content

    def score(self, report: dict) -> int:
        """Get the threat score for the submitted sample.

        :param report: The report returned from FireEye for the submitted sample.
        :return: The threat score.
        """
        self._authenticate()
        score = 0
        alert = report['alert']
        if isinstance(alert, list):
            severity = alert[0].get('severity', '')
            if severity == 'MAJR':
                score = 8
            elif severity == 'MINR':
                score = 2
        return score

    def logout(self) -> None:
        """Disables the API token."""
        self._authenticate()
        response = requests.post(
            '{}/auth/logout'.format(self.base_url),
            headers=self._headers,
            **self._request_opts,
        )
        if response.status_code != requests.codes.no_content:
            raise SandboxError('{}: {}'.format(response.content.decode("utf-8"), response.status_code))
        self._api_token = ''

    @property
    def has_token(self) -> bool:
        """Check to see if the FireEyeSandbox object has an api token or not."""
        return True if self._api_token else False


class FireEyeAPI(SandboxAPI):
    """FireEye Sandbox API wrapper."""

    def __init__(self, username, password, url, profile, legacy_api=False, verify_ssl=True, **kwargs):
        """Initialize the interface to FireEye Sandbox API."""
        SandboxAPI.__init__(self, **kwargs)

        self.base_url = url
        self.username = username
        self.password = password
        self.profile = profile or 'winxp-sp3'
        self.api_token = None
        self.verify_ssl = verify_ssl

        if legacy_api:
            # Use v1.1.0 endpoints for v7.x appliances.
            self.api_url = url + '/wsapis/v1.1.0'
        else:
            self.api_url = url + '/wsapis/v1.2.0'

    def _request(self, uri, method='GET', params=None, files=None, headers=None, auth=None):
        """Override the parent _request method.

        We have to do this here because FireEye requires some extra
        authentication steps. On each request we pass the auth headers, and
        if the session has expired, we automatically reauthenticate.
        """
        if headers:
            headers['Accept'] = 'application/json'
        else:
            headers = {
                'Accept': 'application/json',
            }

        if not self.api_token:
            # need to log in
            response = SandboxAPI._request(
                self, '/auth/login', 'POST', headers=headers, auth=HTTPBasicAuth(self.username, self.password)
            )
            if response.status_code != 200:
                raise SandboxError("Can't log in, HTTP Error {e}".format(e=response.status_code))
            # we are now logged in, save the token
            self.api_token = response.headers.get('X-FeApi-Token')

        headers['X-FeApi-Token'] = self.api_token

        response = SandboxAPI._request(self, uri, method, params, files, headers)

        # handle session timeout
        unauthorized = False
        try:
            if json.loads(response.content.decode('utf-8'))['fireeyeapis']['httpStatus'] == 401:
                unauthorized = True
        except (ValueError, KeyError, TypeError):
            # non-JSON response, or no such keys.
            pass

        if response.status_code == 401 or unauthorized:
            self.api_token = None
            try:
                headers.pop('X-FeApi-Token')
            except KeyError:
                pass

            # recurse
            return self._request(uri, method, params, files, headers)

        return response

    def analyze(self, handle, filename):
        """Submit a file for analysis.

        :type  handle:   File handle
        :param handle:   Handle to file to upload for analysis.
        :type  filename: str
        :param filename: File name.

        :rtype:  str
        :return: File ID as a string
        """
        # multipart post files.
        files = {"file": (filename, handle)}

        # ensure the handle is at offset 0.
        handle.seek(0)

        # add submission options
        data = {
            # FIXME: These may need to change, see docs page 36
            'options': '{"application":"0","timeout":"500","priority":"0","profiles":["%s"],'
                       '"analysistype":"0","force":"true","prefetch":"1"}' % self.profile,
        }

        response = self._request("/submissions", method='POST', params=data, files=files)

        try:
            if response.status_code == 200:
                # good response
                try:
                    return response.json()['ID']
                except TypeError:
                    return response.json()[0]['ID']
            else:
                raise SandboxError("api error in analyze ({u}): {r}".format(u=response.url, r=response.content))
        except (ValueError, KeyError) as e:
            raise SandboxError("error in analyze: {e}".format(e=e))

    def check(self, item_id):
        """Check if an analysis is complete.

        :type  item_id: str
        :param item_id: File ID to check.

        :rtype:  bool
        :return: Boolean indicating if a report is done or not.
        """
        response = self._request("/submissions/status/{file_id}".format(file_id=item_id))

        if response.status_code == 404:
            # unknown id
            return False

        try:
            status = response.json()['submissionStatus']
            if status == 'Done':
                return True

        except ValueError as e:
            raise SandboxError(e)

        return False

    def is_available(self):
        """Determine if the FireEye API server is alive.

        :rtype:  bool
        :return: True if service is available, False otherwise.
        """
        # if the availability flag is raised, return True immediately.
        # NOTE: subsequent API failures will lower this flag. we do this here
        # to ensure we don't keep hitting FireEye with requests while
        # availability is there.
        if self.server_available:
            return True

        # otherwise, we have to check with the cloud.
        else:
            try:
                response = self._request("/config")

                # we've got fireeye.
                if response.status_code == 200:
                    self.server_available = True
                    return True

            except SandboxError:
                pass

        self.server_available = False
        return False

    def report(self, item_id, report_format="json"):
        """Retrieves the specified report for the analyzed item, referenced by item_id.

        Available formats include: json.

        :type  item_id:       str
        :param item_id:       File ID number
        :type  report_format: str
        :param report_format: Return format

        :rtype:  dict
        :return: Dictionary representing the JSON parsed data or raw, for other
                 formats / JSON parsing failure.
        """
        if report_format == "html":
            return "Report Unavailable"

        # else we try JSON
        response = self._request("/submissions/results/{file_id}?info_level=extended".format(file_id=item_id))

        # if response is JSON, return it as an object
        try:
            return response.json()
        except ValueError:
            pass

        # otherwise, return the raw content.
        return response.content

    @staticmethod
    def score(report):
        """Pass in the report from self.report(), get back an int."""
        score = 0
        if report['alert'][0]['severity'] == 'MAJR':
            score = 8

        return score

    def logout(self):
        """The FireEye AX has a limit of 100 concurrent sessions, so be sure to logout"""
        if self.api_token:
            self._request("/auth/logout")
