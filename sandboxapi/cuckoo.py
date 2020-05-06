"""This module hosts the Cuckoo Sandbox class."""

import json
from pathlib import Path
from typing import Any, List, Union

import requests
from requests.auth import HTTPBasicAuth

from sandboxapi.base import Sandbox, SandboxAPI, SandboxError


class CuckooSandbox(Sandbox):
    """Represents the Cuckoo Sandbox API.

    :param username: A valid user if using authentication.
    :param password: The user's password if using authentication.
    :param host: The IP address or hostname of the Cuckoo server.
    :param port: The port of the Cuckoo server.
    :param use_https: Use https if True, otherwise use http.
    """

    __slots__ = ['_request_opts']

    def __init__(
            self,
            username: str = '',
            password: str = '',
            host: str = 'localhost',
            port: int = 8090,
            use_https: bool = False,
            **kwargs,
    ) -> None:
        """Instantiate a new CuckooSandbox object."""
        super().__init__(alias=Path(__file__).stem, **kwargs)
        username = self._set_attribute(username, '', 'username')
        password = self._set_attribute(password, '', 'password')
        host = self._set_attribute(host, 'localhost', 'host')
        host = self._format_host(host)
        port = self._set_attribute(port, 8090, 'port')
        use_https = self._set_attribute(use_https, False, 'use_https')
        if use_https:
            scheme = 'https'
        else:
            scheme = 'http'
        self.base_url = '{}://{}:{}'.format(scheme, host, port)
        if username and password:
            self._request_opts['auth'] = HTTPBasicAuth(username, password)

    def enqueued(self) -> List[Any]:
        """Lists all tasks on the Cuckoo server."""
        response = requests.get(
            '{}/tasks/list'.format(self.base_url),
            **self._request_opts,
        )
        output = self.decode(response)
        return output['tasks']

    # def analyze(self, handle: IO[Any], filename: str) -> str:
    #     """A wrapper method for the new submit_sample() method. This method will be deprecated in a future version.
    #
    #     .. deprecated:: 2.0.0
    #
    #     :param handle: A file-like object.
    #     :param filename: The name of the file.
    #     :return: The item ID of the submitted sample.
    #     """
    #     warnings.warn('The analyze() method is deprecated in favor of submit_sample().', DeprecationWarning)
    #     handle.seek(0)
    #     response = requests.post(
    #         '{}/task/create/file'.format(self.base_url),
    #         files={'file': (filename, handle)},
    #         **self._request_opts,
    #     )
    #
    #     if response.status_code != requests.codes.ok:
    #         raise SandboxError('{}: {}'.format(response.content, response.status_code))
    #
    #     output = self.decode(response)
    #     return output['task_id']

    def submit_sample(self, filepath: Union[str, Path]) -> str:
        """Submit a new sample to the Cuckoo sandbox for analysis.

        :param filepath: The path to the sample to submit.
        :return: The ID of the created task.
        """
        with self._get_file(filepath) as file:
            response = requests.post(
                '{}/task/create/file'.format(self.base_url),
                files={'file': file},
                **self._request_opts,
            )

        if response.status_code != requests.codes.ok:
            raise SandboxError('{}: {}'.format(response.content, response.status_code))

        output = self.decode(response)
        return output['task_id']

    def check_item_status(self, item_id: Union[int, str]) -> bool:
        """Check to see if a particular sample analysis is complete.

        :param item_id: The task ID of the sample to check.
        :return: True if the sample analysis is ready, otherwise False.
        """
        response = requests.get(
            '{}/tasks/view/{}'.format(self.base_url, item_id),
            **self._request_opts,
        )

        if response.status_code == requests.codes.not_found:
            raise SandboxError('Task ID {} not found.'.format(item_id))
        elif response.status_code != requests.codes.ok:
            raise SandboxError('{}: {}'.format(response.content, response.status_code))

        output = self.decode(response)
        status = output['task']['status']
        if status and status in {'completed', 'reported'}:
            return True
        else:
            return False

    def delete_item(self, item_id: int) -> bool:
        """Remove a task from the list of tasks on the Cuckoo server.

        :param item_id: The task ID of the sample to remove.
        :return: True if the task was successfully removed.
        """
        response = requests.get(
            '{}/tasks/delete/{}'.format(self.base_url, item_id),
            **self._request_opts,
        )

        if response.status_code == requests.codes.not_found:
            raise SandboxError('Task ID {} not found.'.format(item_id))
        elif response.status_code == requests.codes.server_error:
            raise SandboxError('Could not delete task ID {}.'.format(item_id))
        elif response.status_code != requests.codes.ok:
            raise SandboxError('Server Error: {}'.format(response.status_code))

        return True

    @property
    def available(self) -> bool:
        """Checks to see if the Cuckoo sandbox is up and running.

        :return: True if the Cuckoo sandbox is responding, otherwise False.
        """
        response = requests.get(
            '{}/cuckoo/status'.format(self.base_url),
            **self._request_opts,
        )
        return True if response.status_code == requests.codes.ok else False

    @property
    def queue_size(self) -> int:
        """Checks to see how many tasks are currently pending on the Cuckoo server.

        :return: The number of pending tasks on the Cuckoo server.
        """
        tasks = self.enqueued()
        return len([t for t in tasks if t.get('status', '') in {'pending', 'running'}])

    def report(self, item_id: Union[int, str]) -> dict:
        """Pulls the threat report from Cuckoo for the submitted sample.

        :param item_id: The task ID for the submitted sample.
        :return: The threat report.
        """
        response = requests.get(
            '{}/tasks/report/{}/json'.format(self.base_url, item_id),
            **self._request_opts,
        )
        output = self.decode(response)

        if response.status_code == requests.codes.not_found:
            raise SandboxError('Task ID {} not found.'.format(item_id))
        elif response.status_code != requests.codes.ok:
            raise SandboxError('{}: {}'.format(response.content.decode("utf-8"), response.status_code))
        return output

    def score(self, report: dict) -> int:
        """Get the threat score for the submitted sample.

        :param report: The report returned from Cuckoo for the submitted sample.
        :return: The threat score.
        """
        score = report.get('malscore')
        if score is None:
            score = report['info']['score']
        return score


# class CuckooAPI(CuckooSandbox):
#     """Legacy Cuckoo Sandbox class used for backwards compatibility.
#
#     .. deprecated:: 2.0.0
#
#     :param url: Cuckoo API URL or host.
#     :param port: The Cuckoo API port.
#     :param api_path: The endpoint to reach the Cuckoo API.
#     """
#
#     def __init__(self, url: str, port: int = 8090, api_path: str = '/', verify_ssl: bool = False, **kwargs) -> None:
#         """Initialize the interface to Cuckoo Sandbox API with host and port."""
#         warnings.warn('The CuckooAPI class is deprecated in favor of CuckooSandbox.', DeprecationWarning)
#         if '://' in url:
#             _, host = url.split('//', maxsplit=1)
#         else:
#             host = url
#         if ':' in host:
#             host, port = host.split(':', maxsplit=1)
#         if '/' in host:
#             host, api_path = host.split('/', maxsplit=1)
#         super().__init__(host=host, port=int(port), verify_ssl=verify_ssl, **kwargs)
#         if api_path != '/':
#             if not api_path.startswith('/'):
#                 api_path = '/{}'.format(api_path)
#             self.base_url = 'http://{}:{}{}'.format(host, port, api_path)


class CuckooAPI(SandboxAPI):
    """Cuckoo Sandbox API wrapper."""

    def __init__(self, url, port=8090, api_path='/', verify_ssl=False, **kwargs):
        """Initialize the interface to Cuckoo Sandbox API with host and port.

        :type  url:      str
        :param url:      Cuckoo API URL. (Currently treated as host if not a fully formed URL -
                         this will be removed in a future version.)
        :type  port:     int
        :param port:     DEPRECATED! Use fully formed url instead. Will be removed in future version.
        :type  api_path: str
        :param api_path: DEPRECATED! Use fully formed url instead. Will be removed in future version.
        """
        SandboxAPI.__init__(self, **kwargs)

        if not url:
            url = ''

        # NOTE: host/port/api_path support is DEPRECATED!
        if url.startswith('http://') or url.startswith('https://'):
            # Assume new-style url param. Ignore port and api_path.
            self.api_url = url
        else:
            # This is for backwards compatability and will be removed in a future version.
            self.api_url = 'http://' + url + ':' + str(port) + api_path

        self.verify_ssl = verify_ssl

        # assume Cuckoo is *not* available.
        self.server_available = False

    def analyses(self):
        """Retrieve a list of analyzed samples.

        :rtype:  list
        :return: List of objects referencing each analyzed file.
        """
        response = self._request("tasks/list")

        return json.loads(response.content.decode('utf-8'))['tasks']

    def analyze(self, handle, filename):
        """Submit a file for analysis.

        :type  handle:   File handle
        :param handle:   Handle to file to upload for analysis.
        :type  filename: str
        :param filename: File name.

        :rtype:  str
        :return: Task ID as a string
        """
        # multipart post files.
        files = {"file": (filename, handle)}

        # ensure the handle is at offset 0.
        handle.seek(0)

        response = self._request("tasks/create/file", method='POST', files=files)

        # return task id; try v1.3 and v2.0 API response formats
        try:
            return str(json.loads(response.content.decode('utf-8'))["task_id"])
        except KeyError:
            return str(json.loads(response.content.decode('utf-8'))["task_ids"][0])

    def check(self, item_id):
        """Check if an analysis is complete

        :type  item_id: int
        :param item_id: task_id to check.

        :rtype:  bool
        :return: Boolean indicating if a report is done or not.
        """
        response = self._request("tasks/view/{id}".format(id=item_id))

        if response.status_code == 404:
            # probably an unknown task id
            return False

        try:
            content = json.loads(response.content.decode('utf-8'))
            status = content['task']["status"]
            if status == 'completed' or status == "reported":
                return True

        except ValueError as e:
            raise SandboxError(e)

        return False

    def delete(self, item_id):
        """Delete the reports associated with the given item_id.

        :type  item_id: int
        :param item_id: Report ID to delete.

        :rtype:  bool
        :return: True on success, False otherwise.
        """
        try:
            response = self._request("tasks/delete/{id}".format(id=item_id))

            if response.status_code == 200:
                return True

        except SandboxError:
            pass

        return False

    def is_available(self):
        """Determine if the Cuckoo Sandbox API servers are alive or in maintenance mode.

        :rtype:  bool
        :return: True if service is available, False otherwise.
        """
        # if the availability flag is raised, return True immediately.
        # NOTE: subsequent API failures will lower this flag. we do this here
        # to ensure we don't keep hitting Cuckoo with requests while
        # availability is there.
        if self.server_available:
            return True

        # otherwise, we have to check with the cloud.
        else:
            try:
                response = self._request("cuckoo/status")

                # we've got cuckoo.
                if response.status_code == 200:
                    self.server_available = True
                    return True

            except SandboxError:
                pass

        self.server_available = False
        return False

    def queue_size(self):
        """Determine Cuckoo sandbox queue length

        There isn't a built in way to do this like with Joe

        :rtype:  int
        :return: Number of submissions in sandbox queue.
        """
        response = self._request("tasks/list")
        tasks = json.loads(response.content.decode('utf-8'))["tasks"]

        return len([t for t in tasks if t['status'] == 'pending'])

    def report(self, item_id, report_format="json"):
        """Retrieves the specified report for the analyzed item, referenced by item_id.

        Available formats include: json, html, all, dropped, package_files.

        :type  item_id:       int
        :param item_id:       Task ID number
        :type  report_format: str
        :param report_format: Return format

        :rtype:  dict
        :return: Dictionary representing the JSON parsed data or raw, for other
                 formats / JSON parsing failure.
        """
        report_format = report_format.lower()

        response = self._request("tasks/report/{id}/{format}".format(id=item_id, format=report_format))

        # if response is JSON, return it as an object
        if report_format == "json":
            try:
                return json.loads(response.content.decode('utf-8'))
            except ValueError:
                pass

        # otherwise, return the raw content.
        return response.content

    def score(self, report):
        """Pass in the report from self.report(), get back an int."""
        score = 0

        try:
            # cuckoo-modified format
            score = report['malscore']
        except KeyError:
            # cuckoo-2.0 format
            score = report.get('info', {}).get('score', 0)
        except TypeError as e:
            raise SandboxError(e)

        return score
