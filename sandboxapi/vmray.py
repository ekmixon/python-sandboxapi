"""This module hosts the VMRay Sandbox class."""

from pathlib import Path
from typing import Union

import requests

from sandboxapi.base import Sandbox, SandboxAPI, SandboxError


class VMRaySandbox(Sandbox):
    """Represents the VMRay Sandbox API.

    :param api_key: The customer API key.
    :param host: The IP address or hostname of the VMRay sandbox server.
    """

    __slots__ = ['api_key', '_headers']

    def __init__(
            self,
            api_key: str = '',
            host: str = 'cloud.vmray.com',
            **kwargs,
    ) -> None:
        """Instantiate a new VMRaySandbox object."""
        super().__init__(alias=Path(__file__).stem, **kwargs)
        host = self._set_attribute(host, 'cloud.vmray.com', 'host')
        host = self._format_host(host)
        self.api_key = self._set_attribute(api_key, '', 'api_key')
        self.base_url = 'https://{}/rest'.format(host)
        self._headers = {
            'Authorization': 'api_key {}'.format(self.api_key)
        }

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
    #         '{}/sample/submit'.format(self.base_url),
    #         headers=self._headers,
    #         files={'sample_file': (filename, handle)},
    #         **self._request_opts,
    #     )
    #     if response.status_code != requests.codes.ok:
    #         raise SandboxError('{}'.format(self.decode(response)["error_msg"]))
    #
    #     output = self.decode(response)
    #     return output['data']['samples'][0]['sample_id']

    def submit_sample(self, filepath: Union[str, Path]) -> str:
        """Submit a new sample to the VMRay sandbox for analysis.

        :param filepath: The path to the sample to submit.
        :return: The sample ID for the submitted sample.
        """
        with self._get_file(filepath) as file:
            response = requests.post(
                '{}/sample/submit'.format(self.base_url),
                headers=self._headers,
                files={'sample_file': file},
                **self._request_opts,
            )

        if response.status_code != requests.codes.ok:
            raise SandboxError('{}'.format(self.decode(response)["error_msg"]))

        output = self.decode(response)
        return output['data']['samples'][0]['sample_id']

    def check_item_status(self, item_id: Union[int, str]) -> bool:
        """Check to see if a particular sample analysis is complete.

        :param item_id: The sample ID.
        :return: True if the report is ready, otherwise False.
        """
        response = requests.get(
            '{}/submission/sample/{}'.format(self.base_url, item_id),
            headers=self._headers,
            **self._request_opts,
        )

        if response.status_code != requests.codes.ok:
            raise SandboxError('{}'.format(self.decode(response)["error_msg"]))

        output = self.decode(response)
        return output['data'][0]['submission_finished']

    @property
    def available(self) -> bool:
        """Designates if a sandbox is up and available.

        :return: True if the sandbox is available, else False.
        """
        response = requests.get(
            '{}/system_info'.format(self.base_url),
            headers=self._headers,
            **self._request_opts,
        )

        return True if response.status_code == requests.codes.ok else False

    def report(self, item_id: Union[int, str]) -> dict:
        """Pulls the threat report from VMRay for the submitted sample.

        :param item_id: The sample ID of the analyzed sample.
        :return: The report of the analyzed sample.

        The VMRay report has several different analyses -- one for each environment.
        They all might or might not have the same score.
        """
        # the highest score is probably the most interesting.
        # vmray uses this internally with sample_highest_vti_score so this seems like a safe assumption.
        response = requests.get(
            '{}/analysis/sample/{}'.format(self.base_url, item_id),
            headers=self._headers,
            **self._request_opts,
        )

        if response.status_code != requests.codes.ok:
            raise SandboxError('{}'.format(self.decode(response)["error_msg"]))

        return self.decode(response)

    def detailed_report(self, analysis_id: Union[int, str]) -> dict:
        """Pulls the detailed analysis report from VMRay for a particular analysis.

        :param analysis_id: The ID for a particular analysis.
        :return: The report of the analysis.

        .. note:: The analysis ID is NOT the same as the item ID.
        """
        response = requests.get(
            '{}/analysis/{}/archive/logs/summary.json'.format(self.base_url, analysis_id),
            headers=self._headers,
            **self._request_opts,
        )

        if response.status_code != requests.codes.ok:
            raise SandboxError('{}'.format(self.decode(response)["error_msg"]))

        return self.decode(response)

    @staticmethod
    def top_ranked_analysis(report: dict) -> int:
        """Loops over each analysis in the report and finds the one with the highest vti score.

        :param report: The report returned from VMRay for the submitted sample.
        :return: The analysis ID of the highest ranked analysis.

        This method is used to obtain an analysis ID for the detailed_report() method.

        .. note:: In the event of a tie, the first analysis is given.
        """
        top_score = -1
        analysis_id = -1
        for analysis in report.get('data', {}):
            if analysis.get('analysis_vti_score', -1) > top_score:
                top_score = analysis['analysis_vti_score']
                analysis_id = analysis['analysis_id']
        if analysis_id < 0:
            raise IndexError('No analysis found in report.')
        return analysis_id

    def score(self, report: dict) -> int:
        """Get the threat score for the submitted sample.

        :param report: The report returned from VMRay for the submitted sample.
        :return: The threat score.
        """
        top_score = -1
        if 'data' in report.keys():
            # This is a regular report.
            for analysis in report['data']:
                if analysis['analysis_vti_score'] > top_score:
                    top_score = int(analysis['analysis_vti_score'])
        elif 'vti' in report.keys():
            # This is a detailed report.
            top_score = int(report['vti']['vti_score'])
        return top_score // 10


# class VMRayAPI(VMRaySandbox):
#     """Legacy VMRay Sandbox class used for backwards compatibility.
#
#     .. deprecated:: 2.0.0
#
#     :param api_key: The API key to access the VMRay sandbox.
#     :param url: The VMRay API URL.
#     :param verify_ssl: Verify SSL Certificates if True, otherwise ignore self-signed certificates.
#     """
#
#     def __init__(self, api_key: str, url: Optional[str] = None, verify_ssl: bool = True, **kwargs) -> None:
#         """Initialize the interface to VMRay Sandbox API."""
#         warnings.warn('The VMRayAPI class is deprecated in favor of VMRaySandbox.', DeprecationWarning)
#         api = ''
#         url = url or 'https://cloud.vmray.com'
#         if '://' in url:
#             _, host = url.split('//', maxsplit=1)
#         else:
#             host = url
#         if '/' in host:
#             host, api = host.split('/', maxsplit=1)
#         super().__init__(api_key=api_key, host=host, verify_ssl=verify_ssl, **kwargs)
#         if api:
#             self.base_url = 'https://{}/{}'.format(host, api)


class VMRayAPI(SandboxAPI):
    """VMRay Sandbox API wrapper."""

    def __init__(self, api_key, url=None, verify_ssl=True, **kwargs):
        """Initialize the interface to VMRay Sandbox API."""
        SandboxAPI.__init__(self, **kwargs)

        self.base_url = url or 'https://cloud.vmray.com'
        self.api_url = self.base_url + '/rest'
        self.api_key = api_key
        self.verify_ssl = verify_ssl

        # define once and use later
        self.headers = {'Authorization': 'api_key {a}'.format(a=api_key)}

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
        files = {"sample_file": (filename, handle)}

        # ensure the handle is at offset 0.
        handle.seek(0)

        response = self._request("/sample/submit", method='POST', files=files, headers=self.headers)

        try:
            if response.status_code == 200 and not response.json()['data']['errors']:
                # only support single-file submissions; just grab the first one.
                return response.json()['data']['samples'][0]['sample_id']
            else:
                raise SandboxError("api error in analyze ({u}): {r}".format(u=response.url, r=response.content))
        except (ValueError, KeyError, IndexError) as e:
            raise SandboxError("error in analyze: {e}".format(e=e))

    def check(self, item_id):
        """Check if an analysis is complete.

        :type  item_id: str
        :param item_id: File ID to check.

        :rtype:  bool
        :return: Boolean indicating if a report is done or not.
        """
        response = self._request("/submission/sample/{sample_id}".format(sample_id=item_id), headers=self.headers)

        if response.status_code == 404:
            # unknown id
            return False

        try:
            finished = False
            for submission in response.json()['data']:
                finished = finished or submission['submission_finished']
            if finished:
                return True

        except (ValueError, KeyError) as e:
            raise SandboxError(e)

        return False

    def is_available(self):
        """Determine if the VMRay API server is alive.

        :rtype:  bool
        :return: True if service is available, False otherwise.
        """
        # if the availability flag is raised, return True immediately.
        # NOTE: subsequent API failures will lower this flag. we do this here
        # to ensure we don't keep hitting VMRay with requests while
        # availability is there.
        if self.server_available:
            return True

        # otherwise, we have to check with the cloud.
        else:
            try:
                response = self._request("/system_info", headers=self.headers)

                # we've got vmray.
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

        # grab an analysis id from the submission id.
        response = self._request("/analysis/sample/{sample_id}".format(sample_id=item_id),
                                 headers=self.headers)

        try:
            # the highest score is probably the most interesting.
            # vmray uses this internally with sample_highest_vti_score so this seems like a safe assumption.
            analysis_id = 0
            top_score = -1
            for analysis in response.json()['data']:
                if analysis['analysis_vti_score'] > top_score:
                    top_score = analysis['analysis_vti_score']
                    analysis_id = analysis['analysis_id']

        except (ValueError, KeyError) as e:
            raise SandboxError(e)

        # assume report format json.
        response = self._request("/analysis/{analysis_id}/archive/logs/summary.json".format(analysis_id=analysis_id),
                   headers=self.headers)

        # if response is JSON, return it as an object.
        try:
            return response.json()
        except ValueError:
            pass

        # otherwise, return the raw content.
        return response.content

    def score(self, report):
        """Pass in the report from self.report(), get back an int 0-100"""
        try:
            return report['vti']['vti_score']
        except KeyError:
            return 0
