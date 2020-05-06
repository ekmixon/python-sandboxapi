"""This module hosts the Joe Sandbox class."""

import json
from pathlib import Path
from typing import Union

import jbxapi
from jbxapi import ApiError, ConnectionError

from sandboxapi.base import Sandbox, SandboxAPI, SandboxError


class JoeSandbox(Sandbox):
    """Represents the Joe Sandbox API.

    :param api_key: The customer API key.
    :param host: The IP address or hostname of the Joe sandbox server.
    :param verify_ssl: Enable or disable checking SSL certificates.
    """

    __slots__ = ['jbx']

    accept_tac = True

    def __init__(
            self,
            api_key: str = '',
            host: str = 'jbxcloud.joesecurity.org',
            **kwargs,
    ) -> None:
        """Instantiate a new JoeSandbox object."""
        super().__init__(alias=Path(__file__).stem, **kwargs)
        api_key = self._set_attribute(api_key, '', 'api_key')
        host = self._set_attribute(host, 'jbxcloud.joesecurity.org', 'host')
        host = self._format_host(host)
        self.base_url = 'https://{}/api'.format(host) or jbxapi.API_URL
        self.jbx = jbxapi.JoeSandbox(
            apikey=api_key,
            apiurl=self.base_url,
            accept_tac=self.accept_tac,
            timeout=self.timeout_secs,
            verify_ssl=self.verify_ssl,
            user_agent='Inquest SandboxAPI',
        )

    # def analyze(self, handle: IO[Any], filename: str) -> str:
    #     """A wrapper method for the new submit_sample() method. This method will be deprecated in a future version.
    #
    #     .. deprecated:: 2.0.0
    #
    #     :param handle: A file-like object.
    #     :param filename: The name of the file.
    #     :return: The item ID of the submitted sample.
    #     """
    #     del filename
    #     warnings.warn('The analyze() method is deprecated in favor of submit_sample().', DeprecationWarning)
    #     handle.seek(0)
    #     try:
    #         response = self.jbx.submit_sample(handle)
    #     except (ApiError, ConnectionError) as err:
    #         raise SandboxError(err)
    #     return response['submission_id']

    def submit_sample(self, filepath: Union[str, Path]) -> str:
        """Submit a new sample to the Joe sandbox for analysis.

        :param filepath: The path to the sample to submit.
        :return: The submission id for the submitted sample.
        """
        try:
            with self._get_file(filepath) as file:
                response = self.jbx.submit_sample(file)
        except (ApiError, ConnectionError) as err:
            raise SandboxError(err)
        return response['submission_id']

    def check_item_status(self, item_id: Union[int, str]) -> bool:
        """Check to see if a particular sample analysis is complete.

        :param item_id: The submission id.
        :return: True if the report is ready, otherwise False.
        """
        try:
            status = self.jbx.submission_info(int(item_id))
        except (ApiError, ConnectionError) as err:
            raise SandboxError(err)
        if status['status'] == 'finished':
            return True
        else:
            return False

    def get_webid(self, item_id: Union[int, str]) -> str:
        """Provides the web id for the given submission id.

        :param item_id: The submission id.
        :return: The corresponding web id.
        """
        try:
            status = self.jbx.submission_info(int(item_id))
        except (ApiError, ConnectionError) as err:
            raise SandboxError(err)
        return status['most_relevant_analysis']['webid']

    @property
    def available(self) -> bool:
        """Checks to see if the Joe sandbox is up and running.

        :return: True if the Joe sandbox is responding, otherwise False.
        """
        try:
            status = self.jbx.server_online()
            return status['online']
        except (ApiError, ConnectionError, KeyError) as err:
            raise SandboxError(err)

    def report(self, item_id: Union[int, str]) -> dict:
        """Pulls the threat report from Joe for the submitted sample.

        :param item_id: The submission id.
        :return: The threat report.
        """
        webid = self.get_webid(item_id)
        try:
            _, report = self.jbx.analysis_download(str(webid), 'irjsonfixed')
        except (ApiError, ConnectionError) as err:
            raise SandboxError(err)
        return json.loads(report.decode('utf-8'))

    def pdf_report(self, item_id: Union[int, str]) -> bytes:
        """Pulls the threat report as a PDF from Joe for the submitted sample.

        :param item_id: The submission id.
        :return: The PDF threat report.
        """
        webid = self.get_webid(item_id)
        try:
            _, report = self.jbx.analysis_download(str(webid), 'pdf')
        except (ApiError, ConnectionError) as err:
            raise SandboxError(err)
        return report

    def xml_report(self, item_id: Union[int, str]) -> bytes:
        """Pulls the threat report as a XML file from Joe for the submitted sample.

        :param item_id: The submission id.
        :return: The XML threat report.
        """
        webid = self.get_webid(item_id)
        try:
            _, report = self.jbx.analysis_download(str(webid), 'xml')
        except (ApiError, ConnectionError) as err:
            raise SandboxError(err)
        return report

    def score(self, report: dict) -> int:
        """Get the threat score for the submitted sample.

        :param report: The report returned from Joe for the submitted sample.
        :return: The threat score.
        """
        try:
            max_score = report['analysis']['detection']['maxscore']
            score = report['analysis']['detection']['score']
        except (ApiError, ConnectionError) as err:
            raise SandboxError(err)
        return int(score / max_score * 10)


# class JoeAPI(JoeSandbox):
#     """Legacy Joe Sandbox class used for backwards compatibility.
#
#     .. deprecated:: 2.0.0
#
#     :param apikey: The API key to access Joe sandbox.
#     :param apiurl: The Joe API URL.
#     :param accept_tac: True to accept the Terms and Conditions.
#     :param timeout: The number of seconds to wait for a response.
#     :param verify_ssl: Verify SSL Certificates if True, otherwise ignore self-signed certificates.
#     :param retries: The number of times to retry after an error occurs.
#     """
#
#     def __init__(
#             self,
#             apikey: str,
#             apiurl: str,
#             accept_tac: bool,
#             timeout: Optional[int] = None,
#             verify_ssl: bool = True,
#             retries: int = 3,
#             **kwargs,
#     ) -> None:
#         """Initialize the interface to Joe Sandbox API."""
#         warnings.warn('The JoeAPI class is deprecated in favor of JoeSandbox.', DeprecationWarning)
#         api = ''
#         apiurl = apiurl or 'jbxcloud.joesecurity.org'
#         if '://' in apiurl:
#             _, host = apiurl.split('//', maxsplit=1)
#         else:
#             host = apiurl
#         if '/' in host:
#             host, api = host.split('/', maxsplit=1)
#         super().__init__(api_key=apikey, host=host, verify_ssl=verify_ssl, **kwargs)
#         if api:
#             self.base_url = 'https://{}/{}'.format(host, api)
#         self.jbx = jbxapi.JoeSandbox(
#             apikey=apikey,
#             apiurl=self.base_url,
#             accept_tac=accept_tac,
#             timeout=timeout,
#             verify_ssl=self.verify_ssl,
#             retries=retries,
#         )


class JoeAPI(SandboxAPI):
    """Joe Sandbox API wrapper.

    This class is actually just a convenience wrapper around jbxapi.JoeSandbox.
    """

    def __init__(self, apikey, apiurl, accept_tac, timeout=None, verify_ssl=True, retries=3, **kwargs):
        """Initialize the interface to Joe Sandbox API."""
        SandboxAPI.__init__(self)
        self.jbx = jbxapi.JoeSandbox(apikey, apiurl or jbxapi.API_URL, accept_tac, timeout, verify_ssl, retries,
                                     **kwargs)

    def analyze(self, handle, filename):
        """Submit a file for analysis.

        :type  handle:   File handle
        :param handle:   Handle to file to upload for analysis.
        :type  filename: str
        :param filename: File name.

        :rtype:  str
        :return: Task ID as a string
        """
        # ensure the handle is at offset 0.
        handle.seek(0)

        try:
            return self.jbx.submit_sample(handle)['webids'][0]
        except (jbxapi.JoeException, KeyError, IndexError) as e:
            raise SandboxError("error in analyze: {e}".format(e=e))

    def check(self, item_id):
        """Check if an analysis is complete.

        :type  item_id: str
        :param item_id: File ID to check.

        :rtype:  bool
        :return: Boolean indicating if a report is done or not.
        """
        try:
            return self.jbx.info(item_id).get('status').lower() == 'finished'
        except jbxapi.JoeException:
            return False

        return False

    def is_available(self):
        """Determine if the Joe Sandbox API server is alive.

        :rtype:  bool
        :return: True if service is available, False otherwise.
        """
        # if the availability flag is raised, return True immediately.
        # NOTE: subsequent API failures will lower this flag. we do this here
        # to ensure we don't keep hitting Joe with requests while availability
        # is there.
        if self.server_available:
            return True

        # otherwise, we have to check with the cloud.
        else:

            try:
                self.server_available = self.jbx.server_online()
                return self.server_available
            except jbxapi.JoeException:
                pass

        self.server_available = False
        return False

    def report(self, item_id, report_format="json"):
        """Retrieves the specified report for the analyzed item, referenced by item_id.

        For available report formats, see online Joe Sandbox documentation.

        :type  item_id:       str
        :param item_id:       File ID number
        :type  report_format: str
        :param report_format: Return format

        :rtype:  dict
        :return: Dictionary representing the JSON parsed data or raw, for other
                 formats / JSON parsing failure.
        """
        if report_format == "json":
            report_format = "jsonfixed"

        try:
            return json.loads(self.jbx.download(item_id, report_format)[1].decode('utf-8'))
        except (jbxapi.JoeException, ValueError, IndexError) as e:
            raise SandboxError("error in report fetch: {e}".format(e=e))

    def score(self, report):
        """Pass in the report from self.report(), get back an int."""
        try:
            return report['analysis']['signaturedetections']['strategy'][1]['score']
        except (KeyError, IndexError):
            return 0
