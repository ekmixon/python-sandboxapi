"""This module hosts the Joe Sandbox class."""

import json
from pathlib import Path
from typing import Optional, Union

import jbxapi
from jbxapi import ApiError, ConnectionError

from sandboxapi.base import Sandbox, SandboxAPI, SandboxError
from sandboxapi.common import BENIGN, CommonReport, Domain, File, MALICIOUS, Session, SUSPICIOUS, UNKNOWN


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
            api_key: Optional[str] = None,
            host: Optional[str] = None,
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

    def common_report(self, item_id: Union[int, str]) -> dict:
        """Pulls the common format report for the submitted sample.

        :param item_id: The submission id.
        :return: The common format report.
        """
        report = self.report(item_id)
        common = JoeReport()
        return common(report)

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


class JoeReport(CommonReport):
    """Represents the Joe Sandbox common format report."""

    def populate(self, report: dict, **kwargs) -> None:
        """Maps parameters in the Joe report to the equivalent parameter in the CommonReport.

        :param report: The Joe analysis report to convert.
        """
        # Sandbox info
        if 'analysis' not in report:
            raise SandboxError('The report is not formatted correctly.')
        else:
            analysis = report['analysis']
        self._sandbox.vendor = 'Joe'
        self._sandbox.submission_id = analysis.get('id')
        self._sandbox.start_time = '{} {}'.format(
            analysis.get('startdate'),
            analysis.get('starttime'),
        )
        self._sandbox.environment = analysis.get('system')

        # Classification
        status = analysis.get('detection', {})
        states = {
            'malicious': MALICIOUS,
            'suspicious': SUSPICIOUS,
            'clean': BENIGN,
            'unknown': UNKNOWN,
        }
        for state in states:
            if status.get(state) is True:
                self._classification.label = states[state]
                break
        self._classification.score = int(int(status.get('score', 0)) / int(status.get('maxscore')) * 10)

        # Files
        file = File()
        file.name = analysis.get('sample')
        file.md5 = analysis['hashes'].get('md5')
        file.sha1 = analysis['hashes'].get('sha1')
        file.sha256 = analysis['hashes'].get('sha256')
        file.classification.label = self._classification.label
        file.classification.score = self._classification.score
        self._files.submitted.append(file)
        for file in analysis.get('dropped', {}).get('file'):
            created = File()
            created.name = file.get('name')
            created.md5 = file.get('md5')
            created.sha1 = file.get('sha1')
            created.sha256 = file.get('sha256')
            self._files.created.append(created)

        # Network
        dom_path = analysis.get('contacted', {}).get('domains', {})
        if dom_path:
            for domain in dom_path.get('domain', []):
                dom = Domain()
                dom.name = domain.get('name')
                dom.ip = domain.get('ip')
                dom.label = MALICIOUS if domain.get('malicious', False) is True else UNKNOWN
                self._network.domains.append(dom)
        sess_path = analysis.get('contacted', {}).get('ips', {})

        if sess_path:
            for ip in sess_path.get('ip', []):
                sess = Session()
                sess.src_ip = ip.get('$')
                sess.label = MALICIOUS if ip.get('@malicious', "false") == "true" else UNKNOWN
                self._network.sessions.append(sess)


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

    @staticmethod
    def score(report):
        """Pass in the report from self.report(), get back an int."""
        try:
            return report['analysis']['signaturedetections']['strategy'][1]['score']
        except (KeyError, IndexError):
            return 0
