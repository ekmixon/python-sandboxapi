"""This module hosts the VMRay Sandbox class."""

from pathlib import Path
from typing import Optional, Union

import requests

from sandboxapi.base import Sandbox, SandboxAPI, SandboxError
from sandboxapi.common import BENIGN, CommonReport, Domain, File, MALICIOUS, Session, SUSPICIOUS, UNKNOWN


class VMRaySandbox(Sandbox):
    """Represents the VMRay Sandbox API.

    :param api_key: The customer API key.
    :param host: The IP address or hostname of the VMRay sandbox server.
    """

    __slots__ = ['api_key', '_headers']

    def __init__(
            self,
            api_key: Optional[str] = None,
            host: Optional[str] = None,
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

    def common_report(self, item_id: Union[int, str]) -> dict:
        """Pulls the common format report for the submitted sample.

        :param item_id: The submission id.
        :return: The common format report.
        """
        report = self.report(item_id)
        common = VMRayReport()
        return common(report)

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


class VMRayReport(CommonReport):
    """Represents the VMRay Sandbox common format report."""

    def populate(self, report: dict, **kwargs) -> None:
        """Maps parameters in the VMRay report to the equivalent parameter in the CommonReport.

        :param report: The VMRay analysis report to convert.
        """
        # Sandbox info
        if 'analysis_details' not in report:
            raise SandboxError('The report is not formatted correctly.')
        else:
            analysis = report['analysis_details']
        self._sandbox.vendor = 'VMRay'
        self._sandbox.submission_id = analysis.get('job_id')
        self._sandbox.start_time = analysis.get('creation_time')
        self._sandbox.duration = analysis.get('vm_analysis_duration_time')
        self._sandbox.environment = report.get('vm_and_analyzer_details', {}).get('vm_description')

        # Classification
        status = []
        states = [
            ('malicious', MALICIOUS),
            ('suspicious', SUSPICIOUS),
            ('not_suspicious', BENIGN),
        ]
        artifact_types = report.get('artifacts', {})
        # "version" is not a valid artifact so it needs to be removed.
        if 'version' in artifact_types:
            artifact_types.pop('version')
        for artifact_type, artifacts in artifact_types.items():
            for artifact in artifacts:
                if 'severity' in artifact:
                    status.append(artifact['severity'])
        for state in states:
            if state[0] in status:
                self._classification.label = state[1]
                break
        else:
            self._classification.label = UNKNOWN
        self._classification.score = int(report['vti'].get('vti_score', 0)) // 10
        self._classification.category = report.get('classifications')[0]

        # Files
        for artifact in artifact_types.get('files', []):
            hashes = artifact.get('hashes', {})[0]
            if artifact.get('category', '') == 'SAMPLE':
                file = File()
                file.name = artifact.get('filename')
                file.size = artifact.get('file_size')
                file.mime = artifact.get('mime_type')
                file.md5 = hashes.get('md5_hash')
                file.sha1 = hashes.get('sha1_hash')
                file.sha256 = hashes.get('sha256_hash')
                file.ssdeep = hashes.get('ssdeep_hash')
                for state in states:
                    if artifact.get('severity', UNKNOWN) == state[0]:
                        file.classification.label = state[1]
                        break
                else:
                    file.classification.label = UNKNOWN
                self._files.submitted.append(file)
            else:
                created = File()
                created.name = artifact.get('filename')
                created.size = artifact.get('file_size')
                created.mime = artifact.get('mime_type')
                created.md5 = hashes.get('md5_hash')
                created.sha1 = hashes.get('sha1_hash')
                created.sha256 = hashes.get('sha256_hash')
                created.ssdeep = hashes.get('ssdeep_hash')
                created.classification.label = artifact.get('severity')
                self._files.created.append(created)

        # Network
        network = report.get('network', {})
        if 'dns_requests' in network:
            for domain in network['dns_requests']:
                dom = Domain()
                if domain.get('hostnames'):
                    dom.name = domain.get('hostnames')[0]
                if domain.get('ip_addresses'):
                    dom.ip = domain.get('ip_addresses')[0]
                self._network.domains.append(dom)
        sessions = network.get('tcp_sessions', []) + network.get('udp_sessions', [])
        for session in sessions:
            sess = Session()
            conn = session.get('connection', {})
            sess.des_ip = conn.get('remote_ip_address')
            sess.des_port = conn.get('remote_port')
            sess.src_ip = conn.get('local_ip_address')
            sess.src_port = conn.get('local_port')
            sess.protocol = session.get('service')
            self._network.sessions.append(sess)


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
        response = self._request("/analysis/{analysis_id}/archive/logs/summary.json".format(
            analysis_id=analysis_id),
            headers=self.headers,
        )

        # if response is JSON, return it as an object.
        try:
            return response.json()
        except ValueError:
            pass

        # otherwise, return the raw content.
        return response.content

    @staticmethod
    def score(report):
        """Pass in the report from self.report(), get back an int 0-100"""
        try:
            return report['vti']['vti_score']
        except KeyError:
            return 0
