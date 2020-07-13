"""This module hosts the Common Sandbox Report and it's components."""

from pathlib import Path
from typing import List, Optional, Union


# Classifications
MALICIOUS = 'MALICIOUS'
SUSPICIOUS = 'SUSPICIOUS'
BENIGN = 'BENIGN'
UNKNOWN = 'UNKNOWN'
ERROR = 'FAILED'


class CommonReport:
    """Class representing the common report format that can be shared amongst Sandboxes."""

    __slots__ = ['_sandbox', '_classification', '_files', '_network']

    def __init__(self) -> None:
        """Instantiate a new CommonReport object."""
        self._sandbox = SandboxInfo()
        self._classification = Classification()
        self._network = Network()
        self._files = Files()

    def to_dict(self) -> dict:
        """Represents the CommonReport object as a dictionary.

        The format of the returned dictionary represents the schema for the CommonReport.

        :return: A dictionary representation of the CommonReport object.
        """
        out = {
            'sandbox_report': {
                'sandbox_info': {
                    'vendor': self._sandbox.vendor,
                    'url': self._sandbox.url,
                    'id': self._sandbox.submission_id,
                    'start_time': self._sandbox.start_time,
                    'environment': self._sandbox.environment,
                },
                'classification': self._classification.to_dict(),
                'files': self._files.to_dict(),
                'network': self._network.to_dict(),
            }
        }
        return out

    def populate(self, report: dict, **kwargs) -> None:
        """This method maps parameters in a Sandbox report to the equivalent parameter in the CommonReport.

        This method should be defined for each Sandbox.

        :param report: The Sandbox report to map.
        """
        raise NotImplementedError

    def __call__(self, report: dict, **kwargs) -> dict:
        """Calls the ``populate()`` method when calling the CommonReport object.

        :param report: The Sandbox report to map.
        :return: The dictionary representation of the CommonReport.
        """
        self.populate(report, **kwargs)
        return self.to_dict()


class SandboxInfo:
    """Class representing the general Sandbox information in a Sandbox report."""

    __slots__ = ['vendor', 'url', 'submission_id', 'start_time', 'duration', 'environment']

    def __init__(
            self,
            vendor: Optional[str] = None,
            url: Optional[str] = None,
            submission_id: Optional[str] = None,
            start_time: Optional[str] = None,
            duration: Optional[int] = None,
            environment: Optional[str] = None,
    ) -> None:
        """Instantiates a new SandboxInfo object."""
        self.vendor = vendor
        self.url = url
        self.submission_id = submission_id
        self.start_time = start_time
        self.duration = duration
        self.environment = environment


class Classification:
    """Class representing the Sandbox analysis classification in a Sandbox report."""

    __slots__ = ['label', 'score', 'category']

    labels = (
        MALICIOUS,
        SUSPICIOUS,
        BENIGN,
        UNKNOWN,
        ERROR,
    )

    def __init__(
            self,
            label: Optional[str] = None,
            score: Optional[int] = None,
            category: Optional[str] = None,
    ) -> None:
        """Instantiates a new Classification object."""
        self.label = label
        self.score = score
        self.category = category

    def to_dict(self) -> dict:
        """Represents a Classification object as a dictionary.

        :return: The Classification object as a dictionary.
        """
        return {
            'label': self.label,
            'score': self.score,
            'category': self.category,
        }


class File:
    """Class representing a Sandbox analyzed file in a Sandbox report."""

    __slots__ = ['name', 'path', 'md5', 'sha1', 'sha256', 'ssdeep', 'mime', 'size', 'classification']

    def __init__(
            self,
            name: Optional[str] = None,
            path: Optional[Union[str, Path]] = None,
            md5: Optional[str] = None,
            sha1: Optional[str] = None,
            sha256: Optional[str] = None,
            ssdeep: Optional[str] = None,
            mime: Optional[str] = None,
            size: Optional[int] = None,
            classification: Optional['Classification'] = None,
    ) -> None:
        """Instantiates a new File object."""
        self.name = name
        self.path = path
        self.md5 = md5
        self.sha1 = sha1
        self.sha256 = sha256
        self.ssdeep = ssdeep
        self.mime = mime
        self.size = size
        self.classification = classification if classification else Classification()

    @property
    def hashes(self) -> dict:
        """A dictionary of all the known file hashes for the File object.

        :return: A dictionary of the file hashes.
        """
        return {
            'md5': self.md5,
            'sha1': self.sha1,
            'sha256': self.sha256,
            'ssdeep': self.ssdeep,
        }

    def to_dict(self) -> dict:
        """Represents a File object as a dictionary.

        :return: A dictionary representation of the File object.
        """
        return {
            'name': self.name,
            'path': self.path,
            'hashes': self.hashes,
            'mime': self.mime,
            'size': self.size,
            'classification': self.classification.to_dict()
        }


class Files:
    """Class representing the files associated with an analysis in a Sandbox report."""

    __slots__ = ['submitted', 'created', 'modified', 'deleted']

    def __init__(
            self,
            submitted: Optional[List['File']] = None,
            created: Optional[List['File']] = None,
            modified: Optional[List['File']] = None,
            deleted: Optional[List['File']] = None,
    ) -> None:
        """Instantiates a new Files object."""
        self.submitted = submitted or []
        self.created = created or []
        self.modified = modified or []
        self.deleted = deleted or []

    def to_dict(self) -> dict:
        """Represents a Files object as a dictionary.

        :return: A dictionary representation of the Files object.
        """
        return {
            'submitted': [file.to_dict() for file in self.submitted],
            'created': [file.to_dict() for file in self.created],
            'modified': [file.to_dict() for file in self.modified],
            'deleted': [file.to_dict() for file in self.deleted],
        }


class Domain:
    """Class representing a domain in a Sandbox report."""

    __slots__ = ['name', 'ip', 'label']

    def __init__(self, name: Optional[str] = None, ip: Optional[str] = None, label: Optional[str] = None) -> None:
        """Instantiates a new Domain object."""
        self.name = name
        self.ip = ip
        self.label = label

    def to_dict(self) -> dict:
        """Represents a Domain object as a dictionary.

        :return: A dictionary representation of the Domain object.
        """
        return {
            'name': self.name,
            'ip': self.ip,
            'label': self.label,
        }


class Session:
    """Class representing a network session in a Sandbox report."""

    __slots__ = ['des_ip', 'des_port', 'label', 'pcap', 'protocol', 'src_ip', 'src_port']

    def __init__(
            self,
            des_ip: Optional[str] = None,
            des_port: Optional[str] = None,
            label: Optional[str] = None,
            pcap: Optional[str] = None,
            protocol: Optional[str] = None,
            src_ip: Optional[str] = None,
            src_port: Optional[str] = None,
    ) -> None:
        """Instantiates a new Session object."""
        self.des_ip = des_ip
        self.des_port = des_port
        self.label = label
        self.pcap = pcap
        self.protocol = protocol
        self.src_ip = src_ip
        self.src_port = src_port

    def to_dict(self) -> dict:
        """Represents a Session object as a dictionary.

        :return: A dictionary representation of the Session object.
        """
        return {
            'label': self.label,
            'protocol': self.protocol,
            'source_ip': self.src_ip,
            'source_port': self.src_port,
            'destination_ip': self.des_ip,
            'destination_port': self.des_port,
            'pcap': self.pcap,
        }


class Network:
    """Class representing network properties as part of a Sandbox report."""

    __slots__ = ['domains', 'sessions']

    def __init__(self, domains: Optional[List[Domain]] = None, sessions: Optional[List[Session]] = None) -> None:
        """Instantiates a new Network object."""
        self.domains = domains or []
        self.sessions = sessions or []

    def to_dict(self) -> dict:
        """Represents a Network object as a dictionary.

        :return: A dictionary representation of the Network object.
        """
        return {
            'domains': [domain.to_dict() for domain in self.domains],
            'sessions': [session.to_dict() for session in self.sessions],
        }
