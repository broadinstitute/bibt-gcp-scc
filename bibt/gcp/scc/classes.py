import logging

from google.cloud import securitycenter
from google.cloud import securitycenter_v1

from . import methods

_LOGGER = logging.getLogger(__name__)


class FindingInfo:
    """This class compiles information related to a given SCC finding in a standard
    way. One of the issues with SCC findings is that different SCC sources pass
    different fields; here, we can standardize how fields are passed around in
    functions and pipelines.

    """

    def __init__(self, notification, gcp_org_id, client=None):
        _LOGGER.info(
            f"Creating FindingInfo object for finding: {notification.finding.name}"
        )
        if not (
            isinstance(client, securitycenter.SecurityCenterClient)
            or isinstance(client, securitycenter_v1.SecurityCenterClient)
            or client is None
        ):
            _LOGGER.warning(
                "The `client` parameter must be an instance of "
                "securitycenter.SecurityCenterClient, "
                "securitycenter_v1.SecurityCenterClient, "
                "a derived subclass, or None. "
                f"You passed: {str(client.__class__.__mro__)}. Proceeding "
                "without the use of the client."
            )
            client = None

        self._client = client
        self.name = notification.finding.name
        self.category = notification.finding.category
        self.source = self._get_finding_source(
            notification.finding.parent, client=self._client
        )
        self.severity = notification.finding.severity.name
        self.eventTime = notification.finding.event_time
        self.createTime = notification.finding.create_time
        self.resourceName = notification.finding.resource_name
        self.securityMarks = self._get_finding_security_marks(
            notification.finding.name, gcp_org_id, client=self._client
        )
        self.parentInfo = None

    def _get_finding_source(self, finding_source, client=None):
        source_parent = "/".join(finding_source.split("/")[:2])
        sources = methods.get_sources(source_parent, client=client)
        for source in sources:
            if source.name == finding_source:
                return source.display_name
        return None

    def _get_finding_security_marks(self, finding_name, gcp_org_id, client=None):
        return methods.get_security_marks(finding_name, gcp_org_id, client=client)

    def package(self):
        """Converts this object into a dict."""
        return {
            "name": self.name,
            "category": self.category,
            "source": self.source,
            "severity": self.severity,
            "event_time": self.eventTime.isoformat(),
            "create_time": self.createTime.isoformat(),
            "resource_name": self.resourceName,
            "security_marks": self.securityMarks,
        }
