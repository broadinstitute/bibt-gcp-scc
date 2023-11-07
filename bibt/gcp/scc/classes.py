"""
Classes
~~~~~~~

Classes which may be used to handle or interact with the SCC API.

"""
import json
import logging

from google.cloud import securitycenter

from . import methods

_LOGGER = logging.getLogger(__name__)


class FindingInfo:
    r"""This class compiles information related to a given SCC finding in a standard way.
    One of the issues with SCC findings is that different SCC sources pass different fields;
    here, we can standardize how fields are passed around in functions and pipelines.

    Attributes:
        name (:py:class:`str`):
            The finding name, e.g. ``organizations/123123/sources/123123/findings/123123``.
        category (:py:class:`str`):
            The finding category, e.g. ``PUBLIC_BUCKET_ACL`` or ``Persistence: New Geography``.
        source (:py:class:`str`):
            The source of the finding, e.g. ``Security Health Analytics``.
        severity (:py:class:`str`):
            The finding severity, one of: ``CRITICAL``, ``HIGH``, ``MEDIUM``, ``LOW``, ``UNDEFINED``.
        eventTime (:py:class:`datetime.datetime`):
            The event time of the finding, typically when it was most recently triggered.
        createTime (:py:class:`datetime.datetime`):
            The create time of the finding, typically when it was initially triggered.
        resourceName (:py:class:`str`):
            The name of the resource attached to the finding, e.g. ``//storage.googleapis.com/my-bucket``.
        securityMarks (:py:class:`dict`):
            Any security marks set on the finding.
        assetSecurityMarks (:py:class:`dict`):
            Any security marks set on the finding's resource.
        parentInfo (:py:class:`bibt.gcp.scc.classes.FindingParentInfo`):
            A FindingParentInfo instance containing information related to the finding's parent project, folder, or organization.
    """

    def __init__(self, notification, gcp_org_id, client=None):
        _LOGGER.info(
            f"Creating FindingInfo object for finding: {notification.finding.name}"
        )
        if not (
            isinstance(client, securitycenter.SecurityCenterClient) or client is None
        ):
            _LOGGER.error(
                "The `client` parameter must be an instance of "
                "securitycenter.SecurityCenterClient, bibt.gcp.scc.Client, "
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
        # self.assetSecurityMarks = self._get_asset_security_marks(
        #     notification.finding.resource_name, gcp_org_id, client=self._client
        # )
        self.parentInfo = None

        # # Do a type check to confirm parentInfo is an instance of FindingParentInfo or None.
        # if not (
        #     isinstance(self.parentInfo, FindingParentInfo) or self.parentInfo == None
        # ):
        #     raise TypeError(
        #         "FindingInfo.parentInfo must be an instance of "
        #         "FindingParentInfo or a derived subclass (or None). "
        #         f"You passed: {str(self.parentInfo.__class__.__mro__)}"
        #     )

    def _get_finding_source(self, finding_source, client=None):
        source_parent = "/".join(finding_source.split("/")[:2])
        sources = methods.get_sources(source_parent, client=client)
        for source in sources:
            if source.name == finding_source:
                return source.display_name
        return None

    # def _get_parent_info(self, notification, gcp_org_id, client=None):
    #     """Returns a FindingParentInfo with the relevant information. ETD sourced findings
    #     need special handling as they often just pass the organization as the finding's resource_name.
    #     """
    #     try:
    #         if self.source == "Event Threat Detection":
    #             # Some ETD findings include a projectNumber. Use that if present.
    #             if "projectNumber" in notification.finding.source_properties.get(
    #                 "sourceId"
    #             ):
    #                 _LOGGER.debug(f"Using projectNumber for ETD finding parent info...")
    #                 project_num = methods.get_value(
    #                     notification, "finding.sourceProperties.sourceId.projectNumber"
    #                 )
    #                 return self._generate_parent_info(
    #                     f"//cloudresourcemanager.googleapis.com/projects/{project_num}",
    #                     gcp_org_id,
    #                     client=client,
    #                 )
    #             # Otherwise, use the resourceContainer of the audit log evidence.
    #             else:
    #                 _LOGGER.debug(
    #                     f"Using resourceContainer for ETD finding parent info..."
    #                 )
    #                 res_container = methods.get_value(
    #                     notification,
    #                     "finding.sourceProperties.evidence[0].sourceLogId.resourceContainer",
    #                 )
    #                 return self._generate_parent_info(
    #                     f"//cloudresourcemanager.googleapis.com/{res_container}",
    #                     gcp_org_id,
    #                     client=client,
    #                 )
    #     except (ValueError, KeyError) as e:
    #         _LOGGER.warning(f"Error getting ETD parent info: {type(e).__name__}: {e}")
    #         pass

    #     # If a non-ETD finding, try using resource.project_name
    #     if "resource" in notification and "project_name" in notification.resource:
    #         _LOGGER.debug(f"Using resource.project_name for finding parent info...")
    #         return self._generate_parent_info(
    #             notification.resource.project_name, gcp_org_id, client=client
    #         )

    #     # If all else fails, use finding.resource_name
    #     _LOGGER.debug(f"Using resource_name for finding parent info...")
    #     return self._generate_parent_info(
    #         notification.finding.resource_name, gcp_org_id, client=client
    #     )

    # def _generate_parent_info(self, resource_name, gcp_org_id, client=None):
    #     return FindingParentInfo(resource_name, gcp_org_id, client)

    def _get_finding_security_marks(self, finding_name, gcp_org_id, client=None):
        return methods.get_security_marks(finding_name, gcp_org_id, client=client)

    # def _get_asset_security_marks(self, resource_name, gcp_org_id, client=None):
    #     """If the resource name isn't an organization, try getting the resource's
    #     security marks in SCC. If any errors are encountered, or it is an org, return None.
    #     """
    #     if not "/organizations/" in resource_name:
    #         try:
    #             if client:
    #                 return client.get_security_marks(resource_name, gcp_org_id)
    #             return methods.get_security_marks(resource_name, gcp_org_id)
    #         except ValueError as e:
    #             _LOGGER.warning(
    #                 "Exception caught getting asset security marks, it "
    #                 f"may have been deleted: {type(e).__name__}: {e}"
    #             )
    #             pass
    #     else:
    #         _LOGGER.info("Not getting security marks for organization.")
    #     return None

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
            # "asset_security_marks": self.assetSecurityMarks,
        }
