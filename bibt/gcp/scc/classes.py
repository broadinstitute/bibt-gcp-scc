import json
import logging
import os

from . import scc


class FindingInfo:
    def __init__(self, notification):
        logging.info(
            f"Creating FindingInfo object for finding: {notification.finding.name}"
        )
        self.name = notification.finding.name
        self.category = notification.finding.category
        self.severity = notification.finding.severity.name
        self.securityMarks = scc.get_security_marks(
            notification.finding.name, os.environ["GCP_ORG_ID"]
        )
        self.assetSecurityMarks = scc.get_security_marks(
            notification.resource.name, os.environ["GCP_ORG_ID"]
        )
        try:
            source = self._get_finding_source(notification.finding.parent)
            if not source:
                logging.warning(
                    f"Error extracting source information: {notification.finding.parent}"
                )
            if source and source.display_name == "Event Threat Detection":
                if "projectNumber" in notification.finding.source_properties.get(
                    "sourceId"
                ):
                    logging.debug(f"Using projectNumber for ETD finding parent info...")
                    project_num = scc.get_value(
                        notification, "finding.sourceProperties.sourceId.projectNumber"
                    )
                    self.parentInfo = FindingParentInfo(
                        f"//cloudresourcemanager.googleapis.com/projects/{project_num}"
                    )
                else:
                    logging.debug(
                        f"Using resourceContainer for ETD finding parent info..."
                    )
                    folder_num = scc.get_value(
                        notification,
                        "finding.sourceProperties.evidence[0].sourceLogId.resourceContainer",
                    )
                    self.parentInfo = FindingParentInfo(
                        f"//cloudresourcemanager.googleapis.com/{folder_num}"
                    )
            elif "resource" in notification and "project_name" in notification.resource:
                logging.debug(f"Using resource.project_name for finding parent info...")
                self.parentInfo = FindingParentInfo(notification.resource.project_name)
            else:
                logging.debug(f"Using resource.name for finding parent info...")
                self.parentInfo = FindingParentInfo(notification.finding.resource_name)
        except (ValueError, KeyError) as e:
            logging.error(f"Error getting parent: {type(e).__name__}: {e}")
            self.parentInfo = None

        if not (isinstance(self.parentInfo, FindingParentInfo) or self.parentInfo):
            raise TypeError(
                "FindingInfo.parentInfo must be an instance of "
                "FindingParentInfo or a derived subclass (or None)."
            )

    def _get_finding_source(self, finding_source):
        source_parent = "/".join(finding_source.split("/")[:2])
        sources = scc.get_sources(source_parent)
        for source in sources:
            if source.name == finding_source:
                return source
        return None

    def package(self):
        return {
            "name": self.name,
            "category": self.category,
            "severity": self.severity,
            "security_marks": self.securityMarks,
            "asset_security_marks": self.assetSecurityMarks,
            "parent_info": self.parentInfo.package() if self.parentInfo else None,
        }


class FindingParentInfo:
    def __init__(self, resource):
        """Resource must be in the format: //compute.googleapis.com/projects/PROJECT_ID/zones/ZONE/instances/INSTANCE

        See more: https://cloud.google.com/asset-inventory/docs/resource-name-format
        """
        logging.info(f"Getting parent info for resource: {resource}")
        try:
            (
                self.displayName,
                self.type,
                self.resourceName,
                self.idNum,
                self.owners,
            ) = self._get_parent_info(resource)
        except ValueError as e:
            logging.error(
                f"Error while extracting parent info: {type(e).__name__}: {e}"
            )
            raise e

        logging.debug(f"Parent info: {json.dumps(self.package(), indent=2)}")

    def _get_parent_info(self, resource):
        from bibt.gcp.scc import get_asset

        a = get_asset(resource, os.environ["GCP_ORG_ID"])
        while a.security_center_properties.resource_type not in [
            "google.cloud.resourcemanager.Project",
            "google.cloud.resourcemanager.Folder",
            "google.cloud.resourcemanager.Organization",
        ]:
            a = get_asset(
                a.security_center_properties.resource_parent, os.environ["GCP_ORG_ID"]
            )

        owners = []
        if (
            a.security_center_properties.resource_type
            == "google.cloud.resourcemanager.Project"
        ):
            id_num = a.resource_properties.get("projectNumber")
            owners = list(a.security_center_properties.resource_owners)
        elif (
            a.security_center_properties.resource_type
            == "google.cloud.resourcemanager.Folder"
        ):
            if "folderId" in a.resource_properties:
                id_num = a.resource_properties.get("folderId")
            else:
                id_num = a.resource_properties.get("name").split("/")[1]
            iam_bindings = json.loads(a.iam_policy.policy_blob).get("bindings", None)
            if iam_bindings:
                for binding in iam_bindings:
                    if binding["role"] in [
                        "roles/resourcemanager.folderAdmin",
                        "roles/owner",
                    ]:
                        owners.extend(binding["members"])
                owners = list(set(owners))
        else:
            id_num = a.resource_properties.get("organizationId")

        return (
            a.security_center_properties.resource_display_name,
            a.security_center_properties.resource_type,
            a.security_center_properties.resource_name,
            id_num,
            owners,
        )

    def package(self):
        return {
            "display_name": self.displayName,
            "type": self.type,
            "resource_name": self.resourceName,
            "id_num": self.idNum,
            "owners": self.owners,
        }
