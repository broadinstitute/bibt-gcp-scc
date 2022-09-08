import json
import logging
import os

from . import scc


class FindingInfo:
    """This class compiles information related to a given SCC finding in a standard way.
    One of the issues with SCC findings is that different SCC sources pass different fields;
    here, we can standardize how fields are passed around in functions and pipelines.
    """

    def __init__(self, notification, gcp_org_id):
        logging.info(
            f"Creating FindingInfo object for finding: {notification.finding.name}"
        )
        self.name = notification.finding.name
        self.category = notification.finding.category
        self.severity = notification.finding.severity.name
        self.resourceName = notification.finding.resource_name
        self.securityMarks = scc.get_security_marks(
            notification.finding.name, gcp_org_id
        )
        self.assetSecurityMarks = self._get_asset_security_marks(
            notification.finding.resource_name, gcp_org_id
        )
        self.parentInfo = self._get_parent_info(notification, gcp_org_id)

        # Do a type check to confirm parentInfo is an instance of FindingParentInfo or None.
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
                return source.display_name
        return None

    def _get_parent_info(self, notification, gcp_org_id):
        """Returns a FindingParentInfo with the relevant information. ETD sourced findings
        need special handling as they often just pass the organization as the finding's resource_name.
        """
        try:
            if (
                self._get_finding_source(notification.finding.parent)
                == "Event Threat Detection"
            ):
                # Some ETD findings include a projectNumber. Use that if present.
                if "projectNumber" in notification.finding.source_properties.get(
                    "sourceId"
                ):
                    logging.debug(f"Using projectNumber for ETD finding parent info...")
                    project_num = scc.get_value(
                        notification, "finding.sourceProperties.sourceId.projectNumber"
                    )
                    return self._generate_parent_info(
                        f"//cloudresourcemanager.googleapis.com/projects/{project_num}",
                        gcp_org_id,
                    )
                # Otherwise, use the resourceContainer of the audit log evidence.
                else:
                    logging.debug(
                        f"Using resourceContainer for ETD finding parent info..."
                    )
                    res_container = scc.get_value(
                        notification,
                        "finding.sourceProperties.evidence[0].sourceLogId.resourceContainer",
                    )
                    return self._generate_parent_info(
                        f"//cloudresourcemanager.googleapis.com/{res_container}",
                        gcp_org_id,
                    )
        except (ValueError, KeyError) as e:
            logging.error(f"Error getting ETD parent info: {type(e).__name__}: {e}")
            pass

        # If a non-ETD finding, try using resource.project_name
        if "resource" in notification and "project_name" in notification.resource:
            logging.debug(f"Using resource.project_name for finding parent info...")
            return self._generate_parent_info(
                notification.resource.project_name, gcp_org_id
            )

        # If all else fails, use finding.resource_name
        logging.debug(f"Using resource_name for finding parent info...")
        return self._generate_parent_info(
            notification.finding.resource_name, gcp_org_id
        )

    def _generate_parent_info(self, resource_name, gcp_org_id):
        return FindingParentInfo(resource_name, gcp_org_id)

    def _get_asset_security_marks(self, resource_name, gcp_org_id):
        """If the resource name isn't an organization, try getting the resource's
        security marks in SCC. If any errors are encountered, or it is an org, return None.
        """
        if not "/organizations/" in resource_name:
            try:
                return scc.get_security_marks(resource_name, gcp_org_id)
            except ValueError as e:
                logging.error(
                    "Exception caught getting asset security marks, it "
                    f"may have been deleted: {type(e).__name__}: {e}"
                )
                pass
        else:
            logging.info("Not getting security marks for organization.")
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
    """This class houses information related to the parent project, folder,
    or organization (whichever is found first in the asset's parent tree) for
    the asset of a given SCC finding. This is mostly useful in tracking down
    the appropriate owners to contact, but also helps as SCC findings don't
    pass asset/parent information in a standardized way.
    """

    def __init__(self, resource, gcp_org_id):
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
            ) = self._get_parent_info(resource, gcp_org_id)
        except ValueError as e:
            logging.error(
                f"Error while extracting parent info: {type(e).__name__}: {e}"
            )
            raise e

    def _get_parent_info(self, resource, gcp_org_id):
        """Starting with the resource name passed, begins iterating up the
        resource parents until it hits a project, folder, or organization.
        Then grabs that asset's metadata to return relevant parent info.
        """
        from bibt.gcp.scc import get_asset

        # Begin iterating through asset parents until we hit a project, folder, or organization
        a = get_asset(resource, gcp_org_id)
        while a.security_center_properties.resource_type not in [
            "google.cloud.resourcemanager.Project",
            "google.cloud.resourcemanager.Folder",
            "google.cloud.resourcemanager.Organization",
        ]:
            a = get_asset(a.security_center_properties.resource_parent, gcp_org_id)

        # Now we have a project, folder, or organization, get the relevant metadata and return
        owners = []
        if (
            a.security_center_properties.resource_type
            == "google.cloud.resourcemanager.Project"
        ):
            id_num, owners = self._extract_parent_info_project(a)
        elif (
            a.security_center_properties.resource_type
            == "google.cloud.resourcemanager.Folder"
        ):
            id_num, owners = self._extract_parent_info_folder(a)
        else:
            # No owners will be extracted if it is an organization
            id_num, owners = self._extract_parent_info_org(a)

        return (
            a.security_center_properties.resource_display_name,
            a.security_center_properties.resource_type,
            a.security_center_properties.resource_name,
            id_num,
            owners,
        )

    def _extract_parent_info_project(self, asset):
        return (
            asset.resource_properties.get("projectNumber"),
            list(asset.security_center_properties.resource_owners),
        )

    def _extract_parent_info_folder(self, asset):
        if "folderId" in asset.resource_properties:
            id_num = asset.resource_properties.get("folderId")
        else:
            id_num = asset.resource_properties.get("name").split("/")[1]
        # Get folder owners from the IAM blob
        iam_bindings = json.loads(asset.iam_policy.policy_blob).get("bindings", None)
        if iam_bindings:
            for binding in iam_bindings:
                if binding["role"] in [
                    "roles/resourcemanager.folderAdmin",
                    "roles/owner",
                ]:
                    owners.extend(binding["members"])
            owners = list(set(owners))
        return (id_num, owners)

    def _extract_parent_info_org(self, asset):
        return (asset.resource_properties.get("organizationId"), [])

    def package(self):
        """Converts this object into a dict."""
        return {
            "display_name": self.displayName,
            "type": self.type,
            "resource_name": self.resourceName,
            "id_num": self.idNum,
            "owners": self.owners,
        }
