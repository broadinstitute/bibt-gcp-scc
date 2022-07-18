"""
bibtutils.gcp.scc
~~~~~~~~~~~~~~~~~

Functionality making use of GCP's Security Command Center.

See the official Security Center Python Client documentation here: `link <https://googleapis.dev/python/securitycenter/latest/index.html>`_.

"""
import logging
from datetime import datetime

from google.cloud import securitycenter
from google.cloud.securitycenter_v1 import Finding
from google.protobuf import field_mask_pb2


logging.getLogger(__name__).addHandler(logging.NullHandler())


def set_finding_state(finding_name, state="INACTIVE", credentials=None):
    """This method will set the finding to inactive state by default.

    :type finding_name: :py:class:`str`
    :param finding_name: the finding.name whose state to modify.

    :type state: :py:class:`str`
    :param state: the state to set the finding to. must be valid according to
        :py:class:`gcp_scc:google.cloud.securitycenter_v1.types.Finding.State`.
        defaults to "INACTIVE".

    :type credentials: :py:class:`google_auth:google.oauth2.credentials.Credentials`
    :param credentials: the credentials object to use when making the API call, if not to
        use the account running the function for authentication.

    :raises KeyError: if the argument supplied for ``state`` is not a valid name
        for :py:class:`gcp_scc:google.cloud.securitycenter_v1.types.Finding.State`.
    """
    client = securitycenter.SecurityCenterClient(credentials=credentials)
    try:
        state_enum = Finding.State[state]
    except KeyError:
        raise KeyError(
            f"Supplied state ({state}) not recognized. Must be one of {[s.name for s in Finding.State]}"
        )

    client.set_finding_state(
        request={
            "name": finding_name,
            "state": state_enum,
            "start_time": datetime.now(),
        }
    )
    return


def set_security_mark(scc_name, marks, credentials=None):
    """Sets security marks on an asset or finding in SCC. Usually, if we're setting
    them on a finding, it means we're setting a mark of ``reason`` for setting it to inactive.
    if we're setting them on an asset, it is usually to ``allow_{finding.category}=true`` .

    :type scc_name: :py:class:`str`
    :param scc_name: may be either an SCC asset.name or finding.name. format is:
        ``organizations/123123/assets/123123`` or ``organizations/123123/sources/123123/findings/123123``

    :type marks: :py:class:`dict`
    :param marks: a dictionary of marks to set on the asset or finding. **note this must be a dict
        and not a list!** e.g.,
        ``marks={"allow_public_bucket_acl": "true", "reason": "intentional"}``

    :type credentials: :py:class:`google_auth:google.oauth2.credentials.Credentials`
    :param credentials: the credentials object to use when making the API call, if not to
        use the account running the function for authentication.

    :raises TypeError: if the argument supplied for ``marks`` is not a :py:class:`dict`
    """
    client = securitycenter.SecurityCenterClient(credentials=credentials)
    if not isinstance(marks, dict):
        raise TypeError(
            f"Argument: 'marks' must be a dict! You passed a {type(marks).__name__}."
        )
    mask_paths = [f"marks.{k}" for k in marks.keys()]
    client.update_security_marks(
        request={
            "security_marks": {"name": f"{scc_name}/securityMarks", "marks": marks},
            "update_mask": field_mask_pb2.FieldMask(paths=mask_paths),
        }
    )
    return


def get_finding(name, gcp_org_id, credentials=None):
    """This function returns the finding object specified by name.

    :type name: :py:class:`str`
    :param name: the ``finding.name`` to fetch.

    :type gcp_org_id: :py:class:`str`
    :param gcp_org_id: the GCP organization ID under which to search.

    :type credentials: :py:class:`google_auth:google.oauth2.credentials.Credentials`
    :param credentials: the credentials object to use when making the API call, if not to
        use the account running the function for authentication.

    :rtype: :py:class:`gcp_scc:google.cloud.securitycenter_v1.types.Finding`
    :returns: the specified finding object.

    :raises ValueError: if no finding under the supplied name is found.
    """
    findings = _get_all_findings_iter(
        request={
            "parent": f"organizations/{gcp_org_id}",
            "filter": f"name={name}",
            "page_size": 1,
        },
        credentials=credentials,
    )
    try:
        i, f = next(enumerate(findings))
        return f
    except StopIteration:
        raise ValueError(f'No finding object returned for name="{name}"')


def get_asset(resource_name, gcp_org_id, credentials=None):
    """This function returns the asset object specified by name.

    :type resource_name: :py:class:`str`
    :param resource_name: the ``resource.name`` to fetch.

    :type gcp_org_id: :py:class:`str`
    :param gcp_org_id: the GCP organization ID under which to search.

    :type credentials: :py:class:`google_auth:google.oauth2.credentials.Credentials`
    :param credentials: the credentials object to use when making the API call, if not to
        use the account running the function for authentication.

    :rtype: :py:class:`gcp_scc:google.cloud.securitycenter_v1.types.Asset`
    :returns: the specified asset object.

    :raises ValueError: if no asset under the supplied resource_name is found.
    """
    assets = _get_all_assets_iter(
        request={
            "parent": f"organizations/{gcp_org_id}",
            "filter": f'security_center_properties.resource_name="{resource_name}"',
            "page_size": 1,
        },
        credentials=credentials,
    )
    try:
        i, a = next(enumerate(assets))
        return a
    except StopIteration:
        raise ValueError(
            "No asset object returned for "
            f'security_center_properties.resource_name="{resource_name}"'
        )


def get_all_findings(filter, gcp_org_id, page_size=1000, credentials=None):
    """Returns all findings matching a particular filter.

    :type filter: :py:class:`str`
    :param filter: the filter to use. See
        `here <https://cloud.google.com/security-command-center/docs/reference/rest/v1p1beta1/organizations.sources.findings/list#query-parameters>`_
        for more on valid filter syntax.

    :type gcp_org_id: :py:class:`str`
    :param gcp_org_id: the GCP organization ID under which to search.

    :type page_size: :py:class:`int`
    :param page_size: the page size for the API requests. max and default is ``1000`` .

    :type credentials: :py:class:`google_auth:google.oauth2.credentials.Credentials`
    :param credentials: the credentials object to use when making the API call, if not to
        use the account running the function for authentication.

    :rtype: :py:class:`list`
    :returns: A list of :py:class:`gcp_scc:google.cloud.securitycenter_v1.types.Finding` objects matching the filter.
    """
    return [
        asset
        for asset in _get_all_findings_iter(
            request={
                "parent": f"organizations/{gcp_org_id}",
                "filter": filter,
                "page_size": page_size,
            },
            credentials=credentials,
        )
    ]


def get_all_assets(filter, gcp_org_id, page_size=1000, credentials=None):
    """Returns all assets matching a particular filter.

    :type filter: :py:class:`str`
    :param filter: the filter to use. See
        `here <https://cloud.google.com/security-command-center/docs/reference/rest/v1p1beta1/organizations.sources.findings/list#query-parameters>`_
        for more on valid filter syntax.

    :type gcp_org_id: :py:class:`str`
    :param gcp_org_id: the GCP organization ID under which to search.

    :type page_size: :py:class:`int`
    :param page_size: the page size for the API requests. max and default is ``1000`` .

    :type credentials: :py:class:`google_auth:google.oauth2.credentials.Credentials`
    :param credentials: the credentials object to use when making the API call, if not to
        use the account running the function for authentication.

    :rtype: :py:class:`list`
    :returns: A list of :py:class:`gcp_scc:google.cloud.securitycenter_v1.types.Asset` objects matching the filter.
    """
    return [
        asset
        for asset in _get_all_assets_iter(
            request={
                "parent": f"organizations/{gcp_org_id}/sources/-",
                "filter": filter,
                "page_size": page_size,
            },
            credentials=credentials,
        )
    ]


def _get_all_findings_iter(request, credentials=None):
    """A helper method to make a list_findings API call. Expects a valid ``request``
    dictionary and can optionally be supplied with a credentials object.

    Returns: :py:class:`gcp_scc:google.cloud.securitycenter_v1.services.security_center.pagers.ListFindingsPager`
    """
    client = securitycenter.SecurityCenterClient(credentials=credentials)
    return client.list_findings(request)


def _get_all_assets_iter(request, credentials=None):
    """A helper method to make a list_assets API call. Expects a valid ``request``
    dictionary and can optionally be supplied with a credentials object.

    Returns: :py:class:`gcp_scc:google.cloud.securitycenter_v1.services.security_center.pagers.ListAssetsPager`
    """
    client = securitycenter.SecurityCenterClient(credentials=credentials)
    return client.list_assets(request)
