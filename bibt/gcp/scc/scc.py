"""
bibt.gcp.scc
~~~~~~~~~~~~

Functionality making use of GCP's Security Command Center.

See the official Security Center Python Client documentation here: `link <https://googleapis.dev/python/securitycenter/latest/index.html>`_.

"""
import logging
from datetime import datetime
from typing import Type

import pytz
from google.cloud import securitycenter
from google.cloud.securitycenter_v1 import Finding
from google.protobuf import field_mask_pb2
from google.protobuf import message
from google.protobuf.json_format import ParseError
from inflection import camelize
from inflection import underscore

_LOGGER = logging.getLogger(__name__)


def get_all_assets(
    filter, gcp_org_id, order_by=None, page_size=1000, credentials=None, client=None
):
    """Returns all assets matching a particular filter.

    .. code:: python

        from bibt.gcp import scc
        for _ in scc.get_all_assets(
            filter='securityCenterProperties.resourceType="google.container.Cluster"',
            gcp_org_id=123123
        ):
            print(_.asset.name)

    :type filter: :py:class:`str`
    :param filter: the filter to use. See
        `here <https://googleapis.dev/python/securitycenter/latest/securitycenter_v1/types.html#google.cloud.securitycenter_v1.types.ListAssetsRequest.filter>`__
        for more on valid filter syntax.

    :type order_by: :py:class:`str`
    :param order_by: the sort order of the assets. See
        `here <https://googleapis.dev/python/securitycenter/latest/securitycenter_v1/types.html#google.cloud.securitycenter_v1.types.ListAssetsRequest.order_by>`__
        for more on valid arguments. Default is None.

    :type gcp_org_id: :py:class:`str`
    :param gcp_org_id: the GCP organization ID under which to search.

    :type page_size: :py:class:`int`
    :param page_size: the page size for the API requests. max and default is ``1000`` .

    :type credentials: :py:class:`google_auth:google.oauth2.credentials.Credentials`
    :param credentials: the credentials object to use when making the API call, if not to
        use the account running the function for authentication.

    :rtype: :py:class:`gcp_scc:google.cloud.securitycenter_v1.types.ListAssetsResponse`
    :returns: an iterator for all assets matching the specified filter.
    """
    return _get_all_assets_iter(
        request={
            "parent": f"organizations/{gcp_org_id}",
            "filter": filter,
            "order_by": order_by,
            "page_size": page_size,
        },
        credentials=credentials,
        client=client,
    )


def get_all_findings(
    filter, gcp_org_id, order_by=None, page_size=1000, credentials=None, client=None
):
    """Returns an iterator for all findings matching a particular filter.

    .. code:: python

        from bibt.gcp.scc import get_all_findings
        for _ in get_all_findings(
            filter='category="PUBLIC_BUCKET_ACL"',
            order_by='eventTime desc',
            gcp_org_id=123123
        ):
            print(_.finding.name, _.resource.name)

    :type filter: :py:class:`str`
    :param filter: the filter to use. See
        `here <https://googleapis.dev/python/securitycenter/latest/securitycenter_v1/types.html#google.cloud.securitycenter_v1.types.ListFindingsRequest.filter>`__
        for more on valid filter syntax.

    :type gcp_org_id: :py:class:`str`
    :param gcp_org_id: the GCP organization ID under which to search.

    :type order_by: :py:class:`str`
    :param order_by: (optional) the sort order of the findings. See
        `here <https://googleapis.dev/python/securitycenter/latest/securitycenter_v1/types.html#google.cloud.securitycenter_v1.types.ListFindingsRequest.order_by>`__
        for more on valid arguments. Default is None.
    :type page_size: :py:class:`int`
    :param page_size: (optional) the page size for the API requests. max and default is ``1000`` .

    :type credentials: :py:class:`google_auth:google.oauth2.credentials.Credentials`
    :param credentials: (optional) the credentials object to use when making the API call, if not to
        use the account running the function for authentication.

    :type client: :py:class:`gcp_scc:google.cloud.securitycenter.SecurityCenterClient`
    :param client: (optional) the SCC client to use for API calls. will generate one if not passed.

    :rtype: :py:class:`gcp_scc:google.cloud.securitycenter_v1.types.ListFindingsResponse`
    :returns: an iterator for all findings matching the filter.
    """
    return _get_all_findings_iter(
        request={
            "parent": f"organizations/{gcp_org_id}/sources/-",
            "filter": filter,
            "page_size": page_size,
            "order_by": order_by,
        },
        credentials=credentials,
        client=client,
    )


def get_asset(resource_name, gcp_org_id, credentials=None, client=None):
    """This function returns the asset object specified by name.

    .. code:: python

        from bibt.gcp import scc
        a = scc.get_asset(
            resource_name='//container.googleapis.com/projects/123123/zones/us-central1-a/clusters/my-cluster',
            gcp_org_id=123123
        )
        print(a.asset.name, a.asset.createTime)

    :type resource_name: :py:class:`str`
    :param resource_name: the ``resource.name`` to fetch.

    :type gcp_org_id: :py:class:`str`
    :param gcp_org_id: the GCP organization ID under which to search.

    :type credentials: :py:class:`google_auth:google.oauth2.credentials.Credentials`
    :param credentials: the credentials object to use when making the API call, if not to
        use the account running the function for authentication.

    :type client: :py:class:`gcp_scc:google.cloud.securitycenter.SecurityCenterClient`
    :param client: (optional) the SCC client to use for API calls. will generate one if not passed.

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
        client=client,
    )
    try:
        _, a = next(enumerate(assets))
        return a.asset
    except StopIteration:
        raise ValueError(
            "No asset object returned for "
            f'security_center_properties.resource_name="{resource_name}" in '
            f"organizations/{gcp_org_id}"
        )


def get_value(obj, path, raise_exception=True):
    """Fetches the value in the given ``obj`` according to the given ``path``. Works on objects and dicts.
    Supports arrays in a few ways:

    * if the ``path`` is ``resource.folders[].resource_folder_display_name`` OR
      ``resource.folders[0].resource_folder_display_name``,
      it will just consider the first element in the array.

    * if the ``path`` is ``resource.folders[*].resource_folder_display_name``,
      it will return a list of ``resource_folder_display_name`` values,
      one for each folder.

    Additionally, if unsuccessful with exactly what was passed as ``path``, it will convert and try
    both camelized and underscored attribute names (``resource_folder_display_name`` and ``resourceFolderDisplayName``).
    As a last resort it will try a key lookup (e.g. ``obj[key]``).

    .. code:: python

        from bibt.gcp import scc
        f = scc.get_finding(name="organizations/123123/sources/123123/findings/123123", gcp_org_id=123123)
        v = scc.get_value(
            f,
            "finding.source_properties.abuse_target_ips"
        )
        print(v)

    :type obj: :py:class:`object`
    :param obj: the object from which to extract a value.

    :type path: :py:class:`str`
    :param path: the path to follow to find the desired value(s).

    :type raise_exception: :py:class:`bool`
    :param raise_exception: whether it should raise an exception if the path isn't
        resolved successfully, or just return None.

    :returns: whatever it finds at the end of the specified ``path``.

    :raises KeyError: if the next part of the path cannot be found.
    """
    if path == "":
        return obj
    attr, _, remaining = path.partition(".")
    grab_one = grab_all = False
    if attr.endswith("[]"):
        attr = attr[:-2]
        grab_one = True
    elif attr.endswith("[0]"):
        attr = attr[:-3]
        grab_one = True
    elif attr.endswith("[*]"):
        attr = attr[:-3]
        grab_all = True
    obj = _get(obj, attr, raise_exception=raise_exception)
    if not obj:
        return None
    if grab_one:
        obj = obj[0]
    elif grab_all:
        return [
            get_value(_obj, remaining, raise_exception=raise_exception) for _obj in obj
        ]
    return get_value(obj, remaining, raise_exception=raise_exception)


def get_finding(name, gcp_org_id, credentials=None, client=None):
    """This function returns the finding object specified by name.

    .. code:: python

        from bibt.gcp import scc
        f = scc.get_finding(
            name="organizations/123123/sources/123123/findings/123123",
            gcp_org_id=123123
        )
        print(f.finding.name, f.resource.name)

    :type name: :py:class:`str`
    :param name: the ``finding.name`` to fetch.

    :type gcp_org_id: :py:class:`str`
    :param gcp_org_id: the GCP organization ID under which to search.

    :type credentials: :py:class:`google_auth:google.oauth2.credentials.Credentials`
    :param credentials: the credentials object to use when making the API call, if not to
        use the account running the function for authentication.

    :type client: :py:class:`gcp_scc:google.cloud.securitycenter.SecurityCenterClient`
    :param client: (optional) the SCC client to use for API calls. will generate one if not passed.

    :rtype: :py:class:`gcp_scc:google.cloud.securitycenter_v1.types.ListFindingsResponse.ListFindingsResult`
    :returns: the specified finding object, paired with its resource information.

    :raises ValueError: if no finding under the supplied name is found.
    """
    findings = _get_all_findings_iter(
        request={
            "parent": f"organizations/{gcp_org_id}/sources/-",
            "filter": f'name="{name}"',
            "page_size": 1,
        },
        credentials=credentials,
        client=client,
    )
    try:
        _, f = next(enumerate(findings))
        return f
    except StopIteration:
        raise ValueError(
            f'No finding object returned for name="{name}" in '
            f"organizations/{gcp_org_id}"
        )


def get_security_marks(scc_name, gcp_org_id, credentials=None, client=None):
    """Gets security marks on an asset or finding in SCC and returns them as a dict.

    .. code:: python

        from bibt.gcp import scc
        for k, v in scc.get_security_marks(
            scc_name="organizations/123123/sources/123123/findings/123123",
            os.environ["GCP_ORG_ID"]
        ).items():
            print(k, v)

    :type scc_name: :py:class:`str`
    :param scc_name: may be either an SCC ``finding.name`` or a GCP ``resourceName`` . format is:
        ``organizations/123123/sources/123123/findings/123123`` or ``//storage.googleapis.com/my-bucket``.
        **note this does not accept ``asset.name`` format!**

    :type gcp_org_id: :py:class:`str`
    :param gcp_org_id: the GCP organization ID under which to search.

    :type credentials: :py:class:`google_auth:google.oauth2.credentials.Credentials`
    :param credentials: the credentials object to use when making the API call, if not to
        use the account running the function for authentication.

    :type client: :py:class:`gcp_scc:google.cloud.securitycenter.SecurityCenterClient`
    :param client: (optional) the SCC client to use for API calls. will generate one if not passed.

    :rtype: :py:class:`dict`
    :returns: a dictionary containing security marks as key/value pairs.

    :raises TypeError: if scc_name is not in a recognizeable format.
    """
    if "/findings/" in scc_name:
        _LOGGER.debug(f'Assuming type "finding" from scc_name format: {scc_name}')
        f = get_finding(scc_name, gcp_org_id, credentials, client)
        if "security_marks" in f.finding:
            return dict(f.finding.security_marks.marks)
    elif scc_name.startswith("//"):
        _LOGGER.debug(f'Assuming type "asset" from scc_name format: {scc_name}')
        a = get_asset(scc_name, gcp_org_id, credentials, client)
        if "security_marks" in a:
            return dict(a.security_marks.marks)
    else:
        raise TypeError(f"Unrecognized scc_name type: {scc_name}")
    return {}


def get_sources(parent_name, credentials=None, client=None):
    """Returns a list of all sources in the parent.

    .. code:: python

        for source in get_sources("organizations/123456"):
            print(source.display_name)

    :type parent_name: :py:class:`str`
    :param parent_name: the parent name, e.g. "organizations/123456" or "projects/123456"

    :type credentials: :py:class:`google_auth:google.oauth2.credentials.Credentials`
    :param credentials: the credentials object to use when making the API call, if not to
        use the account running the function for authentication.

    :type client: :py:class:`gcp_scc:google.cloud.securitycenter.SecurityCenterClient`
    :param client: (optional) the SCC client to use for API calls. will generate one if not passed.

    :rtype: :py:class:`list` :py:class:`gcp_scc:google.cloud.securitycenter_v1.types.Sources`
    :returns: a list of SCC Source objects
    """
    if not client:
        client = securitycenter.SecurityCenterClient(credentials=credentials)
    return [source for source in client.list_sources(parent=parent_name)]


def parse_notification(notification, ignore_unknown_fields=False):
    """This method takes the notification received from a SCC Notification Pubsub
    and returns a Python object.

    .. code:: python

        import base64
        from bibt.gcp import scc
        def main(event, context):
            raw_notification = base64.b64decode(event["data"]).decode("utf-8")
            notification = scc.parse_notification(raw_notification)
            print(notification.finding.name, notification.finding.category, notification.resource.name)

    :type notification: :py:class:`str` OR :py:class:`dict`
    :param notification: the notification to parse. may be either a dictionary or a json string.

    :type ignore_unknown_fields: :py:class:`bool`
    :param ignore_unknown_fields: whether or not unrecognized fields should be ignored when parsing.
        fields may be unrecognized if they are added to the finding category in later releases of
        google-cloud-securitycenter library.

    :rtype: :py:class:`gcp_scc:google.cloud.securitycenter_v1.types.ListFindingsResponse.ListFindingsResult`
    :returns: the finding notification as a Python object.

    :raises TypeError: if it is passed anything aside from a :py:class:`str` or :py:class:`dict`, or
        it has an issue parsing the finding into an object.
    """
    from google.cloud.securitycenter_v1.types import ListFindingsResponse

    if isinstance(notification, dict):
        import json

        notification = json.dumps(notification)
    elif not isinstance(notification, str):
        raise TypeError(
            "Notification must be either a string or a dict! "
            f"You passed a {type(notification).__name__}"
        )
    try:
        return ListFindingsResponse.ListFindingsResult.from_json(
            notification, ignore_unknown_fields=ignore_unknown_fields
        )
    except ParseError as e:
        raise TypeError(
            "Error encountered while attempting to parse into finding object, "
            "try setting ignore_unknown_fields=True or updating the google-cloud-securitycenter package: "
            f"{type(e).__name__}: {e}"
        )


def set_finding_state(finding_name, state="INACTIVE", credentials=None, client=None):
    """This method will set the finding to inactive state by default.

    .. code:: python

        from bibt.gcp import scc
        scc.set_finding_state(
            finding_name="organizations/123123/sources/123123/findings/123123"
        )

    :type finding_name: :py:class:`str`
    :param finding_name: the finding.name whose state to modify.

    :type state: :py:class:`str`
    :param state: the state to set the finding to. must be valid according to
        :py:class:`gcp_scc:google.cloud.securitycenter_v1.types.Finding.State`.
        defaults to "INACTIVE".

    :type credentials: :py:class:`google_auth:google.oauth2.credentials.Credentials`
    :param credentials: the credentials object to use when making the API call, if not to
        use the account running the function for authentication.

    :type client: :py:class:`gcp_scc:google.cloud.securitycenter.SecurityCenterClient`
    :param client: (optional) the SCC client to use for API calls. will generate one if not passed.

    :raises KeyError: if the argument supplied for ``state`` is not a valid name
        for :py:class:`gcp_scc:google.cloud.securitycenter_v1.types.Finding.State`.
    """
    try:
        state_enum = Finding.State[state]
    except KeyError:
        raise KeyError(
            f"Supplied state ({state}) not recognized. Must be one of {[s.name for s in Finding.State]}"
        )

    if not client:
        client = securitycenter.SecurityCenterClient(credentials=credentials)
    client.set_finding_state(
        request={
            "name": finding_name,
            "state": state_enum,
            "start_time": datetime.now(pytz.UTC),
        }
    )
    return


def set_security_marks(scc_name, marks, gcp_org_id=None, credentials=None, client=None):
    """Sets security marks on an asset or finding in SCC. Usually, if we're setting
    them on a finding, it means we're setting a mark of ``reason`` for setting it to inactive.
    if we're setting them on an asset, it is usually to ``allow_{finding.category}=true`` .

    .. code:: python

        from bibt.gcp import scc
        scc.set_security_mark(
            scc_name="organizations/123123/sources/123123/findings/123123",
            marks={
                'reason': 'intentionally public'
            }
        )

    :type scc_name: :py:class:`str`
    :param scc_name: may be either an SCC ``finding.name`` or a GCP ``resourceName`` . format is:
        ``organizations/123123/sources/123123/findings/123123`` or ``//storage.googleapis.com/my-bucket``.
        **note this does not accept ``asset.name`` format!**

    :type marks: :py:class:`dict`
    :param marks: a dictionary of marks to set on the asset or finding. format it:
        ``marks={"allow_public_bucket_acl": "true", "reason": "intentional"}`` . **note this must be a dict
        and not a list!**

    :type credentials: :py:class:`google_auth:google.oauth2.credentials.Credentials`
    :param credentials: the credentials object to use when making the API call, if not to
        use the account running the function for authentication.

    :type client: :py:class:`gcp_scc:google.cloud.securitycenter.SecurityCenterClient`
    :param client: (optional) the SCC client to use for API calls. will generate one if not passed.

    :raises TypeError: if the argument supplied for ``marks`` is not a :py:class:`dict`
    """
    if not isinstance(marks, dict):
        raise TypeError(
            f"Argument: 'marks' must be a dict! You passed a {type(marks).__name__}."
        )
    if scc_name.startswith("//"):
        _LOGGER.debug(f'Assuming type "asset" from scc_name format: {scc_name}')
        if not gcp_org_id:
            raise TypeError(
                f"When setting security marks on an asset, a `gcp_org_id` must be supplied."
            )
        a = get_asset(scc_name, gcp_org_id, credentials)
        scc_name = a.name

    mask_paths = [f"marks.{k}" for k in marks.keys()]

    if not client:
        client = securitycenter.SecurityCenterClient(credentials=credentials)
    client.update_security_marks(
        request={
            "security_marks": {"name": f"{scc_name}/securityMarks", "marks": marks},
            "update_mask": field_mask_pb2.FieldMask(paths=mask_paths),
        }
    )
    return


def set_mute_status(finding_name, status="MUTED", credentials=None, client=None):
    """This method will mute the finding by default. May also be used to unmute with
    ``status="UNMUTED"`` .

    .. code:: python

        from bibt.gcp import scc
        scc.set_mute_status(
            finding_name="organizations/123123/sources/123123/findings/123123"
        )

    :type finding_name: :py:class:`str`
    :param finding_name: the finding.name whose state to modify.

    :type status: :py:class:`str`
    :param status: whether the finding should be muted or unmuted. must be a valid value of
        ``MUTED`` or ``UNMUTED`` . defaults to ``MUTED`` .

    :type credentials: :py:class:`google_auth:google.oauth2.credentials.Credentials`
    :param credentials: the credentials object to use when making the API call, if not to
        use the account running the function for authentication.

    :type client: :py:class:`gcp_scc:google.cloud.securitycenter.SecurityCenterClient`
    :param client: (optional) the SCC client to use for API calls. will generate one if not passed.

    :raises KeyError: if the argument supplied for ``status`` is not ``MUTED`` or ``UNMUTED`` .
    """
    if not client:
        client = securitycenter.SecurityCenterClient(credentials=credentials)

    if status in ["MUTED", "UNMUTED"]:
        mute_enum = Finding.Mute[status]
    else:
        raise KeyError(
            f"Supplied status ({status}) not recognized. Must be one of ['MUTED','UNMUTED']"
        )

    client.set_mute(request={"name": finding_name, "mute": mute_enum})
    return


def _get_all_findings_iter(request, credentials=None, client=None):
    """A helper method to make a list_findings API call. Expects a valid ``request``
    dictionary and can optionally be supplied with a credentials object.

    Returns: :py:class:`gcp_scc:google.cloud.securitycenter_v1.services.security_center.pagers.ListFindingsPager`
    """
    if not client:
        client = securitycenter.SecurityCenterClient(credentials=credentials)
    return client.list_findings(request)


def _get_all_assets_iter(request, credentials=None, client=None):
    """A helper method to make a list_assets API call. Expects a valid ``request``
    dictionary and can optionally be supplied with a credentials object.

    Returns: :py:class:`gcp_scc:google.cloud.securitycenter_v1.services.security_center.pagers.ListAssetsPager`
    """
    if not client:
        client = securitycenter.SecurityCenterClient(credentials=credentials)
    return client.list_assets(request)


def _get(obj, attr, raise_exception):
    """A helper function to get attributes. Works with objects as well as dictionaries.
    Will attempt in this order: 1) exactly what was passed (obj.my_attr) 2) underscored (obj.my_attr) 3) camelized (obj.myAttr) 4) key (obj[attr])

    Returns: whatever the value of the attribute is.
    Raises: KeyError if the key could not be found in the object.
    """
    try:
        return getattr(obj, attr)
    except AttributeError:
        pass
    try:
        return getattr(obj, underscore(attr))
    except AttributeError:
        pass
    try:
        return getattr(obj, camelize(attr, False))
    except AttributeError:
        pass
    try:
        return obj.get(attr)
    except (KeyError, AttributeError):
        if raise_exception:
            raise KeyError(
                f"Could not find attribute value [{attr}] in object of type: {type(obj).__name__}"
            )
        else:
            _LOGGER.error(
                f"Could not find attribute value [{attr}] in object of type: {type(obj).__name__}; returning None."
            )
            return None
