# Changelog

[PyPI History](https://pypi.org/project/bibt-gcp-scc/#history)

## 1.0.0 (2023-08-10)

- **[BREAKING CHANGE]** [SCC Asset API is being deprecated](https://cloud.google.com/security-command-center/docs/release-notes#June_28_2023). This version simply remove all calls going to this API.

## 0.8.0 (2023-03-07)

- Updated dependencies across the project (pre-commit, github actions, python deps).

## 0.6.16 (2022-09-13)

- Added support for `bibt.gcp.scc.Client` to `bibt.gcp.scc.FindingInfo` and `bibt.gcp.scc.FindingParentInfo`. A `Client` can be passed to these classes' constructors for use by that class's methods. This can significantly cut down on API calls as authentication only needs to happen once.

## 0.6.13 (2022-09-09)

- Added `event_time`, `create_time`, and `source` attributes to the FindingInfo class.

## 0.6.11 (2022-09-08)

- **New class:** `Client` constructs a single SecurityCommandCenter client object and can be used to call the API without reauthenticating each time.
- Support for passing clients to any relevant function.

## 0.6.4 (2022-08-30)

### Features

- **New function:** `set_mute_status()` brings the functionality to MUTE or UNMUTE a finding in SCC.
- Fixes to docstrings so that readthedocs builds it correctly.

## 0.6.3 (2022-08-24)

### Features

- **New function:** `get_sources()` will return a list of all SCC sources under the provided parent (parent in the form of `organizations/123456`, for example).
- **New classes:** `FindingInfo` extracts some characteristics of interest from findings and is category-agnostic. `FindingParentInfo` is used by `FindingInfo` to gather information about the concerned resource's parent project/folder/organization.

## 0.6.2 (2022-08-09)

### Features

- added support for "order_by" argument in `get_all_findings()` and `get_all_assets()`. See here for details on valid values: https://googleapis.dev/python/securitycenter/latest/securitycenter_v1/types.html#google.cloud.securitycenter_v1.types.ListAssetsRequest.order_by

## 0.6.0 (2022-08-01)

### Features

- **[BREAKING CHANGE]** `set_security_marks()`: for setting security marks on an asset, now accepts a `resoruceName` instead of an `asset.name`. Additionally, when setting a mark on an asset, a `gcp_org_id` must be supplied.
- **New function:** `get_security_marks()` returns security marks on an asset or finding as a dictionary.
- fixed a typo in `get_finding()` which compiled an improper filter.

## 0.5.0 (2022-07-28)

### Features

- `parse_notification()` now allows the option to ignore_unknown_fields when parsing. Additionally, it will intercept exceptions thrown when parsing and spit out its own TypeError.

## 0.4.0 (2022-07-26)

### Features

- **New function:** `parse_notification()` may be used to generate a Python object from a SCC notification received via pubsub.
- **New function:** `get_value()` can be used to extract field values from finding notification objects (among other objects).

## 0.2.0 (2022-07-18)

### Features

- **[BREAKING CHANGE]** Instead of return lists of Finding objects, `get_all_findings` and `get_all_assets` return iterators which improves reliability when dealing with large result sets.
- Added code samples to docstrings.
- Removed unused dependencies.

## 0.1.0 (2022-07-18)

### Features

- Initial release. Basic finding and asset functionality.
