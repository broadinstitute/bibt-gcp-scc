# Changelog

[PyPI History](https://pypi.org/project/bibt-gcp-scc/#history)

## 0.6.2 (2022-08-09)

### Features

* added support for "order_by" argument in `get_all_findings()` and `get_all_assets()`. See here for details on valid values: https://googleapis.dev/python/securitycenter/latest/securitycenter_v1/types.html#google.cloud.securitycenter_v1.types.ListAssetsRequest.order_by

## 0.6.0 (2022-08-01)

### Features

* **[BREAKING CHANGE]** `set_security_marks()`: for setting security marks on an asset, now accepts a `resoruceName` instead of an `asset.name`. Additionally, when setting a mark on an asset, a `gcp_org_id` must be supplied.
* **New function:** `get_security_marks()` returns security marks on an asset or finding as a dictionary.
* fixed a typo in `get_finding()` which compiled an improper filter.

## 0.5.0 (2022-07-28)

### Features

* `parse_notification()` now allows the option to ignore_unknown_fields when parsing. Additionally, it will intercept exceptions thrown when parsing and spit out its own TypeError.

## 0.4.0 (2022-07-26)

### Features

* **New function:** `parse_notification()` may be used to generate a Python object from a SCC notification received via pubsub.
* **New function:** `get_value()` can be used to extract field values from finding notification objects (among other objects).

## 0.2.0 (2022-07-18)

### Features

* **[BREAKING CHANGE]** Instead of return lists of Finding objects, `get_all_findings` and `get_all_assets` return iterators which improves reliability when dealing with large result sets.
* Added code samples to docstrings.
* Removed unused dependencies.

## 0.1.0 (2022-07-18)

### Features

* Initial release. Basic finding and asset functionality.
