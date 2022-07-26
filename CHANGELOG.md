# Changelog

[PyPI History](https://pypi.org/project/bibt-gcp-scc/#history)

## 0.3.0 (2022-07-26)

### Features

* **New function:** `parse_notification()` may be used to generate a Python object from a SCC notification received via pubsub.
* Removed unused imports.

## 0.2.0 (2022-07-18)

### Features

* **[BREAKING CHANGE]** Instead of return lists of Finding objects, `get_all_findings` and `get_all_assets` return iterators which improves reliability when dealing with large result sets.
* Added code samples to docstrings.
* Removed unused dependencies.

## 0.1.0 (2022-07-18)

### Features

* Initial release. Basic finding and asset functionality.
