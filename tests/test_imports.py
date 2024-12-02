def test_level1_import():
    try:
        import bibt  # noqa: F401
    except ImportError:
        assert False
    assert True


def test_level2_import():
    try:
        from bibt import gcp  # noqa: F401
    except ImportError:
        assert False
    assert True


def test_level3_import():
    try:
        from bibt.gcp import scc  # noqa: F401
    except ImportError:
        assert False
    assert True


def test_level4_import():
    try:
        from bibt.gcp.scc import FindingInfo  # noqa: F401
    except ImportError:
        assert False
    assert True


def test_level4_impor_method():
    try:
        from bibt.gcp.scc import get_all_findings  # noqa: F401
    except ImportError:
        assert False
    assert True
