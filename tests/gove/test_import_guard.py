import importlib


def test_gove_subpackage_importable():
    mod = importlib.import_module("acgs_lite.gove")
    assert hasattr(mod, "GOVE_AVAILABLE")


def test_available_flag_matches_reality():
    from acgs_lite.gove import GOVE_AVAILABLE
    try:
        import gove_zone  # noqa: F401
        assert GOVE_AVAILABLE is True
    except ImportError:
        assert GOVE_AVAILABLE is False
