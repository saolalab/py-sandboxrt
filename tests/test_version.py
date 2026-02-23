"""Tests for package version."""

import srt


def test_version_exists():
    """Test that version is defined."""
    assert hasattr(srt, "__version__")


def test_version_format():
    """Test that version follows semantic versioning pattern."""
    version = srt.__version__
    parts = version.split(".")
    assert len(parts) >= 2
    assert all(part.isdigit() or part.split("-")[0].isdigit() for part in parts)
