"""
Tests for symlink boundary validation.

Ported from: test/sandbox/symlink-boundary.test.ts
"""

from __future__ import annotations

import os
import shutil

import pytest

from srt.sandbox_utils import is_symlink_outside_boundary, normalize_path_for_sandbox
from tests.conftest import skip_if_not_macos


class TestIsSymlinkOutsideBoundary:
    """Unit tests for is_symlink_outside_boundary()."""

    class TestOutsideBoundaryDetection:
        def test_symlink_to_root(self):
            assert is_symlink_outside_boundary("/tmp/claude", "/") is True
            assert is_symlink_outside_boundary("/private/tmp/claude", "/") is True
            assert is_symlink_outside_boundary("/home/user/data", "/") is True

        def test_symlink_to_ancestor(self):
            assert is_symlink_outside_boundary("/tmp/claude/data", "/tmp") is True
            assert is_symlink_outside_boundary("/tmp/claude/data", "/tmp/claude") is True
            assert is_symlink_outside_boundary("/home/user/project/src", "/home") is True
            assert is_symlink_outside_boundary("/home/user/project/src", "/home/user") is True

        def test_very_short_resolved(self):
            assert is_symlink_outside_boundary("/tmp/claude", "/tmp") is True
            assert is_symlink_outside_boundary("/var/data", "/var") is True
            assert is_symlink_outside_boundary("/usr/local/bin", "/usr") is True

        def test_unrelated_directory(self):
            assert is_symlink_outside_boundary("/tmp/claude", "/Users/dworken") is True
            assert is_symlink_outside_boundary("/tmp/claude", "/home/user") is True
            assert is_symlink_outside_boundary("/tmp/claude", "/etc") is True
            assert is_symlink_outside_boundary("/tmp/claude", "/opt/data") is True
            assert is_symlink_outside_boundary("/var/data", "/Users/someone/data") is True

    class TestValidResolutions:
        def test_same_path(self):
            assert is_symlink_outside_boundary("/tmp/claude", "/tmp/claude") is False
            assert is_symlink_outside_boundary("/home/user", "/home/user") is False

        def test_macos_tmp_canonical(self):
            assert is_symlink_outside_boundary("/tmp/claude", "/private/tmp/claude") is False
            assert (
                is_symlink_outside_boundary("/tmp/claude/data", "/private/tmp/claude/data") is False
            )

        def test_macos_var_canonical(self):
            assert (
                is_symlink_outside_boundary("/var/folders/xx/yy", "/private/var/folders/xx/yy")
                is False
            )

        def test_deeper_resolution(self):
            assert is_symlink_outside_boundary("/tmp/claude", "/tmp/claude/actual") is False
            assert is_symlink_outside_boundary("/home/user", "/home/user/real") is False

    class TestEdgeCases:
        def test_trailing_slashes(self):
            assert is_symlink_outside_boundary("/tmp/claude/", "/") is True

        def test_private_paths_resolve_to_self(self):
            assert (
                is_symlink_outside_boundary("/private/tmp/claude", "/private/tmp/claude") is False
            )
            assert is_symlink_outside_boundary("/private/var/data", "/private/var/data") is False


@skip_if_not_macos
class TestGlobPatternSymlinkBoundary:
    """Tests for glob pattern symlink boundary validation (macOS only)."""

    @pytest.fixture(autouse=True)
    def cleanup_tmp_claude(self):
        yield
        for p in ("/tmp/claude", "/private/tmp/claude"):
            try:
                if os.path.islink(p) or os.path.isfile(p):
                    os.unlink(p)
                elif os.path.isdir(p):
                    shutil.rmtree(p, ignore_errors=True)
            except OSError:
                pass

    def test_preserve_glob_when_symlink_to_root(self):
        for p in ("/tmp/claude", "/private/tmp/claude"):
            try:
                if os.path.islink(p) or os.path.isfile(p):
                    os.unlink(p)
                elif os.path.isdir(p):
                    shutil.rmtree(p)
            except OSError:
                pass

        os.symlink("/", "/tmp/claude")
        result = normalize_path_for_sandbox("/tmp/claude/**")
        assert result == "/tmp/claude/**"
        assert result != "/**"

    def test_preserve_glob_when_symlink_to_parent(self):
        for p in ("/tmp/claude", "/private/tmp/claude"):
            try:
                if os.path.islink(p) or os.path.isfile(p):
                    os.unlink(p)
                elif os.path.isdir(p):
                    shutil.rmtree(p)
            except OSError:
                pass

        os.symlink("/tmp", "/tmp/claude")
        result = normalize_path_for_sandbox("/tmp/claude/**")
        assert result == "/tmp/claude/**"
        assert result != "/tmp/**"
