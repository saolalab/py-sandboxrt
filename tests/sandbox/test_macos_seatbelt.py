"""
Tests for macOS Seatbelt sandbox profile generation and enforcement.

Ported from: test/sandbox/macos-seatbelt.test.ts

IMPORTANT: These tests use /private/tmp (not pytest's tmp_path which is under
/var/folders/...) because /var/folders is automatically allowed by the sandbox
via the TMPDIR parent rule.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time

import pytest

from srt.macos_sandbox import (
    FsReadRestrictionConfig,
    FsWriteRestrictionConfig,
    MacOSSandboxParams,
    wrap_command_with_sandbox_macos,
)
from tests.conftest import skip_if_not_macos


def _make_test_base() -> str:
    """Create a unique test dir under /private/tmp (outside TMPDIR parent)."""
    base = f"/private/tmp/seatbelt-test-{os.getpid()}-{int(time.time())}"
    os.makedirs(base, exist_ok=True)
    return base


@skip_if_not_macos
class TestSeatbeltReadBypassPrevention:
    """Verify that files protected by read deny rules cannot be exfiltrated via mv."""

    @pytest.fixture(autouse=True)
    def setup_test_dirs(self):
        self.test_base = _make_test_base()
        self.denied_dir = os.path.join(self.test_base, "denied-dir")
        self.secret_file = os.path.join(self.denied_dir, "secret.txt")
        self.secret_content = "SECRET_CREDENTIAL_DATA"
        self.moved_file = os.path.join(self.test_base, "moved-secret.txt")
        self.moved_dir = os.path.join(self.test_base, "moved-denied-dir")

        os.makedirs(self.denied_dir, exist_ok=True)
        with open(self.secret_file, "w") as f:
            f.write(self.secret_content)

        self.glob_dir = os.path.join(self.test_base, "glob-test")
        self.glob_file1 = os.path.join(self.glob_dir, "secret1.txt")
        self.glob_file2 = os.path.join(self.glob_dir, "secret2.log")
        self.glob_moved = os.path.join(self.test_base, "moved-glob.txt")

        os.makedirs(self.glob_dir, exist_ok=True)
        with open(self.glob_file1, "w") as f:
            f.write("GLOB_SECRET_1")
        with open(self.glob_file2, "w") as f:
            f.write("GLOB_SECRET_2")

        yield
        if os.path.exists(self.test_base):
            shutil.rmtree(self.test_base, ignore_errors=True)

    def _run(self, cmd: str, timeout: int = 5) -> subprocess.CompletedProcess:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)

    def test_block_move_read_denied_file(self):
        read_config = FsReadRestrictionConfig(deny_only=[self.denied_dir])
        wrapped = wrap_command_with_sandbox_macos(
            MacOSSandboxParams(
                command=f"mv {self.secret_file} {self.moved_file}",
                needs_network_restriction=False,
                read_config=read_config,
            )
        )
        result = self._run(wrapped)
        assert result.returncode != 0
        assert "operation not permitted" in (result.stderr or "").lower()
        assert os.path.exists(self.secret_file)
        assert not os.path.exists(self.moved_file)

    def test_still_blocks_reading(self):
        read_config = FsReadRestrictionConfig(deny_only=[self.denied_dir])
        wrapped = wrap_command_with_sandbox_macos(
            MacOSSandboxParams(
                command=f"cat {self.secret_file}",
                needs_network_restriction=False,
                read_config=read_config,
            )
        )
        result = self._run(wrapped)
        assert result.returncode != 0
        assert self.secret_content not in result.stdout

    def test_block_move_ancestor_directory(self):
        read_config = FsReadRestrictionConfig(deny_only=[self.denied_dir])
        wrapped = wrap_command_with_sandbox_macos(
            MacOSSandboxParams(
                command=f"mv {self.denied_dir} {self.moved_dir}",
                needs_network_restriction=False,
                read_config=read_config,
            )
        )
        result = self._run(wrapped)
        assert result.returncode != 0
        assert os.path.exists(self.denied_dir)
        assert not os.path.exists(self.moved_dir)

    def test_block_move_glob_matching_file(self):
        glob_pattern = os.path.join(self.glob_dir, "*.txt")
        read_config = FsReadRestrictionConfig(deny_only=[glob_pattern])
        wrapped = wrap_command_with_sandbox_macos(
            MacOSSandboxParams(
                command=f"mv {self.glob_file1} {self.glob_moved}",
                needs_network_restriction=False,
                read_config=read_config,
            )
        )
        result = self._run(wrapped)
        assert result.returncode != 0
        assert os.path.exists(self.glob_file1)
        assert not os.path.exists(self.glob_moved)

    def test_still_blocks_reading_glob(self):
        glob_pattern = os.path.join(self.glob_dir, "*.txt")
        read_config = FsReadRestrictionConfig(deny_only=[glob_pattern])
        wrapped = wrap_command_with_sandbox_macos(
            MacOSSandboxParams(
                command=f"cat {self.glob_file1}",
                needs_network_restriction=False,
                read_config=read_config,
            )
        )
        result = self._run(wrapped)
        assert result.returncode != 0

    def test_allow_non_matching_glob_file(self):
        glob_pattern = os.path.join(self.glob_dir, "*.txt")
        read_config = FsReadRestrictionConfig(deny_only=[glob_pattern])
        wrapped = wrap_command_with_sandbox_macos(
            MacOSSandboxParams(
                command=f"cat {self.glob_file2}",
                needs_network_restriction=False,
                read_config=read_config,
            )
        )
        result = self._run(wrapped)
        assert result.returncode == 0
        assert "GLOB_SECRET_2" in result.stdout


@skip_if_not_macos
class TestSeatbeltWriteRestrictions:
    """Test write allow/deny enforcement."""

    @pytest.fixture(autouse=True)
    def setup_dirs(self):
        self.test_base = _make_test_base()
        self.write_dir = os.path.join(self.test_base, "writeable")
        os.makedirs(self.write_dir, exist_ok=True)
        with open(os.path.join(self.test_base, "readonly.txt"), "w") as f:
            f.write("ORIGINAL")
        yield
        if os.path.exists(self.test_base):
            shutil.rmtree(self.test_base, ignore_errors=True)

    def _run(self, cmd: str, timeout: int = 5) -> subprocess.CompletedProcess:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)

    def test_allow_write_within_allowed_path(self):
        write_config = FsWriteRestrictionConfig(
            allow_only=[self.write_dir],
            deny_within_allow=[],
        )
        wrapped = wrap_command_with_sandbox_macos(
            MacOSSandboxParams(
                command=f'echo "NEW" > {os.path.join(self.write_dir, "new.txt")}',
                needs_network_restriction=False,
                write_config=write_config,
            )
        )
        result = self._run(wrapped)
        assert result.returncode == 0
        assert os.path.exists(os.path.join(self.write_dir, "new.txt"))

    def test_block_write_outside_allowed_path(self):
        write_config = FsWriteRestrictionConfig(
            allow_only=[self.write_dir],
            deny_within_allow=[],
        )
        outside = os.path.join(self.test_base, "outside.txt")
        wrapped = wrap_command_with_sandbox_macos(
            MacOSSandboxParams(
                command=f'echo "HACKED" > {outside}',
                needs_network_restriction=False,
                write_config=write_config,
            )
        )
        result = self._run(wrapped)
        assert result.returncode != 0
        assert not os.path.exists(outside)

    def test_deny_within_allow(self):
        deny_file = os.path.join(self.write_dir, "secret.env")
        with open(deny_file, "w") as f:
            f.write("ORIGINAL")

        write_config = FsWriteRestrictionConfig(
            allow_only=[self.write_dir],
            deny_within_allow=[deny_file],
        )
        wrapped = wrap_command_with_sandbox_macos(
            MacOSSandboxParams(
                command=f'echo "OVERWRITTEN" > {deny_file}',
                needs_network_restriction=False,
                write_config=write_config,
            )
        )
        result = self._run(wrapped)
        assert result.returncode != 0
        with open(deny_file) as f:
            assert f.read() == "ORIGINAL"
