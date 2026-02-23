"""
Tests for wrap_with_sandbox behavior and restriction pattern semantics.

Ported from: test/sandbox/wrap-with-sandbox.test.ts
"""

from __future__ import annotations

import os
import tempfile

from srt.linux_sandbox import (
    FsReadRestrictionConfig as LinuxRead,
)
from srt.linux_sandbox import (
    FsWriteRestrictionConfig as LinuxWrite,
)
from srt.linux_sandbox import (
    LinuxSandboxParams,
    wrap_command_with_sandbox_linux,
)
from srt.macos_sandbox import (
    FsReadRestrictionConfig as MacRead,
)
from srt.macos_sandbox import (
    FsWriteRestrictionConfig as MacWrite,
)
from srt.macos_sandbox import (
    MacOSSandboxParams,
    wrap_command_with_sandbox_macos,
)
from tests.conftest import skip_if_not_linux, skip_if_not_macos

COMMAND = "echo hello"


class TestNoSandboxingNeeded:
    """When no restrictions are configured, the command should be returned unchanged."""

    @skip_if_not_linux
    def test_unchanged_when_no_restrictions_linux(self):
        result = wrap_command_with_sandbox_linux(
            LinuxSandboxParams(
                command=COMMAND,
                needs_network_restriction=False,
                read_config=LinuxRead(deny_only=[]),
                write_config=None,
            )
        )
        assert result == COMMAND

    @skip_if_not_macos
    def test_unchanged_when_no_restrictions_macos(self):
        result = wrap_command_with_sandbox_macos(
            MacOSSandboxParams(
                command=COMMAND,
                needs_network_restriction=False,
                read_config=MacRead(deny_only=[]),
                write_config=None,
            )
        )
        assert result == COMMAND

    @skip_if_not_linux
    def test_unchanged_with_none_read_linux(self):
        result = wrap_command_with_sandbox_linux(
            LinuxSandboxParams(
                command=COMMAND,
                needs_network_restriction=False,
                read_config=None,
                write_config=None,
            )
        )
        assert result == COMMAND

    @skip_if_not_macos
    def test_unchanged_with_none_read_macos(self):
        result = wrap_command_with_sandbox_macos(
            MacOSSandboxParams(
                command=COMMAND,
                needs_network_restriction=False,
                read_config=None,
                write_config=None,
            )
        )
        assert result == COMMAND


class TestReadRestrictions:
    """Deny-only read pattern semantics."""

    @skip_if_not_linux
    def test_empty_deny_still_wraps_with_write_linux(self):
        result = wrap_command_with_sandbox_linux(
            LinuxSandboxParams(
                command=COMMAND,
                needs_network_restriction=False,
                read_config=LinuxRead(deny_only=[]),
                write_config=LinuxWrite(allow_only=["/tmp"], deny_within_allow=[]),
            )
        )
        assert result != COMMAND
        assert "bwrap" in result

    @skip_if_not_linux
    def test_non_empty_deny_wraps_linux(self):
        result = wrap_command_with_sandbox_linux(
            LinuxSandboxParams(
                command=COMMAND,
                needs_network_restriction=False,
                read_config=LinuxRead(deny_only=["/secret"]),
                write_config=None,
            )
        )
        assert result != COMMAND
        assert "bwrap" in result


class TestWriteRestrictions:
    """Allow-only write pattern semantics."""

    @skip_if_not_linux
    def test_none_write_no_restrictions_linux(self):
        result = wrap_command_with_sandbox_linux(
            LinuxSandboxParams(
                command=COMMAND,
                needs_network_restriction=False,
                read_config=LinuxRead(deny_only=["/secret"]),
                write_config=None,
            )
        )
        assert result != COMMAND

    @skip_if_not_linux
    def test_empty_allow_maximally_restrictive_linux(self):
        result = wrap_command_with_sandbox_linux(
            LinuxSandboxParams(
                command=COMMAND,
                needs_network_restriction=False,
                read_config=LinuxRead(deny_only=[]),
                write_config=LinuxWrite(allow_only=[], deny_within_allow=[]),
            )
        )
        assert result != COMMAND
        assert "bwrap" in result

    @skip_if_not_macos
    def test_any_write_config_means_restrictions_macos(self):
        result = wrap_command_with_sandbox_macos(
            MacOSSandboxParams(
                command=COMMAND,
                needs_network_restriction=False,
                read_config=MacRead(deny_only=[]),
                write_config=MacWrite(allow_only=[], deny_within_allow=[]),
            )
        )
        assert result != COMMAND
        assert "sandbox-exec" in result


class TestNetworkRestrictions:
    """Network isolation semantics."""

    @skip_if_not_linux
    def test_no_network_restriction_no_unshare_linux(self):
        result = wrap_command_with_sandbox_linux(
            LinuxSandboxParams(
                command=COMMAND,
                needs_network_restriction=False,
                read_config=LinuxRead(deny_only=["/secret"]),
                write_config=None,
            )
        )
        assert result != COMMAND
        assert "--unshare-net" not in result

    @skip_if_not_macos
    def test_no_network_restriction_macos(self):
        result = wrap_command_with_sandbox_macos(
            MacOSSandboxParams(
                command=COMMAND,
                needs_network_restriction=False,
                read_config=MacRead(deny_only=["/secret"]),
                write_config=None,
            )
        )
        assert result != COMMAND
        assert "sandbox-exec" in result

    @skip_if_not_linux
    def test_network_restriction_blocks_all_without_proxy_linux(self):
        result = wrap_command_with_sandbox_linux(
            LinuxSandboxParams(
                command=COMMAND,
                needs_network_restriction=True,
                http_socket_path=None,
                socks_socket_path=None,
                read_config=LinuxRead(deny_only=[]),
                write_config=LinuxWrite(allow_only=["/tmp"], deny_within_allow=[]),
            )
        )
        assert result != COMMAND
        assert "bwrap" in result
        assert "--unshare-net" in result
        assert "HTTP_PROXY" not in result

    @skip_if_not_macos
    def test_network_restriction_blocks_all_without_proxy_macos(self):
        result = wrap_command_with_sandbox_macos(
            MacOSSandboxParams(
                command=COMMAND,
                needs_network_restriction=True,
                http_proxy_port=None,
                socks_proxy_port=None,
                read_config=MacRead(deny_only=[]),
                write_config=MacWrite(allow_only=["/tmp"], deny_within_allow=[]),
            )
        )
        assert result != COMMAND
        assert "sandbox-exec" in result

    @skip_if_not_linux
    def test_network_restriction_with_proxy_linux(self):
        http_sock = os.path.join(tempfile.gettempdir(), f"test-http-{os.getpid()}.sock")
        socks_sock = os.path.join(tempfile.gettempdir(), f"test-socks-{os.getpid()}.sock")
        try:
            with open(http_sock, "w"):
                pass
            with open(socks_sock, "w"):
                pass

            result = wrap_command_with_sandbox_linux(
                LinuxSandboxParams(
                    command=COMMAND,
                    needs_network_restriction=True,
                    http_socket_path=http_sock,
                    socks_socket_path=socks_sock,
                    http_proxy_port=3128,
                    socks_proxy_port=1080,
                    read_config=LinuxRead(deny_only=[]),
                    write_config=LinuxWrite(allow_only=["/tmp"], deny_within_allow=[]),
                )
            )
            assert result != COMMAND
            assert "bwrap" in result
            assert "--unshare-net" in result
            assert http_sock in result
            assert socks_sock in result
        finally:
            for s in (http_sock, socks_sock):
                try:
                    os.unlink(s)
                except OSError:
                    pass

    @skip_if_not_macos
    def test_network_restriction_with_proxy_macos(self):
        result = wrap_command_with_sandbox_macos(
            MacOSSandboxParams(
                command=COMMAND,
                needs_network_restriction=True,
                http_proxy_port=3128,
                socks_proxy_port=1080,
                read_config=MacRead(deny_only=[]),
                write_config=MacWrite(allow_only=["/tmp"], deny_within_allow=[]),
            )
        )
        assert result != COMMAND
        assert "sandbox-exec" in result
        assert "HTTP_PROXY" in result
        assert "HTTPS_PROXY" in result
