"""Tests for workspace-root mode and per-command overrides."""

from __future__ import annotations

import sys

import pytest

from srt.config import FilesystemConfig, SandboxRuntimeConfig
from srt.sandbox_manager import CommandOverrides, SandboxManager, _essential_read_paths


class TestWorkspaceRootMode:
    """workspace_root auto-populates filesystem allow_read/allow_write."""

    def test_auto_populates_allow_read(self):
        mgr = SandboxManager()
        cfg = SandboxRuntimeConfig(workspace_root="/home/user/project")
        mgr._config = cfg
        mgr._apply_workspace_root()
        assert "/home/user/project" in cfg.filesystem.allow_read
        for p in _essential_read_paths():
            assert p in cfg.filesystem.allow_read

    def test_auto_populates_allow_write(self):
        mgr = SandboxManager()
        cfg = SandboxRuntimeConfig(workspace_root="/home/user/project")
        mgr._config = cfg
        mgr._apply_workspace_root()
        assert "/home/user/project" in cfg.filesystem.allow_write
        assert "/tmp" in cfg.filesystem.allow_write

    def test_does_not_overwrite_explicit_allow_read(self):
        mgr = SandboxManager()
        cfg = SandboxRuntimeConfig(
            workspace_root="/home/user/project",
            filesystem=FilesystemConfig(allow_read=["/custom/path"]),
        )
        mgr._config = cfg
        mgr._apply_workspace_root()
        assert cfg.filesystem.allow_read == ["/custom/path"]

    def test_does_not_overwrite_explicit_allow_write(self):
        mgr = SandboxManager()
        cfg = SandboxRuntimeConfig(
            workspace_root="/home/user/project",
            filesystem=FilesystemConfig(allow_write=["/custom/write"]),
        )
        mgr._config = cfg
        mgr._apply_workspace_root()
        assert cfg.filesystem.allow_write == ["/custom/write"]

    def test_noop_without_workspace_root(self):
        mgr = SandboxManager()
        cfg = SandboxRuntimeConfig()
        mgr._config = cfg
        mgr._apply_workspace_root()
        assert cfg.filesystem.allow_read == []
        assert cfg.filesystem.allow_write == []


class TestCommandOverridesConfig:
    """CommandOverrides dataclass validation."""

    def test_default_values(self):
        o = CommandOverrides()
        assert o.extra_allow_read is None
        assert o.extra_allow_write is None
        assert o.extra_deny_read is None
        assert o.extra_deny_write is None
        assert o.extra_allowed_domains is None
        assert o.env_mode is None
        assert o.env_extra_allow == []
        assert o.env_inject == {}

    def test_custom_values(self):
        o = CommandOverrides(
            extra_allow_read=["/mcp/data"],
            extra_allow_write=["/mcp/out"],
            extra_allowed_domains=["api.mcp.dev"],
            env_mode="passthrough",
            env_inject={"MCP": "1"},
        )
        assert o.extra_allow_read == ["/mcp/data"]
        assert o.extra_allow_write == ["/mcp/out"]
        assert o.extra_allowed_domains == ["api.mcp.dev"]
        assert o.env_mode == "passthrough"
        assert o.env_inject == {"MCP": "1"}


class TestFsReadConfigWithOverrides:
    """get_fs_read_config merges overrides for per-command flexibility."""

    def test_get_fs_read_config_reflects_workspace_root(self):
        mgr = SandboxManager()
        mgr._config = SandboxRuntimeConfig(workspace_root="/ws")
        mgr._apply_workspace_root()
        read_cfg = mgr.get_fs_read_config()
        assert "/ws" in (read_cfg.allow_only or [])

    def test_get_fs_write_config_reflects_workspace_root(self):
        mgr = SandboxManager()
        mgr._config = SandboxRuntimeConfig(workspace_root="/ws")
        mgr._apply_workspace_root()
        write_cfg = mgr.get_fs_write_config()
        assert "/ws" in write_cfg.allow_only
