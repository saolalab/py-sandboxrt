"""
Tests for mandatory deny paths (dangerous files and directories).

Ported from: test/sandbox/mandatory-deny-paths.test.ts
"""

from __future__ import annotations

import os
import subprocess

import pytest

from srt.macos_sandbox import (
    FsWriteRestrictionConfig,
    MacOSSandboxParams,
    mac_get_mandatory_deny_patterns,
    wrap_command_with_sandbox_macos,
)
from srt.sandbox_utils import DANGEROUS_DIRECTORIES, DANGEROUS_FILES
from tests.conftest import skip_if_not_macos

ORIGINAL_CONTENT = "ORIGINAL"
MODIFIED_CONTENT = "MODIFIED"


@skip_if_not_macos
class TestMacOSMandatoryDenyFiles:
    """Test that macOS sandbox blocks writes to dangerous files."""

    @pytest.fixture(autouse=True)
    def setup_test_dir(self, tmp_path):
        self.test_dir = str(tmp_path)
        self.original_cwd = os.getcwd()

        for name in [
            ".bashrc",
            ".bash_profile",
            ".gitconfig",
            ".gitmodules",
            ".zshrc",
            ".zprofile",
            ".profile",
            ".ripgreprc",
            ".mcp.json",
        ]:
            with open(os.path.join(self.test_dir, name), "w") as f:
                f.write(ORIGINAL_CONTENT)

        git_hooks = os.path.join(self.test_dir, ".git", "hooks")
        os.makedirs(git_hooks, exist_ok=True)
        with open(os.path.join(self.test_dir, ".git", "config"), "w") as f:
            f.write(ORIGINAL_CONTENT)
        with open(os.path.join(git_hooks, "pre-commit"), "w") as f:
            f.write(ORIGINAL_CONTENT)

        vscode = os.path.join(self.test_dir, ".vscode")
        os.makedirs(vscode, exist_ok=True)
        with open(os.path.join(vscode, "settings.json"), "w") as f:
            f.write(ORIGINAL_CONTENT)

        idea = os.path.join(self.test_dir, ".idea")
        os.makedirs(idea, exist_ok=True)
        with open(os.path.join(idea, "workspace.xml"), "w") as f:
            f.write(ORIGINAL_CONTENT)

        claude_cmds = os.path.join(self.test_dir, ".claude", "commands")
        claude_agents = os.path.join(self.test_dir, ".claude", "agents")
        os.makedirs(claude_cmds, exist_ok=True)
        os.makedirs(claude_agents, exist_ok=True)
        with open(os.path.join(claude_cmds, "test.md"), "w") as f:
            f.write(ORIGINAL_CONTENT)
        with open(os.path.join(claude_agents, "test-agent.md"), "w") as f:
            f.write(ORIGINAL_CONTENT)

        with open(os.path.join(self.test_dir, "safe-file.txt"), "w") as f:
            f.write(ORIGINAL_CONTENT)

        git_objs = os.path.join(self.test_dir, ".git", "objects")
        os.makedirs(git_objs, exist_ok=True)
        with open(os.path.join(git_objs, "test-obj"), "w") as f:
            f.write(ORIGINAL_CONTENT)

        os.chdir(self.test_dir)
        yield
        os.chdir(self.original_cwd)

    def _run(self, cmd: str, timeout: int = 5) -> subprocess.CompletedProcess:
        return subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout, cwd=self.test_dir
        )

    @pytest.mark.parametrize(
        "filename",
        [
            ".bashrc",
            ".bash_profile",
            ".gitconfig",
            ".gitmodules",
            ".zshrc",
            ".zprofile",
            ".profile",
            ".ripgreprc",
            ".mcp.json",
        ],
    )
    def test_block_write_to_dangerous_file(self, filename):
        filepath = os.path.join(self.test_dir, filename)
        write_config = FsWriteRestrictionConfig(
            allow_only=[self.test_dir],
            deny_within_allow=[],
        )
        wrapped = wrap_command_with_sandbox_macos(
            MacOSSandboxParams(
                command=f'echo "{MODIFIED_CONTENT}" > {filepath}',
                needs_network_restriction=False,
                write_config=write_config,
            )
        )
        result = self._run(wrapped)
        assert result.returncode != 0
        with open(filepath) as f:
            assert f.read() == ORIGINAL_CONTENT

    def test_allow_write_to_safe_file(self):
        filepath = os.path.join(self.test_dir, "safe-file.txt")
        write_config = FsWriteRestrictionConfig(
            allow_only=[self.test_dir],
            deny_within_allow=[],
        )
        wrapped = wrap_command_with_sandbox_macos(
            MacOSSandboxParams(
                command=f'echo "{MODIFIED_CONTENT}" > {filepath}',
                needs_network_restriction=False,
                write_config=write_config,
            )
        )
        result = self._run(wrapped)
        assert result.returncode == 0
        with open(filepath) as f:
            assert MODIFIED_CONTENT in f.read()


@skip_if_not_macos
class TestMacOSMandatoryDenyDirectories:
    """Test that macOS sandbox blocks writes to dangerous directories."""

    @pytest.fixture(autouse=True)
    def setup_test_dir(self, tmp_path):
        self.test_dir = str(tmp_path)
        self.original_cwd = os.getcwd()

        git_hooks = os.path.join(self.test_dir, ".git", "hooks")
        os.makedirs(git_hooks, exist_ok=True)
        with open(os.path.join(self.test_dir, ".git", "config"), "w") as f:
            f.write(ORIGINAL_CONTENT)
        with open(os.path.join(git_hooks, "pre-commit"), "w") as f:
            f.write(ORIGINAL_CONTENT)

        vscode = os.path.join(self.test_dir, ".vscode")
        os.makedirs(vscode, exist_ok=True)
        with open(os.path.join(vscode, "settings.json"), "w") as f:
            f.write(ORIGINAL_CONTENT)

        idea = os.path.join(self.test_dir, ".idea")
        os.makedirs(idea, exist_ok=True)
        with open(os.path.join(idea, "workspace.xml"), "w") as f:
            f.write(ORIGINAL_CONTENT)

        claude_cmds = os.path.join(self.test_dir, ".claude", "commands")
        os.makedirs(claude_cmds, exist_ok=True)
        with open(os.path.join(claude_cmds, "test.md"), "w") as f:
            f.write(ORIGINAL_CONTENT)

        git_objs = os.path.join(self.test_dir, ".git", "objects")
        os.makedirs(git_objs, exist_ok=True)
        with open(os.path.join(git_objs, "test-obj"), "w") as f:
            f.write(ORIGINAL_CONTENT)

        os.chdir(self.test_dir)
        yield
        os.chdir(self.original_cwd)

    def _run(self, cmd: str, timeout: int = 5) -> subprocess.CompletedProcess:
        return subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout, cwd=self.test_dir
        )

    def test_block_write_to_git_hooks(self):
        filepath = os.path.join(self.test_dir, ".git", "hooks", "pre-commit")
        write_config = FsWriteRestrictionConfig(
            allow_only=[self.test_dir],
            deny_within_allow=[],
        )
        wrapped = wrap_command_with_sandbox_macos(
            MacOSSandboxParams(
                command=f'echo "{MODIFIED_CONTENT}" > {filepath}',
                needs_network_restriction=False,
                write_config=write_config,
            )
        )
        result = self._run(wrapped)
        assert result.returncode != 0
        with open(filepath) as f:
            assert f.read() == ORIGINAL_CONTENT

    def test_block_write_to_git_config(self):
        filepath = os.path.join(self.test_dir, ".git", "config")
        write_config = FsWriteRestrictionConfig(
            allow_only=[self.test_dir],
            deny_within_allow=[],
        )
        wrapped = wrap_command_with_sandbox_macos(
            MacOSSandboxParams(
                command=f'echo "{MODIFIED_CONTENT}" > {filepath}',
                needs_network_restriction=False,
                write_config=write_config,
            )
        )
        result = self._run(wrapped)
        assert result.returncode != 0
        with open(filepath) as f:
            assert f.read() == ORIGINAL_CONTENT

    def test_block_write_to_vscode(self):
        filepath = os.path.join(self.test_dir, ".vscode", "settings.json")
        write_config = FsWriteRestrictionConfig(
            allow_only=[self.test_dir],
            deny_within_allow=[],
        )
        wrapped = wrap_command_with_sandbox_macos(
            MacOSSandboxParams(
                command=f'echo "{MODIFIED_CONTENT}" > {filepath}',
                needs_network_restriction=False,
                write_config=write_config,
            )
        )
        result = self._run(wrapped)
        assert result.returncode != 0
        with open(filepath) as f:
            assert f.read() == ORIGINAL_CONTENT

    def test_block_write_to_idea(self):
        filepath = os.path.join(self.test_dir, ".idea", "workspace.xml")
        write_config = FsWriteRestrictionConfig(
            allow_only=[self.test_dir],
            deny_within_allow=[],
        )
        wrapped = wrap_command_with_sandbox_macos(
            MacOSSandboxParams(
                command=f'echo "{MODIFIED_CONTENT}" > {filepath}',
                needs_network_restriction=False,
                write_config=write_config,
            )
        )
        result = self._run(wrapped)
        assert result.returncode != 0
        with open(filepath) as f:
            assert f.read() == ORIGINAL_CONTENT

    def test_block_write_to_claude_commands(self):
        filepath = os.path.join(self.test_dir, ".claude", "commands", "test.md")
        write_config = FsWriteRestrictionConfig(
            allow_only=[self.test_dir],
            deny_within_allow=[],
        )
        wrapped = wrap_command_with_sandbox_macos(
            MacOSSandboxParams(
                command=f'echo "{MODIFIED_CONTENT}" > {filepath}',
                needs_network_restriction=False,
                write_config=write_config,
            )
        )
        result = self._run(wrapped)
        assert result.returncode != 0
        with open(filepath) as f:
            assert f.read() == ORIGINAL_CONTENT

    def test_allow_write_to_git_objects(self):
        filepath = os.path.join(self.test_dir, ".git", "objects", "test-obj")
        write_config = FsWriteRestrictionConfig(
            allow_only=[self.test_dir],
            deny_within_allow=[],
        )
        wrapped = wrap_command_with_sandbox_macos(
            MacOSSandboxParams(
                command=f'echo "{MODIFIED_CONTENT}" > {filepath}',
                needs_network_restriction=False,
                write_config=write_config,
            )
        )
        result = self._run(wrapped)
        assert result.returncode == 0
        with open(filepath) as f:
            assert MODIFIED_CONTENT in f.read()


class TestMandatoryDenyPatterns:
    """Test that mac_get_mandatory_deny_patterns returns expected patterns."""

    def test_includes_dangerous_files(self, tmp_path):
        test_dir = str(tmp_path)
        original_cwd = os.getcwd()
        try:
            os.chdir(test_dir)
            patterns = mac_get_mandatory_deny_patterns()
            normalized = [p.lower() for p in patterns]
            for f in DANGEROUS_FILES:
                expected = os.path.join(test_dir, f).lower()
                assert any(expected in p for p in normalized), f"Expected mandatory deny for {f}"
        finally:
            os.chdir(original_cwd)

    def test_includes_dangerous_directories(self, tmp_path):
        test_dir = str(tmp_path)
        original_cwd = os.getcwd()
        try:
            os.chdir(test_dir)
            patterns = mac_get_mandatory_deny_patterns()
            for d in DANGEROUS_DIRECTORIES:
                expected_prefix = os.path.join(test_dir, d)
                found = any(expected_prefix in p for p in patterns)
                assert found, f"Expected mandatory deny for {d}"
        finally:
            os.chdir(original_cwd)
