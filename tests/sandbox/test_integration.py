"""
Integration tests for SandboxManager (high-level orchestration).

Ported from: test/sandbox/integration.test.ts

IMPORTANT: Tests that verify write blocking use a dedicated temp directory
(not pytest's tmp_path) because /var/folders is auto-allowed by the sandbox
via TMPDIR. On macOS this uses /private/tmp, on Linux this uses /tmp.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time

import pytest

from srt.config import FilesystemConfig, NetworkConfig, SandboxRuntimeConfig
from srt.platform_utils import get_platform
from srt.sandbox_manager import SandboxManager
from tests.conftest import skip_if_not_macos, skip_if_unsupported, skip_on_linux_ci


def _create_test_config(test_dir: str) -> SandboxRuntimeConfig:
    return SandboxRuntimeConfig(
        network=NetworkConfig(
            allowed_domains=["example.com"],
            denied_domains=[],
        ),
        filesystem=FilesystemConfig(
            deny_read=[],
            allow_write=[test_dir],
            deny_write=[],
        ),
    )


def _make_test_base() -> str:
    """Create a unique test dir outside TMPDIR parent for write restriction tests.

    On macOS: /private/tmp/srt-integ-test-...
    On Linux: /tmp/srt-integ-test-...
    """
    platform = get_platform()
    if platform == "macos":
        base_prefix = "/private/tmp"
    else:
        base_prefix = tempfile.gettempdir()

    base = os.path.join(base_prefix, f"srt-integ-test-{os.getpid()}-{int(time.time())}")
    os.makedirs(base, exist_ok=True)
    return base


@skip_if_unsupported
@skip_on_linux_ci
class TestSandboxManagerBasic:
    """Basic SandboxManager integration tests."""

    @pytest.fixture(autouse=True)
    async def setup_manager(self, tmp_path):
        self.test_dir = str(tmp_path)
        self.mgr = SandboxManager()
        yield
        await self.mgr.reset()

    @pytest.mark.asyncio
    async def test_initialize(self):
        config = _create_test_config(self.test_dir)
        await self.mgr.initialize(config)

    @pytest.mark.asyncio
    async def test_wrap_command_basic(self):
        config = _create_test_config(self.test_dir)
        await self.mgr.initialize(config)
        command = "echo hello"
        wrapped = await self.mgr.wrap_with_sandbox(command)
        assert wrapped != command
        assert len(wrapped) > len(command)

    @pytest.mark.asyncio
    async def test_wrap_command_runs_successfully(self):
        config = _create_test_config(self.test_dir)
        await self.mgr.initialize(config)
        wrapped = await self.mgr.wrap_with_sandbox("echo sandbox_test_output")
        result = subprocess.run(wrapped, shell=True, capture_output=True, text=True, timeout=10)
        assert result.returncode == 0
        assert "sandbox_test_output" in result.stdout


@skip_if_not_macos
class TestSandboxManagerMacOSFilesystem:
    """macOS-specific filesystem restriction tests via SandboxManager."""

    @pytest.fixture(autouse=True)
    async def setup(self):
        self.test_dir = _make_test_base()
        self.mgr = SandboxManager()
        yield
        await self.mgr.reset()
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)

    @pytest.mark.asyncio
    async def test_read_restriction_blocks_file(self):
        secret_dir = os.path.join(self.test_dir, "secrets")
        os.makedirs(secret_dir, exist_ok=True)
        secret_file = os.path.join(secret_dir, "key.txt")
        with open(secret_file, "w") as f:
            f.write("TOP_SECRET")

        config = SandboxRuntimeConfig(
            network=NetworkConfig(allowed_domains=[], denied_domains=[]),
            filesystem=FilesystemConfig(
                deny_read=[secret_dir],
                allow_write=[self.test_dir],
                deny_write=[],
            ),
        )
        await self.mgr.initialize(config)
        wrapped = await self.mgr.wrap_with_sandbox(f"cat {secret_file}")
        result = subprocess.run(wrapped, shell=True, capture_output=True, text=True, timeout=5)
        assert result.returncode != 0
        assert "TOP_SECRET" not in result.stdout

    @pytest.mark.asyncio
    async def test_write_restriction_blocks_outside(self):
        allowed_dir = os.path.join(self.test_dir, "allowed")
        os.makedirs(allowed_dir, exist_ok=True)
        outside_file = os.path.join(self.test_dir, "outside.txt")

        config = SandboxRuntimeConfig(
            network=NetworkConfig(allowed_domains=[], denied_domains=[]),
            filesystem=FilesystemConfig(
                deny_read=[],
                allow_write=[allowed_dir],
                deny_write=[],
            ),
        )
        await self.mgr.initialize(config)
        wrapped = await self.mgr.wrap_with_sandbox(f'echo "HACKED" > {outside_file}')
        result = subprocess.run(wrapped, shell=True, capture_output=True, text=True, timeout=5)
        assert result.returncode != 0
        assert not os.path.exists(outside_file)

    @pytest.mark.asyncio
    async def test_write_allowed_within_path(self):
        allowed_dir = os.path.join(self.test_dir, "allowed")
        os.makedirs(allowed_dir, exist_ok=True)
        target = os.path.join(allowed_dir, "output.txt")

        config = SandboxRuntimeConfig(
            network=NetworkConfig(allowed_domains=[], denied_domains=[]),
            filesystem=FilesystemConfig(
                deny_read=[],
                allow_write=[allowed_dir],
                deny_write=[],
            ),
        )
        await self.mgr.initialize(config)
        wrapped = await self.mgr.wrap_with_sandbox(f'echo "ALLOWED" > {target}')
        result = subprocess.run(wrapped, shell=True, capture_output=True, text=True, timeout=5)
        assert result.returncode == 0
        assert os.path.exists(target)
        with open(target) as f:
            assert "ALLOWED" in f.read()


@skip_if_not_macos
class TestSandboxManagerMacOSNetwork:
    """macOS-specific network restriction tests via SandboxManager."""

    @pytest.fixture(autouse=True)
    async def setup(self):
        self.test_dir = _make_test_base()
        self.mgr = SandboxManager()
        yield
        await self.mgr.reset()
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)

    @pytest.mark.asyncio
    async def test_network_block_unlisted_domain(self):
        config = SandboxRuntimeConfig(
            network=NetworkConfig(
                allowed_domains=["example.com"],
                denied_domains=[],
            ),
            filesystem=FilesystemConfig(
                deny_read=[],
                allow_write=[self.test_dir],
                deny_write=[],
            ),
        )
        await self.mgr.initialize(config)
        wrapped = await self.mgr.wrap_with_sandbox("curl -s --max-time 3 https://www.anthropic.com")
        result = subprocess.run(wrapped, shell=True, capture_output=True, text=True, timeout=10)
        assert result.returncode != 0 or "anthropic" not in result.stdout.lower()


@skip_if_unsupported
@skip_on_linux_ci
class TestSandboxManagerUpdateConfig:
    """Tests for update_config correctly updating sandbox behavior."""

    @pytest.fixture(autouse=True)
    async def setup(self):
        self.test_dir = _make_test_base()
        self.mgr = SandboxManager()
        yield
        await self.mgr.reset()
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)

    @pytest.mark.asyncio
    async def test_update_adds_write_path(self):
        config = SandboxRuntimeConfig(
            network=NetworkConfig(allowed_domains=[], denied_domains=[]),
            filesystem=FilesystemConfig(
                deny_read=[],
                allow_write=[],
                deny_write=[],
            ),
        )
        await self.mgr.initialize(config)

        new_config = SandboxRuntimeConfig(
            network=NetworkConfig(allowed_domains=[], denied_domains=[]),
            filesystem=FilesystemConfig(
                deny_read=[],
                allow_write=[self.test_dir],
                deny_write=[],
            ),
        )
        self.mgr.update_config(new_config)

        target = os.path.join(self.test_dir, "test.txt")
        wrapped = await self.mgr.wrap_with_sandbox(f'echo "WRITTEN" > {target}')
        result = subprocess.run(wrapped, shell=True, capture_output=True, text=True, timeout=5)
        assert result.returncode == 0
        assert os.path.exists(target)

    @pytest.mark.asyncio
    async def test_update_adds_deny_read(self):
        secret_dir = os.path.join(self.test_dir, "secrets")
        os.makedirs(secret_dir)
        secret_file = os.path.join(secret_dir, "key.txt")
        with open(secret_file, "w") as f:
            f.write("SECRET_DATA")

        config = SandboxRuntimeConfig(
            network=NetworkConfig(allowed_domains=[], denied_domains=[]),
            filesystem=FilesystemConfig(
                deny_read=[],
                allow_write=[self.test_dir],
                deny_write=[],
            ),
        )
        await self.mgr.initialize(config)

        wrapped = await self.mgr.wrap_with_sandbox(f"cat {secret_file}")
        result = subprocess.run(wrapped, shell=True, capture_output=True, text=True, timeout=5)
        assert "SECRET_DATA" in result.stdout

        new_config = SandboxRuntimeConfig(
            network=NetworkConfig(allowed_domains=[], denied_domains=[]),
            filesystem=FilesystemConfig(
                deny_read=[secret_dir],
                allow_write=[self.test_dir],
                deny_write=[],
            ),
        )
        self.mgr.update_config(new_config)

        wrapped = await self.mgr.wrap_with_sandbox(f"cat {secret_file}")
        result = subprocess.run(wrapped, shell=True, capture_output=True, text=True, timeout=5)
        assert "SECRET_DATA" not in result.stdout


@skip_if_unsupported
@skip_on_linux_ci
class TestSandboxManagerCustomConfig:
    """Tests for wrap_with_sandbox behavior with custom config overrides."""

    @pytest.fixture(autouse=True)
    async def setup(self):
        self.test_dir = _make_test_base()
        self.mgr = SandboxManager()
        yield
        await self.mgr.reset()
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)

    @pytest.mark.asyncio
    async def test_empty_allowed_domains_blocks_network(self):
        config = SandboxRuntimeConfig(
            network=NetworkConfig(
                allowed_domains=["example.com"],
                denied_domains=[],
            ),
            filesystem=FilesystemConfig(
                deny_read=[],
                allow_write=[self.test_dir],
                deny_write=[],
            ),
        )
        await self.mgr.initialize(config)

        self.mgr.update_config(
            SandboxRuntimeConfig(
                network=NetworkConfig(allowed_domains=[], denied_domains=[]),
                filesystem=FilesystemConfig(
                    deny_read=[],
                    allow_write=[self.test_dir],
                    deny_write=[],
                ),
            )
        )

        command = "curl https://example.com"
        wrapped = await self.mgr.wrap_with_sandbox(command)
        assert wrapped != command
        platform = get_platform()
        if platform == "macos":
            assert "sandbox-exec" in wrapped
        elif platform == "linux":
            assert "bwrap" in wrapped
            assert "--unshare-net" in wrapped
