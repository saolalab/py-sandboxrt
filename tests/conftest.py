"""Shared pytest fixtures for the test suite."""

from __future__ import annotations

import os

import pytest

from srt.platform_utils import get_platform


def is_macos() -> bool:
    return get_platform() == "macos"


def is_linux() -> bool:
    return get_platform() == "linux"


def is_ci() -> bool:
    """Check if running in a CI environment (GitHub Actions, GitLab CI, etc.)."""
    return any(
        os.environ.get(var)
        for var in ["CI", "GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL", "CIRCLECI"]
    )


def is_linux_ci_without_cap_net_admin() -> bool:
    """
    Check if running on Linux CI where CAP_NET_ADMIN is unavailable.

    bubblewrap's --unshare-net requires CAP_NET_ADMIN to configure loopback,
    which GitHub Actions runners don't have.
    """
    return is_linux() and is_ci()


skip_if_not_macos = pytest.mark.skipif(not is_macos(), reason="macOS only")
skip_if_not_linux = pytest.mark.skipif(not is_linux(), reason="Linux only")
skip_if_unsupported = pytest.mark.skipif(
    not is_macos() and not is_linux(),
    reason="Requires macOS or Linux",
)
skip_on_linux_ci = pytest.mark.skipif(
    is_linux_ci_without_cap_net_admin(),
    reason="Linux CI lacks CAP_NET_ADMIN for bwrap network namespace",
)


@pytest.fixture
def sample_network_config() -> dict:
    """Sample network configuration for testing."""
    return {
        "allowed_domains": ["example.com", "*.github.com"],
        "denied_domains": ["malicious.com"],
    }


@pytest.fixture
def sample_filesystem_config() -> dict:
    """Sample filesystem configuration for testing."""
    return {
        "deny_read": ["~/.ssh"],
        "allow_write": [".", "/tmp"],
        "deny_write": [".env"],
    }
