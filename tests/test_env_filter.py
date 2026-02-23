"""Tests for environment variable filtering."""

from __future__ import annotations

import pytest

from srt.config import EnvironmentConfig, SandboxRuntimeConfig
from srt.sandbox_manager import CommandOverrides, SandboxManager


@pytest.fixture
def mgr_with_config() -> SandboxManager:
    """SandboxManager with config set but not fully initialized (no proxies)."""
    mgr = SandboxManager()
    mgr._config = SandboxRuntimeConfig()
    return mgr


class TestDenySecretsMode:
    """Default mode: strip vars whose names look like secrets."""

    def test_strips_api_key(self, mgr_with_config: SandboxManager):
        env = {"PATH": "/usr/bin", "OPENAI_API_KEY": "sk-xxx", "HOME": "/home/me"}
        result = mgr_with_config.get_filtered_env(env)
        assert "OPENAI_API_KEY" not in result
        assert result["PATH"] == "/usr/bin"
        assert result["HOME"] == "/home/me"

    def test_strips_secret_patterns(self, mgr_with_config: SandboxManager):
        env = {
            "MY_SECRET_VALUE": "s3cr3t",
            "AWS_ACCESS_KEY_ID": "AKIA...",
            "GITHUB_TOKEN": "ghp_...",
            "STRIPE_SECRET_KEY": "sk_...",
            "NORMAL_VAR": "hello",
        }
        result = mgr_with_config.get_filtered_env(env)
        assert "MY_SECRET_VALUE" not in result
        assert "AWS_ACCESS_KEY_ID" not in result
        assert "GITHUB_TOKEN" not in result
        assert "STRIPE_SECRET_KEY" not in result
        assert result["NORMAL_VAR"] == "hello"

    def test_preserves_always_allow(self, mgr_with_config: SandboxManager):
        env = {"PATH": "/usr/bin", "SHELL": "/bin/zsh", "TERM": "xterm-256color"}
        result = mgr_with_config.get_filtered_env(env)
        assert result == env


class TestPassthroughMode:
    def test_passes_everything(self):
        mgr = SandboxManager()
        mgr._config = SandboxRuntimeConfig(
            environment=EnvironmentConfig(mode="passthrough"),
        )
        env = {"OPENAI_API_KEY": "sk-xxx", "PATH": "/usr/bin"}
        result = mgr.get_filtered_env(env)
        assert result["OPENAI_API_KEY"] == "sk-xxx"
        assert result["PATH"] == "/usr/bin"


class TestAllowlistMode:
    def test_only_keeps_allowlisted(self):
        mgr = SandboxManager()
        mgr._config = SandboxRuntimeConfig(
            environment=EnvironmentConfig(mode="allowlist"),
        )
        env = {"PATH": "/usr/bin", "HOME": "/home/me", "RANDOM_VAR": "42"}
        result = mgr.get_filtered_env(env)
        assert "PATH" in result
        assert "HOME" in result
        assert "RANDOM_VAR" not in result


class TestInjectVars:
    def test_inject_adds_vars(self, mgr_with_config: SandboxManager):
        mgr_with_config._config.environment.inject = {"SANDBOX_RUNTIME": "1"}
        result = mgr_with_config.get_filtered_env({"PATH": "/usr/bin"})
        assert result["SANDBOX_RUNTIME"] == "1"
        assert result["PATH"] == "/usr/bin"

    def test_inject_overrides_existing(self, mgr_with_config: SandboxManager):
        mgr_with_config._config.environment.inject = {"HOME": "/sandboxed"}
        result = mgr_with_config.get_filtered_env({"HOME": "/real/home"})
        assert result["HOME"] == "/sandboxed"


class TestExtraAllow:
    def test_extra_allow_exempts_from_deny(self):
        mgr = SandboxManager()
        mgr._config = SandboxRuntimeConfig(
            environment=EnvironmentConfig(extra_allow=["MY_API_KEY"]),
        )
        env = {"MY_API_KEY": "kept", "OTHER_API_KEY": "stripped"}
        result = mgr.get_filtered_env(env)
        assert result["MY_API_KEY"] == "kept"
        assert "OTHER_API_KEY" not in result


class TestCommandOverrides:
    def test_override_env_mode(self, mgr_with_config: SandboxManager):
        env = {"OPENAI_API_KEY": "sk-xxx", "PATH": "/usr/bin"}
        overrides = CommandOverrides(env_mode="passthrough")
        result = mgr_with_config.get_filtered_env(env, overrides=overrides)
        assert result["OPENAI_API_KEY"] == "sk-xxx"

    def test_override_extra_allow(self, mgr_with_config: SandboxManager):
        env = {"MY_SECRET_TOKEN": "tok-xxx", "PATH": "/usr/bin"}
        overrides = CommandOverrides(env_extra_allow=["MY_SECRET_TOKEN"])
        result = mgr_with_config.get_filtered_env(env, overrides=overrides)
        assert result["MY_SECRET_TOKEN"] == "tok-xxx"

    def test_override_inject(self, mgr_with_config: SandboxManager):
        env = {"PATH": "/usr/bin"}
        overrides = CommandOverrides(env_inject={"MCP_SERVER": "true"})
        result = mgr_with_config.get_filtered_env(env, overrides=overrides)
        assert result["MCP_SERVER"] == "true"

    def test_override_inject_wins_over_config_inject(self):
        mgr = SandboxManager()
        mgr._config = SandboxRuntimeConfig(
            environment=EnvironmentConfig(inject={"K": "from_config"}),
        )
        overrides = CommandOverrides(env_inject={"K": "from_override"})
        result = mgr.get_filtered_env({"PATH": "/usr/bin"}, overrides=overrides)
        assert result["K"] == "from_override"


class TestNoConfig:
    def test_returns_input_env_when_no_config(self):
        mgr = SandboxManager()
        env = {"FOO": "bar"}
        result = mgr.get_filtered_env(env)
        assert result["FOO"] == "bar"
