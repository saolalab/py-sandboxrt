"""
Tests for configuration validation.

Ported from: test/config-validation.test.ts
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from srt.config import SandboxRuntimeConfig, _parse_config_dict


def _parse(data: dict) -> SandboxRuntimeConfig | None:
    """Try to parse a config dict, return None on validation failure."""
    try:
        return _parse_config_dict(data)
    except (ValidationError, ValueError):
        return None


class TestConfigValidation:
    def test_valid_minimal_config(self):
        cfg = _parse(
            {
                "network": {"allowedDomains": [], "deniedDomains": []},
                "filesystem": {"denyRead": [], "allowWrite": [], "denyWrite": []},
            }
        )
        assert cfg is not None

    def test_valid_domains(self):
        cfg = _parse(
            {
                "network": {
                    "allowedDomains": ["example.com", "*.github.com", "localhost"],
                    "deniedDomains": ["evil.com"],
                },
                "filesystem": {"denyRead": [], "allowWrite": [], "denyWrite": []},
            }
        )
        assert cfg is not None

    def test_reject_invalid_domain_patterns(self):
        cfg = _parse(
            {
                "network": {"allowedDomains": ["not-a-domain"], "deniedDomains": []},
                "filesystem": {"denyRead": [], "allowWrite": [], "denyWrite": []},
            }
        )
        assert cfg is None

    def test_reject_domain_with_protocol(self):
        cfg = _parse(
            {
                "network": {"allowedDomains": ["https://example.com"], "deniedDomains": []},
                "filesystem": {"denyRead": [], "allowWrite": [], "denyWrite": []},
            }
        )
        assert cfg is None

    def test_reject_empty_filesystem_paths(self):
        cfg = _parse(
            {
                "network": {"allowedDomains": [], "deniedDomains": []},
                "filesystem": {"denyRead": [""], "allowWrite": [], "denyWrite": []},
            }
        )
        assert cfg is None

    def test_valid_config_with_optional_fields(self):
        cfg = _parse(
            {
                "network": {
                    "allowedDomains": ["example.com"],
                    "deniedDomains": [],
                    "allowUnixSockets": ["/var/run/docker.sock"],
                    "allowAllUnixSockets": False,
                    "allowLocalBinding": True,
                },
                "filesystem": {
                    "denyRead": ["/etc/shadow"],
                    "allowWrite": ["/tmp"],
                    "denyWrite": ["/etc"],
                },
                "ignoreViolations": {
                    "*": ["/usr/bin"],
                    "git push": ["/usr/bin/nc"],
                },
                "enableWeakerNestedSandbox": True,
                "enableWeakerNetworkIsolation": False,
            }
        )
        assert cfg is not None

    def test_missing_fields_get_defaults(self):
        """Pydantic fills in defaults for missing list fields, unlike Zod."""
        cfg = _parse(
            {
                "network": {"allowedDomains": []},
                "filesystem": {"denyRead": []},
            }
        )
        assert cfg is not None
        assert cfg.network.denied_domains == []
        assert cfg.filesystem.allow_write == []
        assert cfg.filesystem.deny_write == []

    @pytest.mark.parametrize(
        "domain",
        [
            "*.example.com",
            "*.github.io",
            "*.co.uk",
        ],
    )
    def test_valid_wildcard_domains(self, domain):
        cfg = _parse(
            {
                "network": {"allowedDomains": [domain], "deniedDomains": []},
                "filesystem": {"denyRead": [], "allowWrite": [], "denyWrite": []},
            }
        )
        assert cfg is not None

    @pytest.mark.parametrize(
        "domain",
        [
            "*example.com",
            "*.com",
            "*.",
        ],
    )
    def test_invalid_wildcard_domains(self, domain):
        cfg = _parse(
            {
                "network": {"allowedDomains": [domain], "deniedDomains": []},
                "filesystem": {"denyRead": [], "allowWrite": [], "denyWrite": []},
            }
        )
        assert cfg is None

    def test_enable_weaker_network_isolation(self):
        cfg = _parse(
            {
                "network": {"allowedDomains": ["example.com"], "deniedDomains": []},
                "filesystem": {"denyRead": [], "allowWrite": [], "denyWrite": []},
                "enableWeakerNetworkIsolation": True,
            }
        )
        assert cfg is not None
        assert cfg.enable_weaker_network_isolation is True

    def test_custom_ripgrep_command(self):
        cfg = _parse(
            {
                "network": {"allowedDomains": [], "deniedDomains": []},
                "filesystem": {"denyRead": [], "allowWrite": [], "denyWrite": []},
                "ripgrep": {"command": "/usr/local/bin/rg"},
            }
        )
        assert cfg is not None
        assert cfg.ripgrep is not None
        assert cfg.ripgrep.command == "/usr/local/bin/rg"

    def test_custom_ripgrep_command_and_args(self):
        cfg = _parse(
            {
                "network": {"allowedDomains": [], "deniedDomains": []},
                "filesystem": {"denyRead": [], "allowWrite": [], "denyWrite": []},
                "ripgrep": {"command": "claude", "args": ["--ripgrep"]},
            }
        )
        assert cfg is not None
        assert cfg.ripgrep.command == "claude"
        assert cfg.ripgrep.args == ["--ripgrep"]

    def test_default_ripgrep_not_set(self):
        cfg = _parse(
            {
                "network": {"allowedDomains": [], "deniedDomains": []},
                "filesystem": {"denyRead": [], "allowWrite": [], "denyWrite": []},
            }
        )
        assert cfg is not None
        assert cfg.ripgrep is None
