"""
Configuration models for Sandbox Runtime.

Mirrors the TypeScript SandboxRuntimeConfig with Pydantic validation.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from pydantic import BaseModel, Field, field_validator


def _validate_domain_pattern(val: str) -> str:
    if "://" in val or "/" in val or ":" in val:
        raise ValueError(
            f"Invalid domain pattern '{val}': must not contain protocols, paths, or ports"
        )

    if val == "localhost":
        return val

    if val.startswith("*."):
        domain = val[2:]
        if "." not in domain or domain.startswith(".") or domain.endswith("."):
            raise ValueError(
                f"Invalid wildcard pattern '{val}': must have at least two parts after *."
            )
        parts = domain.split(".")
        if len(parts) < 2 or any(len(p) == 0 for p in parts):
            raise ValueError(f"Invalid wildcard pattern '{val}': overly broad or malformed")
        return val

    if "*" in val:
        raise ValueError(
            f"Invalid domain pattern '{val}': wildcards only allowed as '*.domain.tld'"
        )

    if "." not in val or val.startswith(".") or val.endswith("."):
        raise ValueError(
            f"Invalid domain pattern '{val}': must be a valid domain (e.g., 'example.com')"
        )

    return val


class MitmProxyConfig(BaseModel):
    socket_path: str = Field(min_length=1, description="Unix socket path to the MITM proxy")
    domains: list[str] = Field(
        min_length=1,
        description="Domains to route through the MITM proxy",
    )

    @field_validator("domains", mode="before")
    @classmethod
    def validate_domains(cls, v: list[str]) -> list[str]:
        return [_validate_domain_pattern(d) for d in v]


class NetworkConfig(BaseModel):
    allowed_domains: list[str] = Field(
        default_factory=list,
        description="List of allowed domains (e.g., ['github.com', '*.npmjs.org'])",
    )
    denied_domains: list[str] = Field(
        default_factory=list,
        description="List of denied domains",
    )
    allow_unix_sockets: list[str] | None = Field(
        default=None,
        description="macOS only: Unix socket paths to allow.",
    )
    allow_all_unix_sockets: bool | None = Field(
        default=None,
        description="If true, allow all Unix sockets.",
    )
    allow_local_binding: bool | None = Field(
        default=None,
        description="Whether to allow binding to local ports (default: false)",
    )
    http_proxy_port: int | None = Field(
        default=None,
        ge=1,
        le=65535,
        description="Port of an external HTTP proxy to use instead of the built-in one.",
    )
    socks_proxy_port: int | None = Field(
        default=None,
        ge=1,
        le=65535,
        description="Port of an external SOCKS proxy to use instead of the built-in one.",
    )
    mitm_proxy: MitmProxyConfig | None = Field(
        default=None,
        description="Optional MITM proxy configuration.",
    )

    @field_validator("allowed_domains", "denied_domains", mode="before")
    @classmethod
    def validate_domain_list(cls, v: list[str]) -> list[str]:
        return [_validate_domain_pattern(d) for d in v]


class FilesystemConfig(BaseModel):
    allow_read: list[str] = Field(
        default_factory=list,
        description=(
            "Paths allowed for reading (allowlist). When non-empty, only these paths "
            "(and essential OS paths) are readable; everything else is denied. "
            "When empty, all reads are allowed (subject to deny_read)."
        ),
    )
    deny_read: list[str] = Field(
        default_factory=list,
        description="Paths denied for reading (takes precedence over allow_read)",
    )
    allow_write: list[str] = Field(
        default_factory=list,
        description="Paths allowed for writing",
    )
    deny_write: list[str] = Field(
        default_factory=list,
        description="Paths denied for writing (takes precedence over allow_write)",
    )
    allow_git_config: bool | None = Field(
        default=None,
        description="Allow writes to .git/config files (default: false).",
    )

    @field_validator("allow_read", "deny_read", "allow_write", "deny_write", mode="before")
    @classmethod
    def validate_paths_nonempty(cls, v: list[str]) -> list[str]:
        for p in v:
            if not p:
                raise ValueError("Filesystem paths must not be empty strings")
        return v


_DEFAULT_ENV_DENY_PATTERNS: list[str] = [
    r"(?i).*api[_-]?key.*",
    r"(?i).*secret.*",
    r"(?i).*token.*",
    r"(?i).*password.*",
    r"(?i).*credential.*",
    r"(?i).*private[_-]?key.*",
    r"(?i).*auth.*",
    r"(?i)^AWS_.*",
    r"(?i)^GITHUB_TOKEN$",
    r"(?i)^GH_TOKEN$",
    r"(?i)^OPENAI_.*",
    r"(?i)^ANTHROPIC_.*",
    r"(?i)^GOOGLE_.*KEY.*",
    r"(?i)^AZURE_.*",
    r"(?i)^DATABASE_URL$",
    r"(?i)^REDIS_URL$",
    r"(?i)^MONGO.*URI$",
    r"(?i)^SMTP_.*",
    r"(?i)^SENDGRID_.*",
    r"(?i)^STRIPE_.*",
    r"(?i)^TWILIO_.*",
]

_DEFAULT_ENV_ALLOW: list[str] = [
    "PATH", "HOME", "USER", "SHELL", "LANG", "LC_ALL", "LC_CTYPE",
    "TERM", "TMPDIR", "TMP", "TEMP", "EDITOR", "VISUAL",
    "PWD", "OLDPWD", "SHLVL", "LOGNAME", "HOSTNAME",
    "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_RUNTIME_DIR",
    "NODE_NO_WARNINGS", "PYTHONDONTWRITEBYTECODE", "PYTHONUNBUFFERED",
    "SANDBOX_RUNTIME",
]


class EnvironmentConfig(BaseModel):
    """Controls which environment variables are passed into sandboxed processes."""

    mode: str = Field(
        default="deny_secrets",
        description=(
            "Filtering mode: 'passthrough' (no filtering), "
            "'deny_secrets' (block vars matching deny_patterns), "
            "'allowlist' (only pass vars in allow list)."
        ),
    )
    deny_patterns: list[str] = Field(
        default_factory=lambda: list(_DEFAULT_ENV_DENY_PATTERNS),
        description="Regex patterns for env var names to strip (used in deny_secrets mode).",
    )
    allow: list[str] = Field(
        default_factory=lambda: list(_DEFAULT_ENV_ALLOW),
        description="Env var names to always pass through (used in allowlist mode, also exempts from deny).",
    )
    extra_allow: list[str] = Field(
        default_factory=list,
        description="Additional env var names to pass through.",
    )
    inject: dict[str, str] = Field(
        default_factory=dict,
        description="Env vars to forcibly set (overrides).",
    )

    @field_validator("mode")
    @classmethod
    def validate_mode(cls, v: str) -> str:
        allowed = {"passthrough", "deny_secrets", "allowlist"}
        if v not in allowed:
            raise ValueError(f"mode must be one of {allowed}, got '{v}'")
        return v


class RipgrepConfig(BaseModel):
    command: str = Field(description="The ripgrep command to execute (e.g., 'rg')")
    args: list[str] | None = Field(
        default=None,
        description="Additional arguments to pass before ripgrep args.",
    )


class SeccompConfig(BaseModel):
    bpf_path: str | None = Field(default=None, description="Path to the unix-block.bpf filter file")
    apply_path: str | None = Field(default=None, description="Path to the apply-seccomp binary")


class SandboxRuntimeConfig(BaseModel):
    network: NetworkConfig = Field(
        default_factory=NetworkConfig,
        description="Network restrictions configuration",
    )
    filesystem: FilesystemConfig = Field(
        default_factory=FilesystemConfig,
        description="Filesystem restrictions configuration",
    )
    environment: EnvironmentConfig = Field(
        default_factory=EnvironmentConfig,
        description="Environment variable filtering for sandboxed processes.",
    )
    workspace_root: str | None = Field(
        default=None,
        description=(
            "Workspace root path. When set, enables workspace-root mode: "
            "allow_read and allow_write are auto-populated relative to this "
            "directory (plus OS essentials), giving chroot-like isolation."
        ),
    )
    ignore_violations: dict[str, list[str]] | None = Field(
        default=None,
        description="Map of command patterns to filesystem paths to ignore violations for.",
    )
    enable_weaker_nested_sandbox: bool | None = Field(
        default=None,
        description="Enable weaker nested sandbox mode (for Docker environments)",
    )
    enable_weaker_network_isolation: bool | None = Field(
        default=None,
        description="Enable weaker network isolation (macOS only, for Go TLS)",
    )
    ripgrep: RipgrepConfig | None = Field(
        default=None,
        description="Custom ripgrep configuration (default: { command: 'rg' })",
    )
    mandatory_deny_search_depth: int | None = Field(
        default=None,
        ge=1,
        le=10,
        description="Max directory depth to search for dangerous files on Linux (default: 3).",
    )
    allow_pty: bool | None = Field(
        default=None,
        description="Allow pseudo-terminal (pty) operations (macOS only)",
    )
    seccomp: SeccompConfig | None = Field(
        default=None,
        description="Custom seccomp binary paths (Linux only).",
    )


def load_config(config_path: str | Path) -> SandboxRuntimeConfig | None:
    """Load configuration from a JSON file, returning None if not found."""
    path = Path(config_path).expanduser()
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return _parse_config_dict(data)
    except (json.JSONDecodeError, Exception):
        return None


def load_config_from_string(raw: str) -> SandboxRuntimeConfig | None:
    """Parse configuration from a JSON string."""
    try:
        data = json.loads(raw)
        return _parse_config_dict(data)
    except (json.JSONDecodeError, Exception):
        return None


_CAMEL_RE = re.compile(r"([a-z0-9])([A-Z])")


def _camel_to_snake(name: str) -> str:
    return _CAMEL_RE.sub(r"\1_\2", name).lower()


def _normalize_keys(obj: object) -> object:
    """Recursively convert camelCase keys to snake_case."""
    if isinstance(obj, dict):
        return {_camel_to_snake(k): _normalize_keys(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_normalize_keys(item) for item in obj]
    return obj


def _parse_config_dict(data: dict) -> SandboxRuntimeConfig:
    normalized = _normalize_keys(data)
    return SandboxRuntimeConfig.model_validate(normalized)
