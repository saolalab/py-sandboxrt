"""Shared sandbox utilities: path normalization, proxy env vars, glob helpers."""

from __future__ import annotations

import base64
import os
import re
from pathlib import Path

from srt.debug import log_debug
from srt.platform_utils import get_platform

DANGEROUS_FILES: tuple[str, ...] = (
    ".gitconfig",
    ".gitmodules",
    ".bashrc",
    ".bash_profile",
    ".zshrc",
    ".zprofile",
    ".profile",
    ".ripgreprc",
    ".mcp.json",
)

DANGEROUS_DIRECTORIES: tuple[str, ...] = (".git", ".vscode", ".idea")


def get_dangerous_directories() -> list[str]:
    """
    Directories to deny writes to.
    Excludes .git (we need it writable for git operations) — instead we block
    specific paths within .git (hooks, config).
    """
    dirs = [d for d in DANGEROUS_DIRECTORIES if d != ".git"]
    dirs.extend([".claude/commands", ".claude/agents"])
    return dirs


def normalize_case_for_comparison(path_str: str) -> str:
    return path_str.lower()


def contains_glob_chars(path_pattern: str) -> bool:
    return any(c in path_pattern for c in ("*", "?", "[", "]"))


def remove_trailing_glob_suffix(path_pattern: str) -> str:
    if path_pattern.endswith("/**"):
        return path_pattern[:-3]
    return path_pattern


def is_symlink_outside_boundary(original_path: str, resolved_path: str) -> bool:
    """Check if symlink resolution crosses expected path boundaries."""
    norm_orig = os.path.normpath(original_path)
    norm_res = os.path.normpath(resolved_path)

    if norm_res == norm_orig:
        return False

    # macOS /tmp -> /private/tmp canonical resolution
    if norm_orig.startswith("/tmp/") and norm_res == "/private" + norm_orig:
        return False
    if norm_orig.startswith("/var/") and norm_res == "/private" + norm_orig:
        return False
    if norm_orig.startswith("/private/tmp/") and norm_res == norm_orig:
        return False
    if norm_orig.startswith("/private/var/") and norm_res == norm_orig:
        return False

    if norm_res == "/":
        return True

    resolved_parts = [p for p in norm_res.split("/") if p]
    if len(resolved_parts) <= 1:
        return True

    if norm_orig.startswith(norm_res + "/"):
        return True

    canonical_orig = norm_orig
    if norm_orig.startswith("/tmp/"):
        canonical_orig = "/private" + norm_orig
    elif norm_orig.startswith("/var/"):
        canonical_orig = "/private" + norm_orig

    if canonical_orig != norm_orig and canonical_orig.startswith(norm_res + "/"):
        return True

    resolved_starts_with_orig = norm_res.startswith(norm_orig + "/")
    resolved_starts_with_canonical = canonical_orig != norm_orig and norm_res.startswith(
        canonical_orig + "/"
    )
    resolved_is_canonical = canonical_orig != norm_orig and norm_res == canonical_orig
    resolved_is_same = norm_res == norm_orig

    if not (
        resolved_is_same
        or resolved_is_canonical
        or resolved_starts_with_orig
        or resolved_starts_with_canonical
    ):
        return True

    return False


def normalize_path_for_sandbox(path_pattern: str) -> str:
    """
    Normalize a path for sandbox configuration.

    Handles ~ expansion, relative -> absolute conversion, symlink resolution,
    and glob-pattern normalization.
    """
    cwd = os.getcwd()
    normalized = path_pattern

    if path_pattern == "~":
        normalized = str(Path.home())
    elif path_pattern.startswith("~/"):
        normalized = str(Path.home()) + path_pattern[1:]
    elif path_pattern.startswith("./") or path_pattern.startswith("../"):
        normalized = os.path.normpath(os.path.join(cwd, path_pattern))
    elif not os.path.isabs(path_pattern):
        normalized = os.path.normpath(os.path.join(cwd, path_pattern))

    if contains_glob_chars(normalized):
        static_prefix = re.split(r"[*?\[\]]", normalized)[0]
        if static_prefix and static_prefix != "/":
            base_dir = (
                static_prefix.rstrip("/")
                if static_prefix.endswith("/")
                else os.path.dirname(static_prefix)
            )
            try:
                resolved_base = os.path.realpath(base_dir)
                if not is_symlink_outside_boundary(base_dir, resolved_base):
                    suffix = normalized[len(base_dir) :]
                    return resolved_base + suffix
            except OSError:
                pass
        return normalized

    try:
        resolved = os.path.realpath(normalized)
        if not is_symlink_outside_boundary(normalized, resolved):
            normalized = resolved
    except OSError:
        pass

    return normalized


def get_default_write_paths() -> list[str]:
    """
    Recommended system paths that should be writable for commands to work.

    WARNING: These defaults are broad for compatibility but may allow access
    to files from other processes.
    """
    home = str(Path.home())
    return [
        "/dev/stdout",
        "/dev/stderr",
        "/dev/null",
        "/dev/tty",
        "/dev/dtracehelper",
        "/dev/autofs_nowait",
        "/tmp/claude",
        "/private/tmp/claude",
        os.path.join(home, ".npm/_logs"),
        os.path.join(home, ".claude/debug"),
    ]


def generate_proxy_env_vars(
    http_proxy_port: int | None = None,
    socks_proxy_port: int | None = None,
) -> list[str]:
    """Generate environment variable assignments for sandboxed processes."""
    tmpdir = os.environ.get("CLAUDE_TMPDIR", "/tmp/claude")
    env_vars: list[str] = [
        "SANDBOX_RUNTIME=1",
        f"TMPDIR={tmpdir}",
    ]

    if not http_proxy_port and not socks_proxy_port:
        return env_vars

    no_proxy = ",".join(
        [
            "localhost",
            "127.0.0.1",
            "::1",
            "*.local",
            ".local",
            "169.254.0.0/16",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
        ]
    )
    env_vars.append(f"NO_PROXY={no_proxy}")
    env_vars.append(f"no_proxy={no_proxy}")

    if http_proxy_port:
        for name in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
            env_vars.append(f"{name}=http://localhost:{http_proxy_port}")

    if socks_proxy_port:
        env_vars.append(f"ALL_PROXY=socks5h://localhost:{socks_proxy_port}")
        env_vars.append(f"all_proxy=socks5h://localhost:{socks_proxy_port}")

        if get_platform() == "macos":
            env_vars.append(
                f"GIT_SSH_COMMAND=ssh -o ProxyCommand='nc -X 5 -x localhost:{socks_proxy_port} %h %p'"
            )

        env_vars.append(f"FTP_PROXY=socks5h://localhost:{socks_proxy_port}")
        env_vars.append(f"ftp_proxy=socks5h://localhost:{socks_proxy_port}")
        env_vars.append(f"RSYNC_PROXY=localhost:{socks_proxy_port}")

        proxy_port = http_proxy_port or socks_proxy_port
        env_vars.append(f"DOCKER_HTTP_PROXY=http://localhost:{proxy_port}")
        env_vars.append(f"DOCKER_HTTPS_PROXY=http://localhost:{proxy_port}")

        if http_proxy_port:
            env_vars.append("CLOUDSDK_PROXY_TYPE=https")
            env_vars.append("CLOUDSDK_PROXY_ADDRESS=localhost")
            env_vars.append(f"CLOUDSDK_PROXY_PORT={http_proxy_port}")

        env_vars.append(f"GRPC_PROXY=socks5h://localhost:{socks_proxy_port}")
        env_vars.append(f"grpc_proxy=socks5h://localhost:{socks_proxy_port}")

    return env_vars


def encode_sandboxed_command(command: str) -> str:
    """Truncate to 100 chars and base64-encode for sandbox monitoring."""
    truncated = command[:100]
    return base64.b64encode(truncated.encode("utf-8")).decode("ascii")


def decode_sandboxed_command(encoded: str) -> str:
    return base64.b64decode(encoded.encode("ascii")).decode("utf-8")


def glob_to_regex(glob_pattern: str) -> str:
    """
    Convert a gitignore-style glob pattern to a regex string.

    Supports: * (not /), ** (anything), ? (single non-/), [abc] character sets.
    """
    result = "^"
    pattern = glob_pattern
    # Escape regex specials except glob chars
    pattern = re.sub(r"([.^$+{}()|\\])", r"\\\1", pattern)
    # Escape unclosed brackets
    pattern = re.sub(r"\[([^\]]*?)$", r"\\[\1", pattern)
    # Order matters: ** before *
    pattern = pattern.replace("**/", "__GLOBSTAR_SLASH__")
    pattern = pattern.replace("**", "__GLOBSTAR__")
    pattern = pattern.replace("*", "[^/]*")
    pattern = pattern.replace("?", "[^/]")
    pattern = pattern.replace("__GLOBSTAR_SLASH__", "(.*/)?")
    pattern = pattern.replace("__GLOBSTAR__", ".*")
    result += pattern + "$"
    return result


def expand_glob_pattern(glob_path: str) -> list[str]:
    """
    Expand a glob pattern into concrete paths.
    Used on Linux where bubblewrap doesn't support glob patterns.
    """
    normalized = normalize_path_for_sandbox(glob_path)
    static_prefix = re.split(r"[*?\[\]]", normalized)[0]
    if not static_prefix or static_prefix == "/":
        log_debug(f"Glob pattern too broad, skipping: {glob_path}")
        return []

    base_dir = (
        static_prefix.rstrip("/") if static_prefix.endswith("/") else os.path.dirname(static_prefix)
    )

    if not os.path.exists(base_dir):
        log_debug(f"Base directory for glob does not exist: {base_dir}")
        return []

    regex = re.compile(glob_to_regex(normalized))
    results: list[str] = []
    try:
        for root, dirs, files in os.walk(base_dir):
            for name in files:
                full = os.path.join(root, name)
                if regex.match(full):
                    results.append(full)
            for name in dirs:
                full = os.path.join(root, name)
                if regex.match(full):
                    results.append(full)
    except OSError as exc:
        log_debug(f"Error expanding glob pattern {glob_path}: {exc}")

    return results
