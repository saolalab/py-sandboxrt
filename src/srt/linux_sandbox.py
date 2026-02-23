"""
Linux sandbox implementation using bubblewrap (bwrap).

Provides filesystem isolation through bind mounts and network isolation via
network namespace unsharing, with socat bridges for proxy communication.
"""

from __future__ import annotations

import atexit
import os
import secrets
import shlex
import subprocess
import tempfile
import time
from dataclasses import dataclass, field

from srt.debug import log_debug
from srt.platform_utils import which_sync
from srt.sandbox_utils import (
    DANGEROUS_FILES,
    generate_proxy_env_vars,
    get_dangerous_directories,
    is_symlink_outside_boundary,
    normalize_case_for_comparison,
    normalize_path_for_sandbox,
)

# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

DEFAULT_MANDATORY_DENY_SEARCH_DEPTH = 3


@dataclass
class FsReadRestrictionConfig:
    deny_only: list[str] = field(default_factory=list)


@dataclass
class FsWriteRestrictionConfig:
    allow_only: list[str] = field(default_factory=list)
    deny_within_allow: list[str] = field(default_factory=list)


@dataclass
class LinuxNetworkBridgeContext:
    http_socket_path: str
    socks_socket_path: str
    http_bridge_process: subprocess.Popen
    socks_bridge_process: subprocess.Popen
    http_proxy_port: int
    socks_proxy_port: int


@dataclass
class LinuxSandboxParams:
    command: str
    needs_network_restriction: bool
    http_socket_path: str | None = None
    socks_socket_path: str | None = None
    http_proxy_port: int | None = None
    socks_proxy_port: int | None = None
    read_config: FsReadRestrictionConfig | None = None
    write_config: FsWriteRestrictionConfig | None = None
    enable_weaker_nested_sandbox: bool | None = None
    allow_all_unix_sockets: bool | None = None
    bin_shell: str | None = None
    ripgrep_config: dict | None = None
    mandatory_deny_search_depth: int = DEFAULT_MANDATORY_DENY_SEARCH_DEPTH
    allow_git_config: bool = False


@dataclass
class SandboxDependencyCheck:
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Module state for cleanup tracking
# ---------------------------------------------------------------------------

_bwrap_mount_points: set[str] = set()
_exit_handler_registered = False


def _register_exit_cleanup() -> None:
    global _exit_handler_registered
    if _exit_handler_registered:
        return

    def _cleanup() -> None:
        cleanup_bwrap_mount_points()

    atexit.register(_cleanup)
    _exit_handler_registered = True


def cleanup_bwrap_mount_points() -> None:
    """Remove empty files/dirs created by bwrap as mount points."""
    for mp in list(_bwrap_mount_points):
        try:
            st = os.stat(mp)
            if os.path.isfile(mp) and st.st_size == 0:
                os.unlink(mp)
                log_debug(f"[Sandbox Linux] Cleaned up bwrap mount point (file): {mp}")
            elif os.path.isdir(mp) and not os.listdir(mp):
                os.rmdir(mp)
                log_debug(f"[Sandbox Linux] Cleaned up bwrap mount point (dir): {mp}")
        except OSError:
            pass
    _bwrap_mount_points.clear()


# ---------------------------------------------------------------------------
# Dependency checking
# ---------------------------------------------------------------------------


def check_linux_dependencies() -> SandboxDependencyCheck:
    errors: list[str] = []
    warnings: list[str] = []

    if which_sync("bwrap") is None:
        errors.append("bubblewrap (bwrap) not installed")
    if which_sync("socat") is None:
        errors.append("socat not installed")

    return SandboxDependencyCheck(warnings=warnings, errors=errors)


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------


def _find_symlink_in_path(target_path: str, allowed_write_paths: list[str]) -> str | None:
    """Find symlink in path within allowed write paths (symlink replacement attack prevention)."""
    parts = target_path.split(os.sep)
    current = ""
    for part in parts:
        if not part:
            continue
        next_path = current + os.sep + part
        try:
            if os.path.islink(next_path):
                within_allowed = any(
                    next_path.startswith(ap + "/") or next_path == ap for ap in allowed_write_paths
                )
                if within_allowed:
                    return next_path
        except OSError:
            break
        current = next_path
    return None


def _has_file_ancestor(target_path: str) -> bool:
    """Check if any existing component is a file, not a directory."""
    parts = target_path.split(os.sep)
    current = ""
    for part in parts:
        if not part:
            continue
        next_path = current + os.sep + part
        try:
            os.stat(next_path)
            if os.path.isfile(next_path) or os.path.islink(next_path):
                return True
        except OSError:
            break
        current = next_path
    return False


def _find_first_nonexistent_component(target_path: str) -> str:
    parts = target_path.split(os.sep)
    current = ""
    for part in parts:
        if not part:
            continue
        next_path = current + os.sep + part
        if not os.path.exists(next_path):
            return next_path
        current = next_path
    return target_path


# ---------------------------------------------------------------------------
# Mandatory deny paths
# ---------------------------------------------------------------------------


def _linux_get_mandatory_deny_paths(
    max_depth: int = DEFAULT_MANDATORY_DENY_SEARCH_DEPTH,
    allow_git_config: bool = False,
) -> list[str]:
    """
    Get mandatory deny paths using ripgrep on Linux.
    Falls back to os.walk if rg is unavailable.
    """
    cwd = os.getcwd()
    dangerous_dirs = get_dangerous_directories()

    deny_paths: list[str] = []

    for f in DANGEROUS_FILES:
        deny_paths.append(os.path.join(cwd, f))
    for d in dangerous_dirs:
        deny_paths.append(os.path.join(cwd, d))

    dot_git = os.path.join(cwd, ".git")
    dot_git_is_dir = os.path.isdir(dot_git)

    if dot_git_is_dir:
        deny_paths.append(os.path.join(cwd, ".git/hooks"))
        if not allow_git_config:
            deny_paths.append(os.path.join(cwd, ".git/config"))

    # Use ripgrep for fast scanning of nested dangerous files
    rg = which_sync("rg")
    if rg:
        iglob_args: list[str] = []
        for fname in DANGEROUS_FILES:
            iglob_args.extend(["--iglob", fname])
        for dname in dangerous_dirs:
            iglob_args.extend(["--iglob", f"**/{dname}/**"])
        iglob_args.extend(["--iglob", "**/.git/hooks/**"])
        if not allow_git_config:
            iglob_args.extend(["--iglob", "**/.git/config"])

        cmd = [
            rg,
            "--files",
            "--hidden",
            "--max-depth",
            str(max_depth),
            *iglob_args,
            "-g",
            "!**/node_modules/**",
        ]
        try:
            result = subprocess.run(
                cmd,
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=10,
            )
            matches = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        except (subprocess.TimeoutExpired, OSError) as exc:
            log_debug(f"[Sandbox] ripgrep scan failed: {exc}")
            matches = []

        for match in matches:
            absolute = os.path.normpath(os.path.join(cwd, match))
            found_dir = False
            for dname in list(dangerous_dirs) + [".git"]:
                norm_dname = normalize_case_for_comparison(dname)
                segments = absolute.split(os.sep)
                try:
                    idx = next(
                        i
                        for i, s in enumerate(segments)
                        if normalize_case_for_comparison(s) == norm_dname
                    )
                except StopIteration:
                    continue

                if dname == ".git":
                    git_dir = os.sep.join(segments[: idx + 1])
                    if ".git/hooks" in match:
                        deny_paths.append(os.path.join(git_dir, "hooks"))
                    elif ".git/config" in match:
                        deny_paths.append(os.path.join(git_dir, "config"))
                else:
                    deny_paths.append(os.sep.join(segments[: idx + 1]))
                found_dir = True
                break

            if not found_dir:
                deny_paths.append(absolute)

    return list(set(deny_paths))


# ---------------------------------------------------------------------------
# Filesystem arguments for bwrap
# ---------------------------------------------------------------------------


def _generate_filesystem_args(
    read_config: FsReadRestrictionConfig | None,
    write_config: FsWriteRestrictionConfig | None,
    mandatory_deny_search_depth: int = DEFAULT_MANDATORY_DENY_SEARCH_DEPTH,
    allow_git_config: bool = False,
) -> list[str]:
    args: list[str] = []

    if write_config is not None:
        args.extend(["--ro-bind", "/", "/"])
        allowed_write_paths: list[str] = []

        for pattern in write_config.allow_only or []:
            normalized = normalize_path_for_sandbox(pattern)
            log_debug(f"[Sandbox Linux] Processing write path: {pattern} -> {normalized}")

            if normalized.startswith("/dev/"):
                continue
            if not os.path.exists(normalized):
                log_debug(f"[Sandbox Linux] Skipping non-existent write path: {normalized}")
                continue
            try:
                resolved = os.path.realpath(normalized)
                norm_compare = normalized.rstrip("/")
                if resolved != norm_compare and is_symlink_outside_boundary(normalized, resolved):
                    log_debug(
                        f"[Sandbox Linux] Skipping symlink write path: {pattern} -> {resolved}"
                    )
                    continue
            except OSError:
                log_debug(f"[Sandbox Linux] Skipping unresolvable write path: {normalized}")
                continue

            args.extend(["--bind", normalized, normalized])
            allowed_write_paths.append(normalized)

        deny_paths = list(write_config.deny_within_allow or []) + _linux_get_mandatory_deny_paths(
            mandatory_deny_search_depth,
            allow_git_config,
        )

        for pattern in deny_paths:
            normalized = normalize_path_for_sandbox(pattern)
            if normalized.startswith("/dev/"):
                continue

            symlink = _find_symlink_in_path(normalized, allowed_write_paths)
            if symlink:
                args.extend(["--ro-bind", "/dev/null", symlink])
                continue

            if not os.path.exists(normalized):
                if _has_file_ancestor(normalized):
                    continue
                ancestor = os.path.dirname(normalized)
                while ancestor != "/" and not os.path.exists(ancestor):
                    ancestor = os.path.dirname(ancestor)

                within_allowed = any(
                    ancestor.startswith(ap + "/")
                    or ancestor == ap
                    or normalized.startswith(ap + "/")
                    for ap in allowed_write_paths
                )
                if within_allowed:
                    first_missing = _find_first_nonexistent_component(normalized)
                    if first_missing != normalized:
                        empty_dir = tempfile.mkdtemp(prefix="srt-empty-")
                        args.extend(["--ro-bind", empty_dir, first_missing])
                    else:
                        args.extend(["--ro-bind", "/dev/null", first_missing])
                    _bwrap_mount_points.add(first_missing)
                    _register_exit_cleanup()
                continue

            within_allowed = any(
                normalized.startswith(ap + "/") or normalized == ap for ap in allowed_write_paths
            )
            if within_allowed:
                args.extend(["--ro-bind", normalized, normalized])
    else:
        args.extend(["--bind", "/", "/"])

    # Read deny paths
    deny_read = list((read_config.deny_only if read_config else []) or [])
    if os.path.exists("/etc/ssh/ssh_config.d"):
        deny_read.append("/etc/ssh/ssh_config.d")

    for pattern in deny_read:
        normalized = normalize_path_for_sandbox(pattern)
        if not os.path.exists(normalized):
            continue
        if os.path.isdir(normalized):
            args.extend(["--tmpfs", normalized])
        else:
            args.extend(["--ro-bind", "/dev/null", normalized])

    return args


# ---------------------------------------------------------------------------
# Network bridge
# ---------------------------------------------------------------------------


def initialize_linux_network_bridge(
    http_proxy_port: int,
    socks_proxy_port: int,
) -> LinuxNetworkBridgeContext:
    """Start socat bridges that relay between Unix sockets and TCP proxy ports."""
    socket_id = secrets.token_hex(8)
    http_sock = os.path.join(tempfile.gettempdir(), f"srt-http-{socket_id}.sock")
    socks_sock = os.path.join(tempfile.gettempdir(), f"srt-socks-{socket_id}.sock")

    http_proc = subprocess.Popen(
        [
            "socat",
            f"UNIX-LISTEN:{http_sock},fork,reuseaddr",
            f"TCP:localhost:{http_proxy_port},keepalive,keepidle=10,keepintvl=5,keepcnt=3",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if http_proc.pid is None:
        raise RuntimeError("Failed to start HTTP bridge process")

    socks_proc = subprocess.Popen(
        [
            "socat",
            f"UNIX-LISTEN:{socks_sock},fork,reuseaddr",
            f"TCP:localhost:{socks_proxy_port},keepalive,keepidle=10,keepintvl=5,keepcnt=3",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if socks_proc.pid is None:
        http_proc.terminate()
        raise RuntimeError("Failed to start SOCKS bridge process")

    max_attempts = 5
    for i in range(max_attempts):
        if http_proc.poll() is not None or socks_proc.poll() is not None:
            raise RuntimeError("Linux bridge process died unexpectedly")
        if os.path.exists(http_sock) and os.path.exists(socks_sock):
            log_debug(f"Linux bridges ready after {i + 1} attempts")
            break
        if i == max_attempts - 1:
            http_proc.terminate()
            socks_proc.terminate()
            raise RuntimeError(f"Failed to create bridge sockets after {max_attempts} attempts")
        time.sleep(i * 0.1)

    return LinuxNetworkBridgeContext(
        http_socket_path=http_sock,
        socks_socket_path=socks_sock,
        http_bridge_process=http_proc,
        socks_bridge_process=socks_proc,
        http_proxy_port=http_proxy_port,
        socks_proxy_port=socks_proxy_port,
    )


# ---------------------------------------------------------------------------
# Build inner sandbox command
# ---------------------------------------------------------------------------


def _build_sandbox_command(
    http_socket_path: str,
    socks_socket_path: str,
    user_command: str,
    shell: str | None = None,
) -> str:
    shell_path = shell or "bash"
    socat_cmds = [
        f"socat TCP-LISTEN:3128,fork,reuseaddr UNIX-CONNECT:{http_socket_path} >/dev/null 2>&1 &",
        f"socat TCP-LISTEN:1080,fork,reuseaddr UNIX-CONNECT:{socks_socket_path} >/dev/null 2>&1 &",
        'trap "kill %1 %2 2>/dev/null; exit" EXIT',
    ]
    inner_script = "\n".join(socat_cmds + [f"eval {shlex.quote(user_command)}"])
    return f"{shell_path} -c {shlex.quote(inner_script)}"


# ---------------------------------------------------------------------------
# Public entry-point
# ---------------------------------------------------------------------------


def wrap_command_with_sandbox_linux(params: LinuxSandboxParams) -> str:
    """
    Wrap a command with bubblewrap restrictions on Linux.

    Returns the fully-escaped command ready for ``subprocess.Popen(shell=True)``.
    """
    has_read = params.read_config is not None and len(params.read_config.deny_only) > 0
    has_write = params.write_config is not None

    if not params.needs_network_restriction and not has_read and not has_write:
        return params.command

    bwrap_args: list[str] = ["--new-session", "--die-with-parent"]

    # Network
    if params.needs_network_restriction:
        bwrap_args.append("--unshare-net")

        if params.http_socket_path and params.socks_socket_path:
            if not os.path.exists(params.http_socket_path):
                raise RuntimeError(f"HTTP bridge socket missing: {params.http_socket_path}")
            if not os.path.exists(params.socks_socket_path):
                raise RuntimeError(f"SOCKS bridge socket missing: {params.socks_socket_path}")

            bwrap_args.extend(["--bind", params.http_socket_path, params.http_socket_path])
            bwrap_args.extend(["--bind", params.socks_socket_path, params.socks_socket_path])

            for env_str in generate_proxy_env_vars(3128, 1080):
                eq = env_str.index("=")
                bwrap_args.extend(["--setenv", env_str[:eq], env_str[eq + 1 :]])

    # Filesystem
    fs_args = _generate_filesystem_args(
        params.read_config,
        params.write_config,
        params.mandatory_deny_search_depth,
        params.allow_git_config,
    )
    bwrap_args.extend(fs_args)
    bwrap_args.extend(["--dev", "/dev"])

    # PID namespace
    bwrap_args.append("--unshare-pid")
    if not params.enable_weaker_nested_sandbox:
        bwrap_args.extend(["--proc", "/proc"])

    # Shell
    shell_name = params.bin_shell or "bash"
    shell_path = which_sync(shell_name)
    if not shell_path:
        raise RuntimeError(f"Shell '{shell_name}' not found in PATH")
    bwrap_args.extend(["--", shell_path, "-c"])

    if params.needs_network_restriction and params.http_socket_path and params.socks_socket_path:
        sandbox_cmd = _build_sandbox_command(
            params.http_socket_path,
            params.socks_socket_path,
            params.command,
            shell_path,
        )
        bwrap_args.append(sandbox_cmd)
    else:
        bwrap_args.append(params.command)

    wrapped = " ".join(shlex.quote(a) for a in ["bwrap"] + bwrap_args)
    restrictions = []
    if params.needs_network_restriction:
        restrictions.append("network")
    if has_read or has_write:
        restrictions.append("filesystem")
    log_debug(
        f"[Sandbox Linux] Wrapped command with bwrap ({', '.join(restrictions)} restrictions)"
    )

    return wrapped
