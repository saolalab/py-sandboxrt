"""
macOS sandbox implementation using sandbox-exec with Seatbelt profiles.

Generates dynamic sandbox profiles that enforce filesystem and network
restrictions via macOS's built-in sandbox-exec mechanism.
"""

from __future__ import annotations

import json
import os
import random
import re
import shlex
import string
import subprocess
from collections.abc import Callable
from dataclasses import dataclass

from srt.debug import log_debug
from srt.platform_utils import which_sync
from srt.sandbox_utils import (
    DANGEROUS_FILES,
    contains_glob_chars,
    decode_sandboxed_command,
    encode_sandboxed_command,
    generate_proxy_env_vars,
    get_dangerous_directories,
    glob_to_regex,
    normalize_path_for_sandbox,
)
from srt.violation_store import SandboxViolationEvent

# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

SandboxViolationCallback = type(lambda v: None)  # just a hint placeholder


@dataclass
class FsReadRestrictionConfig:
    deny_only: list[str]


@dataclass
class FsWriteRestrictionConfig:
    allow_only: list[str]
    deny_within_allow: list[str]


@dataclass
class MacOSSandboxParams:
    command: str
    needs_network_restriction: bool
    http_proxy_port: int | None = None
    socks_proxy_port: int | None = None
    allow_unix_sockets: list[str] | None = None
    allow_all_unix_sockets: bool | None = None
    allow_local_binding: bool | None = None
    read_config: FsReadRestrictionConfig | None = None
    write_config: FsWriteRestrictionConfig | None = None
    ignore_violations: dict[str, list[str]] | None = None
    allow_pty: bool | None = None
    allow_git_config: bool = False
    enable_weaker_network_isolation: bool = False
    bin_shell: str | None = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SESSION_SUFFIX = f"_{''.join(random.choices(string.ascii_lowercase + string.digits, k=9))}_SBX"


def _generate_log_tag(command: str) -> str:
    encoded = encode_sandboxed_command(command)
    return f"CMD64_{encoded}_END_{_SESSION_SUFFIX}"


def _escape_path(path_str: str) -> str:
    return json.dumps(path_str)


def _get_ancestor_directories(path_str: str) -> list[str]:
    ancestors: list[str] = []
    current = os.path.dirname(path_str)
    while current not in ("/", "."):
        ancestors.append(current)
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    return ancestors


# ---------------------------------------------------------------------------
# Mandatory deny patterns
# ---------------------------------------------------------------------------


def mac_get_mandatory_deny_patterns(allow_git_config: bool = False) -> list[str]:
    """Glob patterns always blocked from writes on macOS."""
    cwd = os.getcwd()
    deny: list[str] = []

    for fname in DANGEROUS_FILES:
        deny.append(os.path.join(cwd, fname))
        deny.append(f"**/{fname}")

    for dname in get_dangerous_directories():
        deny.append(os.path.join(cwd, dname))
        deny.append(f"**/{dname}/**")

    deny.append(os.path.join(cwd, ".git/hooks"))
    deny.append("**/.git/hooks/**")

    if not allow_git_config:
        deny.append(os.path.join(cwd, ".git/config"))
        deny.append("**/.git/config")

    return list(set(deny))


# ---------------------------------------------------------------------------
# Profile rule generators
# ---------------------------------------------------------------------------


def _generate_move_blocking_rules(path_patterns: list[str], log_tag: str) -> list[str]:
    rules: list[str] = []
    for pattern in path_patterns:
        normalized = normalize_path_for_sandbox(pattern)
        if contains_glob_chars(normalized):
            regex_pat = glob_to_regex(normalized)
            rules.extend(
                [
                    "(deny file-write-unlink",
                    f"  (regex {_escape_path(regex_pat)})",
                    f'  (with message "{log_tag}"))',
                ]
            )
            static_prefix = re.split(r"[*?\[\]]", normalized)[0]
            if static_prefix and static_prefix != "/":
                base_dir = (
                    static_prefix.rstrip("/")
                    if static_prefix.endswith("/")
                    else os.path.dirname(static_prefix)
                )
                rules.extend(
                    [
                        "(deny file-write-unlink",
                        f"  (literal {_escape_path(base_dir)})",
                        f'  (with message "{log_tag}"))',
                    ]
                )
                for ancestor in _get_ancestor_directories(base_dir):
                    rules.extend(
                        [
                            "(deny file-write-unlink",
                            f"  (literal {_escape_path(ancestor)})",
                            f'  (with message "{log_tag}"))',
                        ]
                    )
        else:
            rules.extend(
                [
                    "(deny file-write-unlink",
                    f"  (subpath {_escape_path(normalized)})",
                    f'  (with message "{log_tag}"))',
                ]
            )
            for ancestor in _get_ancestor_directories(normalized):
                rules.extend(
                    [
                        "(deny file-write-unlink",
                        f"  (literal {_escape_path(ancestor)})",
                        f'  (with message "{log_tag}"))',
                    ]
                )
    return rules


def _generate_read_rules(config: FsReadRestrictionConfig | None, log_tag: str) -> list[str]:
    if config is None:
        return ["(allow file-read*)"]

    rules = ["(allow file-read*)"]

    for pattern in config.deny_only or []:
        normalized = normalize_path_for_sandbox(pattern)
        if contains_glob_chars(normalized):
            regex_pat = glob_to_regex(normalized)
            rules.extend(
                [
                    "(deny file-read*",
                    f"  (regex {_escape_path(regex_pat)})",
                    f'  (with message "{log_tag}"))',
                ]
            )
        else:
            rules.extend(
                [
                    "(deny file-read*",
                    f"  (subpath {_escape_path(normalized)})",
                    f'  (with message "{log_tag}"))',
                ]
            )

    rules.extend(_generate_move_blocking_rules(config.deny_only or [], log_tag))
    return rules


def _get_tmpdir_parent_if_macos_pattern() -> list[str]:
    tmpdir = os.environ.get("TMPDIR", "")
    if not tmpdir:
        return []
    match = re.match(r"^/(private/)?var/folders/[^/]{2}/[^/]+/T/?$", tmpdir)
    if not match:
        return []
    parent = re.sub(r"/T/?$", "", tmpdir)
    if parent.startswith("/private/var/"):
        return [parent, parent.replace("/private", "", 1)]
    if parent.startswith("/var/"):
        return [parent, "/private" + parent]
    return [parent]


def _generate_write_rules(
    config: FsWriteRestrictionConfig | None,
    log_tag: str,
    allow_git_config: bool = False,
) -> list[str]:
    if config is None:
        return ["(allow file-write*)"]

    rules: list[str] = []

    for tmpdir_parent in _get_tmpdir_parent_if_macos_pattern():
        normalized = normalize_path_for_sandbox(tmpdir_parent)
        rules.extend(
            [
                "(allow file-write*",
                f"  (subpath {_escape_path(normalized)})",
                f'  (with message "{log_tag}"))',
            ]
        )

    for pattern in config.allow_only or []:
        normalized = normalize_path_for_sandbox(pattern)
        if contains_glob_chars(normalized):
            regex_pat = glob_to_regex(normalized)
            rules.extend(
                [
                    "(allow file-write*",
                    f"  (regex {_escape_path(regex_pat)})",
                    f'  (with message "{log_tag}"))',
                ]
            )
        else:
            rules.extend(
                [
                    "(allow file-write*",
                    f"  (subpath {_escape_path(normalized)})",
                    f'  (with message "{log_tag}"))',
                ]
            )

    deny_paths = list(config.deny_within_allow or []) + mac_get_mandatory_deny_patterns(
        allow_git_config
    )
    for pattern in deny_paths:
        normalized = normalize_path_for_sandbox(pattern)
        if contains_glob_chars(normalized):
            regex_pat = glob_to_regex(normalized)
            rules.extend(
                [
                    "(deny file-write*",
                    f"  (regex {_escape_path(regex_pat)})",
                    f'  (with message "{log_tag}"))',
                ]
            )
        else:
            rules.extend(
                [
                    "(deny file-write*",
                    f"  (subpath {_escape_path(normalized)})",
                    f'  (with message "{log_tag}"))',
                ]
            )

    rules.extend(_generate_move_blocking_rules(deny_paths, log_tag))
    return rules


# ---------------------------------------------------------------------------
# Full profile generation
# ---------------------------------------------------------------------------


def _generate_sandbox_profile(
    *,
    read_config: FsReadRestrictionConfig | None,
    write_config: FsWriteRestrictionConfig | None,
    http_proxy_port: int | None,
    socks_proxy_port: int | None,
    needs_network_restriction: bool,
    allow_unix_sockets: list[str] | None,
    allow_all_unix_sockets: bool | None,
    allow_local_binding: bool | None,
    allow_pty: bool | None,
    allow_git_config: bool,
    enable_weaker_network_isolation: bool,
    log_tag: str,
) -> str:
    lines: list[str] = [
        "(version 1)",
        f'(deny default (with message "{log_tag}"))',
        "",
        f"; LogTag: {log_tag}",
        "",
        "; Essential permissions",
        "(allow process-exec)",
        "(allow process-fork)",
        "(allow process-info* (target same-sandbox))",
        "(allow signal (target same-sandbox))",
        "(allow mach-priv-task-port (target same-sandbox))",
        "",
        "(allow user-preference-read)",
        "",
        "; Mach IPC services",
        "(allow mach-lookup",
        '  (global-name "com.apple.audio.systemsoundserver")',
        '  (global-name "com.apple.distributed_notifications@Uv3")',
        '  (global-name "com.apple.FontObjectsServer")',
        '  (global-name "com.apple.fonts")',
        '  (global-name "com.apple.logd")',
        '  (global-name "com.apple.lsd.mapdb")',
        '  (global-name "com.apple.PowerManagement.control")',
        '  (global-name "com.apple.system.logger")',
        '  (global-name "com.apple.system.notification_center")',
        '  (global-name "com.apple.system.opendirectoryd.libinfo")',
        '  (global-name "com.apple.system.opendirectoryd.membership")',
        '  (global-name "com.apple.bsd.dirhelper")',
        '  (global-name "com.apple.securityd.xpc")',
        '  (global-name "com.apple.coreservices.launchservicesd")',
        ")",
        "",
    ]

    if enable_weaker_network_isolation:
        lines.extend(
            [
                "; trustd.agent for Go TLS verification",
                '(allow mach-lookup (global-name "com.apple.trustd.agent"))',
            ]
        )

    lines.extend(
        [
            "",
            "(allow ipc-posix-shm)",
            "(allow ipc-posix-sem)",
            "",
            "(allow iokit-open",
            '  (iokit-registry-entry-class "IOSurfaceRootUserClient")',
            '  (iokit-registry-entry-class "RootDomainUserClient")',
            '  (iokit-user-client-class "IOSurfaceSendRight")',
            ")",
            "(allow iokit-get-properties)",
            "",
            "(allow system-socket (require-all (socket-domain AF_SYSTEM) (socket-protocol 2)))",
            "",
            "; sysctl reads",
            "(allow sysctl-read",
            '  (sysctl-name "hw.activecpu")',
            '  (sysctl-name "hw.memsize")',
            '  (sysctl-name "hw.ncpu")',
            '  (sysctl-name "hw.logicalcpu")',
            '  (sysctl-name "hw.logicalcpu_max")',
            '  (sysctl-name "hw.physicalcpu")',
            '  (sysctl-name "hw.physicalcpu_max")',
            '  (sysctl-name "hw.pagesize")',
            '  (sysctl-name "hw.pagesize_compat")',
            '  (sysctl-name "hw.cputype")',
            '  (sysctl-name "hw.cpufamily")',
            '  (sysctl-name "hw.machine")',
            '  (sysctl-name "hw.byteorder")',
            '  (sysctl-name "hw.busfrequency_compat")',
            '  (sysctl-name "hw.cachelinesize_compat")',
            '  (sysctl-name "hw.cpufrequency")',
            '  (sysctl-name "hw.cpufrequency_compat")',
            '  (sysctl-name "hw.l1dcachesize_compat")',
            '  (sysctl-name "hw.l1icachesize_compat")',
            '  (sysctl-name "hw.l2cachesize_compat")',
            '  (sysctl-name "hw.l3cachesize_compat")',
            '  (sysctl-name "hw.packages")',
            '  (sysctl-name "hw.tbfrequency_compat")',
            '  (sysctl-name "hw.vectorunit")',
            '  (sysctl-name "hw.cacheconfig")',
            '  (sysctl-name "hw.nperflevels")',
            '  (sysctl-name "kern.argmax")',
            '  (sysctl-name "kern.bootargs")',
            '  (sysctl-name "kern.hostname")',
            '  (sysctl-name "kern.maxfiles")',
            '  (sysctl-name "kern.maxfilesperproc")',
            '  (sysctl-name "kern.maxproc")',
            '  (sysctl-name "kern.ngroups")',
            '  (sysctl-name "kern.osproductversion")',
            '  (sysctl-name "kern.osrelease")',
            '  (sysctl-name "kern.ostype")',
            '  (sysctl-name "kern.osvariant_status")',
            '  (sysctl-name "kern.osversion")',
            '  (sysctl-name "kern.secure_kernel")',
            '  (sysctl-name "kern.tcsm_available")',
            '  (sysctl-name "kern.tcsm_enable")',
            '  (sysctl-name "kern.usrstack64")',
            '  (sysctl-name "kern.version")',
            '  (sysctl-name "kern.willshutdown")',
            '  (sysctl-name "machdep.cpu.brand_string")',
            '  (sysctl-name "machdep.ptrauth_enabled")',
            '  (sysctl-name "security.mac.lockdown_mode_state")',
            '  (sysctl-name "sysctl.proc_cputype")',
            '  (sysctl-name "vm.loadavg")',
            '  (sysctl-name-prefix "hw.optional.arm")',
            '  (sysctl-name-prefix "hw.optional.arm.")',
            '  (sysctl-name-prefix "hw.optional.armv8_")',
            '  (sysctl-name-prefix "hw.perflevel")',
            '  (sysctl-name-prefix "kern.proc.all")',
            '  (sysctl-name-prefix "kern.proc.pgrp.")',
            '  (sysctl-name-prefix "kern.proc.pid.")',
            '  (sysctl-name-prefix "machdep.cpu.")',
            '  (sysctl-name-prefix "net.routetable.")',
            ")",
            "",
            '(allow sysctl-write (sysctl-name "kern.tcsm_enable"))',
            "",
            "(allow distributed-notification-post)",
            '(allow mach-lookup (global-name "com.apple.SecurityServer"))',
            "",
            '(allow file-ioctl (literal "/dev/null"))',
            '(allow file-ioctl (literal "/dev/zero"))',
            '(allow file-ioctl (literal "/dev/random"))',
            '(allow file-ioctl (literal "/dev/urandom"))',
            '(allow file-ioctl (literal "/dev/dtracehelper"))',
            '(allow file-ioctl (literal "/dev/tty"))',
            "",
            "(allow file-ioctl file-read-data file-write-data",
            "  (require-all",
            '    (literal "/dev/null")',
            "    (vnode-type CHARACTER-DEVICE)",
            "  )",
            ")",
            "",
        ]
    )

    # Network rules
    lines.append("; Network")
    if not needs_network_restriction:
        lines.append("(allow network*)")
    else:
        if allow_local_binding:
            lines.append('(allow network-bind (local ip "*:*"))')
            lines.append('(allow network-inbound (local ip "*:*"))')
            lines.append('(allow network-outbound (local ip "*:*"))')

        if allow_all_unix_sockets:
            lines.append("(allow system-socket (socket-domain AF_UNIX))")
            lines.append('(allow network-bind (local unix-socket (path-regex #"^/")))')
            lines.append('(allow network-outbound (remote unix-socket (path-regex #"^/")))')
        elif allow_unix_sockets:
            lines.append("(allow system-socket (socket-domain AF_UNIX))")
            for sock_path in allow_unix_sockets:
                normalized = normalize_path_for_sandbox(sock_path)
                lines.append(
                    f"(allow network-bind (local unix-socket (subpath {_escape_path(normalized)})))"
                )
                lines.append(
                    f"(allow network-outbound (remote unix-socket (subpath {_escape_path(normalized)})))"
                )

        if http_proxy_port is not None:
            lines.append(f'(allow network-bind (local ip "localhost:{http_proxy_port}"))')
            lines.append(f'(allow network-inbound (local ip "localhost:{http_proxy_port}"))')
            lines.append(f'(allow network-outbound (remote ip "localhost:{http_proxy_port}"))')

        if socks_proxy_port is not None:
            lines.append(f'(allow network-bind (local ip "localhost:{socks_proxy_port}"))')
            lines.append(f'(allow network-inbound (local ip "localhost:{socks_proxy_port}"))')
            lines.append(f'(allow network-outbound (remote ip "localhost:{socks_proxy_port}"))')

    lines.append("")

    # File read
    lines.append("; File read")
    lines.extend(_generate_read_rules(read_config, log_tag))
    lines.append("")

    # File write
    lines.append("; File write")
    lines.extend(_generate_write_rules(write_config, log_tag, allow_git_config))

    # PTY
    if allow_pty:
        lines.extend(
            [
                "",
                "; Pseudo-terminal (pty) support",
                "(allow pseudo-tty)",
                "(allow file-ioctl",
                '  (literal "/dev/ptmx")',
                '  (regex #"^/dev/ttys")',
                ")",
                "(allow file-read* file-write*",
                '  (literal "/dev/ptmx")',
                '  (regex #"^/dev/ttys")',
                ")",
            ]
        )

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Public entry-point
# ---------------------------------------------------------------------------


def wrap_command_with_sandbox_macos(params: MacOSSandboxParams) -> str:
    """
    Wrap a shell command string with macOS sandbox-exec restrictions.

    Returns the fully-escaped command ready for ``subprocess.Popen(shell=True)``.
    """
    has_read_restrictions = params.read_config is not None and len(params.read_config.deny_only) > 0
    has_write_restrictions = params.write_config is not None

    if (
        not params.needs_network_restriction
        and not has_read_restrictions
        and not has_write_restrictions
    ):
        return params.command

    log_tag = _generate_log_tag(params.command)

    profile = _generate_sandbox_profile(
        read_config=params.read_config,
        write_config=params.write_config,
        http_proxy_port=params.http_proxy_port,
        socks_proxy_port=params.socks_proxy_port,
        needs_network_restriction=params.needs_network_restriction,
        allow_unix_sockets=params.allow_unix_sockets,
        allow_all_unix_sockets=params.allow_all_unix_sockets,
        allow_local_binding=params.allow_local_binding,
        allow_pty=params.allow_pty,
        allow_git_config=params.allow_git_config,
        enable_weaker_network_isolation=params.enable_weaker_network_isolation,
        log_tag=log_tag,
    )

    proxy_env_args = generate_proxy_env_vars(params.http_proxy_port, params.socks_proxy_port)

    shell_name = params.bin_shell or "bash"
    shell_path = which_sync(shell_name)
    if not shell_path:
        raise RuntimeError(f"Shell '{shell_name}' not found in PATH")

    parts = (
        ["env"]
        + proxy_env_args
        + [
            "sandbox-exec",
            "-p",
            profile,
            shell_path,
            "-c",
            params.command,
        ]
    )
    return " ".join(shlex.quote(p) for p in parts)


# ---------------------------------------------------------------------------
# Log monitor
# ---------------------------------------------------------------------------


def start_macos_sandbox_log_monitor(
    callback: Callable[[SandboxViolationEvent], None],
    ignore_violations: dict[str, list[str]] | None = None,
) -> subprocess.Popen[str] | None:
    """
    Start streaming macOS system logs for sandbox violations.

    Returns the subprocess so the caller can terminate it, or None on failure.
    """
    cmd_extract_re = re.compile(r"CMD64_(.+?)_END")
    sandbox_extract_re = re.compile(r"Sandbox:\s+(.+)$")

    wildcard_paths = (ignore_violations or {}).get("*", [])
    command_patterns = [
        (pattern, paths) for pattern, paths in (ignore_violations or {}).items() if pattern != "*"
    ]

    try:
        proc = subprocess.Popen(
            [
                "log",
                "stream",
                "--predicate",
                f'(eventMessage ENDSWITH "{_SESSION_SUFFIX}")',
                "--style",
                "compact",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except OSError as exc:
        log_debug(f"Failed to start log stream: {exc}")
        return None

    import threading

    def _reader() -> None:
        assert proc.stdout is not None
        for raw_line in proc.stdout:
            line = raw_line.rstrip("\n")
            if "Sandbox:" not in line or "deny" not in line:
                continue

            sandbox_match = sandbox_extract_re.search(line)
            if not sandbox_match:
                continue
            details = sandbox_match.group(1)

            # Noisy violations to always skip
            if any(
                tok in details
                for tok in ("mDNSResponder", "com.apple.diagnosticd", "com.apple.analyticsd")
            ):
                continue

            cmd_match = cmd_extract_re.search(line)
            command: str | None = None
            encoded_cmd: str | None = None
            if cmd_match:
                encoded_cmd = cmd_match.group(1)
                try:
                    command = decode_sandboxed_command(encoded_cmd)
                except Exception:
                    pass

            if command and ignore_violations:
                if wildcard_paths and any(p in details for p in wildcard_paths):
                    continue
                skip = False
                for pattern, paths in command_patterns:
                    if pattern in command and any(p in details for p in paths):
                        skip = True
                        break
                if skip:
                    continue

            callback(
                SandboxViolationEvent(
                    line=details,
                    command=command,
                    encoded_command=encoded_cmd,
                )
            )

    t = threading.Thread(target=_reader, daemon=True)
    t.start()
    return proc
