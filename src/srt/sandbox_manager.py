"""
Central sandbox manager that orchestrates network and filesystem sandboxing.

Runs on the host machine — starts proxy servers, generates sandbox profiles,
and wraps user commands with OS-level restrictions.
"""

from __future__ import annotations

import copy
import os
import subprocess
from collections.abc import Awaitable, Callable

from srt.config import SandboxRuntimeConfig
from srt.debug import log_debug
from srt.http_proxy import HttpProxyServer
from srt.linux_sandbox import (
    FsReadRestrictionConfig as LinuxFsRead,
)
from srt.linux_sandbox import (
    FsWriteRestrictionConfig as LinuxFsWrite,
)
from srt.linux_sandbox import (
    LinuxNetworkBridgeContext,
    LinuxSandboxParams,
    SandboxDependencyCheck,
    check_linux_dependencies,
    cleanup_bwrap_mount_points,
    initialize_linux_network_bridge,
    wrap_command_with_sandbox_linux,
)
from srt.macos_sandbox import (
    FsReadRestrictionConfig as MacFsRead,
)
from srt.macos_sandbox import (
    FsWriteRestrictionConfig as MacFsWrite,
)
from srt.macos_sandbox import (
    MacOSSandboxParams,
    start_macos_sandbox_log_monitor,
    wrap_command_with_sandbox_macos,
)
from srt.platform_utils import get_platform, is_supported_platform, which_sync
from srt.sandbox_utils import (
    contains_glob_chars,
    expand_glob_pattern,
    get_default_write_paths,
    remove_trailing_glob_suffix,
)
from srt.socks_proxy import SocksProxyServer
from srt.violation_store import SandboxViolationStore

NetworkAskCallback = Callable[[str, int], Awaitable[bool]]


class SandboxManager:
    """
    Global sandbox manager that handles both network and filesystem restrictions.

    This runs outside of the sandbox, on the host machine.

    Usage::

        mgr = SandboxManager()
        await mgr.initialize(config)
        cmd = await mgr.wrap_with_sandbox("curl https://example.com")
        # execute *cmd* via subprocess
        await mgr.reset()
    """

    def __init__(self) -> None:
        self._config: SandboxRuntimeConfig | None = None
        self._http_proxy: HttpProxyServer | None = None
        self._socks_proxy: SocksProxyServer | None = None
        self._http_proxy_port: int | None = None
        self._socks_proxy_port: int | None = None
        self._linux_bridge: LinuxNetworkBridgeContext | None = None
        self._initialized = False
        self._violation_store = SandboxViolationStore()
        self._log_monitor_proc: subprocess.Popen | None = None

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def config(self) -> SandboxRuntimeConfig | None:
        return self._config

    @property
    def is_sandboxing_enabled(self) -> bool:
        return self._config is not None

    @property
    def violation_store(self) -> SandboxViolationStore:
        return self._violation_store

    @property
    def http_proxy_port(self) -> int | None:
        return self._http_proxy_port

    @property
    def socks_proxy_port(self) -> int | None:
        return self._socks_proxy_port

    # ------------------------------------------------------------------
    # Initialization
    # ------------------------------------------------------------------

    async def initialize(
        self,
        runtime_config: SandboxRuntimeConfig,
        *,
        enable_log_monitor: bool = False,
    ) -> None:
        """
        Initialize the sandbox: validate dependencies, start proxy servers, and
        set up platform-specific infrastructure.
        """
        if self._initialized:
            return

        self._config = runtime_config

        deps = self.check_dependencies()
        if deps.errors:
            raise RuntimeError(f"Sandbox dependencies not available: {', '.join(deps.errors)}")

        if enable_log_monitor and get_platform() == "macos":
            self._log_monitor_proc = start_macos_sandbox_log_monitor(
                self._violation_store.add_violation,
                runtime_config.ignore_violations,
            )
            log_debug("Started macOS sandbox log monitor")

        # Start proxy servers
        if runtime_config.network.http_proxy_port is not None:
            self._http_proxy_port = runtime_config.network.http_proxy_port
            log_debug(f"Using external HTTP proxy on port {self._http_proxy_port}")
        else:
            self._http_proxy = HttpProxyServer(filter_func=self._filter_request)
            self._http_proxy_port = await self._http_proxy.start()

        if runtime_config.network.socks_proxy_port is not None:
            self._socks_proxy_port = runtime_config.network.socks_proxy_port
            log_debug(f"Using external SOCKS proxy on port {self._socks_proxy_port}")
        else:
            self._socks_proxy = SocksProxyServer(filter_func=self._filter_request)
            self._socks_proxy_port = await self._socks_proxy.start()

        # Linux network bridge
        if get_platform() == "linux" and self._http_proxy_port and self._socks_proxy_port:
            self._linux_bridge = initialize_linux_network_bridge(
                self._http_proxy_port,
                self._socks_proxy_port,
            )

        self._initialized = True
        log_debug("Network infrastructure initialized")

    # ------------------------------------------------------------------
    # Dependency checking
    # ------------------------------------------------------------------

    def check_dependencies(self) -> SandboxDependencyCheck:
        if not is_supported_platform():
            return SandboxDependencyCheck(errors=["Unsupported platform"])

        errors: list[str] = []
        warnings: list[str] = []

        rg_cmd = "rg"
        if self._config and self._config.ripgrep:
            rg_cmd = self._config.ripgrep.command
        if which_sync(rg_cmd) is None:
            errors.append(f"ripgrep ({rg_cmd}) not found")

        if get_platform() == "linux":
            linux_deps = check_linux_dependencies()
            errors.extend(linux_deps.errors)
            warnings.extend(linux_deps.warnings)

        return SandboxDependencyCheck(warnings=warnings, errors=errors)

    # ------------------------------------------------------------------
    # Configuration helpers
    # ------------------------------------------------------------------

    def get_fs_read_config(self) -> MacFsRead:
        if not self._config:
            return MacFsRead(deny_only=[])

        deny: list[str] = []
        for p in self._config.filesystem.deny_read:
            stripped = remove_trailing_glob_suffix(p)
            if get_platform() == "linux" and contains_glob_chars(stripped):
                deny.extend(expand_glob_pattern(p))
            else:
                deny.append(stripped)
        return MacFsRead(deny_only=deny)

    def get_fs_write_config(self) -> MacFsWrite:
        if not self._config:
            return MacFsWrite(allow_only=get_default_write_paths(), deny_within_allow=[])

        allow_paths = [remove_trailing_glob_suffix(p) for p in self._config.filesystem.allow_write]
        if get_platform() == "linux":
            allow_paths = [p for p in allow_paths if not contains_glob_chars(p)]

        deny_paths = [remove_trailing_glob_suffix(p) for p in self._config.filesystem.deny_write]
        if get_platform() == "linux":
            deny_paths = [p for p in deny_paths if not contains_glob_chars(p)]

        return MacFsWrite(
            allow_only=get_default_write_paths() + allow_paths,
            deny_within_allow=deny_paths,
        )

    def get_network_restriction_config(self) -> dict:
        if not self._config:
            return {}
        allowed = self._config.network.allowed_domains
        denied = self._config.network.denied_domains
        result: dict = {}
        if allowed:
            result["allowed_hosts"] = allowed
        if denied:
            result["denied_hosts"] = denied
        return result

    def update_config(self, new_config: SandboxRuntimeConfig) -> None:
        self._config = copy.deepcopy(new_config)
        log_debug("Sandbox configuration updated")

    # ------------------------------------------------------------------
    # Wrap command
    # ------------------------------------------------------------------

    async def wrap_with_sandbox(self, command: str, *, bin_shell: str | None = None) -> str:
        """
        Wrap *command* with platform-appropriate sandbox restrictions.

        Returns a shell string that can be passed to ``subprocess.Popen(shell=True)``.
        """
        platform = get_platform()

        cfg = self._config
        read_config = self.get_fs_read_config()
        write_config = self.get_fs_write_config()

        has_network = cfg is not None and cfg.network.allowed_domains is not None
        needs_network_restriction = has_network
        needs_network_proxy = has_network

        if platform == "macos":
            return wrap_command_with_sandbox_macos(
                MacOSSandboxParams(
                    command=command,
                    needs_network_restriction=needs_network_restriction,
                    http_proxy_port=self._http_proxy_port if needs_network_proxy else None,
                    socks_proxy_port=self._socks_proxy_port if needs_network_proxy else None,
                    read_config=read_config,
                    write_config=write_config,
                    allow_unix_sockets=cfg.network.allow_unix_sockets if cfg else None,
                    allow_all_unix_sockets=cfg.network.allow_all_unix_sockets if cfg else None,
                    allow_local_binding=cfg.network.allow_local_binding if cfg else None,
                    ignore_violations=cfg.ignore_violations if cfg else None,
                    allow_pty=cfg.allow_pty if cfg else None,
                    allow_git_config=cfg.filesystem.allow_git_config or False if cfg else False,
                    enable_weaker_network_isolation=cfg.enable_weaker_network_isolation or False
                    if cfg
                    else False,
                    bin_shell=bin_shell,
                )
            )

        if platform == "linux":
            linux_read = LinuxFsRead(deny_only=read_config.deny_only)
            linux_write = LinuxFsWrite(
                allow_only=write_config.allow_only,
                deny_within_allow=write_config.deny_within_allow,
            )
            return wrap_command_with_sandbox_linux(
                LinuxSandboxParams(
                    command=command,
                    needs_network_restriction=needs_network_restriction,
                    http_socket_path=self._linux_bridge.http_socket_path
                    if self._linux_bridge
                    else None,
                    socks_socket_path=self._linux_bridge.socks_socket_path
                    if self._linux_bridge
                    else None,
                    http_proxy_port=self._http_proxy_port if needs_network_proxy else None,
                    socks_proxy_port=self._socks_proxy_port if needs_network_proxy else None,
                    read_config=linux_read,
                    write_config=linux_write,
                    enable_weaker_nested_sandbox=cfg.enable_weaker_nested_sandbox if cfg else None,
                    allow_all_unix_sockets=cfg.network.allow_all_unix_sockets if cfg else None,
                    bin_shell=bin_shell,
                    mandatory_deny_search_depth=cfg.mandatory_deny_search_depth or 3 if cfg else 3,
                    allow_git_config=cfg.filesystem.allow_git_config or False if cfg else False,
                )
            )

        raise RuntimeError(f"Sandbox not supported on platform: {platform}")

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def cleanup_after_command(self) -> None:
        """Clean up bwrap mount-point artifacts (Linux). No-op on macOS."""
        cleanup_bwrap_mount_points()

    async def reset(self) -> None:
        """Tear down all sandbox infrastructure."""
        self.cleanup_after_command()

        if self._log_monitor_proc:
            self._log_monitor_proc.terminate()
            self._log_monitor_proc = None

        if self._linux_bridge:
            for proc in (
                self._linux_bridge.http_bridge_process,
                self._linux_bridge.socks_bridge_process,
            ):
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
            for sock in (self._linux_bridge.http_socket_path, self._linux_bridge.socks_socket_path):
                try:
                    os.unlink(sock)
                except OSError:
                    pass
            self._linux_bridge = None

        if self._http_proxy:
            await self._http_proxy.stop()
            self._http_proxy = None

        if self._socks_proxy:
            await self._socks_proxy.stop()
            self._socks_proxy = None

        self._http_proxy_port = None
        self._socks_proxy_port = None
        self._initialized = False

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _matches_domain_pattern(self, hostname: str, pattern: str) -> bool:
        if pattern.startswith("*."):
            base = pattern[2:]
            return hostname.lower().endswith("." + base.lower())
        return hostname.lower() == pattern.lower()

    async def _filter_request(self, port: int, host: str) -> bool:
        """Domain-based allow/deny filter invoked by both proxy servers."""
        if not self._config:
            log_debug("No config available, denying network request")
            return False

        for denied in self._config.network.denied_domains:
            if self._matches_domain_pattern(host, denied):
                log_debug(f"Denied by config rule: {host}:{port}")
                return False

        for allowed in self._config.network.allowed_domains:
            if self._matches_domain_pattern(host, allowed):
                log_debug(f"Allowed by config rule: {host}:{port}")
                return True

        log_debug(f"No matching config rule, denying: {host}:{port}")
        return False
