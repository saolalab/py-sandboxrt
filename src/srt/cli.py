"""
CLI entrypoint for py-srt.

Mirrors the TypeScript ``srt`` command, wrapping any command with network
and filesystem sandbox restrictions.
"""

from __future__ import annotations

import asyncio
import json
import os
import signal
import subprocess
import sys
from pathlib import Path

import click

from srt.config import SandboxRuntimeConfig, load_config
from srt.debug import log_debug
from srt.sandbox_manager import SandboxManager


def _default_config_path() -> Path:
    return Path.home() / ".srt-settings.json"


def _default_config() -> SandboxRuntimeConfig:
    return SandboxRuntimeConfig()


async def _run(
    command: str,
    settings_path: str | None,
    debug: bool,
) -> int:
    if debug:
        os.environ["SRT_DEBUG"] = "1"

    config_path = settings_path or str(_default_config_path())
    runtime_config = load_config(config_path)

    if runtime_config is None:
        log_debug(f"No config found at {config_path}, using default config")
        runtime_config = _default_config()

    mgr = SandboxManager()

    log_debug("Initializing sandbox...")
    await mgr.initialize(runtime_config)

    log_debug(f"Network config: {json.dumps(mgr.get_network_restriction_config(), indent=2)}")

    sandboxed_command = await mgr.wrap_with_sandbox(command)
    log_debug(f"Running: {command}")

    proc = subprocess.Popen(sandboxed_command, shell=True)

    def _sighandler(signum: int, frame: object) -> None:
        proc.send_signal(signum)

    signal.signal(signal.SIGINT, _sighandler)
    signal.signal(signal.SIGTERM, _sighandler)

    exit_code = proc.wait()

    mgr.cleanup_after_command()
    await mgr.reset()

    return exit_code


@click.command(context_settings={"ignore_unknown_options": True})
@click.argument("command_args", nargs=-1, type=click.UNPROCESSED)
@click.option("-d", "--debug", is_flag=True, help="Enable debug logging")
@click.option(
    "-s",
    "--settings",
    type=click.Path(),
    default=None,
    help="Path to config file (default: ~/.srt-settings.json)",
)
@click.option(
    "-c",
    "command_string",
    type=str,
    default=None,
    help="Run command string directly (like sh -c)",
)
@click.version_option(version="0.1.0", prog_name="srt")
def main(
    command_args: tuple[str, ...],
    debug: bool,
    settings: str | None,
    command_string: str | None,
) -> None:
    """Run commands in a sandbox with network and filesystem restrictions."""
    if debug:
        os.environ["SRT_DEBUG"] = "1"

    if command_string:
        log_debug(f"Command string mode: {command_string}")
        command = command_string
    elif command_args:
        log_debug(f"Original command: {command_args}")
        command = " ".join(command_args)
    else:
        click.echo(
            "Error: No command specified. Use -c <cmd> or provide command arguments.", err=True
        )
        sys.exit(1)

    exit_code = asyncio.run(_run(command, settings, debug))
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
