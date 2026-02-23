"""
Tests for the CLI entrypoint.

Ported from: test/cli.test.ts
"""

from __future__ import annotations

import os
import subprocess
import sys

from tests.conftest import skip_on_linux_ci


def _run_srt(
    args: list[str], *, debug: bool = False, env_override: dict | None = None
) -> subprocess.CompletedProcess:
    """Run the srt CLI and capture output."""
    env = {**os.environ}
    env["HOME"] = "/tmp/cli-test-nonexistent"
    if debug:
        env["SRT_DEBUG"] = "1"
    if env_override:
        env.update(env_override)

    return subprocess.run(
        [sys.executable, "-m", "srt.cli", *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=15,
    )


@skip_on_linux_ci
class TestCFlag:
    """Tests for -c flag (command string mode)."""

    def test_executes_simple_command(self):
        result = _run_srt(["-c", "echo hello"])
        assert result.stdout.strip() == "hello"
        assert result.returncode == 0

    def test_passes_command_string_directly(self):
        result = _run_srt(["-c", 'echo "hello world"'])
        assert result.stdout.strip() == "hello world"
        assert result.returncode == 0

    def test_handles_json_arguments(self):
        result = _run_srt(["-c", 'echo \'{"key": "value"}\''])
        assert result.stdout.strip() == '{"key": "value"}'
        assert result.returncode == 0

    def test_handles_shell_expansion(self):
        result = _run_srt(["-c", "echo $HOME"])
        assert result.stdout.strip() != "$HOME"
        assert result.returncode == 0

    def test_handles_pipes(self):
        result = _run_srt(["-c", "echo 'hello world' | wc -w"])
        assert result.stdout.strip() == "2"
        assert result.returncode == 0

    def test_handles_command_substitution(self):
        result = _run_srt(["-c", 'echo "count: $(echo 1 2 3 | wc -w)"'])
        assert "3" in result.stdout.strip()
        assert result.returncode == 0


@skip_on_linux_ci
class TestPositionalArgs:
    """Tests for default mode (positional arguments)."""

    def test_executes_simple_command(self):
        result = _run_srt(["echo", "hello"])
        assert result.stdout.strip() == "hello"
        assert result.returncode == 0

    def test_joins_multiple_args(self):
        result = _run_srt(["echo", "hello", "world"])
        assert result.stdout.strip() == "hello world"
        assert result.returncode == 0


class TestErrorHandling:
    def test_error_when_no_command(self):
        result = _run_srt([])
        assert "No command specified" in result.stderr
        assert result.returncode != 0

    def test_error_when_only_options(self):
        result = _run_srt(["-d"])
        assert "No command specified" in result.stderr
        assert result.returncode != 0


@skip_on_linux_ci
class TestDebugOutput:
    def test_debug_enables_output_positional(self):
        result = _run_srt(["echo", "test"], debug=True)
        assert "[SandboxDebug]" in result.stderr
        assert "Original command" in result.stderr
        assert result.returncode == 0

    def test_debug_enables_output_c_mode(self):
        result = _run_srt(["-c", "echo test"], debug=True)
        assert "[SandboxDebug]" in result.stderr
        assert "Command string mode" in result.stderr
        assert result.returncode == 0

    def test_no_debug_without_flag(self):
        result = _run_srt(["-c", "echo test"], debug=False)
        assert "[SandboxDebug]" not in result.stderr
        assert result.returncode == 0
