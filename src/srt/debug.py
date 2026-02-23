"""Debug logging utilities for Sandbox Runtime."""

from __future__ import annotations

import os
import sys


def log_debug(message: str, *, level: str = "info") -> None:
    """
    Log a debug message to stderr when SRT_DEBUG is set.

    Uses stderr to avoid corrupting stdout JSON streams.
    """
    if not os.environ.get("SRT_DEBUG"):
        return

    prefix = "[SandboxDebug]"
    text = f"{prefix} {message}"

    if level == "error":
        print(text, file=sys.stderr)
    elif level == "warn":
        print(text, file=sys.stderr)
    else:
        print(text, file=sys.stderr)
