"""Platform detection utilities."""

from __future__ import annotations

import platform
import shutil
from typing import Literal

Platform = Literal["macos", "linux", "windows", "unknown"]


def get_platform() -> Platform:
    """Detect the current OS platform."""
    system = platform.system().lower()
    if system == "darwin":
        return "macos"
    if system == "linux":
        return "linux"
    if system == "windows":
        return "windows"
    return "unknown"


def get_wsl_version() -> str | None:
    """Detect WSL version on Linux. Returns '1', '2', or None if not WSL."""
    if get_platform() != "linux":
        return None

    try:
        with open("/proc/version", encoding="utf-8") as f:
            version_info = f.read().lower()
    except OSError:
        return None

    if "microsoft" not in version_info:
        return None

    if "wsl2" in version_info or "microsoft-standard" in version_info:
        return "2"
    return "1"


def which_sync(command: str) -> str | None:
    """Find executable in PATH, like `which`. Returns full path or None."""
    return shutil.which(command)


def is_supported_platform() -> bool:
    """Check if the current platform supports sandboxing."""
    p = get_platform()
    if p == "linux":
        return get_wsl_version() != "1"
    return p == "macos"
