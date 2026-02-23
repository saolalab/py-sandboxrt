"""
py-srt: Python Sandbox Runtime

A lightweight sandboxing tool for enforcing filesystem and network restrictions
on arbitrary processes at the OS level, without requiring a container.
"""

__version__ = "0.1.0"

from srt.config import (
    FilesystemConfig,
    NetworkConfig,
    SandboxRuntimeConfig,
)
from srt.sandbox_manager import SandboxManager
from srt.violation_store import SandboxViolationStore

__all__ = [
    "__version__",
    "SandboxManager",
    "SandboxViolationStore",
    "SandboxRuntimeConfig",
    "NetworkConfig",
    "FilesystemConfig",
]
