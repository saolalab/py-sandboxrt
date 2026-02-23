"""In-memory store for sandbox violation events."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime

from srt.sandbox_utils import encode_sandboxed_command


@dataclass
class SandboxViolationEvent:
    line: str
    command: str | None = None
    encoded_command: str | None = None
    timestamp: datetime = field(default_factory=datetime.now)


class SandboxViolationStore:
    """Bounded in-memory tail of sandbox violations."""

    def __init__(self, max_size: int = 100) -> None:
        self._violations: list[SandboxViolationEvent] = []
        self._total_count: int = 0
        self._max_size = max_size
        self._listeners: set[Callable[[list[SandboxViolationEvent]], None]] = set()

    def add_violation(self, violation: SandboxViolationEvent) -> None:
        self._violations.append(violation)
        self._total_count += 1
        if len(self._violations) > self._max_size:
            self._violations = self._violations[-self._max_size :]
        self._notify_listeners()

    def get_violations(self, limit: int | None = None) -> list[SandboxViolationEvent]:
        if limit is None:
            return list(self._violations)
        return list(self._violations[-limit:])

    @property
    def count(self) -> int:
        return len(self._violations)

    @property
    def total_count(self) -> int:
        return self._total_count

    def get_violations_for_command(self, command: str) -> list[SandboxViolationEvent]:
        encoded = encode_sandboxed_command(command)
        return [v for v in self._violations if v.encoded_command == encoded]

    def clear(self) -> None:
        self._violations = []
        self._notify_listeners()

    def subscribe(
        self, listener: Callable[[list[SandboxViolationEvent]], None]
    ) -> Callable[[], None]:
        self._listeners.add(listener)
        listener(self.get_violations())

        def unsubscribe() -> None:
            self._listeners.discard(listener)

        return unsubscribe

    def _notify_listeners(self) -> None:
        violations = self.get_violations()
        for listener in self._listeners:
            listener(violations)
