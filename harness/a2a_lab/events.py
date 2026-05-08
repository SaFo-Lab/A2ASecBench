from __future__ import annotations

from dataclasses import asdict, dataclass, field
import time
from typing import Any


@dataclass(frozen=True)
class HarnessEvent:
    event_type: str
    case_id: str
    trial_id: str
    timestamp_monotonic: float
    component: str
    actor_id: str | None = None
    public_surface: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    private_tags: dict[str, Any] = field(default_factory=dict)

    def to_dict(self, include_private: bool = True) -> dict[str, Any]:
        payload = asdict(self)
        payload["type"] = self.event_type
        if not include_private:
            payload.pop("private_tags", None)
        return payload


class EventRecorder:
    def __init__(self, case_id: str, trial_id: str) -> None:
        self.case_id = case_id
        self.trial_id = trial_id
        self._events: list[HarnessEvent] = []

    def record(
        self,
        event_type: str,
        component: str,
        *,
        actor_id: str | None = None,
        public_surface: str | None = None,
        evidence: dict[str, Any] | None = None,
        private_tags: dict[str, Any] | None = None,
    ) -> HarnessEvent:
        event = HarnessEvent(
            event_type=event_type,
            case_id=self.case_id,
            trial_id=self.trial_id,
            timestamp_monotonic=time.monotonic(),
            component=component,
            actor_id=actor_id,
            public_surface=public_surface,
            evidence=dict(evidence or {}),
            private_tags=dict(private_tags or {}),
        )
        self._events.append(event)
        return event

    def to_dicts(self, include_private: bool = True) -> list[dict[str, Any]]:
        return [event.to_dict(include_private=include_private) for event in self._events]

    @property
    def events(self) -> list[HarnessEvent]:
        return list(self._events)
