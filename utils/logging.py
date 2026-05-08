from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass
class StructuredLogger:
    name: str

    def _emit(self, level: str, message: str, payload: dict | None = None) -> None:
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": level,
            "logger": self.name,
            "message": message,
        }
        if payload:
            record["payload"] = payload
        print(json.dumps(record, sort_keys=True), file=sys.stderr, flush=True)

    def info(self, message: str, payload: dict | None = None) -> None:
        self._emit("INFO", message, payload)

    def warning(self, message: str, payload: dict | None = None) -> None:
        self._emit("WARNING", message, payload)

    def error(self, message: str, payload: dict | None = None) -> None:
        self._emit("ERROR", message, payload)


def get_logger(name: str) -> StructuredLogger:
    return StructuredLogger(name=name)
