from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class SelectionResult:
    choice: int
    raw: str | None = None
    meta: dict = field(default_factory=dict)


@dataclass
class CompareResult:
    consistent: bool
    raw: str | None = None
    meta: dict = field(default_factory=dict)


@dataclass
class A2AProbeResult:
    response_text: str = ""
    events: list[dict[str, Any]] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)
    blocked: bool = False
    error_message: str | None = None
    meta: dict[str, Any] = field(default_factory=dict)


class SelectorSUT(ABC):
    @abstractmethod
    def select(self, task_prompt: str, cards: list[dict]) -> SelectionResult:
        raise NotImplementedError


class ComparatorSUT(ABC):
    @abstractmethod
    def compare_whitebox(self, card: dict, backend_code: str) -> CompareResult:
        raise NotImplementedError

    @abstractmethod
    def compare_blackbox(self, card: dict, backend_endpoint: str) -> CompareResult:
        raise NotImplementedError


class A2ASecuritySUT(ABC):
    @abstractmethod
    def run_probe(self, case: dict[str, Any], env: Any | None = None) -> A2AProbeResult:
        raise NotImplementedError
