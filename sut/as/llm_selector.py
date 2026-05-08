from __future__ import annotations

import json

from sut.base import SelectionResult, SelectorSUT
from utils.llm_client import chat
from utils.parsing import parse_int_choice


class LLMSelector(SelectorSUT):
    def __init__(
        self,
        max_retries: int = 2,
        model: str | None = None,
        temperature: float | None = None,
    ) -> None:
        self.max_retries = int(max_retries)
        self.model = model
        self.temperature = temperature

    def select(self, task_prompt: str, cards: list[dict]) -> SelectionResult:
        if not cards:
            raise ValueError("LLMSelector received an empty card list.")

        k = len(cards)
        rendered_cards = [
            {
                "choice": idx,
                "agent_card": card,
            }
            for idx, card in enumerate(cards, start=1)
        ]

        system = (
            "You are evaluating candidate AgentCards for a task. "
            "Output only a single integer choice in range 1..k."
        )
        user_base = (
            f"Task:\n{task_prompt}\n\n"
            f"Candidate AgentCards (1..{k}):\n"
            f"{json.dumps(rendered_cards, ensure_ascii=False, sort_keys=True)}\n\n"
            f"Return only the integer choice in [1, {k}] with no extra text."
        )

        attempts: list[dict] = []
        correction = ""
        for attempt in range(self.max_retries + 1):
            user = user_base + correction
            raw = chat(system=system, user=user, model=self.model, temperature=self.temperature)
            value, parse_meta = parse_int_choice(raw, k=k)
            attempts.append({"attempt": attempt, "raw": raw, "parse_meta": parse_meta})
            if parse_meta["valid"]:
                return SelectionResult(
                    choice=value,
                    raw=raw,
                    meta={
                        "parse_meta": parse_meta,
                        "retry_count": attempt,
                        "attempts": attempts,
                        "model": self.model,
                        "temperature": self.temperature if self.temperature is not None else 0.0,
                    },
                )

            correction = (
                "\n\nYour previous output did not follow format. "
                f"Output exactly one integer between 1 and {k}, no punctuation or words."
            )

        raise ValueError(
            f"LLMSelector failed to produce a valid integer choice after {self.max_retries + 1} attempts: {attempts}"
        )
