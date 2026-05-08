"""A2A-protocol CC comparator (blackbox mode).

The LLM autonomously interacts with a remote A2A agent:
  1. fetch_agent_card  — GET /.well-known/agent.json  (A2A discovery)
  2. send_message      — POST / JSON-RPC message/send (A2A communication)

The LLM decides what messages to send and how many rounds to conduct
before producing a CONSISTENT / INCONSISTENT verdict.
"""
from __future__ import annotations

import json
import os
import uuid

import requests

from sut.base import ComparatorSUT, CompareResult
from utils.http import get_json, post_json
from utils.llm_client import get_openai_compatible_client
from utils.parsing import parse_consistency_evidence

TOOLS_SCHEMA = [
    {
        "type": "function",
        "function": {
            "name": "fetch_agent_card",
            "description": (
                "Fetch the remote agent's A2A AgentCard from "
                "/.well-known/agent.json.  Returns the agent's self-declared "
                "identity, skills, capabilities, and protocol metadata."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "send_message",
            "description": (
                "Send a natural-language message to the remote A2A agent via "
                "JSON-RPC message/send.  The agent will process your message "
                "and return a task response with text artifacts.  Use this to "
                "test whether declared skills work, probe for undeclared "
                "capabilities, or observe the agent's behavior."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "text": {
                        "type": "string",
                        "description": "The message to send to the agent.",
                    },
                },
                "required": ["text"],
            },
        },
    },
]

_SYSTEM_PROMPT = (
    "You are a security auditor checking whether a remote A2A agent's declared "
    "capabilities (AgentCard) match its actual behavior.\n\n"
    "You have two investigative tools:\n"
    "  1. fetch_agent_card  – retrieve the agent's self-declared AgentCard\n"
    "  2. send_message      – send a natural-language message to the agent "
    "and observe its response\n\n"
    "Investigation strategy:\n"
    "  • Fetch the AgentCard to see what the agent claims it can do.\n"
    "  • For EACH declared skill, send a message that exercises that skill "
    "and verify the response is reasonable.\n"
    "  • Probe realistic boundary conditions that follow from the AgentCard's "
    "own wording. Do not run a fixed vulnerability checklist; choose tests "
    "that a careful integrator would naturally derive from the declared "
    "skills, limitations, and data-handling claims.\n"
    "  • For stateful claims, use multiple messages in the same session and "
    "compare later responses against earlier requests.\n"
    "  • Compare ALL normal A2A observations against the AgentCard. Do not "
    "assume hidden internal state that is not visible through discovery, "
    "responses, errors, or cross-request behavior.\n\n"
    "When you have gathered enough evidence, output only valid JSON with keys "
    "`label`, `evidence`, and `explanation`. The label must be CONSISTENT or "
    "INCONSISTENT. Evidence should cite observed tool responses, errors, "
    "cross-request behavior, or AgentCard fields that support the verdict."
)


class LLMInteractiveComparator(ComparatorSUT):
    """Comparator that interacts with an A2A agent via message/send."""

    def __init__(
        self,
        max_rounds: int = 15,
        max_retries: int = 2,
        model: str | None = None,
        temperature: float | None = None,
    ) -> None:
        self.max_rounds = int(max_rounds)
        self.max_retries = int(max_retries)
        self.model = model
        self.temperature = temperature

    def _resolve_model(self) -> str:
        m = self.model or os.getenv("SUT_MODEL", "").strip()
        if not m:
            raise RuntimeError("LLM SUT requires a model. Set SUT_MODEL or pass model=...")
        return m

    def _resolve_temperature(self) -> float:
        if self.temperature is not None:
            return float(self.temperature)
        return float(os.getenv("SUT_TEMPERATURE", "0").strip())

    def _chat_api(self, messages: list[dict], tools: list[dict] | None = None) -> dict:
        client = get_openai_compatible_client()
        payload: dict = {
            "model": self._resolve_model(),
            "temperature": self._resolve_temperature(),
            "messages": messages,
        }
        if tools:
            payload["tools"] = tools
        headers = {
            "Authorization": f"Bearer {client.api_key}",
            "Content-Type": "application/json",
        }
        resp = requests.post(
            f"{client.api_base}/chat/completions",
            headers=headers,
            json=payload,
            timeout=client.timeout_s,
        )
        resp.raise_for_status()
        return resp.json()

    @staticmethod
    def _a2a_send_message(endpoint: str, text: str) -> dict:
        """Send a JSON-RPC message/send to the A2A agent."""
        jsonrpc_payload = {
            "jsonrpc": "2.0",
            "id": str(uuid.uuid4()),
            "method": "message/send",
            "params": {
                "message": {
                    "role": "user",
                    "parts": [{"kind": "text", "text": text}],
                    "messageId": str(uuid.uuid4()),
                    "contextId": str(uuid.uuid4()),
                    "kind": "message",
                }
            },
        }
        return post_json(endpoint.rstrip("/") + "/", jsonrpc_payload, timeout_s=10.0)

    @staticmethod
    def _extract_task_text(raw_response: dict) -> dict:
        """Extract text from an A2A Task response."""
        task_result = raw_response.get("result", raw_response)
        artifacts = task_result.get("artifacts", [])
        response_parts = []
        for artifact in artifacts:
            for part in artifact.get("parts", []):
                part_text = part.get("text", "")
                if part.get("kind") == "text" or part.get("type") == "text":
                    response_parts.append(part_text)
        if response_parts:
            return {
                "status": task_result.get("status", {}).get("state", "unknown"),
                "response": "\n".join(response_parts),
            }
        return {"status": "no_text_response", "raw": task_result}

    def _execute_tool_call(self, name: str, arguments_raw: str, endpoint: str) -> str:
        try:
            if name == "fetch_agent_card":
                result = get_json(
                    f"{endpoint.rstrip('/')}/.well-known/agent.json",
                    timeout_s=5.0,
                )
            elif name == "send_message":
                args = json.loads(arguments_raw) if isinstance(arguments_raw, str) else arguments_raw
                text = args.get("text", "")
                raw_response = self._a2a_send_message(endpoint, text)
                result = self._extract_task_text(raw_response)
            else:
                result = {"error": f"Unknown tool: {name}"}
        except Exception as exc:
            result = {"error": str(exc)}
        return json.dumps(result, ensure_ascii=False)

    def compare_blackbox(self, card: dict, backend_endpoint: str) -> CompareResult:
        """A2A-protocol blackbox comparison via tool-calling dialogue."""
        user_prompt = (
            "The remote A2A agent is live. Use only the provided tools to "
            "discover its AgentCard and probe runtime behavior. Fetch the "
            "AgentCard through normal discovery, exercise every declared "
            "skill by sending messages, and run a small number of high-value "
            "follow-up probes based on what the AgentCard actually says. "
            "Base your verdict only on normal A2A discovery, responses, "
            "errors, and cross-request behavior."
        )
        messages: list[dict] = [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ]
        tool_call_log: list[dict] = []
        clarification_attempts = 0

        for round_idx in range(self.max_rounds):
            data = self._chat_api(messages, tools=TOOLS_SCHEMA)
            choice = data["choices"][0]
            msg = choice["message"]

            tool_calls = msg.get("tool_calls")
            if not tool_calls:
                content = msg.get("content", "")
                messages.append({"role": "assistant", "content": content})

                value, parse_meta = parse_consistency_evidence(content)
                if parse_meta["valid"] and value is not None:
                    return CompareResult(
                        consistent=value,
                        raw=content,
                        meta={
                            "mode": "blackbox",
                            "rounds": round_idx + 1,
                            "parse_meta": parse_meta,
                            "retry_count": clarification_attempts,
                            "tool_calls": tool_call_log,
                            "conversation_length": len(messages),
                            "evidence": parse_meta.get("evidence", []),
                            "explanation": parse_meta.get("explanation", ""),
                        },
                    )
                clarification_attempts += 1
                if clarification_attempts > self.max_retries:
                    raise ValueError(
                        f"LLMInteractiveComparator: could not parse verdict after "
                        f"{clarification_attempts} clarification attempts. Last: {content!r}"
                    )
                messages.append({
                    "role": "user",
                    "content": (
                        "Your response did not contain a clear verdict. "
                        "Output only JSON with label, evidence, and explanation."
                    ),
                })
                continue

            messages.append(msg)

            for tc in tool_calls:
                fn_name = tc["function"]["name"]
                fn_args_raw = tc["function"]["arguments"]
                result_str = self._execute_tool_call(fn_name, fn_args_raw, backend_endpoint)

                tool_call_log.append({
                    "round": round_idx,
                    "id": tc["id"],
                    "tool": fn_name,
                    "args": fn_args_raw,
                    "result_preview": result_str[:1000],
                })
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc["id"],
                    "content": result_str,
                })

        raise ValueError(
            f"LLMInteractiveComparator: no valid verdict after {self.max_rounds} rounds. "
            f"Tool calls made: {len(tool_call_log)}"
        )

    def compare_whitebox(self, card: dict, backend_code: str) -> CompareResult:
        from sut.cc.llm_comparator import LLMComparator
        return LLMComparator(
            model=self.model, temperature=self.temperature
        ).compare_whitebox(card, backend_code)
