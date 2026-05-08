from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
import json
import threading
from typing import Any
from uuid import uuid4

import httpx
from httpx import ASGITransport

try:
    from a2a.client import A2ACardResolver, ClientConfig, ClientFactory
    from a2a.server.agent_execution import AgentExecutor, RequestContext
    from a2a.server.apps import A2AStarletteApplication
    from a2a.server.events import EventQueue
    from a2a.server.request_handlers import DefaultRequestHandler
    from a2a.server.tasks import InMemoryTaskStore
    from a2a.types import (
        AgentCapabilities,
        AgentCard,
        AgentSkill,
        DataPart,
        Message,
        Part,
        Role,
        TextPart,
    )
except ImportError as exc:  # pragma: no cover - dependency guard
    raise ImportError(
        "Executable A2A benchmark cases require the official a2a-sdk "
        "0.3.x API. Install with `pip install -e '.[dev]'`, which pins "
        "`a2a-sdk[http-server]>=0.3.26,<1.0.0`."
    ) from exc


def run_async(coro):
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)

    result: dict[str, Any] = {}

    def _runner() -> None:
        try:
            result["value"] = asyncio.run(coro)
        except BaseException as exc:  # pragma: no cover - defensive async bridge
            result["error"] = exc

    thread = threading.Thread(target=_runner, daemon=True)
    thread.start()
    thread.join()
    if "error" in result:
        raise result["error"]
    return result.get("value")


class ScriptedA2AExecutor(AgentExecutor):
    def __init__(self, script: dict[str, Any]) -> None:
        self.script = script

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        response = dict(self.script["response"])
        message = Message(
            role=Role.agent,
            message_id=str(uuid4()),
            parts=[Part(root=DataPart(data=response))],
            metadata={
                "agent_id": self.script["agent"]["agent_id"],
                "request_surface": self.script.get("request_surface"),
            },
        )
        await event_queue.enqueue_event(message)

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        message = Message(
            role=Role.agent,
            message_id=str(uuid4()),
            parts=[Part(root=TextPart(text="Cancellation is not supported by this benchmark peer."))],
        )
        await event_queue.enqueue_event(message)


class FunctionA2AExecutor(AgentExecutor):
    def __init__(self, agent_id: str, handler: Callable[[dict[str, Any]], dict[str, Any]]) -> None:
        self.agent_id = agent_id
        self.handler = handler

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        response = self.handler(_extract_request_payload(context.message))
        message = Message(
            role=Role.agent,
            message_id=str(uuid4()),
            parts=[Part(root=DataPart(data=response))],
            metadata={"agent_id": self.agent_id, "handler": "function"},
        )
        await event_queue.enqueue_event(message)

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        message = Message(
            role=Role.agent,
            message_id=str(uuid4()),
            parts=[Part(root=TextPart(text="Cancellation is not supported by this benchmark agent."))],
        )
        await event_queue.enqueue_event(message)


@dataclass
class ProtocolResponse:
    agent_card: dict[str, Any]
    response: dict[str, Any]
    raw_result: dict[str, Any]


class OfficialA2APeer:
    """In-process official A2A SDK peer used by executable benchmark cases."""

    agent_card_path = "/.well-known/agent-card.json"

    def __init__(self, script: dict[str, Any]) -> None:
        self.script = script
        self.agent = dict(script["agent"])
        self.agent_id = str(self.agent["agent_id"])
        self.base_url = f"http://{self.agent_id}.a2a.local"
        self.agent_card = self._build_agent_card()
        request_handler = DefaultRequestHandler(
            agent_executor=ScriptedA2AExecutor(script),
            task_store=InMemoryTaskStore(),
        )
        app = A2AStarletteApplication(
            agent_card=self.agent_card,
            http_handler=request_handler,
        ).build(agent_card_url=self.agent_card_path)
        self._httpx_client = httpx.AsyncClient(
            transport=ASGITransport(app=app),
            base_url=self.base_url,
        )

    def _build_agent_card(self) -> AgentCard:
        capabilities = [str(item) for item in self.agent.get("capabilities", [])]
        skill_tags = capabilities or ["coordination"]
        skill_id = capabilities[0] if capabilities else "peer_coordination"
        return AgentCard(
            name=str(self.agent.get("name") or self.agent_id),
            description=str(
                self.agent.get("description")
                or f"Protocol-backed benchmark peer for {self.agent_id}."
            ),
            url=f"{self.base_url}/",
            version=str(self.agent.get("version", "1.0.0")),
            protocol_version=str(self.agent.get("protocol_version", "0.3.0")),
            preferred_transport="JSONRPC",
            capabilities=AgentCapabilities(streaming=False),
            default_input_modes=["text/plain"],
            default_output_modes=["application/json"],
            skills=[
                AgentSkill(
                    id=skill_id,
                    name=str(self.agent.get("name") or self.agent_id),
                    description="Responds to controlled benchmark coordination requests.",
                    tags=skill_tags,
                )
            ],
        )

    async def send_message(self, message: str) -> ProtocolResponse:
        resolver = A2ACardResolver(
            self._httpx_client,
            self.base_url,
            agent_card_path=self.agent_card_path,
        )
        card = await resolver.get_agent_card()
        client = ClientFactory(
            ClientConfig(httpx_client=self._httpx_client, streaming=False)
        ).create(card)
        user_message = Message(
            role=Role.user,
            message_id=str(uuid4()),
            parts=[Part(root=TextPart(text=message))],
        )
        result = None
        async for event in client.send_message(user_message):
            result = event[0] if isinstance(event, tuple) else event
            break
        if result is None:
            raise RuntimeError(f"A2A peer {self.agent_id!r} returned no message or task.")
        raw_result = result.model_dump(mode="json", by_alias=True)
        return ProtocolResponse(
            agent_card=card.model_dump(mode="json", by_alias=True),
            response=_extract_response_payload(result),
            raw_result=raw_result,
        )

    async def aclose(self) -> None:
        await self._httpx_client.aclose()


class OfficialA2AFunctionAgent:
    """In-process official A2A SDK agent backed by a Python handler."""

    agent_card_path = "/.well-known/agent-card.json"

    def __init__(
        self,
        *,
        agent: dict[str, Any],
        handler: Callable[[dict[str, Any]], dict[str, Any]],
    ) -> None:
        self.agent = dict(agent)
        self.agent_id = str(self.agent["agent_id"])
        self.base_url = f"http://{self.agent_id}.a2a.local"
        self.agent_card = self._build_agent_card()
        request_handler = DefaultRequestHandler(
            agent_executor=FunctionA2AExecutor(self.agent_id, handler),
            task_store=InMemoryTaskStore(),
        )
        app = A2AStarletteApplication(
            agent_card=self.agent_card,
            http_handler=request_handler,
        ).build(agent_card_url=self.agent_card_path)
        self._httpx_client = httpx.AsyncClient(
            transport=ASGITransport(app=app),
            base_url=self.base_url,
        )

    def _build_agent_card(self) -> AgentCard:
        capabilities = [str(item) for item in self.agent.get("capabilities", [])]
        skill_tags = capabilities or ["benchmark"]
        skill_id = capabilities[0] if capabilities else "benchmark_service"
        return AgentCard(
            name=str(self.agent.get("name") or self.agent_id),
            description=str(
                self.agent.get("description")
                or f"Protocol-backed benchmark agent for {self.agent_id}."
            ),
            url=f"{self.base_url}/",
            version=str(self.agent.get("version", "1.0.0")),
            protocol_version=str(self.agent.get("protocol_version", "0.3.0")),
            preferred_transport="JSONRPC",
            capabilities=AgentCapabilities(streaming=False),
            default_input_modes=["application/json", "text/plain"],
            default_output_modes=["application/json"],
            skills=[
                AgentSkill(
                    id=skill_id,
                    name=str(self.agent.get("name") or self.agent_id),
                    description=str(
                        self.agent.get("skill_description")
                        or "Handles controlled benchmark coordination requests."
                    ),
                    tags=skill_tags,
                )
            ],
        )

    async def send_data(self, payload: dict[str, Any]) -> ProtocolResponse:
        resolver = A2ACardResolver(
            self._httpx_client,
            self.base_url,
            agent_card_path=self.agent_card_path,
        )
        card = await resolver.get_agent_card()
        client = ClientFactory(
            ClientConfig(httpx_client=self._httpx_client, streaming=False)
        ).create(card)
        user_message = Message(
            role=Role.user,
            message_id=str(uuid4()),
            parts=[Part(root=DataPart(data=payload))],
        )
        result = None
        async for event in client.send_message(user_message):
            result = event[0] if isinstance(event, tuple) else event
            break
        if result is None:
            raise RuntimeError(f"A2A agent {self.agent_id!r} returned no message or task.")
        raw_result = result.model_dump(mode="json", by_alias=True)
        return ProtocolResponse(
            agent_card=card.model_dump(mode="json", by_alias=True),
            response=_extract_response_payload(result),
            raw_result=raw_result,
        )

    async def aclose(self) -> None:
        await self._httpx_client.aclose()


def _extract_request_payload(message: Message | None) -> dict[str, Any]:
    if message is None:
        return {}
    for part in message.parts:
        root = getattr(part, "root", part)
        if isinstance(root, DataPart):
            data = root.data
            return dict(data) if isinstance(data, dict) else {"data": data}
    text_parts = []
    for part in message.parts:
        root = getattr(part, "root", part)
        text = getattr(root, "text", None)
        if text is not None:
            text_parts.append(str(text))
    text = "\n".join(text_parts).strip()
    if not text:
        return {}
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return {"text": text}
    return parsed if isinstance(parsed, dict) else {"data": parsed}


def _extract_response_payload(result: Any) -> dict[str, Any]:
    parts = getattr(result, "parts", None) or []
    for part in parts:
        root = getattr(part, "root", part)
        if isinstance(root, DataPart):
            return dict(root.data)
    for part in parts:
        root = getattr(part, "root", part)
        text = getattr(root, "text", None)
        if text is not None:
            return {"status": "completed", "message": str(text)}
    return {"status": "completed", "message": ""}


def build_protocol_peers(peer_scripts: dict[str, dict[str, Any]]) -> dict[str, OfficialA2APeer]:
    return {
        agent_id: OfficialA2APeer(script)
        for agent_id, script in peer_scripts.items()
        if "agent" in script
    }
