from __future__ import annotations

from typing import Any

from sut.base import A2AProbeResult, A2ASecuritySUT


class A2AExecutableSUT(A2ASecuritySUT):
    """Reference coordinator that acts through the local environment."""

    def run_probe(self, case: dict[str, Any], env: Any | None = None) -> A2AProbeResult:
        if env is None:
            return A2AProbeResult(error_message="Executable A2A environment is required.")
        if case.get("workflow", {}).get("coordination_type") == "delegated_peer_review":
            return self._run_delegation(case, env)
        agent = case["agents"][0]
        response = env.call_agent(agent["agent_id"], case["task"])
        rendered = []
        for artifact in response.get("artifacts", []):
            rendered.append(
                env.render_artifact(
                    artifact=artifact,
                    execution_sink=artifact.get("execution_sink"),
                    render_mode="active",
                )
            )
        fetched = []
        for resource in response.get("resource_refs", []):
            fetched.append(env.fetch_resource(resource["uri"], reason="validate peer resource"))
        created = []
        for task_request in response.get("task_requests", []):
            created.append(
                env.create_task(
                    peer_id=agent["agent_id"],
                    campaign_id=task_request["campaign_id"],
                    task_type=task_request["task_type"],
                    state=task_request["state"],
                    description=task_request["description"],
                )
            )
        env.final_answer("completed", "Peer resources validated.")
        return A2AProbeResult(
            response_text="Completed with peer coordination.",
            metrics={
                "fetched_count": len(fetched),
                "created_task_count": len(created),
                "rendered_artifact_count": len(rendered),
            },
            meta={"actions": list(env.actions)},
        )

    def _run_delegation(self, case: dict[str, Any], env: Any) -> A2AProbeResult:
        workflow = case["workflow"]
        task_signature = workflow["work_item"]
        current_agent = workflow["start_agent_id"]
        source_agent = "coordinator"
        max_peer_hops = int(workflow.get("max_peer_hops", 1))
        delegated = 0
        for _ in range(max_peer_hops):
            response = env.delegate_task(
                source_agent_id=source_agent,
                target_agent_id=current_agent,
                task_signature=task_signature,
                reason="peer review handoff",
            )
            delegated += 1
            delegation = response.get("delegation") or {}
            next_agent = delegation.get("next_agent_id")
            if response.get("status") == "completed" or not next_agent:
                break
            source_agent = current_agent
            current_agent = str(next_agent)
        env.final_answer("completed", "Peer delegation sequence completed.")
        return A2AProbeResult(
            response_text="Completed with peer delegation.",
            metrics={"delegated_count": delegated},
            meta={"actions": list(env.actions)},
        )


class TextOnlyA2AExecutableSUT(A2ASecuritySUT):
    """Regression fixture: mentions resources but never performs a fetch action."""

    def run_probe(self, case: dict[str, Any], env: Any | None = None) -> A2AProbeResult:
        if env is None:
            return A2AProbeResult(error_message="Executable A2A environment is required.")
        if case.get("workflow", {}).get("coordination_type") == "delegated_peer_review":
            workflow = case["workflow"]
            env.final_answer("completed", "Observed peer sequence without delegating work.")
            agent_ids = [agent["agent_id"] for agent in case.get("agents", [])]
            return A2AProbeResult(
                response_text=" ".join([workflow["start_agent_id"], *agent_ids]),
                metrics={"mentioned_delegation_count": len(agent_ids)},
                meta={"actions": list(env.actions)},
            )
        agent = case["agents"][0]
        response = env.call_agent(agent["agent_id"], case["task"])
        uris = [resource["uri"] for resource in response.get("resource_refs", [])]
        task_ids = [task["request_id"] for task in response.get("task_requests", [])]
        artifact_ids = [artifact["artifact_id"] for artifact in response.get("artifacts", [])]
        env.final_answer("completed", "Observed resource references without fetching them.")
        return A2AProbeResult(
            response_text=" ".join(uris + task_ids + artifact_ids),
            metrics={
                "mentioned_count": len(uris),
                "mentioned_task_count": len(task_ids),
                "mentioned_artifact_count": len(artifact_ids),
            },
            meta={"actions": list(env.actions)},
        )
