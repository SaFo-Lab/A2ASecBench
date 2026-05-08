# Architecture

## Overview

A2ASecBench separates attack data, SUT interfaces, orchestration, harness services, scoring, and validation. The main entrypoint is `orchestration.py`: it loads a config, imports case classes, loads the requested SUT, runs trials, writes JSONL records, and creates a summary file.

## Repository Layout

```text
A2ASecBench/
├── orchestration.py
├── attacks/
│   ├── base.py
│   ├── as_attack.py
│   ├── cc_attack.py
│   ├── a2a_attack.py
│   ├── fixtures/
│   └── instances/
├── harness/a2a_lab/
├── sut/
├── configs/
├── scripts/
├── tests/
└── docs/
```

Important release paths:

- `attacks/instances/as/`: AS cases.
- `attacks/instances/cc_whitebox/`: CC whitebox cases and source-visible backends.
- `attacks/instances/cc_blackbox/`: CC blackbox cases and localhost service backends.
- `attacks/instances/{asrf,atsi,co,hotf}/executable.py`: executable A2A evaluation and control splits.
- `attacks/instances/{asrf,atsi,co,hotf}/calibration.py`: structured-oracle calibration splits.
- `attacks/fixtures/`: AgentCard JSON fixtures.
- `harness/a2a_lab/`: official SDK-backed executable peer environments and local scoring sinks.
- `sut/`: SUT interfaces and reference implementations.
- `configs/`: offline, LLM, smoke, and calibration configs.
- `scripts/`: release validators and evidence judges.

## Attacks

All benchmark cases inherit from `AttackCase` in `attacks/base.py`.

- `ASCase` presents multiple AgentCards and expects a selector to choose the benign card.
- `CCCase` presents an AgentCard plus either backend source code or a localhost A2A endpoint.
- `A2ASecurityCase` provides structured-oracle calibration probes for ASRF, ATSI, CO, and HOTF.
- `A2AExecutableCase` starts an official `a2a-sdk` in-process peer environment and scores real environment events.

## System Under Test (SUT)

SUTs are loaded by dynamic import paths in config files:

```yaml
sut:
  selector: "sut.as.heuristic_selector:HeuristicSelector"
  kwargs: {}
```

Main interfaces:

- `SelectorSUT.select(task_prompt, cards)` for AS.
- `ComparatorSUT.compare_whitebox(card, backend_code)` for CC whitebox.
- `ComparatorSUT.compare_blackbox(card, backend_endpoint)` for CC blackbox.
- `A2ASecuritySUT.run_probe(case, env=None)` for protocol-level A2A attacks.

Raw chat-completion LLMs are suitable for AS and CC SUTs. Executable A2A attacks require an action-capable coordinator wrapper that calls harness APIs such as `fetch_resource`, `render_artifact`, `delegate_task`, or `create_task`.

## Harness Services

Executable A2A cases use official SDK protocol peers plus local harness components:

- `OfficialA2APeer`: exposes each scripted peer through SDK AgentCard discovery and JSON-RPC `message/send`.
- `LocalHTTPTrapServer`: records local resource dereferences and artifact callbacks.
- `ArtifactRenderer`: records artifact rendering and triggers local callbacks only when active content is rendered.
- `DelegationTracker`: records delegation edges, closed paths, and depth-limit evidence.
- `TaskStore`: records retained half-open tasks and task-store pressure.
- `A2AEnvironmentClient`: exposes controlled actions to executable SUTs.

Harness services are local-only and scoped to one trial. They create protocol events such as `a2a_agent_card_fetched` and `a2a_message_sent`, plus scoring evidence events such as `uri_dereference`, `artifact_executed`, `cycle_detected`, `max_depth_exceeded`, and `task_store_pressure`.
