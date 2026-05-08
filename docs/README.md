# A2ASecBench Documentation

A2ASecBench is a Python benchmark harness for evaluating security behavior in agent-to-agent systems. It provides decoupled benchmark cases, pluggable Systems Under Test (SUTs), deterministic offline baselines, optional LLM-backed SUTs, and executable local environments for coordinator-level attacks.

## Documentation Structure

```text
docs/
├── README.md
├── architecture.md
├── workflows.md
├── datasets.md
└── attacks/
    ├── as.md
    ├── cc.md
    ├── asrf.md
    ├── atsi.md
    ├── co.md
    └── hotf.md
```

## Attack Families

- AgentCard Spoofing (AS)
- Capability Cloaking (CC)
- Agent-Side Request Forgery (ASRF)
- Artifact Triggered Script Injection (ATSI)
- Cycle Overflow (CO)
- Half-Open Task Flooding (HOTF)

## Reading Guide

- [Architecture](architecture.md): repository layout, core abstractions, SUT interfaces, and harness services.
- [Workflows](workflows.md): offline runs, LLM-backed runs, outputs, and validation commands.
- [Datasets](datasets.md): release splits, object model, private metadata, and contributor workflow.
- [AS](attacks/as.md): AgentCard spoofing attack design.
- [CC](attacks/cc.md): capability cloaking attack design (whitebox and blackbox).
- [ASRF](attacks/asrf.md): resource dereference attack design.
- [ATSI](attacks/atsi.md): artifact rendering attack design.
- [CO](attacks/co.md): cyclic delegation attack design.
- [HOTF](attacks/hotf.md): retained half-open task attack design.
