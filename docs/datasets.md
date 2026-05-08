# Datasets

## Release Splits

A2ASecBench includes static, source-review, blackbox service, and executable protocol-backed datasets:

- AS: 100 AgentCard selection cases.
- CC whitebox: 100 source-visible capability consistency cases.
- CC blackbox: 100 source-hidden localhost A2A service cases.
- ASRF, ATSI, CO, HOTF executable evaluation and control: 100 attack cases plus 100 matched controls per family, executed through official `a2a-sdk` AgentCard discovery and JSON-RPC `message/send`. Along with 100 structured-oracle cases per family.

## Structure

A2ASecBench models every benchmark row as an `AttackCase` object. The base contract is small: `get_ground_truth()` returns private oracle data, and `run(sut, **kwargs)` executes one trial and returns a `TrialOutcome`.

The concrete dataset classes follow four patterns:

- `ASCase`: stores a task prompt, AgentCard fixture paths, and a private benign index. At runtime it loads cards, shuffles them deterministically per trial, calls a `SelectorSUT`, and scores whether the selected card is the benign one.
- `CCCase`: stores an AgentCard path, backend module path, private consistency label, reason, evidence hints, and optional blackbox probes. In `whitebox`, it passes backend source to a comparator. In `blackbox`, it starts the localhost backend service and passes only the endpoint plus AgentCard.
- `A2ASecurityCase`: stores structured-oracle calibration metadata for ASRF, ATSI, CO, and HOTF. It passes a public probe payload to an `A2ASecuritySUT` and scores reported events/metrics against private oracle fields.
- `A2AExecutableCase`: stores executable lab metadata with public fields, private environment fields, and oracle fields. It builds a trial-scoped `harness/a2a_lab` environment, exposes official `a2a-sdk` peer calls to the SUT, and scores only observed harness events.

Release case modules are lightweight OO registries. AS uses one Python module per case under `attacks/instances/as/`. CC and A2A splits use package-level `CASE_METADATA` plus generated classes such as `CCWhitebox001`, `CCBlackbox001`, `ASRFEval001`, or `ASRFControl001`. Config files reference these classes with `module:ClassName` strings, and `orchestration.py` imports and instantiates them dynamically for each run.

Fixtures and executable code are deliberately separated from private metadata:

- AgentCards live under `attacks/fixtures/`.
- CC backend modules live under `attacks/instances/cc_whitebox/backends/` and `attacks/instances/cc_blackbox/backends/`.
- Private labels, reasons, evidence hints, validation probes, and executable oracles live in the case metadata objects, not in SUT-facing prompts.

## Expansion

### Adding Attack Instances

Add a case subclass under the matching package:

- `attacks/instances/as/`
- `attacks/instances/cc_whitebox/`
- `attacks/instances/cc_blackbox/`
- `attacks/instances/{asrf,atsi,co,hotf}/executable.py`
- `attacks/instances/{asrf,atsi,co,hotf}/calibration.py`

Add AgentCards under `attacks/fixtures/` when the case needs SUT-facing AgentCard input. Reference new cases from config `cases:` lists with import paths.

### Adding SUTs

Add a selector under `sut/as/`, a comparator under `sut/cc/`, or an A2A security SUT under `sut/a2a/`. Reference it in config via `module.path:ClassName`. no central registry edit is required.
