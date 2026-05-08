# A2ASecBench

A2ASecBench is a benchmark for evaluating security behavior in
agent-to-agent systems. It provides frozen benchmark cases, pluggable Systems
Under Test (SUTs), and local executable environments for protocol-aware attacks.

## Benchmark Scope

| Benchmark | What it evaluates |
| --- | --- |
| AgentCard Spoofing (AS) | Whether a selector chooses the benign AgentCard among spoofed look-alikes. |
| Capability Cloaking, whitebox | Whether a comparator detects mismatches between an AgentCard and source-visible backend behavior. |
| Capability Cloaking, blackbox | Whether a comparator discovers capability mismatches through normal A2A service interaction without source access. |
| Agent-Side Request Forgery (ASRF) | Whether a coordinator safely handles untrusted peer-supplied resource references. |
| Artifact Triggered Script Injection (ATSI) | Whether a coordinator prevents unsafe execution during artifact preview/rendering. |
| Cycle Overflow (CO) | Whether a coordinator bounds cyclic peer delegation. |
| Half-Open Task Flooding (HOTF) | Whether a coordinator limits retained input-required tasks. |

AS and both CC splits include 100 release cases. The executable A2A attack
families include attack cases and matched controls built on the public
`a2a-sdk` protocol implementation.

## Installation

Python 3.10 or newer is required. Using following command:

```bash
pip install -e ".[dev]"
```



## Quick Start

Run deterministic offline baselines without LLM credentials:

```bash
python orchestration.py --config configs/offline/as.yaml --trials 1
python orchestration.py --config configs/offline/cc_whitebox.yaml --mode whitebox --trials 1
python orchestration.py --config configs/smoke/cc_blackbox.yaml --mode blackbox --trials 1
python orchestration.py --config configs/offline/asrf_eval.yaml --trials 1
```

The other executable A2A configs follow the same pattern:
`configs/offline/atsi_eval.yaml`, `configs/offline/co_eval.yaml`, and
`configs/offline/hotf_eval.yaml`.

## Evaluate LLM-Backed SUTs

LLM runs are opt-in. Set credentials in the environment or in `.env`:

```bash
SUT_API_BASE=...
SUT_API_KEY=...
SUT_MODEL=...
```

Start with sample configs before running full splits:

```bash
python orchestration.py --config configs/llm/as_sample.yaml --trials 1
python orchestration.py --config configs/llm/cc_whitebox_sample.yaml --mode whitebox --trials 1
python orchestration.py --config configs/llm/cc_blackbox_sample.yaml --mode blackbox --trials 1
```

Full AS and CC runs are available under `configs/llm/*_full.yaml`.
Executable A2A LLM runs are available as `configs/llm/asrf_eval.yaml`,
`configs/llm/atsi_eval.yaml`, `configs/llm/co_eval.yaml`, and
`configs/llm/hotf_eval.yaml`.

## Results

Each run writes:

- `results/run_<timestamp>.jsonl`: per-trial records.
- `results/summary.json`: aggregate metrics for the latest run.

CC summaries include label accuracy. Evidence quality can be judged separately:

```bash
python scripts/judge_cc_evidence.py --input results/run_YYYY.jsonl
```

## Repository Layout

```text
attacks/          Benchmark case definitions, fixtures, and release instances
configs/          Offline, smoke, calibration, and LLM run configurations
harness/a2a_lab/  Local A2A protocol lab and scoring sinks
sut/              SUT interfaces and reference implementations
scripts/          Release validators and auxiliary scoring tools
tests/            Pytest regression tests
docs/             Maintainer documentation and attack-specific design notes
```

## Validation

Run the standard checks before changing benchmark data, harness behavior, or
SUT interfaces:

```bash
python -m pytest
python scripts/validate_release.py
python scripts/validate_cc_blackbox_observability.py
python -m compileall -q orchestration.py attacks harness sut utils scripts tests
```

The default tests and release validators do not require LLM credentials.

## Documentation

Start with [docs/README.md](docs/README.md). It links to the architecture,
dataset model, workflows, and threat-model notes for each attack family.

## Citation

```bibtex
@inproceedings{
    li2026aasecbench,
    title={A2{AS}ecBench: A Protocol-Aware Security Benchmark for Agent-to-Agent Multi-Agent Systems},
    author={Tianhao Li and Chuangxin Chu and Yujia Zheng and Bohan Zhang and Neil Zhenqiang Gong and Chaowei Xiao},
    booktitle={The Fourteenth International Conference on Learning Representations},
    year={2026},
    url={https://openreview.net/forum?id=LfdFnakqGJ}
}
```

## License

A2ASecBench is released under the MIT License. See [LICENSE](LICENSE).
