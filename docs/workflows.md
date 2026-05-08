# Workflows

Run all commands from the repository root.

## Install

```bash
pip install -e ".[dev]"
```

## Runs

### Offline (w/o LLM)

Offline configs use deterministic baselines and do not require LLM credentials:

```bash
python orchestration.py --config configs/offline/as.yaml --trials 1
python orchestration.py --config configs/offline/cc_whitebox.yaml --mode whitebox --trials 1
python orchestration.py --config configs/offline/asrf_eval.yaml --trials 1
python orchestration.py --config configs/offline/atsi_eval.yaml --trials 1
python orchestration.py --config configs/offline/co_eval.yaml --trials 1
python orchestration.py --config configs/offline/hotf_eval.yaml --trials 1
```

CC requires `--mode`. AS and A2A structured-oracle attacks reject `--mode`.

### Online (w/ LLM)

LLM SUTs are opt-in. Set these environment variables:

- `SUT_API_BASE`
- `SUT_API_KEY`
- `SUT_MODEL`
- optional `SUT_TEMPERATURE`
- optional `SUT_TIMEOUT_S`

Start with sample configs:

```bash
python orchestration.py --config configs/llm/as_sample.yaml --trials 1
python orchestration.py --config configs/llm/cc_whitebox_sample.yaml --mode whitebox --trials 1
python orchestration.py --config configs/llm/cc_blackbox_sample.yaml --mode blackbox --trials 1
```

Full 100-case LLM configs:

```bash
python orchestration.py --config configs/llm/as_full.yaml --trials 1
python orchestration.py --config configs/llm/cc_whitebox_full.yaml --mode whitebox --trials 1
python orchestration.py --config configs/llm/cc_blackbox_full.yaml --mode blackbox --trials 1
```

Executable A2A attack/control configs using the environment-backed LLM coordinator:

```bash
python orchestration.py --config configs/llm/asrf_eval.yaml --trials 1
python orchestration.py --config configs/llm/atsi_eval.yaml --trials 1
python orchestration.py --config configs/llm/co_eval.yaml --trials 1
python orchestration.py --config configs/llm/hotf_eval.yaml --trials 1
```

## Outputs

Each run writes:

- `results/run_<timestamp>.jsonl`: per-trial records.
- `results/summary.json`: aggregate metrics for the latest run.

## Validation

Run release checks before publishing or merging benchmark changes:

```bash
python -m pytest
python scripts/validate_release.py
python scripts/validate_cc_blackbox_observability.py
python -m compileall -q orchestration.py attacks harness sut utils scripts tests
```

`validate_release.py` checks config integrity, importability, case counts, balancing, CC label quality, rename cleanup, executable A2A behavior, source hardening, and secret-like literals.

## CC Evidence Judge

CC run summaries report ASR and deterministic `label_accuracy`. Evidence quality is judged separately:

```bash
python scripts/judge_cc_evidence.py --input results/run_YYYY.jsonl
```

The judge reports `llm_evidence_quality_mean`, `llm_evidence_quality_on_correct_labels`, and `joint_label_evidence_accuracy`.
