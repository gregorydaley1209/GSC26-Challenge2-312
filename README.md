# ghactaint — IEEE GSC Challenge 02

Detect and repair code-injection vulnerabilities in GitHub Actions workflows.
Deterministic taint analysis + env-hoist repair + self-verification. Dataset and
task: https://www.kaggle.com/competitions/detect-and-fix-vulnerabilities-in-github-actions

## Install

```bash
pip install ruamel.yaml pytest
# optional (verify gate 3 only): actionlint  -> https://github.com/rhysd/actionlint
```

Dependencies: `ruamel.yaml` (required, round-trip YAML with source positions),
`pytest` (tests), `actionlint` (optional).

### Python version — 3.9.7, invoked explicitly

Developed and run on **Python 3.9.7**. The pipeline imports `ruamel.yaml`, so it
must be invoked with the interpreter that has the dependencies installed. On this
machine that interpreter is:

```
%LOCALAPPDATA%\Programs\Python\Python39\python.exe
```

A bare `python` on PATH points at a different install (Python 3.12) that does
**not** have `ruamel.yaml`, so `python -m ghactaint.cli ...` there fails at import
with `ModuleNotFoundError: ruamel`. Always call the 3.9 interpreter that has the
deps (or `pip install ruamel.yaml pytest` into whatever interpreter you use).

## Run

```bash
PY="%LOCALAPPDATA%\Programs\Python\Python39\python.exe"   # the interpreter with ruamel.yaml

# 1. unit tests (no dataset needed)
"$PY" -m pytest tests/ -q

# 2. eval harness self-test
"$PY" eval.py --self-test

# 3. end-to-end on the synthetic fixture
"$PY" -m ghactaint.cli --root fixture --split train --out /tmp/fx

# 4. score detection against a labeled split
"$PY" -m ghactaint.cli --root DATASET --split train --out out_train
"$PY" eval.py --gold DATASET/train.csv --pred out_train/train.csv

# 5. FINAL artifact (what the organizers run)
"$PY" -m ghactaint.cli --root DATASET --split test --out .
#   -> test.csv  +  patches/<sample_id>.patch
```

`--root` is the extracted dataset root (containing `train/`, `validation/`,
`test/`, and `untrusted_data.csv`). `<split>.csv` has columns
`sample_id,vulnerabilities,patches`; one patch file per vulnerable sample at
`patches/<sample_id>.patch` (a single git-apply-compatible unified diff, possibly
multi-file). `--untrusted` defaults to `<root>/untrusted_data.csv`.

## LLM / API disclosure

**Zero LLM calls. No API key required.** The pipeline is fully deterministic:
detection is static taint analysis and repair is a deterministic env-hoist
templater. There are no calls to OpenRouter, OpenAI, Anthropic, or any model
endpoint anywhere in the code (`grep` over `ghactaint/` and `eval.py` finds no
HTTP/API/model usage). The competition rules require, *if* the system makes model
calls, that they go through OpenRouter with the organizer-issued team key and that
the exact model identifier be named — this system makes none, so there is nothing
to configure and no model identifier to name.

## Results (measured on disk, this codebase)

Dataset: 150 train samples (31 vulnerable, 20.7%), 62 gold flows; 75 validation
samples.

### Detection — train (labeled)

    flow-level (exact from/to lines):
      TP=62  FP=0  FN=0    precision 1.000  recall 1.000  F1 1.000
    sample-level:
      TP=31  TN=119  FP=0  FN=0   accuracy 1.000
    (eval.py DIAGNOSIS: line convention consistent with gold on all matched flows)

Null baseline is F1 0.000 / accuracy 79.3%. Every gold flow is found on the exact
gold line; every vulnerable sample is classified vulnerable, every clean sample
clean.

### Patches — apply cleanly

    train:      31/31 generated patches pass `git apply --check`
    validation: 16/16 generated patches pass `git apply --check`

(Validation currently reports 16 vulnerable samples / 23 flows. Before the
boolean-sink refinement below it reported 19 vulnerable / 28 flows; three samples
became clean when their only flows were boolean-guarded — see Limitations.)

## Approach (summary)

- **Detection.** Interprocedural taint from the predefined untrusted `github.*`
  contexts (`untrusted_data.csv`) to shell sinks (`run:`), through `with:` inputs,
  `$GITHUB_ENV`/`$GITHUB_OUTPUT`/`::set-output`, job/action outputs, and JS/Docker
  action passthrough (endpoints stay YAML). `uses:` refs resolve to vendored
  `actions/` and `reusable_workflows/` under the split. Sink line = the line of
  the `${{ }}` interpolation.
- **Repair — env-hoist.** Each untrusted `${{ }}` in a `run:` is moved to a
  step-level `env:` entry and replaced with a quoted shell variable reference, so
  the value is delivered through the process environment instead of being
  substituted into the script text.
- **Boolean-result refinement.** An untrusted ref used *only* as an argument to
  `contains()`/`startsWith()`/`endsWith()` yields the function's boolean result,
  never attacker text, so it is not an injection sink and is not reported.
- **Self-verification.** Four gates: `git apply --check`, YAML parses, `actionlint`
  (skipped-as-pass if absent), and re-running the detector on the patched tree
  (zero flows must remain). See `verify.py`.

## Limitations (honest)

- **`63dd94ac` (validation)** still produces malformed patched YAML — its patch
  fails verification gate 2 (YAML parse). Detection for it is unaffected; the
  patch shape needs work.
- **The boolean-result refinement has no train ground truth** — that shape does
  not occur in the labeled train set, so it was verified *inert* on train (train
  detection is unchanged at TP 62 / FP 0 / FN 0) but its correctness on unseen
  data rests on the soundness argument (boolean output ≠ shell text), not on
  gold labels.

## Layout

```
ghactaint/
  cli.py        entry point -> <split>.csv + patches/
  taint.py      taint engine (flow model + boolean-sink refinement)
  loader.py     ruamel YAML load with exact source positions
  expr.py       ${{ }} / context-ref scanning
  resolver.py   uses: -> vendored action / reusable-workflow paths
  patch.py      env-hoist unified-diff generation
  verify.py     four-gate self-verification
eval.py         scorer (flow-level P/R/F1 at line tolerances + sample-level)
tests/          unit tests
fixture/        synthetic 4-file dataset for wiring tests
```
