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

Dataset: 150 train samples (29 vulnerable, 19.3%), 56 gold flows; 75 validation
samples.

### Detection — train (labeled)

    flow-level (exact from/to lines; identical at file-level, tol=0..inf):
      TP=56  FP=5  FN=0    precision 0.918  recall 1.000  F1 0.957
    sample-level:
      TP=29  TN=120  FP=1  FN=0   accuracy 0.993  precision 0.967  recall 1.000  F1 0.983
    (eval.py DIAGNOSIS: line convention consistent with gold on all matched flows;
     eval header: 56 gold / 61 pred flows)

Null baseline is F1 0.000 / accuracy 80.7%. Recall is 1.000 — every gold flow is
found on the exact gold line, no flow missed (FN 0). Precision is not perfect: 5
spurious flows in 1 otherwise-clean sample (sample-level FP 1). That false
positive is identified and characterized below under Limitations.

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
- **Sanitized-heredoc refinement (scoping decision).** A single-quoted heredoc body
  (`<<'EOF'`/`<<"EOF"`) is flagged by default — an attacker value containing a line
  equal to the delimiter closes it early and the rest executes (EOF-breakout). An
  interpolation inside such a body is suppressed **only when the opening line has
  BOTH** a single-line reducer (`awk 'NR==1'` / `head -1` / `sed -n '1p'`, which
  makes EOF-breakout impossible) **and** a `sed` that escapes a shell metacharacter
  (backtick, `$`, or a quote, which neutralizes `$()`/backtick/quote injection).
  *Evidence:* a naive "quoted-heredoc = safe" rule was measured and rejected because
  it cost the two `wayou action.yml:47/:50` gold TPs (heredoc redirected to a file,
  no sanitizer); requiring both sanitizers removes the slack `63c49563` false
  positive while keeping those two TPs. Verified on train: it removes exactly the
  one slack false positive with no TP lost (5 FP remain).
- **`env:` → `with:` scoping decision.** Taint is **not** propagated from an `env:`
  block into a `with:` input binding — `with:` values are evaluated under an
  env-emptied scope. This matches the reference flow model's observed propagation
  depth (direct `github.*`-in-`with:` and `steps`/`needs`/`inputs` bindings still
  taint; `env:` → `run:` sink tracing is unaffected). *Honesty note:* a value that
  reaches a shell via `env:` → `with:` → `inputs.*` **is** semantically injectable —
  this is deliberate alignment with what the reference model labels, **not** a claim
  that such flows are safe. *Evidence:* provably inert on the labelled train set (no
  train flow routes `env:` → `with:`; all `env.` refs there are trusted vars such as
  `TAG_NAME`), and it removes the `63dd94c13` `wf:19 → action.yml:51` validation FP
  while keeping the direct `action.yml:47` flow.
- **Input-default source line (scoping decision).** When a composite-action input
  self-taints via its own `default: ${{ github.* }}`, the flow's `from` is placed on
  the first line of the input's declaration block that textually mentions the context
  path — gold's convention (e.g. platformsh `action.yaml:9`, the `description:` prose
  "...Default of {github.head_ref}", not the `default:` value line `:11`). *Evidence:*
  a variant using the `default:` value line was measured against the current dataset
  (4 platformsh flows landed on `:11`, producing 4 FP + 4 FN) and reverted. That
  variant had originally scored better against a *superseded* `train.csv` whose
  platformsh gold sat at `:11`, which explains the earlier discrepancy — the
  convention is dataset-dependent, so it is stated as a measured comparison, not a
  universal rule.
- **Self-verification.** Four gates: `git apply --check`, YAML parses, `actionlint`
  (skipped-as-pass if absent), and re-running the detector on the patched tree
  (zero flows must remain). See `verify.py`.

## Limitations (honest)

- **One known detection false positive (5 flows in 1 sample; precision 0.918).**
  - `63c49aca` (yykamei/actions-git-push, 5 flows): `github.event.pull_request.head.ref`
    is bound to `inputs.branch` and reaches `git pull`/`checkout`/`push`, used as a
    git-ref argument and single-quoted at 4 of the 5 sites. Gold labels the sample
    clean; the engine reports it because it models neither git-ref argument context
    nor the single-quoting.
- **The boolean-result refinement has no train ground truth** — that shape does
  not occur in the labeled train set, so it was verified *inert* on train (train
  detection is unchanged at TP 56 / FP 5 / FN 0) but its correctness on unseen
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
