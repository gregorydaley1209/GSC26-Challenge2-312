# ghactaint — IEEE GSC Challenge 02

Detect and repair code-injection vulnerabilities in GitHub Actions workflows.
Deterministic taint analysis + env-hoist repair + self-verification.

## Install

```bash
pip install ruamel.yaml pytest
# optional but recommended (verify gate 3):
#   https://github.com/rhysd/actionlint
```

## Run

```bash
# 1. unit tests (no dataset needed)
python -m pytest tests/ -q

# 2. eval harness self-test
python eval.py --self-test
python eval.py --baseline null            # the bar: 80.7% acc, 0.0 detection F1

# 3. end-to-end on the synthetic fixture
python -m ghactaint.cli --root fixture --split train --out /tmp/fx

# 4. line-convention sweep (RESOLVED: expr — kept for reproducibility)
for m in expr run-key step-start; do
  python -m ghactaint.cli --root DATASET --split train --out /tmp/$m --sink-line-mode $m
  echo "== $m"; python eval.py --gold train.csv --pred /tmp/$m/train.csv | grep -A6 'FLOW-LEVEL'
done

# 5. final artifact shape (what organizers run)
python -m ghactaint.cli --root DATASET --split test --out .
#   -> test.csv + patches/<sample_id>.patch
```

## Findings from train.csv (confirmed, not assumed)

| Fact | Value |
|---|---|
| Samples | 150 — **29 vulnerable (19.3%)**, 121 clean |
| Total flows | 56 |
| Null baseline | **80.7% accuracy, 0.0 detection F1** |
| `from == to` | 39/56 (direct inline interpolation) |
| Cross-file flows | 4/56 |
| Untrusted sources | **27** (4 use `[*]` wildcard indices) |
| **Reference patch strategy** | **env-hoist, 36/36 — zero exceptions** |
| Patch files per sample | exactly 1: `patches/<sample_id>.patch`, multi-file diff |
| Patched files vs sink files | identical, 0/29 exceptions |

Two consequences that shape the whole design:

1. **env-hoist is 36/36.** A correct deterministic templater reproduces the
   reference strategy on every training case. The LLM is a quoting fallback,
   not the engine. Less nondeterminism, less shared-key burn.
2. **Patched files == sink files, always.** For cross-file flows, fix at the
   sink *inside the action*, never at the caller's `with:` line.

## Flow model (spec — see taint.py docstring)

- **ROOT** — every direct interpolation of an untrusted `github.*` context starts
  its own flow. Evidence: one sample has 8 flows from 8 independent
  interpolations across different jobs.
- **FROM** — the `with:` key line (cross-component) or the `run:` line (inline).
  Evidence: sample `63dd9558` reports `:16` and `:17`, two adjacent `with:` keys.
- **TO** — first `run:` shell command the value reaches.
- **Task 1 reports first sinks only; Task 2 patches every consumption point.**
  Evidence: `tj-actions/branch-names` reports **1** vuln at `:42` while its
  reference patch touches **3** steps. `Result.flows` vs `Result.consumptions`
  encode exactly this split.

## Verification (`verify.py`)

Four gates; a patch ships only if all pass:

1. `git apply --check`
2. YAML parses
3. `actionlint` (skipped-as-pass if not installed)
4. **re-run our own detector on the patched tree — zero flows must remain**

Gate 4 is the real one and is negative-controlled in the test suite: an empty
patch on a vulnerable sample is *rejected*, naming the surviving flow. Worth a
paragraph in `submission.pdf`.

## Status — measured on the real dataset (150 train samples)

Dataset: https://github.com/XinyuZhangXvX/detect-and-fix-vulnerabilities-in-github-actions

### Task 1 — detection

    flow-level (strict, exact from/to lines):
      TP=56  FP=7  FN=0    precision 0.889   recall 1.000   F1 0.941
    sample-level:
      TP=29  TN=119 FP=2 FN=0   accuracy 0.987   recall 1.000

Null baseline is F1 0.000 — recall is the whole game, and no gold flow is
missed. Strict == file-only at EVERY tolerance: every flow found on the right
file also landed on the exact right line.

All 7 remaining FP flows sit in just 2 samples (63c49aca, 63c49563). Attributed
to curation noise: 29 vulnerable samples == 29 reference patches, so the labels
likely cover only flows with a known upstream fix. Ruled out first — the `on:`
trigger does NOT gate labels (16 gold-vulnerable samples use plain
`pull_request`, two with the same source as the FP).

### Task 2 — patches

    29/29 patches pass all 4 verification gates
    29/29 file-set match against the organizers' reference patches

Scope follows the reference convention: files containing a reported flow sink
are repaired, and every consumption inside such a file is neutralized. A
CALLER's downstream re-consumption of a component's outputs is left alone —
neutralizing the root already kills the flow. tj-actions patches action.yml
:42/:61/:75 but not the workflow's :30/:31; 63dd950d patches only the workflow,
because its sinks live there.

### Resolved empirically, not guessed

1. **Sink-line convention = `expr`** (the line of the `${{ }}` occurrence).
   Three-way sweep against gold: `expr` holds strict == file-only; `run-key` and
   `step-start` collapse as tolerance tightens.
2. **Input defaults self-taint.** A composite action whose input declares
   `default: ${{ github.head_ref }}` taints ITSELF when the caller does not bind
   that input. Whole FN class; invisible without the dataset.
3. **Root vs derived reporting.** Root symbols are reported at every consumption
   (platformsh's `inputs.ref` at :49/:51/:78/:85 = 4 flows); only values produced
   by a step that already reported a sink collapse to the first (tj-actions).

### Rejected: quoted-heredoc-as-safe

Treating `<<'EOF'` bodies as literal data is **unsound** — an attacker value
containing a line equal to the delimiter closes the heredoc early and the rest
executes (EOF breakout). Gold agrees, flagging wayou action.yml :47/:50 where
`${{ inputs.body }}` (a multi-line issue body) sits inside `<<'EOF'`. Cost 2 TP
to remove 1 FP (F1 0.941 -> 0.931). Reverted; `expr.literal_heredoc_spans()` and
its tests are retained.

### Two patch bugs caught by gate 4, not by the fixture

The synthetic fixture is circular — it cannot find bugs it has no shape for.
Re-running the detector on the patched tree found both (now regression-tested):

* **63dd950d** — the file has no trailing newline and its last line IS a sink.
  difflib's final chunk then lacks `\n`, so a naive `join()` welds the next `+`
  onto the preceding `-` line and git rejects the patch as corrupt. Fixed by
  emitting git's `\ No newline at end of file` marker.
* **63dd950c** — a step written `- run: |` carries the `run:` key on the item
  line. The `env:` block was being inserted INTO the shell script, and the step
  indent was sniffed from the script body rather than the item.

### LLM disclosure

**Zero LLM calls.** The pipeline is fully deterministic: env-hoist covers 36/36
reference patches with no exceptions, so no model is invoked at any point. No
API key is required to run this code.

## Compliance checklist

- [x] OpenRouter team key — **not required**: zero LLM calls, nothing to
      configure. If a future edge case ever needs one it is read from
      `os.environ`, never committed.
- [x] Private repo + read access to `XinyuZhangXvX` (post-deadline commits
      are ignored — this had the only unrecoverable deadline)
- [x] README — deps, repro commands, LLM disclosure (no model id: none used)
- [ ] `submission.pdf` — approach, detection, patch, LLM/tool disclosure
- [ ] Validation set drops **2 days** before the deadline; harness is ready:
      `python -m ghactaint.cli --root DATASET --split validation --out .`
