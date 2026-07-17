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

# 4. WHEN THE DATASET REPO LANDS — resolve the line convention first
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

## Status

Complete and tested: `contexts`, `expr`, `resolver`, `loader`, `patch`, `verify`,
`eval`, `cli`. 32 unit tests + harness self-test + 4-pattern end-to-end fixture
(clean / inline / cross-file / downstream-chain) all green.

**Blocked on the dataset repo** (only the two CSVs were in the Kaggle zip):

1. **Sink-line convention** — for a multi-line `run:` block, does gold point at
   the `${{ }}` line, the `run:` key line, or the step start? All three are
   implemented behind `--sink-line-mode`. Step 4 above resolves it empirically.
   **Do not guess this.** `eval.py` reports file-only recall alongside strict
   recall precisely to distinguish a line-convention bug from a detection bug.
2. **Local action layout** (`uses: ./.github/actions/foo`) — candidate paths in
   `resolver.candidate_paths` are guesses; the SHA-pinned remote layout is exact.
3. **Prefix matching** — does `github.event.issue` count as tainted because
   `.title` is? Gold only ever names leaves, so default is off
   (`--prefix-match` to flip).

## Compliance checklist

- [ ] Request OpenRouter **team** API key (personal keys prohibited)
- [ ] Private repo + read access to `XinyuZhangXvX` **before** the deadline
      (post-deadline commits ignored)
- [ ] `submission.pdf` — approach, detection, patch, LLM/tool disclosure
- [ ] README — exact model id, deps, repro commands
- [ ] Validation set drops **2 days** before the deadline; harness is ready now
