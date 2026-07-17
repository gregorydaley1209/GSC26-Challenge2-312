#!/usr/bin/env python3
"""
Eval harness — IEEE GSC Challenge 02 (Detect and Fix Vulnerabilities in GitHub Actions).

Scores a prediction CSV against ground-truth labels in train.csv format.

Reports flow-level detection P/R/F1 at several line tolerances, so you can
separate "found the flow, wrong line convention" from "missed it entirely":

    strict  (tol=0)    -> what the leaderboard most likely scores
    tol=N              -> off-by-N line convention diagnosis
    file    (tol=inf)  -> did we find the right flow at all?

If `file` recall is high but `strict` recall is low, the detector is fine and
the sink-line convention is wrong. Fix the convention, not the engine.

Usage:
    python eval.py --pred pred.csv
    python eval.py --pred pred.csv --verbose
    python eval.py --self-test
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

csv.field_size_limit(10_000_000)

# ---------------------------------------------------------------- data model


@dataclass(frozen=True)
class Endpoint:
    file: str
    line: int

    @staticmethod
    def parse(s: str) -> "Endpoint":
        path, _, line = s.rpartition(":")
        if not path:
            raise ValueError(f"bad endpoint (no ':'): {s!r}")
        return Endpoint(norm_path(path), int(line))

    def __str__(self) -> str:
        return f"{self.file}:{self.line}"


@dataclass(frozen=True)
class Flow:
    src: Endpoint
    dst: Endpoint

    def __str__(self) -> str:
        return f"{self.src} -> {self.dst}"


def norm_path(p: str) -> str:
    p = p.strip().replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p


def matches(a: Flow, b: Flow, tol: Optional[int]) -> bool:
    """tol=None means file-only (ignore lines entirely)."""
    if a.src.file != b.src.file or a.dst.file != b.dst.file:
        return False
    if tol is None:
        return True
    return abs(a.src.line - b.src.line) <= tol and abs(a.dst.line - b.dst.line) <= tol


# ---------------------------------------------------------------- loading


def load_flows(path: str, column: str = "vulnerabilities") -> Dict[str, List[Flow]]:
    out: Dict[str, List[Flow]] = {}
    bad: List[str] = []
    with open(path, newline="", encoding="utf-8-sig") as fh:
        for row in csv.DictReader(fh):
            sid = row["sample_id"].strip()
            raw = (row.get(column) or "").strip() or "[]"
            try:
                items = json.loads(raw)
            except json.JSONDecodeError:
                bad.append(sid)
                items = []
            flows = []
            for it in items:
                try:
                    flows.append(Flow(Endpoint.parse(it["from"]), Endpoint.parse(it["to"])))
                except (KeyError, ValueError):
                    bad.append(sid)
            out[sid] = flows
    if bad:
        print(f"  ! {len(bad)} malformed row(s) in {path}: {sorted(set(bad))[:5]}", file=sys.stderr)
    return out


# ---------------------------------------------------------------- matching


def greedy_match(gold: List[Flow], pred: List[Flow], tol: Optional[int]) -> Tuple[int, List[Flow], List[Flow]]:
    """One-to-one greedy match. Returns (tp, unmatched_gold, unmatched_pred)."""
    used = [False] * len(pred)
    tp = 0
    missed: List[Flow] = []
    for g in gold:
        hit = -1
        for i, p in enumerate(pred):
            if used[i]:
                continue
            if matches(g, p, tol):
                # prefer exact over near
                if hit == -1 or (p.src.line == g.src.line and p.dst.line == g.dst.line):
                    hit = i
                    if p.src.line == g.src.line and p.dst.line == g.dst.line:
                        break
        if hit >= 0:
            used[hit] = True
            tp += 1
        else:
            missed.append(g)
    spurious = [p for i, p in enumerate(pred) if not used[i]]
    return tp, missed, spurious


def prf(tp: int, fp: int, fn: int) -> Tuple[float, float, float]:
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return p, r, f


# ---------------------------------------------------------------- scoring


def score(gold: Dict[str, List[Flow]], pred: Dict[str, List[Flow]], tol: Optional[int]):
    tp = fp = fn = 0
    per_sample = {}
    for sid, gflows in gold.items():
        pflows = pred.get(sid, [])
        s_tp, missed, spurious = greedy_match(gflows, pflows, tol)
        tp += s_tp
        fn += len(missed)
        fp += len(spurious)
        if missed or spurious:
            per_sample[sid] = (missed, spurious)
    return tp, fp, fn, per_sample


def sample_level(gold: Dict[str, List[Flow]], pred: Dict[str, List[Flow]]):
    tp = tn = fp = fn = 0
    wrong = []
    for sid, gflows in gold.items():
        g = len(gflows) > 0
        p = len(pred.get(sid, [])) > 0
        if g and p:
            tp += 1
        elif not g and not p:
            tn += 1
        elif p and not g:
            fp += 1
            wrong.append((sid, "FP"))
        else:
            fn += 1
            wrong.append((sid, "FN"))
    return tp, tn, fp, fn, wrong


def report(gold, pred, verbose=False, tolerances=(0, 1, 2, 5, None)):
    n_gold_flows = sum(len(v) for v in gold.values())
    n_pred_flows = sum(len(v) for v in pred.values())
    n_gold_vuln = sum(1 for v in gold.values() if v)

    missing = [s for s in gold if s not in pred]
    extra = [s for s in pred if s not in gold]

    print("=" * 72)
    print(f"  samples: {len(gold)} gold / {len(pred)} pred"
          + (f"   [{len(missing)} MISSING]" if missing else "")
          + (f"   [{len(extra)} unknown ids]" if extra else ""))
    print(f"  flows:   {n_gold_flows} gold / {n_pred_flows} pred")
    print(f"  gold vulnerable samples: {n_gold_vuln}/{len(gold)} "
          f"({n_gold_vuln/len(gold)*100:.1f}%)  |  null-baseline accuracy: "
          f"{(len(gold)-n_gold_vuln)/len(gold)*100:.1f}%")
    print("=" * 72)

    print("\nFLOW-LEVEL DETECTION  (from/to pair matching)")
    print(f"  {'tol':>6} {'TP':>4} {'FP':>4} {'FN':>4} {'prec':>7} {'recall':>7} {'F1':>7}")
    for tol in tolerances:
        tp, fp, fn, _ = score(gold, pred, tol)
        p, r, f = prf(tp, fp, fn)
        label = "file" if tol is None else f"±{tol}"
        print(f"  {label:>6} {tp:>4} {fp:>4} {fn:>4} {p:>7.3f} {r:>7.3f} {f:>7.3f}")

    tp, tn, fp, fn, wrong = sample_level(gold, pred)
    p, r, f = prf(tp, fp, fn)
    acc = (tp + tn) / len(gold) if gold else 0.0
    print("\nSAMPLE-LEVEL CLASSIFICATION  (vulnerable vs clean)")
    print(f"  TP={tp}  TN={tn}  FP={fp}  FN={fn}")
    print(f"  accuracy={acc:.3f}  precision={p:.3f}  recall={r:.3f}  F1={f:.3f}")

    # diagnosis
    tp0, _, _, _ = score(gold, pred, 0)
    tpf, _, _, _ = score(gold, pred, None)
    print("\nDIAGNOSIS")
    if tpf > tp0:
        print(f"  ! {tpf - tp0} flow(s) matched on file but NOT on line.")
        print("    -> line convention is off. Try --sink-line-mode variants before touching the engine.")
    elif tp0 == 0 and n_pred_flows == 0:
        print("  null predictor: 0 detection credit. Beat this.")
    else:
        print("  line convention consistent with gold on all matched flows.")

    if verbose:
        _, _, _, per_sample = score(gold, pred, 0)
        if per_sample:
            print("\nPER-SAMPLE ERRORS (strict)")
            for sid, (missed, spurious) in sorted(per_sample.items()):
                print(f"  [{sid}]")
                for m in missed:
                    print(f"      FN  {m}")
                for s in spurious:
                    print(f"      FP  {s}")
        if wrong:
            print("\nSAMPLE-LEVEL MISCLASSIFICATIONS")
            for sid, kind in wrong:
                print(f"  {kind}  {sid}")
    print()


# ---------------------------------------------------------------- self-test


def _self_test(gold_path: str):
    """Prove the harness works using synthetic predictors derived from gold."""
    import copy
    import io
    import contextlib

    gold = load_flows(gold_path)

    def shift(g, d):
        return {
            sid: [Flow(Endpoint(f.src.file, f.src.line + d), Endpoint(f.dst.file, f.dst.line + d)) for f in fl]
            for sid, fl in g.items()
        }

    def halve(g):
        return {sid: fl[: len(fl) // 2] for sid, fl in g.items()}

    cases = {
        "oracle (copy of gold)": copy.deepcopy(gold),
        "null (all empty)": {sid: [] for sid in gold},
        "oracle shifted +1 line": shift(gold, 1),
        "oracle, half the flows dropped": halve(gold),
    }
    failures = []
    for name, pred in cases.items():
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            report(gold, pred)
        out = buf.getvalue()
        tp, fp, fn, _ = score(gold, pred, 0)
        p, r, f = prf(tp, fp, fn)
        tpf, fpf, fnf, _ = score(gold, pred, None)
        _, rf, _ = prf(tpf, fpf, fnf)
        print(f"  {name:34s}  strictF1={f:5.3f}  fileRecall={rf:5.3f}")
        if name.startswith("oracle (copy") and f != 1.0:
            failures.append(f"{name}: expected strict F1 1.0, got {f}")
        if name.startswith("null") and f != 0.0:
            failures.append(f"{name}: expected strict F1 0.0, got {f}")
        if name.startswith("oracle shifted"):
            if f != 0.0:
                failures.append(f"{name}: expected strict F1 0.0, got {f}")
            if rf != 1.0:
                failures.append(f"{name}: expected file recall 1.0, got {rf}")
            tp2, fp2, fn2, _ = score(gold, pred, 2)
            _, _, f2 = prf(tp2, fp2, fn2)
            if f2 != 1.0:
                failures.append(f"{name}: expected tol=2 F1 1.0, got {f2}")
    print()
    if failures:
        for x in failures:
            print("  FAIL:", x)
        return 1
    print("  self-test OK — harness scores oracle=1.0, null=0.0, and detects line-shift.")
    return 0


# ---------------------------------------------------------------- cli


def main(argv=None):
    ap = argparse.ArgumentParser(description="Score GHA vuln-detection predictions.")
    ap.add_argument("--gold", default="train.csv")
    ap.add_argument("--pred", help="prediction CSV (same format as train.csv)")
    ap.add_argument("--baseline", choices=["null"], help="score a built-in baseline instead of --pred")
    ap.add_argument("--verbose", action="store_true", help="dump per-sample FP/FN")
    ap.add_argument("--self-test", action="store_true", help="validate the harness itself")
    a = ap.parse_args(argv)

    if a.self_test:
        return _self_test(a.gold)

    gold = load_flows(a.gold)
    if a.baseline == "null":
        pred = {sid: [] for sid in gold}
    elif a.pred:
        pred = load_flows(a.pred)
    else:
        ap.error("need --pred or --baseline or --self-test")
    report(gold, pred, verbose=a.verbose)
    return 0


if __name__ == "__main__":
    sys.exit(main())
