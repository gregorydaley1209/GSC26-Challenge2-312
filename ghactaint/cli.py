"""
CLI entry point.

Produces exactly what the organizers run on the hidden test set:
    test.csv   (sample_id, vulnerabilities, patches)
    patches/   (one <sample_id>.patch per vulnerable sample)

    python -m ghactaint.cli --root DATASET --split test  --out .
    python -m ghactaint.cli --root DATASET --split train --out /tmp/dev \
        --sink-line-mode expr          # then: python eval.py --pred /tmp/dev/train.csv
"""
from __future__ import annotations

import argparse, csv, json, os, sys
from .contexts import UntrustedSet
from .loader import SinkLineMode
from .patch import Patcher
from .taint import Analyzer
from . import verify as V

csv.field_size_limit(10_000_000)


def discover(root: str, split: str):
    d = os.path.join(root, split, "workflows")
    if not os.path.isdir(d):
        sys.exit(f"no workflows dir: {d}")
    out = []
    for f in sorted(os.listdir(d)):
        if f.endswith((".yml", ".yaml")):
            out.append(os.path.splitext(f)[0])
    return out


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True, help="dataset repo root")
    ap.add_argument("--split", default="test", choices=["train", "validation", "test"])
    ap.add_argument("--out", default=".")
    ap.add_argument("--untrusted", default=None, help="untrusted_data.csv (default: <root>/untrusted_data.csv)")
    ap.add_argument("--sink-line-mode", default=SinkLineMode.EXPR, choices=list(SinkLineMode.ALL))
    ap.add_argument("--prefix-match", action="store_true", help="taint parent paths of untrusted leaves")
    ap.add_argument("--no-verify", action="store_true")
    ap.add_argument("--limit", type=int, default=0)
    a = ap.parse_args(argv)

    up = a.untrusted or os.path.join(a.root, "untrusted_data.csv")
    untrusted = UntrustedSet.from_csv(up, prefix_match=a.prefix_match)
    analyzer = Analyzer(root=a.root, untrusted=untrusted, sink_line_mode=a.sink_line_mode)
    patcher = Patcher(root=a.root)

    os.makedirs(os.path.join(a.out, "patches"), exist_ok=True)
    ids = discover(a.root, a.split)
    if a.limit:
        ids = ids[: a.limit]

    rows, n_vuln, n_fail = [], 0, 0
    for sid in ids:
        res = analyzer.analyze_sample(sid, split=a.split)
        vulns, patches = [], []
        if res.flows:
            n_vuln += 1
            vulns = [f.to_json() for f in res.flows]
            sink_files = {f.dst.file for f in res.flows}
            diff, meta = patcher.build(sid, res.consumptions, sink_files=sink_files)
            if diff:
                if not a.no_verify:
                    vr = V.verify(a.root, diff, sid, analyzer, split=a.split)
                    if not vr.ok:
                        n_fail += 1
                        print(f"  ! {sid}: verify failed: {'; '.join(vr.errors)[:120]}", file=sys.stderr)
                pf = os.path.join(a.out, "patches", f"{sid}.patch")
                with open(pf, "w", encoding="utf-8") as fh:
                    fh.write(diff)
                patches = meta
        rows.append({"sample_id": sid,
                     "vulnerabilities": json.dumps(vulns),
                     "patches": json.dumps(patches)})
        for e in res.errors:
            print(f"  ! {sid}: {e}", file=sys.stderr)

    out_csv = os.path.join(a.out, f"{a.split}.csv")
    with open(out_csv, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["sample_id", "vulnerabilities", "patches"])
        w.writeheader()
        w.writerows(rows)

    print(f"{out_csv}: {len(rows)} samples, {n_vuln} vulnerable, {n_fail} patch-verify failures")
    return 0


if __name__ == "__main__":
    sys.exit(main())
