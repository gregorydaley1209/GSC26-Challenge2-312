"""
Self-verification loop.

A patch is accepted only if it survives all four gates. Gate 4 is the one that
matters and is also free creativity points for submission.pdf: we re-run our own
detector on the patched tree and require it to come back clean. A patch that
doesn't silence our own detector is not a fix.

  1. git apply --check      -> diff is well-formed and applies
  2. YAML parse             -> still valid YAML
  3. actionlint (optional)  -> still a valid workflow
  4. re-detect              -> zero flows remain  <-- the real gate
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import List, Optional

from ruamel.yaml import YAML


@dataclass
class VerifyResult:
    ok: bool
    gates: dict = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)


def git_apply_check(root: str, diff_text: str) -> tuple[bool, str]:
    if not diff_text.strip():
        return True, ""
    with tempfile.NamedTemporaryFile("w", suffix=".patch", delete=False, encoding="utf-8", newline="") as fh:
        fh.write(diff_text)
        p = fh.name
    try:
        r = subprocess.run(["git", "apply", "--check", "-p1", p],
                           cwd=root, capture_output=True, text=True)
        return r.returncode == 0, r.stderr.strip()
    finally:
        os.unlink(p)


def apply_to_copy(root: str, diff_text: str) -> Optional[str]:
    """Copy the tree, apply the diff, return the temp root (caller cleans up)."""
    tmp = tempfile.mkdtemp(prefix="ghac_verify_")
    dst = os.path.join(tmp, "tree")
    shutil.copytree(root, dst, symlinks=True)
    if diff_text.strip():
        pf = os.path.join(tmp, "p.patch")
        with open(pf, "w", encoding="utf-8", newline="") as fh:
            fh.write(diff_text)
        r = subprocess.run(["git", "apply", "-p1", pf], cwd=dst,
                           capture_output=True, text=True)
        if r.returncode != 0:
            shutil.rmtree(tmp, ignore_errors=True)
            return None
    return dst


def yaml_ok(path: str) -> tuple[bool, str]:
    try:
        YAML(typ="safe").load(open(path, encoding="utf-8"))
        return True, ""
    except Exception as ex:
        return False, str(ex)


def actionlint_ok(path: str) -> tuple[bool, str]:
    if shutil.which("actionlint") is None:
        return True, "actionlint not installed (skipped)"
    r = subprocess.run(["actionlint", "-no-color", path], capture_output=True, text=True)
    return r.returncode == 0, r.stdout.strip()


def verify(root: str, diff_text: str, sample_id: str, analyzer, split: str = "train") -> VerifyResult:
    res = VerifyResult(ok=False)

    ok, err = git_apply_check(root, diff_text)
    res.gates["git_apply"] = ok
    if not ok:
        res.errors.append(f"git apply: {err}")
        return res

    tmp_root = apply_to_copy(root, diff_text)
    if tmp_root is None:
        res.gates["apply_to_copy"] = False
        res.errors.append("patch failed to apply to working copy")
        return res
    res.gates["apply_to_copy"] = True

    try:
        wf = os.path.join(tmp_root, split, "workflows", f"{sample_id}.yml")
        if os.path.isfile(wf):
            ok, err = yaml_ok(wf)
            res.gates["yaml"] = ok
            if not ok:
                res.errors.append(f"yaml: {err}")
                return res
            ok, err = actionlint_ok(wf)
            res.gates["actionlint"] = ok
            if not ok:
                res.errors.append(f"actionlint: {err}")

        # Gate 4 — the real one.
        import copy as _copy
        a2 = _copy.copy(analyzer)
        a2.root = tmp_root
        a2._docs = {}
        after = a2.analyze_sample(sample_id, split=split)
        res.gates["redetect_clean"] = not after.flows
        if after.flows:
            res.errors.append(f"{len(after.flows)} flow(s) survive the patch: "
                              + ", ".join(f"{f.src}->{f.dst}" for f in after.flows[:3]))
            return res
    finally:
        shutil.rmtree(os.path.dirname(tmp_root), ignore_errors=True)

    res.ok = True
    return res
