"""
YAML loading with exact source positions.

Scoring is `file:line` string matching, so positions are the product. Two rules:

  1. NEVER round-trip dump the YAML. ruamel preserves a lot but not everything,
     and any reflow shifts every downstream line number. Patches are computed as
     surgical edits against the RAW TEXT (see patch.py), not by re-serializing.

  2. A `run:` block is usually a multi-line block scalar. An expression at
     character offset N inside that scalar needs mapping back to an absolute
     file line. That mapping is what `ScalarPos.line_of_offset` does.

THE OPEN QUESTION (needs the dataset repo to settle):
    For a multi-line run: block, does gold point at
      (a) the line containing the ${{ }}         -> SinkLineMode.EXPR
      (b) the `run:` key line                    -> SinkLineMode.RUN_KEY
      (c) the step's first line (`- name:` etc)  -> SinkLineMode.STEP_START
    All three are implemented. When the repo lands, run all three through
    eval.py; exactly one will hit F1=1.0 against the labels. Do not guess.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap, CommentedSeq


class SinkLineMode:
    EXPR = "expr"
    RUN_KEY = "run-key"
    STEP_START = "step-start"
    ALL = (EXPR, RUN_KEY, STEP_START)


@dataclass
class ScalarPos:
    """Position of a scalar value in the source file."""
    line: int          # 1-based line of the scalar's first content char
    col: int           # 0-based column
    text: str

    def line_of_offset(self, off: int) -> int:
        """Absolute 1-based file line for a char offset inside `text`."""
        return self.line + self.text.count("\n", 0, max(0, off))


@dataclass
class Doc:
    path: str          # repo-relative, e.g. "train/workflows/abc.yml"
    raw: str
    lines: List[str]
    data: Any

    @classmethod
    def load(cls, abspath: str, relpath: Optional[str] = None) -> "Doc":
        with open(abspath, "r", encoding="utf-8") as fh:
            raw = fh.read()
        y = YAML(typ="rt")
        y.preserve_quotes = True
        return cls(
            path=relpath or abspath,
            raw=raw,
            lines=raw.splitlines(),
            data=y.load(raw),
        )

    # -- position lookup -------------------------------------------------

    def key_line(self, node: CommentedMap, key: str) -> Optional[int]:
        """1-based line of `key:` within a mapping."""
        try:
            return node.lc.key(key)[0] + 1
        except Exception:
            return None

    def value_pos(self, node: CommentedMap, key: str) -> Optional[ScalarPos]:
        """Position of a mapping VALUE. Handles block scalars."""
        try:
            vline, vcol = node.lc.value(key)
        except Exception:
            return None
        text = node.get(key)
        if not isinstance(text, str):
            return None
        line = vline + 1
        # Block scalar (| or >): ruamel points at the indicator; content starts
        # on the NEXT line. Detect by inspecting the raw source line.
        src = self.lines[vline] if vline < len(self.lines) else ""
        after = src[vcol:].lstrip()
        if after[:1] in ("|", ">"):
            # skip the indicator line, plus any blank lines the scalar swallows
            line = vline + 2
            col = None
            for i in range(vline + 1, len(self.lines)):
                if self.lines[i].strip():
                    line = i + 1
                    col = len(self.lines[i]) - len(self.lines[i].lstrip())
                    break
            return ScalarPos(line=line, col=col or 0, text=text)
        return ScalarPos(line=line, col=vcol, text=text)

    def node_line(self, node: Any) -> Optional[int]:
        """1-based first line of a node (e.g. a step mapping)."""
        try:
            return node.lc.line + 1
        except Exception:
            return None

    def seq_item_line(self, seq: CommentedSeq, idx: int) -> Optional[int]:
        try:
            return seq.lc.item(idx)[0] + 1
        except Exception:
            return None


# -- structural walkers --------------------------------------------------


def iter_jobs(data: Any):
    """Yield (job_id, job_map) for a workflow."""
    jobs = data.get("jobs") if isinstance(data, dict) else None
    if not isinstance(jobs, dict):
        return
    for jid, job in jobs.items():
        if isinstance(job, dict):
            yield jid, job


def iter_steps(container: Any):
    """Yield (idx, step_map) for a job or composite action `runs:`."""
    steps = None
    if isinstance(container, dict):
        steps = container.get("steps")
        if steps is None and isinstance(container.get("runs"), dict):
            steps = container["runs"].get("steps")
    if not isinstance(steps, list):
        return
    for i, st in enumerate(steps):
        if isinstance(st, dict):
            yield i, st


def is_composite(action_data: Any) -> bool:
    runs = action_data.get("runs") if isinstance(action_data, dict) else None
    return isinstance(runs, dict) and runs.get("using") == "composite"


def action_runtime(action_data: Any) -> Optional[str]:
    runs = action_data.get("runs") if isinstance(action_data, dict) else None
    return runs.get("using") if isinstance(runs, dict) else None


def job_needs(job: Any) -> List[str]:
    n = job.get("needs")
    if n is None:
        return []
    return [n] if isinstance(n, str) else list(n)


def topo_jobs(data: Any) -> List[str]:
    """Job ids in a valid execution order (needs DAG). Stable; cycles tolerated."""
    jobs = dict(iter_jobs(data))
    order: List[str] = []
    seen: Dict[str, int] = {}

    def visit(j: str):
        if seen.get(j) == 2:
            return
        if seen.get(j) == 1:
            return  # cycle; workflow would be invalid anyway
        seen[j] = 1
        for d in job_needs(jobs.get(j, {})):
            if d in jobs:
                visit(d)
        seen[j] = 2
        order.append(j)

    for j in jobs:
        visit(j)
    return order
