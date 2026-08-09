"""
Patch generation — env-hoist.

KEY FINDING FROM train.csv: 36/36 reference patches use env-hoisting. Zero use
anything else. 23 mention quoting, 6 handle downstream output-chain
re-consumption, 3 additionally strip `eval` sinks. So a correct deterministic
templater reproduces the reference strategy on every training case, and the LLM
is a fallback for gnarly quoting — not the engine.

    - name: foo
      run: echo "${{ github.head_ref }}"
becomes
    - name: foo
      env:
        HEAD_REF: ${{ github.head_ref }}
      run: echo "$HEAD_REF"

Why this fixes it: `env:` values are passed to the process environment by the
runner, never spliced into the script text. The shell sees `$HEAD_REF` and
performs a variable lookup, not a parse of attacker text.

CRITICAL IMPLEMENTATION RULE: edits are applied to RAW TEXT, never by
re-serializing the YAML. ruamel round-trips reflow whitespace and shift line
numbers, which would corrupt both the diff and the Task 1 answers.

OUTPUT SHAPE (confirmed from train.csv):
  Exactly ONE patch file per sample: patches/<sample_id>.patch — a single
  git apply-compatible unified diff, possibly spanning MULTIPLE files.
  Patched files == sink files, exactly (0/29 exceptions). So for cross-file
  flows, fix at the SINK inside the action, NOT at the caller's `with:` line.
"""
from __future__ import annotations

import difflib
import os
import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

from .taint import Consumption

# Shell-specific env var reference syntax.
SHELL_REF = {
    "bash": '"${name}"',
    "sh": '"${name}"',
    "pwsh": "$env:{name}",
    "powershell": "$env:{name}",
    "cmd": "%{name}%",
    "python": "os.environ['{name}']",
}

_RESERVED = {"HOME", "PATH", "CI", "GITHUB_TOKEN", "RUNNER_OS", "SHELL", "USER", "PWD"}


def var_name(context_path: str, taken: set) -> str:
    """github.event.pull_request.title -> PULL_REQUEST_TITLE (collision-safe)."""
    p = re.sub(r"\[\d+\]", "", context_path)
    parts = [x for x in p.split(".") if x not in ("github", "event")]
    if not parts:
        parts = ["UNTRUSTED"]
    base = "_".join(parts[-2:]).upper()
    base = re.sub(r"[^A-Z0-9_]", "_", base)
    if not re.match(r"^[A-Z_]", base):
        base = "V_" + base
    if base in _RESERVED:
        base = base + "_INPUT"
    name = base
    i = 2
    while name in taken:
        name = f"{base}_{i}"
        i += 1
    taken.add(name)
    return name


def _indent_of(line: str) -> str:
    return line[: len(line) - len(line.lstrip())]


def quote_state(line: str, pos: int) -> Optional[str]:
    """Shell quoting state at `pos`: 'd' inside "..", 's' inside '..', None bare."""
    i, state = 0, None
    while i < pos and i < len(line):
        c = line[i]
        if state is None:
            if c == "\\":
                i += 2
                continue
            if c == '"':
                state = "d"
            elif c == "'":
                state = "s"
        elif state == "d":
            if c == "\\":
                i += 2
                continue
            if c == '"':
                state = None
        elif state == "s":
            if c == "'":
                state = None
        i += 1
    return state


def _replace_expr(line: str, expr_raw: str, var: str, shell: str = "bash") -> str:
    """Swap ${{ ... }} for an env reference, respecting the shell quoting context.

    The naive `"$VAR"` substitution is wrong inside an existing quoted string:
        echo "got ${{ x }}"   -->  echo "got "$VAR""   # VAR ends up UNQUOTED
    ...which reintroduces word-splitting and globbing. Correct per context:
        bare        echo ${{ x }}     -> echo "$VAR"
        in "..."    echo "got ${{ x }}" -> echo "got $VAR"
        in '...'    echo 'got ${{ x }}' -> echo 'got '"$VAR"''   (break out; the
                    shell does not expand inside single quotes)
    """
    sh = str(shell).lower()
    if sh not in ("bash", "sh", ""):
        return line.replace(expr_raw, SHELL_REF.get(sh, SHELL_REF["bash"]).format(name=var))

    out = line
    while True:
        i = out.find(expr_raw)
        if i < 0:
            return out
        st = quote_state(out, i)
        if st == "d":
            rep = f"${{{var}}}"          # already protected by the enclosing "
        elif st == "s":
            rep = f"'\"${{{var}}}\"'"    # close ', quote the var, reopen '
        else:
            rep = f'"${{{var}}}"'
        out = out[:i] + rep + out[i + len(expr_raw):]


@dataclass
class FileEdit:
    path: str
    original: str
    patched: str

    @property
    def changed(self) -> bool:
        return self.original != self.patched


class Patcher:
    """Builds one unified diff per sample from the consumption sites."""

    def __init__(self, root: str):
        self.root = root

    def build(self, sample_id: str, consumptions: List[Consumption],
              sink_files: Optional[Set[str]] = None) -> Tuple[str, List[dict]]:
        """Returns (unified_diff_text, patch_metadata_objects).

        `sink_files` restricts patching to files that contain a reported flow
        sink. The reference patches are upstream fixes: a component's own file
        is repaired, and the CALLER's downstream re-consumption of its outputs
        is left alone (neutralizing the root already kills the flow). tj-actions
        patches action.yml :42/:61/:75 but not the workflow's :30/:31, while
        63dd950d patches only the workflow because its sinks live there. So the
        unit is the file, not the individual sink: within a sink file, every
        consumption is neutralized. Verified: 27/29 -> 29/29 file-set match.
        """
        by_file: Dict[str, List[Consumption]] = defaultdict(list)
        for c in consumptions:
            # Only `run:` sinks get hoisted. `with:` sites are the caller side;
            # patched files == sink files in every gold sample, so leave them.
            if c.scalar_key != "run":
                continue
            if sink_files is not None and c.file not in sink_files:
                continue
            by_file[c.file].append(c)

        edits: List[FileEdit] = []
        meta: List[dict] = []
        for path, cons in sorted(by_file.items()):
            fe = self._patch_file(path, cons)
            if fe and fe.changed:
                edits.append(fe)
                meta.append({
                    "file": path,
                    "patch_file": f"patches/{sample_id}.patch",
                    "explanation": _explain_patch(cons),
                })

        diff = "".join(self._diff(e) for e in edits)
        return diff, meta

    def _patch_file(self, relpath: str, cons: List[Consumption]) -> Optional[FileEdit]:
        abspath = os.path.join(self.root, relpath)
        if not os.path.isfile(abspath):
            return None
        with open(abspath, "r", encoding="utf-8") as fh:
            original = fh.read()
        lines = original.splitlines(keepends=True)

        # Group by step so one `env:` block serves all exprs in that step.
        by_step: Dict[int, List[Consumption]] = defaultdict(list)
        for c in cons:
            by_step[c.step_line or c.line].append(c)

        # Apply bottom-up so earlier line numbers stay valid.
        for step_line in sorted(by_step, reverse=True):
            group = by_step[step_line]
            # `env:` is STEP-scoped, so collisions only matter within a step.
            # Naming per-file would give the same source different names in
            # different steps (HEAD_REF here, HEAD_REF_2 there) for no reason.
            taken: set = set()
            seen: Dict[str, str] = {}
            mapping: List[Tuple[str, str, str]] = []  # (var, expr_raw, shell)
            for c in group:
                if c.expr_raw in seen:          # same expr twice in one step -> one var
                    continue
                v = var_name(c.source, taken)
                seen[c.expr_raw] = v
                mapping.append((v, c.expr_raw, c.shell))

            lines = self._apply_step(lines, step_line, mapping)

        return FileEdit(path=relpath, original=original, patched="".join(lines))

    def _apply_step(self, lines: List[str], step_line: int, mapping) -> List[str]:
        """Rewrite the run: script and insert/extend the step's env: block."""
        idx = step_line - 1
        if idx < 0 or idx >= len(lines):
            return lines

        # Step body = from the `- ` item line until the next item at <= indent.
        item_indent = len(_indent_of(lines[idx]))
        end = len(lines)
        for j in range(idx + 1, len(lines)):
            s = lines[j]
            if s.strip() and len(_indent_of(s)) <= item_indent and s.lstrip().startswith("- "):
                end = j
                break

        # A step can be written `- run: |` with no name:/id:, putting the `run:`
        # key on the item line itself. Then there is no `run:` line to insert
        # before, and the first non-dash line is the SCRIPT BODY, not a key --
        # so indent must be derived from the item, not sniffed. Getting this
        # wrong injects the env: block into the shell script (real case:
        # 63dd950c, guan-kevin/composite-action).
        inline_run = re.match(r"^\s*-\s+run:", lines[idx]) is not None

        # Key indent inside the step: `- name: x` -> keys align under `name`.
        step_indent = " " * (item_indent + 2)
        if not inline_run:
            for j in range(idx + 1, end):
                if lines[j].strip() and not lines[j].lstrip().startswith("-"):
                    step_indent = _indent_of(lines[j])
                    break

        # 1. rewrite the script, but ONLY within this step's body
        for v, expr_raw, shell in mapping:
            for i in range(idx, end):
                if expr_raw in lines[i]:
                    lines[i] = _replace_expr(lines[i], expr_raw, v, shell)

        # 2. locate an existing `env:` and the `run:` key within the step
        env_at = run_at = None
        for j in range(idx, end):
            body = lines[j][len(step_indent):] if lines[j].startswith(step_indent) else lines[j].lstrip()
            if env_at is None and re.match(r"^env:\s*$", body.rstrip("\n")):
                env_at = j
            if run_at is None and re.match(r"^run:", body):
                run_at = j

        block = [f"{step_indent}  {v}: {expr_raw}\n" for v, expr_raw, _ in mapping]
        if env_at is not None:
            # Indent the new entries to match the EXISTING env: block's own children,
            # not step_indent+2 -- the env: may be a job/workflow-level block at a
            # shallower depth than the step, and a mismatched indent yields invalid
            # YAML (a key at the wrong column reads as a new mapping). Sample 63dd94ac.
            env_indent = _indent_of(lines[env_at])
            eblock = [f"{env_indent}  {v}: {expr_raw}\n" for v, expr_raw, _ in mapping]
            lines[env_at + 1 : env_at + 1] = eblock
        elif inline_run:
            # `run:` is on the item line, so env: cannot precede it. Append the
            # block after the step's last line instead (trailing blanks trimmed),
            # which keeps it a sibling key of the inline run:.
            at = end
            while at > idx + 1 and not lines[at - 1].strip():
                at -= 1
            lines[at:at] = [f"{step_indent}env:\n"] + block
        else:
            # Insert immediately before `run:` so env sits adjacent to the script
            # it feeds, rather than splitting `name:`/`id:`.
            at = run_at if run_at is not None else idx + 1
            lines[at:at] = [f"{step_indent}env:\n"] + block
        return lines

    def _diff(self, e: FileEdit) -> str:
        d = difflib.unified_diff(
            e.original.splitlines(keepends=True),
            e.patched.splitlines(keepends=True),
            fromfile=f"a/{e.path}",
            tofile=f"b/{e.path}",
            n=3,
        )
        # A file whose last line has no trailing newline yields a final chunk
        # with no "\n". Naive "".join() then welds the next diff line onto it
        # ("-old...-Application+new...") and git rejects the patch as corrupt.
        # Git's convention is to terminate the line and follow it with the
        # "\ No newline at end of file" marker. Real case: 63dd950d, whose last
        # line IS a sink.
        parts: List[str] = []
        for ln in d:
            if ln.endswith("\n"):
                parts.append(ln)
            else:
                parts.append(ln + "\n\\ No newline at end of file\n")
        body = "".join(parts)
        return f"diff --git a/{e.path} b/{e.path}\n" + body


def _explain_patch(cons: List[Consumption]) -> str:
    srcs = sorted({c.source for c in cons})
    n = len(cons)
    return (
        f"Env-hoisted {n} untrusted interpolation(s) ({', '.join(srcs)}). Each "
        f"`${{{{ ... }}}}` in the `run:` script was moved to a step-level `env:` "
        f"entry and replaced with a quoted shell variable reference, so the value "
        f"is delivered through the process environment instead of being "
        f"substituted into the script text. Behavior is preserved: the shell still "
        f"reads the same value, but it can no longer be parsed as code."
    )
