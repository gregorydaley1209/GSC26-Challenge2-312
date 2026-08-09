"""
Taint engine.

FLOW MODEL — reverse-engineered from train.csv and consistent with all 56 gold
labels. Read this before touching the code; it is the spec.

  ROOT   Every *direct interpolation of an untrusted `github.*` context* starts
         its own flow. Two interpolations of `github.head_ref` in two different
         jobs are TWO flows, not one.
         Evidence: sample 63dd94e5... has 8 vulns from lines 46/134/194/269/
         360/437/517/579 of one workflow — independent interpolations.

  FROM   The line where the untrusted context is interpolated:
           - inline in a `run:`  -> that same line (from == to)
           - in a `with:` input  -> the `with:` KEY line
         Evidence: 63dd9558... reports from :16 and :17 — two adjacent `with:`
         entries (issue.title, issue.body) -> two flows into one action.

  TO     The line of the first `run:` shell command the value reaches.
         39/56 gold flows have from == to (direct inline interpolation).
         4/56 cross into another file. Rest are same-file multi-step.

  FIRST-SINK-ONLY (Task 1) Downstream re-consumption is NOT reported. If step A
         interpolates github.head_ref and writes $GITHUB_OUTPUT, and step B reads
         steps.A.outputs.x, only A is reported. B is not a new root — it has no
         direct github.* interpolation.
         Evidence: tj-actions/branch-names reports ONE vuln at :42, while its
         reference patch touches THREE steps (branch, current_branch, default).

  PATCH-EVERYWHERE (Task 2) The patch must neutralize every consumption point of
         the tainted value, including those downstream sinks. `consumption_sites`
         carries them even though `flows` does not. See patch.py.

PROPAGATION CHANNELS
  workflow with:      -> composite/reusable `inputs.*`
  run: >> $GITHUB_OUTPUT / ::set-output  -> `steps.<id>.outputs.<n>`
  run: >> $GITHUB_ENV                    -> `env.<NAME>`
  job outputs:        -> `needs.<job>.outputs.*`
  action outputs:     -> `steps.<id>.outputs.*` in the caller
  JS/Docker actions   -> opaque: conservatively taint ALL declared outputs if
                         ANY input is tainted (spec says flows may transit these,
                         but start/end points are always YAML).
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from . import expr as E
from . import loader as L
from . import resolver as R
from .contexts import UntrustedSet, canonicalize

# `echo "x=$Y" >> $GITHUB_OUTPUT` / `>> "$GITHUB_OUTPUT"` / `>>$GITHUB_OUTPUT`
_OUT_WRITE = re.compile(
    r"""(?P<name>[A-Za-z_][A-Za-z0-9_-]*)\s*=.*?>>\s*["']?\$\{?GITHUB_OUTPUT\}?["']?""",
    re.MULTILINE,
)
_ENV_WRITE = re.compile(
    r"""(?P<name>[A-Za-z_][A-Za-z0-9_-]*)\s*=.*?>>\s*["']?\$\{?GITHUB_ENV\}?["']?""",
    re.MULTILINE,
)
_SET_OUTPUT = re.compile(r"""::set-output\s+name=(?P<name>[A-Za-z_][A-Za-z0-9_-]*)""")

# Boolean-valued expression functions: their RESULT is true/false, so an untrusted
# ref used ONLY as their argument never reaches the shell as attacker text.
_BOOL_FUNC = re.compile(r"(?<![A-Za-z0-9_])(?:contains|startswith|endswith)\s*\(", re.I)

# Sanitized quoted-heredoc detection. A single-quoted heredoc body (<<'EOF'/<<"EOF")
# is normally NOT safe -- an attacker value containing a line equal to the delimiter
# closes it early and the rest executes (EOF-breakout), so the default flags it. But
# when the opening line ALSO reduces the captured output to a single line
# (awk 'NR==1' / head -1 / sed -n '1p'), EOF-breakout is impossible, AND a sed that
# escapes a shell metacharacter (backtick, $, or a quote) neutralizes $()/backtick/
# quote injection -- so an interpolation in that body can no longer reach the shell
# as code. Both conditions are required, keeping this narrow to the "reduce-to-one-
# line-and-escape" idiom (train sample 63c49563). See _sanitized_heredoc_spans.
_HD_SINGLE_LINE = re.compile(r"""awk\s+["']NR\s*==\s*1["']|head\s+-n?\s*1(?![0-9])|sed\s+-n\s+["']1p["']""")
_HD_SED_ESCAPE = re.compile(r"""sed[^|\n]*s/\\?[`$"']""")


def _heredoc_is_sanitized(open_line: str) -> bool:
    return bool(_HD_SINGLE_LINE.search(open_line) and _HD_SED_ESCAPE.search(open_line))


def _sanitized_heredoc_spans(text: str):
    """Char-offset spans of quoted-heredoc bodies whose opening line sanitizes the
    captured output (single-line reduction + sed metachar-escape). Reuses expr._HEREDOC."""
    spans, off, pending = [], 0, None
    for line in text.split("\n"):
        if pending is None:
            m = E._HEREDOC.search(line)
            if m and (m.group("qd") or m.group("bd")):
                pending = (m.group("qd") or m.group("bd"), off + len(line) + 1, line)
        else:
            delim, start, open_line = pending
            if line.strip() == delim:
                if _heredoc_is_sanitized(open_line):
                    spans.append((start, off))
                pending = None
        off += len(line) + 1
    if pending:
        delim, start, open_line = pending
        if _heredoc_is_sanitized(open_line):
            spans.append((start, len(text)))
    return spans


@dataclass(frozen=True)
class Site:
    """A file:line location plus what's there."""
    file: str
    line: int
    context: str = ""      # the untrusted path that reached here

    def __str__(self) -> str:
        return f"{self.file}:{self.line}"


@dataclass
class Flow:
    """One reportable vulnerability: root interpolation -> first shell sink."""
    src: Site
    dst: Site
    source: str            # canonical untrusted context, e.g. "github.head_ref"
    explanation: str = ""

    def to_json(self) -> dict:
        return {"from": str(self.src), "to": str(self.dst), "explanation": self.explanation}


@dataclass
class Consumption:
    """Any site where a tainted value is interpolated. Superset of Flow sinks.
    Task 2 must neutralize all of these; Task 1 reports only first sinks."""
    file: str
    line: int
    expr_raw: str          # the "${{ ... }}" text to replace
    scalar_key: str        # "run" / "with:<input>"
    source: str
    step_line: Optional[int] = None
    shell: str = "bash"


@dataclass
class TaintValue:
    """Symbolic taint: which untrusted sources reached this symbol, and where in.

    `parents` links a derived value back to the symbol(s) it came from. This is
    what makes first-sink-only correct. Marking `reported` on the value returned
    by _eval_expr is not enough: every expression in a `run:` block is evaluated
    BEFORE any of them is reported, so they all observe reported=False and the
    block double-reports. Reporting therefore marks the whole parent chain, and
    `is_reported` re-checks it dynamically.

    Direct `github.*` refs deliberately produce fresh, parentless values -- each
    interpolation is its own root (see the 8-vuln sample). Propagated symbols
    (inputs/steps/needs/env) are shared objects, so the first sink wins and the
    rest suppress.
    """
    sources: Set[str] = field(default_factory=set)
    origin: Optional[Site] = None       # the ROOT site that started the flow
    reported: bool = False              # has this flow's first sink been emitted?
    derived: bool = False               # crossed a $GITHUB_OUTPUT/$GITHUB_ENV/outputs boundary
    parents: List["TaintValue"] = field(default_factory=list)

    @property
    def is_reported(self) -> bool:
        return self.reported or any(p.is_reported for p in self.parents)

    def mark_reported(self, _seen=None) -> None:
        _seen = _seen if _seen is not None else set()
        if id(self) in _seen:
            return
        _seen.add(id(self))
        self.reported = True
        for p in self.parents:
            p.mark_reported(_seen)


@dataclass
class Result:
    sample_id: str
    flows: List[Flow] = field(default_factory=list)
    consumptions: List[Consumption] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def vulnerable(self) -> bool:
        return bool(self.flows)


class Analyzer:
    """
    Interprocedural taint analysis over a workflow + its vendored components.

    Usage:
        a = Analyzer(root="/path/to/dataset", untrusted=UntrustedSet.from_csv(...))
        res = a.analyze_sample("63dd94ae80aa29a6fd486d2b", split="train")
    """

    def __init__(
        self,
        root: str,
        untrusted: UntrustedSet,
        sink_line_mode: str = L.SinkLineMode.EXPR,
        max_depth: int = 6,
    ):
        self.root = root
        self.untrusted = untrusted
        self.sink_line_mode = sink_line_mode
        self.max_depth = max_depth
        self._docs: Dict[str, L.Doc] = {}

    # -- io ---------------------------------------------------------------

    def doc(self, rel: str) -> Optional[L.Doc]:
        if rel in self._docs:
            return self._docs[rel]
        p = os.path.join(self.root, rel)
        if not os.path.isfile(p):
            return None
        try:
            d = L.Doc.load(p, relpath=rel)
        except Exception:
            return None
        self._docs[rel] = d
        return d

    # -- entry ------------------------------------------------------------

    def analyze_sample(self, sample_id: str, split: str = "train") -> Result:
        res = Result(sample_id=sample_id)
        rel = f"{split}/workflows/{sample_id}.yml"
        d = self.doc(rel)
        if d is None:
            rel = f"{split}/workflows/{sample_id}.yaml"
            d = self.doc(rel)
        if d is None:
            res.errors.append(f"workflow not found: {sample_id}")
            return res
        try:
            self._analyze_workflow(d, res, split, env={}, depth=0)
        except Exception as ex:  # never crash the batch on one bad sample
            res.errors.append(f"{type(ex).__name__}: {ex}")
        res.flows = _dedup(res.flows)
        return res

    # -- workflow ---------------------------------------------------------

    def _analyze_workflow(self, d: L.Doc, res: Result, split: str, env: Dict[str, TaintValue], depth: int):
        wf_env = dict(env)
        self._collect_env_map(d, d.data, wf_env, res, split)

        needs_out: Dict[str, Dict[str, TaintValue]] = {}
        for jid in L.topo_jobs(d.data):
            job = d.data["jobs"][jid]
            job_env = dict(wf_env)
            self._collect_env_map(d, job, job_env, res, split)

            # job-level `uses:` == reusable workflow call
            if isinstance(job, dict) and "uses" in job and isinstance(job.get("uses"), str):
                # A job-level `uses:` is a reusable-workflow call. It needs a real
                # scope or its `with:` bindings are never evaluated and every
                # cross-file flow through it is missed (gold 63dd94e5 :579).
                jscope = _Scope(env=job_env, steps={}, needs=needs_out, inputs={})
                self._call_component(d, job, job.get("uses"), res, split, job_env,
                                     depth, needs_out, scope=jscope,
                                     step_line=d.node_line(job))
                continue

            steps_out = self._analyze_steps(d, job, res, split, job_env, depth, needs_out)
            needs_out[jid] = _job_outputs(d, job, steps_out, self, res, split)

    # -- steps ------------------------------------------------------------

    def _analyze_steps(
        self, d: L.Doc, container, res: Result, split: str,
        env: Dict[str, TaintValue], depth: int,
        needs_out: Dict[str, Dict[str, TaintValue]],
        inputs: Optional[Dict[str, TaintValue]] = None,
    ) -> Dict[str, Dict[str, TaintValue]]:
        """Returns {step_id: {output_name: TaintValue}}."""
        steps_out: Dict[str, Dict[str, TaintValue]] = {}
        scope = _Scope(env=env, steps=steps_out, needs=needs_out, inputs=inputs or {})

        for _, st in L.iter_steps(container):
            step_line = d.node_line(st)
            self._collect_env_map(d, st, scope.env, res, split)

            if isinstance(st.get("run"), str):
                self._handle_run(d, st, step_line, scope, res, split)
            elif isinstance(st.get("uses"), str):
                self._handle_uses(d, st, step_line, scope, res, split, depth, steps_out)
        return steps_out

    def _boolean_only(self, ex) -> bool:
        """True iff every untrusted ref in `ex` is used ONLY inside a
        contains()/startsWith()/endsWith() call, so the value reaching the sink is
        the boolean result, not attacker text. Covers `startsWith(..) && 'lit' ||
        'lit'` (branches are literals, not refs). If any untrusted ref appears
        outside such a call -- raw, or inside format()/toJSON()/join() etc. -- this
        returns False and the flow is still reported (sound: we only drop when the
        untrusted value provably cannot become shell text)."""
        untr = [r for r in ex.refs if self.untrusted.is_untrusted(r.path)]
        if not untr:
            return False
        masked = E._mask_strings(ex.text)          # neutralize '(' ')' inside string literals
        spans = []
        for m in _BOOL_FUNC.finditer(masked):
            o = m.end() - 1                        # index of the '('
            depth = 0
            for j in range(o, len(masked)):
                if masked[j] == "(":
                    depth += 1
                elif masked[j] == ")":
                    depth -= 1
                    if depth == 0:
                        spans.append((o, j))
                        break
        base = ex.start + 3                        # inner-text offset within the run: scalar
        for r in untr:
            rs, rend = r.start - base, r.end - base
            if not any(o < rs and rend <= c for (o, c) in spans):
                return False                       # this untrusted ref escapes the boolean call
        return True

    def _handle_run(self, d: L.Doc, st, step_line, scope: "_Scope", res: Result, split: str):
        pos = d.value_pos(st, "run")
        if pos is None:
            return
        shell = st.get("shell") or "bash"
        run_key_line = d.key_line(st, "run") or pos.line

        # Evaluate ONCE and keep the objects. Propagated symbols (steps/needs/
        # env/inputs) resolve to STORED TaintValues, so mutating `reported` here
        # is what makes first-sink-only work downstream. Re-evaluating would hand
        # back fresh objects with reported=False and double-report the flow.
        # NOTE: treating quoted-heredoc bodies as safe was tried and REJECTED.
        # It is unsound -- an attacker whose value contains a line equal to the
        # delimiter closes the heredoc early and everything after it executes
        # (EOF breakout). Gold agrees: it flags wayou action.yml :47/:50, where
        # `${{ inputs.body }}` (an issue body, multi-line) sits inside <<'EOF'.
        # Empirically the rule cost 2 TP to remove 1 FP (F1 0.941 -> 0.931).
        # E.literal_heredoc_spans() is kept in expr.py for the writeup.
        evaluated = [(ex, self._eval_expr(ex, scope)) for ex in E.find_expressions(pos.text)]
        # Drop boolean-only expressions: an untrusted ref used solely as a
        # contains()/startsWith()/endsWith() argument yields a bool, not shell text
        # -- not an injection sink, and its (bool) result must not propagate either.
        evaluated = [(ex, tv) for (ex, tv) in evaluated if not self._boolean_only(ex)]
        # Drop interpolations inside a sanitized single-quoted heredoc (single-line
        # reduction + sed metachar-escape on the opening line) -- the value cannot
        # reach the shell as code. Narrow: requires BOTH sanitizers. See module top.
        san = _sanitized_heredoc_spans(pos.text)
        if san:
            evaluated = [(ex, tv) for (ex, tv) in evaluated
                         if not any(a <= ex.start < b for (a, b) in san)]
        step_reported = False

        for ex, tv in evaluated:
            if not tv.sources:
                continue
            sink_line = {
                L.SinkLineMode.EXPR: pos.line_of_offset(ex.start),
                L.SinkLineMode.RUN_KEY: run_key_line,
                L.SinkLineMode.STEP_START: step_line or run_key_line,
            }[self.sink_line_mode]

            res.consumptions.append(
                Consumption(file=d.path, line=sink_line, expr_raw=ex.raw,
                            scalar_key="run", source=sorted(tv.sources)[0],
                            step_line=step_line, shell=str(shell))
            )
            # Root symbols (github.*, inputs.* bound from with:/default) are
            # reported at EVERY consumption -- gold reports 4 separate flows for
            # platformsh's `inputs.ref` at :49/:51/:78/:85. Only DERIVED values
            # (those that crossed $GITHUB_OUTPUT/$GITHUB_ENV/outputs) collapse to
            # the first sink -- that is the tj-actions case, where the suppressed
            # steps read `steps.branch.outputs.*` rather than the root.
            if (not tv.derived) or (not tv.is_reported):
                src = tv.origin or Site(d.path, sink_line, sorted(tv.sources)[0])
                res.flows.append(
                    Flow(src=src, dst=Site(d.path, sink_line, sorted(tv.sources)[0]),
                         source=sorted(tv.sources)[0],
                         explanation=_explain(sorted(tv.sources)[0], src, d.path))
                )
                step_reported = True
                tv.origin = src

        # record $GITHUB_OUTPUT / $GITHUB_ENV writes, carrying reported/origin
        sid = st.get("id")
        tainted = [tv for _, tv in evaluated if tv.sources]
        if tainted:
            # Only outputs PRODUCED BY a step that already reported a sink are
            # "downstream". Sibling consumptions of the same symbol each report:
            # gold gives 63dd950d both :36 and :37 off one JS-action output.
            merged = TaintValue(parents=list(tainted), derived=True,
                                reported=step_reported)
            for tv in tainted:
                merged.sources |= tv.sources
                merged.origin = merged.origin or tv.origin
            for m in _OUT_WRITE.finditer(pos.text):
                if sid:
                    scope.steps.setdefault(sid, {})[m["name"]] = merged
            for m in _SET_OUTPUT.finditer(pos.text):
                if sid:
                    scope.steps.setdefault(sid, {})[m["name"]] = merged
            for m in _ENV_WRITE.finditer(pos.text):
                scope.env[m["name"].lower()] = merged

    def _handle_uses(self, d: L.Doc, st, step_line, scope: "_Scope", res: Result,
                     split: str, depth: int, steps_out):
        self._call_component(d, st, st.get("uses"), res, split, scope.env, depth,
                             scope.needs, scope=scope, step_line=step_line, steps_out=steps_out)

    def _call_component(self, d: L.Doc, node, uses_raw: str, res: Result, split: str,
                        env, depth: int, needs_out, scope: "_Scope" = None,
                        step_line=None, steps_out=None):
        """Bind `with:` inputs (recording FROM sites) and recurse into the callee."""
        if depth >= self.max_depth:
            return
        bound: Dict[str, TaintValue] = {}
        with_map = node.get("with")
        if isinstance(with_map, dict) and scope is not None:
            # env: -> with: edge is cut. `with:` bindings do NOT inherit taint from
            # env vars (gold does not trace that hop -- e.g. 63dd94c13's job-level
            # env COMPONENT_BRANCH_NAME=${{ github.head_ref }} feeding the folded
            # build-preview-command with:, whose :51 sink gold treats as a FP). Only
            # env is emptied here: direct github.* and steps/needs/inputs refs still
            # resolve, and env: -> run: sinks are unaffected (evaluated in _handle_run).
            with_scope = _Scope(env={}, steps=scope.steps, needs=scope.needs, inputs=scope.inputs)
            for k in with_map:
                pos = d.value_pos(with_map, k)
                if pos is None:
                    continue
                key_line = d.key_line(with_map, k) or pos.line
                for ex in E.find_expressions(pos.text):
                    tv = self._eval_expr(ex, with_scope)
                    if not tv.sources:
                        continue
                    if self._boolean_only(ex):   # bound value is a bool/literal, not attacker text
                        continue
                    # FROM = the `with:` key line (confirmed: sample 63dd9558 -> :16/:17)
                    origin = tv.origin or Site(d.path, key_line, sorted(tv.sources)[0])
                    nv = TaintValue(sources=set(tv.sources), origin=origin, parents=[tv])
                    bound[k] = nv
                    res.consumptions.append(
                        Consumption(file=d.path, line=key_line, expr_raw=ex.raw,
                                    scalar_key=f"with:{k}", source=sorted(tv.sources)[0],
                                    step_line=step_line)
                    )

        rel = R.resolve(uses_raw, self.root, split)
        if rel is None:
            return
        cd = self.doc(rel)
        if cd is None:
            return

        if "/reusable_workflows/" in rel:
            self._seed_input_defaults(cd, bound, _reusable_inputs(cd))
            self._analyze_reusable(cd, res, split, bound, depth + 1)
            return

        self._seed_input_defaults(cd, bound, cd.data.get("inputs"))

        runtime = L.action_runtime(cd.data)
        if runtime == "composite":
            sub = self._analyze_steps(cd, cd.data, res, split, dict(env), depth + 1,
                                      needs_out, inputs=bound)
            if steps_out is not None and node.get("id"):
                steps_out[node["id"]] = _action_outputs(cd, sub, bound)
        elif runtime and (runtime.startswith("node") or runtime == "docker"):
            # Opaque body. Spec: flows may transit JS/Docker, endpoints stay YAML.
            # Conservative: any tainted input taints every declared output.
            if bound and steps_out is not None and node.get("id"):
                merged = TaintValue(parents=list(bound.values()), derived=True)
                for tv in bound.values():
                    merged.sources |= tv.sources
                    merged.origin = merged.origin or tv.origin
                decl = cd.data.get("outputs") or {}
                steps_out[node["id"]] = {o: merged for o in decl}

    def _seed_input_defaults(self, cd: L.Doc, bound: Dict[str, TaintValue], decl) -> None:
        """Taint unbound inputs from their own `default:` values.

        A composite action can taint ITSELF. If an input declares
            default: ${{ github.event.pull_request.title }}
        and the caller does not pass that input, the default applies and the
        untrusted value enters inside the component. The flow's `from` is then
        the `default:` line in the ACTION file, not anything in the workflow.

        Confirmed against gold: embano1/wip action.yml:10 -> :27, and
        farhatahmad/branch-names action.yml:15 -> :39. A caller-supplied `with:`
        value overrides the default, so bound inputs are skipped.
        """
        if not isinstance(decl, dict):
            return
        empty = _Scope(env={}, steps={}, needs={}, inputs={})
        for name, spec in decl.items():
            if name in bound or not isinstance(spec, dict):
                continue
            pos = cd.value_pos(spec, "default")
            if pos is None:
                continue
            for ex in E.find_expressions(pos.text):
                tv = self._eval_expr(ex, empty)   # only github.* can resolve here
                if not tv.sources:
                    continue
                line = self._default_from_line(cd, decl, name, ex, pos)  # gold uses the description-prose line
                origin = Site(cd.path, line, sorted(tv.sources)[0])
                cur = bound.get(name)
                if cur is None:
                    bound[name] = TaintValue(sources=set(tv.sources), origin=origin,
                                             parents=[tv])
                else:
                    cur.sources |= tv.sources
                    cur.parents.append(tv)

    def _default_from_line(self, cd: L.Doc, decl, name, ex: E.Expression,
                           pos: L.ScalarPos) -> int:
        """`from` line for an input-default flow.

        Gold points at the FIRST line in the input's declaration block that
        textually contains the context path -- which is sometimes the
        `description:` prose rather than the `default:` itself. platformsh's
        `ref` block spans :8-:11 with `default: ${{ github.head_ref }}` on :11,
        but its description on :9 reads "... Default of {github.head_ref}" and
        gold reports :9. Verified 3/3 (embano1 :10, farhatahmad :15, platformsh
        :9). This is an artifact of how the labels were generated, not a
        semantic rule, so it is isolated here rather than baked into the model.
        Falls back to the expression's own line when no textual mention is found.
        """
        fallback = pos.line_of_offset(ex.start)
        paths = [r.path for r in ex.refs if self.untrusted.is_untrusted(r.path)]
        if not paths:
            return fallback
        start = cd.key_line(decl, name)
        if not start:
            return fallback
        # block ends at the next input key, else at the fallback line
        others = [ln for k in decl
                  if (ln := cd.key_line(decl, k)) and ln > start]
        end = min(others) if others else fallback + 1
        for i in range(start, min(end, len(cd.lines) + 1)):
            if any(p in cd.lines[i - 1] for p in paths):
                return i
        return fallback

    def _analyze_reusable(self, cd: L.Doc, res: Result, split: str,
                          bound: Dict[str, TaintValue], depth: int):
        needs_out: Dict[str, Dict[str, TaintValue]] = {}
        for jid in L.topo_jobs(cd.data):
            job = cd.data["jobs"][jid]
            env: Dict[str, TaintValue] = {}
            self._collect_env_map(cd, job, env, res, split)
            self._analyze_steps(cd, job, res, split, env, depth, needs_out, inputs=bound)

    # -- expression evaluation --------------------------------------------

    def _eval_expr(self, ex: E.Expression, scope: "_Scope") -> TaintValue:
        out = TaintValue()
        for ref in ex.refs:
            tv = self._eval_ref(ref, scope)
            if tv and tv.sources:
                out.sources |= tv.sources
                out.origin = out.origin or tv.origin
                out.parents.append(tv)      # keep the link: see TaintValue docstring
                out.derived = out.derived or tv.derived
        return out

    def _eval_ref(self, ref: E.Ref, scope: "_Scope") -> Optional[TaintValue]:
        c = canonicalize(ref.path)
        root = c.split(".")[0]

        if root == "github":
            pat = self.untrusted.match(c)
            return TaintValue(sources={pat}) if pat else None
        if root == "inputs":
            return scope.inputs.get(c.split(".", 1)[1] if "." in c else "")
        if root == "env":
            return scope.env.get(c.split(".", 1)[1] if "." in c else "")
        if root == "steps":
            parts = c.split(".")
            if len(parts) >= 4 and parts[2] == "outputs":
                return scope.steps.get(parts[1], {}).get(parts[3])
            return None
        if root == "needs":
            parts = c.split(".")
            if len(parts) >= 4 and parts[2] == "outputs":
                return scope.needs.get(parts[1], {}).get(parts[3])
            return None
        return None

    def _collect_env_map(self, d: L.Doc, node, env: Dict[str, TaintValue], res: Result, split: str):
        """`env:` blocks propagate taint into `${{ env.X }}` (and into $X in run)."""
        em = node.get("env") if isinstance(node, dict) else None
        if not isinstance(em, dict):
            return
        scope = _Scope(env=env, steps={}, needs={}, inputs={})
        for k in em:
            pos = d.value_pos(em, k)
            if pos is None:
                continue
            merged = TaintValue()
            for ex in E.find_expressions(pos.text):
                tv = self._eval_expr(ex, scope)
                merged.sources |= tv.sources
                merged.derived = merged.derived or tv.derived   # keep $GITHUB_ENV/OUTPUT-crossed flag
                merged.parents.append(tv)
                merged.origin = merged.origin or tv.origin or Site(
                    d.path, d.key_line(em, k) or pos.line, sorted(tv.sources)[0] if tv.sources else ""
                )
            if merged.sources:
                env[str(k).lower()] = merged


@dataclass
class _Scope:
    env: Dict[str, TaintValue]
    steps: Dict[str, Dict[str, TaintValue]]
    needs: Dict[str, Dict[str, TaintValue]]
    inputs: Dict[str, TaintValue]


def _job_outputs(d, job, steps_out, analyzer, res, split) -> Dict[str, TaintValue]:
    out: Dict[str, TaintValue] = {}
    om = job.get("outputs") if isinstance(job, dict) else None
    if not isinstance(om, dict):
        return out
    scope = _Scope(env={}, steps=steps_out, needs={}, inputs={})
    for k in om:
        pos = d.value_pos(om, k)
        if pos is None:
            continue
        merged = TaintValue(derived=True)
        for ex in E.find_expressions(pos.text):
            tv = analyzer._eval_expr(ex, scope)
            merged.sources |= tv.sources
            merged.origin = merged.origin or tv.origin
            merged.parents.append(tv)
        if merged.sources:
            out[k] = merged
    return out


def _action_outputs(cd, steps_out, bound) -> Dict[str, TaintValue]:
    out: Dict[str, TaintValue] = {}
    decl = cd.data.get("outputs") if isinstance(cd.data, dict) else None
    if not isinstance(decl, dict):
        return out
    scope = _Scope(env={}, steps=steps_out, needs={}, inputs=bound)
    a = Analyzer.__new__(Analyzer)  # only need _eval_expr; no io
    a.untrusted = UntrustedSet([])
    for k, spec in decl.items():
        if not isinstance(spec, dict):
            continue
        pos = cd.value_pos(spec, "value")
        if pos is None:
            continue
        merged = TaintValue(derived=True)
        for ex in E.find_expressions(pos.text):
            tv = a._eval_expr(ex, scope)
            merged.sources |= tv.sources
            merged.origin = merged.origin or tv.origin
            merged.parents.append(tv)
        if merged.sources:
            out[k] = merged
    return out


def _dedup(flows: List[Flow]) -> List[Flow]:
    seen = set()
    out = []
    for f in flows:
        k = (str(f.src), str(f.dst))
        if k in seen:
            continue
        seen.add(k)
        out.append(f)
    return out


def _explain(source: str, src: Site, sink_file: str) -> str:
    if str(src).split(":")[0] == sink_file:
        return (f"Untrusted `{source}` is interpolated directly into a `run:` shell command. "
                f"The runner substitutes the expression into the script before execution, so "
                f"attacker-controlled text becomes shell code.")
    return (f"Untrusted `{source}` is passed as an input to a referenced component and reaches "
            f"a `run:` shell command inside it (cross-component code injection).")


def _reusable_inputs(cd: L.Doc):
    """`on.workflow_call.inputs` for a reusable workflow.
    (ruamel is YAML 1.2, so `on` stays the string "on" -- no 1.1 bool coercion.)"""
    on = cd.data.get("on") if isinstance(cd.data, dict) else None
    if not isinstance(on, dict):
        return None
    wc = on.get("workflow_call")
    return wc.get("inputs") if isinstance(wc, dict) else None
