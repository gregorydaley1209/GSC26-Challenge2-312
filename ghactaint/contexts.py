"""
Untrusted-source matching.

untrusted_data.csv gives 28 context paths. Two wrinkles the raw list hides:

  1. `github.event.commits[*].message` uses a wildcard index. Real workflows
     write `github.event.commits[0].message`. The train labels confirm this:
     the only commits-flow in the gold set is `commits[0].message`.
  2. GitHub context property lookup is CASE-INSENSITIVE and supports bracket
     notation, so all of these are the same source:
         github.head_ref
         github.HEAD_REF
         github['head_ref']
         github["head_ref"]

Both are normalized here so the taint engine only ever sees canonical paths.
"""
from __future__ import annotations

import csv
import re
from typing import Iterable, List, Optional

# github['event']['issue'] / github["event"] / github[0]
_BRACKET = re.compile(r"""\[\s*(?:'([^']*)'|"([^"]*)"|(\d+))\s*\]""")


def canonicalize(path: str) -> str:
    """github['event'].Issue["title"] -> github.event.issue.title  (indices kept)."""

    def sub(m: re.Match) -> str:
        if m.group(3) is not None:
            return f"[{m.group(3)}]"  # numeric index: preserve
        return "." + (m.group(1) if m.group(1) is not None else m.group(2))

    out = _BRACKET.sub(sub, path.strip())
    out = re.sub(r"\s*\.\s*", ".", out)
    return out.lower()


def _to_regex(pattern: str) -> re.Pattern:
    """`github.event.commits[*].message` -> matches `github.event.commits[0].message`."""
    parts = re.split(r"(\[\*\])", canonicalize(pattern))
    buf = []
    for p in parts:
        if p == "[*]":
            buf.append(r"\[\d+\]")
        else:
            buf.append(re.escape(p))
    return re.compile("^" + "".join(buf) + "$")


class UntrustedSet:
    """The predefined untrusted inputs. Closed world — do not invent new sources."""

    def __init__(self, patterns: Iterable[str], prefix_match: bool = False):
        self.raw: List[str] = [p.strip() for p in patterns if p and p.strip()]
        self._res = [_to_regex(p) for p in self.raw]
        # prefix_match: treat `github.event.issue` as tainted because
        # `github.event.issue.title` is. UNVERIFIED against the repo — the gold
        # labels only ever name leaf paths, so default off. Flip on and re-run
        # eval.py to see if recall moves.
        self.prefix_match = prefix_match
        self._prefixes = [canonicalize(p).split("[*]")[0].rstrip(".") for p in self.raw]

    @classmethod
    def from_csv(cls, path: str, **kw) -> "UntrustedSet":
        with open(path, newline="", encoding="utf-8-sig") as fh:
            rows = list(csv.DictReader(fh))
        col = "untrusted_input"
        return cls([r[col] for r in rows], **kw)

    def match(self, ref: str) -> Optional[str]:
        """Return the canonical untrusted pattern this ref belongs to, else None."""
        c = canonicalize(ref)
        for pat, rx in zip(self.raw, self._res):
            if rx.match(c):
                return pat
        if self.prefix_match:
            for pat, pre in zip(self.raw, self._prefixes):
                if pre and (c == pre or c.startswith(pre + ".")):
                    return pat
        return None

    def is_untrusted(self, ref: str) -> bool:
        return self.match(ref) is not None

    def __len__(self) -> int:
        return len(self.raw)
