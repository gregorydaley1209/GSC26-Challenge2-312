"""
Resolve `uses:` references to vendored paths.

Fully specified by the competition Data page — this needs no repo to be correct.

  Actions:
    uses: <owner>/<repo>@<sha>
      -> actions/<owner>/<repo>/<sha[:12]>/action.{yml,yaml}
    uses: <owner>/<repo>/<sub/path>@<sha>
      -> actions/<owner>/<repo>/<sha[:12]>/<sub/path>/action.{yml,yaml}

  Reusable workflows:
    uses: <owner>/<repo>/.github/workflows/<f>.yml@<sha>
      -> reusable_workflows/<owner>/<repo>/<sha[:12]>/.github/workflows/<f>.yml

  Local:
    uses: ./.github/actions/foo   -> repo-relative, no SHA dir
    uses: docker://image:tag      -> opaque, not analyzable as YAML
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import List, Optional

SHA_LEN = 12


class Kind:
    ACTION = "action"
    REUSABLE = "reusable_workflow"
    LOCAL = "local"
    DOCKER = "docker"


@dataclass(frozen=True)
class UsesRef:
    raw: str
    kind: str
    owner: Optional[str] = None
    repo: Optional[str] = None
    subpath: Optional[str] = None
    sha: Optional[str] = None

    @property
    def short_sha(self) -> Optional[str]:
        return self.sha[:SHA_LEN] if self.sha else None


_REUSABLE = re.compile(r"^(?P<owner>[^/]+)/(?P<repo>[^/]+)/(?P<path>\.github/workflows/[^@]+)@(?P<sha>.+)$")
_ACTION = re.compile(r"^(?P<owner>[^/]+)/(?P<repo>[^/@]+)(?:/(?P<sub>[^@]+))?@(?P<sha>.+)$")


def parse_uses(raw: str) -> UsesRef:
    s = raw.strip()
    if s.startswith("docker://"):
        return UsesRef(raw=s, kind=Kind.DOCKER)
    if s.startswith("./") or s.startswith("../"):
        return UsesRef(raw=s, kind=Kind.LOCAL, subpath=s.lstrip("./"))
    m = _REUSABLE.match(s)
    if m:
        return UsesRef(raw=s, kind=Kind.REUSABLE, owner=m["owner"], repo=m["repo"],
                       subpath=m["path"], sha=m["sha"])
    m = _ACTION.match(s)
    if m:
        return UsesRef(raw=s, kind=Kind.ACTION, owner=m["owner"], repo=m["repo"],
                       subpath=m["sub"], sha=m["sha"])
    return UsesRef(raw=s, kind=Kind.LOCAL, subpath=s)


def candidate_paths(ref: UsesRef, split: str = "train") -> List[str]:
    """Candidate vendored paths, most likely first. Caller checks existence."""
    if ref.kind == Kind.DOCKER:
        return []
    if ref.kind == Kind.REUSABLE:
        return [f"{split}/reusable_workflows/{ref.owner}/{ref.repo}/{ref.short_sha}/{ref.subpath}"]
    if ref.kind == Kind.ACTION:
        base = f"{split}/actions/{ref.owner}/{ref.repo}/{ref.short_sha}"
        if ref.subpath:
            base = f"{base}/{ref.subpath}"
        return [f"{base}/action.yml", f"{base}/action.yaml"]
    if ref.kind == Kind.LOCAL:
        # Local composite actions live next to the workflow; layout unconfirmed
        # until the repo lands. Try the obvious shapes.
        p = (ref.subpath or "").rstrip("/")
        return [f"{split}/{p}/action.yml", f"{split}/{p}/action.yaml", f"{split}/{p}"]
    return []


def resolve(raw: str, root: str, split: str = "train") -> Optional[str]:
    """Return the first existing vendored path under `root`, or None."""
    ref = parse_uses(raw)
    for rel in candidate_paths(ref, split):
        if os.path.isfile(os.path.join(root, rel)):
            return rel
    return None
