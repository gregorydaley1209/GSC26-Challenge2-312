"""Unit tests for the repo-independent modules. Run: python -m pytest tests/ -q"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ghactaint.contexts import UntrustedSet, canonicalize
from ghactaint.expr import find_expressions, find_refs
from ghactaint.resolver import parse_uses, candidate_paths, Kind
from ghactaint.patch import var_name, _replace_expr

U = UntrustedSet.from_csv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "untrusted_data.csv"))


# ---- contexts ----------------------------------------------------------

def test_untrusted_loaded():
    assert len(U) == 27

def test_plain_match():
    assert U.is_untrusted("github.head_ref")
    assert U.is_untrusted("github.event.pull_request.title")

def test_trusted_not_matched():
    assert not U.is_untrusted("github.ref")
    assert not U.is_untrusted("github.sha")
    assert not U.is_untrusted("github.repository")
    assert not U.is_untrusted("github.event.pull_request.number")

def test_wildcard_index():
    # gold set contains commits[0].message; csv declares commits[*].message
    assert U.is_untrusted("github.event.commits[0].message")
    assert U.is_untrusted("github.event.commits[12].message")
    assert U.match("github.event.commits[0].message") == "github.event.commits[*].message"
    assert not U.is_untrusted("github.event.commits[0].id")

def test_case_insensitive():
    assert U.is_untrusted("github.HEAD_REF")
    assert U.is_untrusted("GitHub.Head_Ref")

def test_bracket_notation():
    assert U.is_untrusted("github['head_ref']")
    assert U.is_untrusted('github["event"]["issue"]["title"]')
    assert U.is_untrusted("github.event['pull_request'].title")

def test_canonicalize():
    assert canonicalize("github['event'].Issue[\"title\"]") == "github.event.issue.title"
    assert canonicalize("github.event.commits[0].message") == "github.event.commits[0].message"

def test_prefix_match_off_by_default():
    assert not U.is_untrusted("github.event.issue")
    P = UntrustedSet.from_csv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "untrusted_data.csv"), prefix_match=True)
    assert P.is_untrusted("github.event.issue.title.something")


# ---- expressions -------------------------------------------------------

def test_simple_expr():
    e = find_expressions('echo "${{ github.head_ref }}"')
    assert len(e) == 1
    assert [r.path for r in e[0].refs] == ["github.head_ref"]

def test_multiple_exprs_offsets():
    s = 'a ${{ github.head_ref }} b ${{ inputs.x }}'
    e = find_expressions(s)
    assert len(e) == 2
    assert e[0].start < e[1].start
    assert s[e[0].start:e[0].end] == "${{ github.head_ref }}"

def test_format_fn():
    e = find_expressions("${{ format('{0}-{1}', github.head_ref, inputs.x) }}")
    paths = {r.path for r in e[0].refs}
    assert "github.head_ref" in paths and "inputs.x" in paths
    assert "format" not in paths

def test_fallback_operator():
    e = find_expressions("${{ github.head_ref || github.ref_name }}")
    assert {r.path for r in e[0].refs} == {"github.head_ref", "github.ref_name"}

def test_string_literal_not_a_ref():
    # 'github.head_ref' inside quotes is data, not a context reference
    e = find_expressions("${{ contains('github.head_ref', 'x') }}")
    assert e[0].refs == []

def test_contains_call_ref_survives():
    e = find_expressions("${{ contains(github.event.pull_request.title, 'wip') }}")
    assert [r.path for r in e[0].refs] == ["github.event.pull_request.title"]

def test_multiline_block():
    s = "line1\n${{ github.head_ref }}\nline3"
    e = find_expressions(s)
    assert s.count("\n", 0, e[0].start) == 1  # offset->line math

def test_steps_and_needs_refs():
    assert [r.path for r in find_refs("steps.a.outputs.b")] == ["steps.a.outputs.b"]
    assert [r.path for r in find_refs("needs.j.outputs.k")] == ["needs.j.outputs.k"]

def test_bare_root_not_a_ref():
    assert find_refs("github") == []


# ---- resolver ----------------------------------------------------------

def test_action_plain():
    r = parse_uses("tj-actions/branch-names@9cd06d955f4184031cd71fbb1717ac268ade2ee0")
    assert r.kind == Kind.ACTION and r.short_sha == "9cd06d955f41"
    assert candidate_paths(r)[0] == "train/actions/tj-actions/branch-names/9cd06d955f41/action.yml"

def test_action_subpath():
    r = parse_uses("github/codeql-action/init@0b2a40fa4a5111111111111111111111111111111")
    assert candidate_paths(r)[0] == "train/actions/github/codeql-action/0b2a40fa4a51/init/action.yml"

def test_action_nested_subpath():
    r = parse_uses("Homebrew/actions/git-user-config@9ce0504c5e4b1111111111111111111111111111")
    assert candidate_paths(r)[0] == "train/actions/Homebrew/actions/9ce0504c5e4b/git-user-config/action.yml"

def test_reusable_workflow():
    r = parse_uses("hirosystems/stacks.js/.github/workflows/tests.yml@c3bca5c2994267b59cc14f4057177222e74ac6f6")
    assert r.kind == Kind.REUSABLE
    assert candidate_paths(r)[0] == "train/reusable_workflows/hirosystems/stacks.js/c3bca5c29942/.github/workflows/tests.yml"

def test_docker_and_local():
    assert parse_uses("docker://alpine:3").kind == Kind.DOCKER
    assert parse_uses("./.github/actions/foo").kind == Kind.LOCAL

def test_split_prefix():
    r = parse_uses("tj-actions/branch-names@9cd06d955f4184031cd71fbb1717ac268ade2ee0")
    assert candidate_paths(r, split="test")[0].startswith("test/actions/")


# ---- patch helpers -----------------------------------------------------

def test_var_name():
    t = set()
    assert var_name("github.head_ref", t) == "HEAD_REF"
    assert var_name("github.event.pull_request.title", t) == "PULL_REQUEST_TITLE"
    assert var_name("github.event.commits[0].message", t) == "COMMITS_MESSAGE"

def test_var_name_collision():
    t = set()
    a = var_name("github.head_ref", t)
    b = var_name("github.head_ref", t)
    assert a == "HEAD_REF" and b == "HEAD_REF_2"

# (superseded by the quote-context tests below)


# ---- quote-context replacement -----------------------------------------

from ghactaint.patch import quote_state

def test_quote_state():
    assert quote_state('echo "a', 7) == "d"
    assert quote_state("echo 'a", 7) == "s"
    assert quote_state('echo a', 6) is None
    assert quote_state('echo "a" b', 10) is None
    assert quote_state('echo "it\'s" ', 12) is None   # ' inside "" is literal

def test_replace_inside_double_quotes():
    # var must NOT gain its own quotes inside an existing quoted string
    out = _replace_expr('echo "got ${{ inputs.title }}"', "${{ inputs.title }}", "TITLE")
    assert out == 'echo "got ${TITLE}"'

def test_replace_bare_gets_quoted():
    out = _replace_expr("echo ${{ github.head_ref }}", "${{ github.head_ref }}", "HEAD_REF")
    assert out == 'echo "${HEAD_REF}"'

def test_replace_whole_quoted_string():
    out = _replace_expr('echo "${{ github.head_ref }}"', "${{ github.head_ref }}", "HEAD_REF")
    assert out == 'echo "${HEAD_REF}"'

def test_replace_inside_single_quotes_breaks_out():
    out = _replace_expr("echo 'got ${{ inputs.title }}'", "${{ inputs.title }}", "TITLE")
    assert out == """echo 'got '"${TITLE}"''"""

def test_replace_multiple_occurrences():
    out = _replace_expr('a ${{ x }} b ${{ x }}', "${{ x }}", "V")
    assert out == 'a "${V}" b "${V}"'

def test_pwsh_shell():
    out = _replace_expr('Write-Host "${{ github.head_ref }}"', "${{ github.head_ref }}", "HEAD_REF", shell="pwsh")
    assert "$env:HEAD_REF" in out


# ---- heredoc safety ----------------------------------------------------

from ghactaint.expr import literal_heredoc_spans, in_spans

def test_quoted_heredoc_is_literal():
    s = "X=$(cat <<'EOF'\n${{ github.head_ref }}\nEOF\n)"
    sp = literal_heredoc_spans(s)
    e = find_expressions(s)[0]
    assert in_spans(e.start, sp)

def test_unquoted_heredoc_still_expands():
    s = "cat <<EOF\n${{ github.head_ref }}\nEOF"
    assert not in_spans(find_expressions(s)[0].start, literal_heredoc_spans(s))

def test_backslash_heredoc_is_literal():
    s = "cat <<\\EOF\n${{ github.head_ref }}\nEOF"
    assert in_spans(find_expressions(s)[0].start, literal_heredoc_spans(s))

def test_dash_heredoc_quoted():
    s = "cat <<-'EOF'\n${{ github.head_ref }}\n\tEOF"
    assert in_spans(find_expressions(s)[0].start, literal_heredoc_spans(s))

def test_expr_after_heredoc_closes_is_a_sink():
    s = "cat <<'EOF'\nplain\nEOF\necho ${{ github.head_ref }}"
    assert not in_spans(find_expressions(s)[0].start, literal_heredoc_spans(s))
