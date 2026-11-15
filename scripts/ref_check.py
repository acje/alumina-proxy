#!/usr/bin/env python3
"""Live symbol-reference detector for the documentation corpus.

WHAT IT PROVES
  Every `path::Symbol` reference in the DOCSLINK_ROOTS corpus resolves to a
  live, index-verified symbol in THIS checkout, and no document that has already
  been migrated off line numbers regains one.

WHY IT IS LIVE
  A line-number citation gate answers "does line 42 of this file exist", which
  silently false-passes when the file was renumbered but still has 42 lines, and
  cannot answer "is this the construct the document means". A symbol reference
  is checked against the code index and re-checked on every run, so the corpus
  cannot drift away from the code while the gate stays green.

ROOTS (single source)
  The scanned corpus is the DOCSLINK_ROOTS value inside scripts/verify.sh, read
  at run time. The list is never duplicated here, so the gate and the docs
  harness cannot drift; an unparseable or absent ROOTS assignment is BLOCKED
  (exit 2), never clean.

EXIT CONTRACT (exactly three outcomes, no folding)
  0  clean. Last line is `REF-CHECK-OK <n>` where n is the number of live
     symbol references that resolved to a verified symbol.
  1  one or more findings (unresolved symbol, unknown path, unverified answer,
     out-of-range bounds, ratchet violation). One `REF-CHECK-FINDING <text>`
     line per finding, deterministically sorted.
  2  operational / BLOCKED: repowise absent from PATH, the index is stale
     (recorded commit != HEAD), DOCSLINK_ROOTS unparseable, a resolver call
     failed or timed out, or the repository state could not be read. An
     operational error is never reported as clean and never as a finding: the
     gate did not run, so nothing was proven.

STALENESS
  The index records the commit it was built from in `.repowise/state.json` under
  the top-level key `last_sync_commit` (the same value the `repowise status`
  table prints as "Last sync commit"). That key is compared against
  `git rev-parse HEAD` before any resolution. A mismatch means the symbol index
  describes a different tree than the working checkout, so a "resolved" answer
  would be an answer about the wrong bytes -- BLOCKED, naming both commits.
  Confidence in the key, reproduced verbatim:
      $ python3 -c "import json;print(json.load(open('.repowise/state.json'))['last_sync_commit'])"
      1812405b5c9130a170d1e00988b2a77d80d86e3d
      $ git rev-parse HEAD
      1812405b5c9130a170d1e00988b2a77d80d86e3d
  and the `repowise status` table reports the identical "Last sync commit".

RESOLVER EXIT CODES (measured, not assumed)
  `repowise symbol <id> --format json` exits 0 for a symbol it found and 1 for a
  symbol it did not find, writing the "not found" explanation as the `{"error":
  ...}` payload on stdout. The exit status alone therefore cannot separate "no
  such symbol" from "resolver broken", and it is never treated as a validity
  signal: the payload decides. Exit 1 carrying a parseable `error` payload is
  the domain answer and a finding (exit 1); exit 2 or higher, an unparseable
  payload, or exit 1 without an `error` payload is BLOCKED (exit 2) because the
  resolver produced no answer at all. Reproduced:
      $ repowise symbol 'src/boot/mod.rs::BootReport' --format json >/dev/null; echo $?
      0
      $ repowise symbol 'src/boot/mod.rs::NoSuchSymbol' --format json >/dev/null; echo $?
      1

RATCHET (structural, no baseline file)
  A document is *locked* when its COMMITTED content (at HEAD) holds zero live
  line references -- the `path:NNN` and `path:NNN-MMM` token class. For a locked
  document every live line reference in the working tree is a finding. The
  floor is the repository's own history, not a curated artifact: no stored list,
  no baseline file, no counter. Lock state read off the working tree instead
  would be self-defeating (planting a token is what would unlock the document),
  so the committed bytes are the only reading under which the ratchet can fire
  at all, and a document locks itself the moment a migration commit lands and
  cannot regress afterwards. A document absent from HEAD counts as locked: it
  holds zero committed references, and a new document must not start on line
  numbers.

EXEMPTIONS ARE STRUCTURAL ONLY
  Two things are exempt, both because of where the text sits, never because of
  what it says: (a) fenced code blocks (``` / ~~~ fences, honouring the info
  string and requiring a closing fence at least as long as the opener), and
  (b) the `git:<commit>:path` receipt form, whose path is immediately preceded
  by `git:<commit>:`. There is deliberately no `# ref-check-disable` marker, no
  allow-list file and no `--ignore` option: a text-based exemption is a baseline
  by another name, and the whole point of this gate is that a finding cannot be
  argued away by annotating the text that caused it.

STYLE
  Stdlib only, no network, no third-party import. Document bytes are read as
  data and never interpolated into a shell: every subprocess call is an argv
  list. Output order is a pure function of the corpus.
"""

import json
import os
import re
import shutil
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VERIFY_SH = os.path.join(REPO_ROOT, "scripts", "verify.sh")
INDEX_STATE = os.path.join(REPO_ROOT, ".repowise", "state.json")
RESOLVER_TIMEOUT_SECONDS = 120

# Two token classes, one path prefix: a live symbol reference (what the gate
# verifies) and a live line reference (what the ratchet forbids from returning).
# The lookbehind keeps a match from starting inside a longer path, and the
# optional `./` form is admitted so a document cannot dodge extraction by
# spelling the same reference slightly differently.
_SOURCE_EXT = r"\.(?:rs|py|sh|mjs|toml|yaml|yml|json|md)"
_PATH_CORE = r"(?:\./)?" + r"[A-Za-z0-9_][A-Za-z0-9_./-]*" + _SOURCE_EXT
SYMBOL_RE = re.compile(
    r"(?<![A-Za-z0-9_./-])(" + _PATH_CORE + r"(?:::[A-Za-z_][A-Za-z0-9_]*)+)"
)
LINE_RE = re.compile(r"(?<![A-Za-z0-9_./-])(" + _PATH_CORE + r":\d+(?:-\d+)?)")
RECEIPT_RE = re.compile(r"git:[0-9a-f]{7,40}:$")
FENCE_RE = re.compile(r"^[ \t]*(`{3,}|~{3,})(.*)$")
ROOTS_RE = re.compile(r'^DOCSLINK_ROOTS="([^"]*)"[ \t]*$', re.MULTILINE)


class Blocked(Exception):
    """Operational failure: the gate could not run, so nothing was proven."""


def _read_text(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read()
    except OSError as exc:
        raise Blocked("cannot read %s: %s" % (path, exc))


def corpus_roots():
    """Return the docslink roots, parsed from scripts/verify.sh (single owner)."""
    text = _read_text(VERIFY_SH)
    matches = ROOTS_RE.findall(text)
    if not matches:
        raise Blocked("DOCSLINK_ROOTS not found in scripts/verify.sh")
    if len(matches) > 1:
        raise Blocked("DOCSLINK_ROOTS defined %d times in scripts/verify.sh" % len(matches))
    roots = matches[0].split()
    if not roots:
        raise Blocked("DOCSLINK_ROOTS is empty in scripts/verify.sh")
    return roots


def _live_lines(raw):
    """Yield (line_number, text) for every line outside a fenced code block.

    Both backticked spans and plain prose are scanned: extraction runs over the
    whole live line rather than over a parsed inline-code tree, so a reference
    written without backticks is caught by the same grammar (and a reference
    cannot hide by dropping its backticks).
    """
    fence = None
    for number, line in enumerate(raw.splitlines(), 1):
        match = FENCE_RE.match(line)
        if fence is not None:
            char, length = fence
            closed = (
                match is not None
                and match.group(1)[0] == char
                and len(match.group(1)) >= length
                and match.group(2).strip() == ""
            )
            if closed:
                fence = None
            continue
        if match is not None:
            fence = (match.group(1)[0], len(match.group(1)))
            continue
        yield number, line


def _is_live(text, start):
    # Structural exemption only: a path that a `git:<commit>:` receipt prefixes
    # is a historical receipt about another tree, not a claim about this one.
    return RECEIPT_RE.search(text[:start]) is None


def scan_text(raw):
    """Return ([(line, token)], [(line, token)]) for live symbol and line refs."""
    symbols = []
    lines = []
    for number, text in _live_lines(raw):
        for match in SYMBOL_RE.finditer(text):
            if _is_live(text, match.start()):
                symbols.append((number, match.group(1)))
        for match in LINE_RE.finditer(text):
            if _is_live(text, match.start()):
                lines.append((number, match.group(1)))
    return symbols, lines


def extract(roots):
    """Scan the working tree of every corpus document."""
    symbols = {}
    lines = {}
    for doc in roots:
        symbols[doc], lines[doc] = scan_text(_read_text(os.path.join(REPO_ROOT, doc)))
    return symbols, lines


def _plain(token):
    return token[2:] if token.startswith("./") else token


def recorded_commit():
    """The commit the symbol index was built from (see STALENESS above)."""
    text = _read_text(INDEX_STATE)
    try:
        state = json.loads(text)
    except ValueError as exc:
        raise Blocked("unparseable %s: %s" % (INDEX_STATE, exc))
    commit = state.get("last_sync_commit") if isinstance(state, dict) else None
    if not isinstance(commit, str) or not commit:
        raise Blocked("%s carries no last_sync_commit" % INDEX_STATE)
    return commit


def git_binary():
    git = shutil.which("git")
    if git is None:
        raise Blocked("git not on PATH (cannot bind docs to a commit)")
    return git


def head_commit(git):
    try:
        proc = subprocess.run(
            [git, "rev-parse", "HEAD"],
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=RESOLVER_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise Blocked("git rev-parse HEAD failed: %s" % exc)
    if proc.returncode != 0:
        raise Blocked(
            "git rev-parse HEAD exit %d: %s"
            % (proc.returncode, proc.stderr.decode("utf-8", "replace").strip())
        )
    head = proc.stdout.decode("utf-8", "replace").strip()
    if not head:
        raise Blocked("git rev-parse HEAD returned nothing")
    return head


def _first_json_object(text):
    # repowise may prefix a human diagnostic on stdout; the answer is the first
    # complete JSON object. Anything else is an answer shape we cannot read.
    for index, char in enumerate(text):
        if char != "{":
            continue
        try:
            return json.loads(text[index:])
        except ValueError:
            continue
    return None


def resolve(repowise, symbol_id):
    """Return the resolver payload for symbol_id, or raise Blocked."""
    try:
        proc = subprocess.run(
            [repowise, "symbol", symbol_id, "--format", "json"],
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=RESOLVER_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        raise Blocked(
            "resolver timed out after %ds for %s" % (RESOLVER_TIMEOUT_SECONDS, symbol_id)
        )
    except OSError as exc:
        raise Blocked("cannot execute repowise: %s" % exc)
    # The resolver answers "no such symbol" with exit 1 plus an `error` payload,
    # so exit status alone is not a validity signal. Where it IS decisive: a
    # non-zero status with no readable answer means the resolver failed, and
    # that is operational, never a finding.
    if proc.returncode >= 2:
        raise Blocked(
            "resolver exit %d for %s: %s"
            % (
                proc.returncode,
                symbol_id,
                proc.stderr.decode("utf-8", "replace").strip()[:200],
            )
        )
    payload = _first_json_object(proc.stdout.decode("utf-8", "replace"))
    if not isinstance(payload, dict):
        raise Blocked(
            "unparseable resolver output for %s (exit %d)" % (symbol_id, proc.returncode)
        )
    if proc.returncode != 0 and "error" not in payload:
        # A failure status without a domain explanation is not an answer.
        raise Blocked(
            "resolver exit %d for %s without an error payload" % (proc.returncode, symbol_id)
        )
    return payload


def _bounds(payload):
    """Containment bounds for the verified construct, or None when unreported.

    The resolver reports `symbol_start_line`/`symbol_end_line` for outlined
    constructs and the narrower `start_line`/`end_line` for a leaf; some
    verified answers carry neither. Bounds are therefore a claim to check when
    they exist, not a precondition of verification.
    """
    for start_key, end_key in (
        ("symbol_start_line", "symbol_end_line"),
        ("start_line", "end_line"),
    ):
        start = payload.get(start_key)
        end = payload.get(end_key)
        if isinstance(start, int) and not isinstance(start, bool):
            if isinstance(end, int) and not isinstance(end, bool):
                return (start, end)
    return None


def verdict(payload, path_part):
    """Return None when the payload verifies the reference, else the finding."""
    if "error" in payload:
        detail = str(payload.get("error")).split(". ")[0].strip()
        return "unresolved symbol: %s" % detail
    if payload.get("verified") is not True:
        return "resolver did not verify the symbol (verified=%r)" % payload.get("verified")
    if payload.get("file") != path_part:
        return "resolver reported file=%r, reference names %r" % (
            payload.get("file"),
            path_part,
        )
    bounds = _bounds(payload)
    if bounds is not None:
        start, end = bounds
        if start < 1 or end < start:
            return "out-of-range bounds: symbol spans %d-%d" % (start, end)
    return None


def _git(git, argv):
    try:
        proc = subprocess.run(
            [git] + argv,
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=RESOLVER_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise Blocked("git %s failed: %s" % (" ".join(argv), exc))
    return proc


def committed_text(git, head, doc):
    """The document as committed at HEAD, or "" when HEAD carries no such path.

    Absent-at-HEAD is deliberately not an error: it means zero committed line
    references, so a brand-new document is locked from birth rather than
    admitted with line numbers nobody has migrated yet.
    """
    present = _git(git, ["cat-file", "-e", "%s:%s" % (head, doc)])
    if present.returncode != 0:
        return ""
    shown = _git(git, ["show", "%s:%s" % (head, doc)])
    if shown.returncode != 0:
        raise Blocked(
            "git show %s:%s exit %d: %s"
            % (head, doc, shown.returncode, shown.stderr.decode("utf-8", "replace").strip())
        )
    return shown.stdout.decode("utf-8", "replace")


def locked_documents(git, head, roots):
    """Documents whose committed content holds zero live line references."""
    locked = []
    for doc in roots:
        _, committed_lines = scan_text(committed_text(git, head, doc))
        if not committed_lines:
            locked.append(doc)
    return locked


def main():
    roots = corpus_roots()
    for doc in roots:
        if not os.path.isfile(os.path.join(REPO_ROOT, doc)):
            raise Blocked("corpus root missing or not a file: %s" % doc)
    symbols, lines = extract(roots)

    # Both operational gates are unconditional. A gate that skipped the index
    # freshness check whenever the corpus happened to hold no symbol references
    # would report clean on a stale index, which is exactly the false pass this
    # tool exists to remove.
    repowise = shutil.which("repowise")
    if repowise is None:
        raise Blocked("repowise not on PATH (no live symbol resolver)")
    git = git_binary()
    head = head_commit(git)
    indexed = recorded_commit()
    if indexed != head:
        raise Blocked(
            "stale symbol index: indexed_commit=%s head=%s (run repowise update)"
            % (indexed, head)
        )

    findings = []
    unique_ids = sorted({_plain(token) for hits in symbols.values() for _, token in hits})
    verified_ids = set()
    for symbol_id in unique_ids:
        path_part = symbol_id.split("::", 1)[0]
        if not os.path.exists(os.path.join(REPO_ROOT, path_part)):
            findings.append(
                "unknown path: %s (no such file in the checkout)" % path_part
            )
            continue
        payload = resolve(repowise, symbol_id)
        reason = verdict(payload, path_part)
        if reason is None:
            verified_ids.add(symbol_id)
            continue
        findings.append("%s: %s" % (symbol_id, reason))

    # Ratchet: the floor is the committed document, so a locked document is one
    # whose bytes at HEAD hold no live line reference at all. Reading lock state
    # off the working tree would let the very act of planting a token unlock the
    # document, which is the one failure mode this class exists to prevent.
    locked = locked_documents(git, head, roots)
    for doc in locked:
        for number, token in lines[doc]:
            findings.append(
                "%s:%d: ratchet violation: locked document regained line reference %s"
                % (doc, number, token)
            )

    if findings:
        for finding in sorted(set(findings)):
            print("REF-CHECK-FINDING %s" % finding)
        return 1

    # n counts live references, not distinct symbols: it is the number of
    # citation sites whose target the resolver verified on this run.
    verified = sum(
        1
        for hits in symbols.values()
        for _, token in hits
        if _plain(token) in verified_ids
    )
    print(
        "REF-CHECK-SCAN: documents=%d symbol-refs=%d unique-symbols=%d line-refs=%d locked=%s"
        % (
            len(roots),
            sum(len(hits) for hits in symbols.values()),
            len(unique_ids),
            sum(len(hits) for hits in lines.values()),
            ",".join(locked) if locked else "-",
        )
    )
    print("REF-CHECK-OK %d" % verified)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Blocked as exc:
        print("REF-CHECK-BLOCKED %s" % exc)
        sys.exit(2)
