#!/usr/bin/env python3
"""Live symbol-reference detector for the documentation corpus.

WHAT IT PROVES
  Every `path::Symbol` reference in the DOCSLINK_ROOTS corpus resolves to a
  live, index-verified symbol in THIS checkout, and no document that has already
  been migrated off line numbers regains one, in path form or in continuation
  form.

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
     out-of-range bounds, type-containment failure, ratchet violation,
     continuation with no path of its own). One `REF-CHECK-FINDING <text>`
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

RESOLUTION (batched, parallel, order-stable)
  `repowise symbol` is still what answers a citation; what changed is how many
  of those subprocesses are needed. Each costs ~0.65s of interpreter start-up
  and the corpus cites 216 distinct ids, so the serial run measured 2m19s --
  long enough that an enforcing gate gets routed around, which is the same as
  having no gate. Two things cut the cost without cutting a check.

  (a) A batched prefilter. A `repowise context <path> --include symbols
      --format json` call reports, for one file, the symbols the index holds in
      it: name, kind and declaration line. A citation is answered from that card
      only when the card names it POSITIVELY -- the leaf name for a
      `path::Name` citation, the full symbol id for a `path::Type::member` one --
      and the card's answer then pays the same checks a resolver payload pays
      (reported file, intermediate kind, member line containment). A card is
      never evidence that something is absent: repowise budgets the whole
      batched response and silently omits targets (see
      CONTEXT_PATHS_PER_CALL), so an id the prefilter did not answer -- target
      omitted, call failed, payload unreadable, call timed out -- is resolved
      with `repowise symbol` exactly as before. The prefilter can make this gate
      slower or faster; it cannot make it prove less.

  (b) Bounded parallelism over the ids that still need that call. The batches
      and the per-symbol resolutions both run on a ThreadPoolExecutor; each
      answer is filed under its symbol id, and the corpus is walked in sorted id
      order afterwards, so findings and counts do not depend on which worker
      finished first. A BLOCKED answer raised anywhere in the pool is reported
      for the first such id in sorted order, for the same reason.

  No cache is kept between runs. The bead that commissioned this allows one
  keyed on both HEAD and `indexed_commit`; it is declined because a stored
  answer table is the exact artifact this gate refuses everywhere else (see
  EXEMPTIONS: a text-based exemption is a baseline by another name), and its own
  key would make it nearly worthless -- HEAD advances with every commit, so a
  run against a new commit is always cold. The speed is bought by batching and
  parallelism, both re-derived from the index on every run.

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

TYPE CONTAINMENT (a leaf name is not a citation)
  `path::A::b` names two constructs, and the resolver answers with one: asked
  for `src/inspection/connect.rs::ConnectError::TooManyHeaderLines` it returns
  the member of `ConnectHeadReason` -- same file, same leaf name, verified:true,
  line 132 instead of 63. A gate that checks only the file and the leaf name
  certifies a citation that names the wrong construct, so every enclosing
  segment is resolved and attributed separately: each `path::A` must resolve,
  verify, and be a type-like construct, and the member's reported line must lie
  inside a declaration of `A` in that file. Nested segments (`path::A::B::b`)
  are matched outermost-first against the enclosing declarations read from the
  source, innermost declaration first.

  The enclosing declaration is read from the file's brace structure rather than
  from the type's resolver answer, because the resolver's span cannot carry
  containment. Measured on this corpus:
    - A type with several impl blocks is reported at ONE of them, arbitrarily:
      `src/runtime/storage.rs::ServeStorage` answers 1770-1786 while the cited
      methods sit in the 336-1724 block.
    - Variants and fields live in the declaration, which the index does not
      report at all once the type has an impl: `ConfigError::InvalidResolver`
      resolves to line 362 while `path::ConfigError` answers the impl 391-527.
  Both readings are legitimately contained members, so span containment against
  the resolver answer would reject 8 of this corpus's 24 qualified references.
  The block header (`impl Trait for X` names X; `pub enum X` names X) is what
  the citation means by `A`, and it is the same reading the compiler uses to
  resolve `X::b`. A member whose enclosing declarations do not name every cited
  segment is a finding, never a pass, and there is no allow-list.

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

CONTINUATIONS (a line number must carry its own path)
  LINE_RE needs a path prefix, so a continuation token is invisible to both the
  resolver check and the ratchet: `:1937` standing in for a path named earlier,
  or a markdown link target with `:12` left outside the link. Two shapes are
  findings. (a) A backticked span holding nothing but `:NNN` or `:N-M`, when a
  citation precedes it on the same line -- the continuation is neither readable
  on its own nor checked, so the document has regained a line number.
  (b) A markdown link whose target is a source path and whose `:NNN` sits
  outside the link -- the shape docs/monitoring.md carried 21 times before it
  was converted.

  A `git:<commit>:` receipt is a citation here, not a licence: the continued
  token must repeat it (`git:<commit>:path#L1937`) to be readable and immovable,
  and that form is not continuation-shaped at all. A receipt anywhere on the
  line therefore covers nothing, because `` `git:<commit>:src/log.rs#L1850`,
  `:1937` `` -- the shape this class was added for -- would otherwise pass on
  the strength of a token it does not belong to. Shape is the entire test: a
  port or a clock time in prose (`:443`, `12:30`) follows no citation and never
  fires.

  KNOWN RESIDUE: continuation detection is grammar-shaped only inside backticks
  and inside markdown link targets. A bare `:1937` written straight into prose
  is not a continuation to this gate (see `_live_lines`).

EXEMPTIONS ARE STRUCTURAL ONLY
  Two things are exempt, both because of where the text sits, never because of
  what it says: (a) fenced code blocks (``` / ~~~ fences, honouring the info
  string and requiring a closing fence at least as long as the opener), and
  (b) a path immediately preceded by `git:<commit>:`, whose live-reference
  claim is about another tree. The continuation class takes no exemption from
  either: a receipt is a citation, never a waiver. There is deliberately no
  `# ref-check-disable` marker, no allow-list file and no `--ignore` option: a
  text-based exemption is a baseline by another name, and the whole point of
  this gate is that a finding cannot be argued away by annotating the text that
  caused it.

STYLE
  Stdlib only, no network, no third-party import. Document bytes are read as
  data and never interpolated into a shell: every subprocess call is an argv
  list. Output order is a pure function of the corpus.
"""

import functools
import json
import os
import re
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VERIFY_SH = os.path.join(REPO_ROOT, "scripts", "verify.sh")
INDEX_STATE = os.path.join(REPO_ROOT, ".repowise", "state.json")
RESOLVER_TIMEOUT_SECONDS = 120
# How many paths one batched prefilter call may ask about, and how wide the pool
# runs. `repowise context` budgets the WHOLE response, not one target within it,
# and drops the targets that do not fit without saying so -- measured on this
# corpus (37 cited files, 216 cited ids): 20 paths answered 2 files / 0 ids, 10
# answered 20 / 11, 5 answered 28 / 41, 2 answered 31 / 126, 1 answered 37 / 165.
# So a call asks about one path, and the parallelism is what makes the prefilter
# cheap; a larger batch would trade coverage (and therefore time) for nothing.
# Coverage only ever costs a fallback call, never a proof (see RESOLUTION).
CONTEXT_PATHS_PER_CALL = 1
RESOLVER_WORKERS = 16

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

# Continuation shapes: a line number whose path was named elsewhere. Shape is
# the entire test, so a port (`:443`), a clock time (`12:30`) or a prose range
# never matches: a span continuation must be a backticked token holding nothing
# but a line number, and a link continuation must be a markdown link to a source
# path with the number left outside the link.
CONTINUATION_SPAN_RE = re.compile(r"`(:[0-9]+(?:-[0-9]+)?)`")
LINK_CONTINUATION_RE = re.compile(
    r"\[[^\]\n]*\]\([^()\s]*" + _SOURCE_EXT + r"\):[0-9]+(?:-[0-9]+)?"
)
LINK_PATH_RE = re.compile(r"\]\([^()\s]*" + _SOURCE_EXT + r"\)")
# A receipt names a pinned tree AND a path, so it is a citation the same way
# `path:NNN` is: a `:NNN` after it continues that path. Recognising it is what
# makes the continuation class see the shape it was added for.
RECEIPT_CITATION_RE = re.compile(r"git:[0-9a-f]{7,40}:[A-Za-z0-9_./-]+")

FENCE_RE = re.compile(r"^[ \t]*(`{3,}|~{3,})(.*)$")
ROOTS_RE = re.compile(r'^DOCSLINK_ROOTS="([^"]*)"[ \t]*$', re.MULTILINE)

# Kinds the index reports for a construct a member can hang off. A type with an
# impl block is spelled `impl` (see TYPE CONTAINMENT), which is why that
# spelling is accepted for a type name.
TYPE_LIKE_KINDS = ("enum", "impl", "struct", "trait", "type", "union")
_DECL_RE = re.compile(
    r"(?:pub(?:\([^)]*\))? )?(?:enum|struct|union|trait) ([A-Za-z_][A-Za-z0-9_]*)"
)
_IMPL_RE = re.compile(r"(?:unsafe )?impl(.*)$")
_PATH_HEAD_RE = re.compile(r"(?:[A-Za-z_][A-Za-z0-9_]*::)*([A-Za-z_][A-Za-z0-9_]*)")


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

    That holds for `path::Symbol` and `path:NNN`, which are grammar-shaped
    wherever they sit, and NOT for continuations. A continuation carries no path
    of its own, so it is only recognisable by the punctuation around it, and
    this reader finds one in exactly two places: a backticked span holding
    nothing but `:NNN` (`CONTINUATION_SPAN_RE`) and a `:NNN` left outside a
    markdown link target (`LINK_CONTINUATION_RE`). A bare `:1937` written
    straight into prose is therefore KNOWN RESIDUE: this gate does not see it,
    and nothing else in the gate does either, so that spelling could regain a
    line number without a finding. It is accepted rather than closed because an
    unquoted `:NNN` is indistinguishable from the port and clock-time prose
    `docs/deployment.md` legitimately holds, and a class that fires on
    `dial :443` costs more in false positives than the residue costs in
    coverage. Diff review is the only cover for the residue; this docstring is
    the record.
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


def _cites_before(text, end):
    """True when a citation precedes `end`, so a `:NNN` there is a continuation.

    A `git:<commit>:path` receipt is a citation on the same footing as a symbol,
    line or link-target reference: it names a pinned tree and a path, so a
    `:NNN` after it continues that path exactly as one after `path:NNN` does.
    Reading the receipt as a citation is what stops the pre-fix spec shape
    (`` `git:<commit>:src/log.rs#L1850`, `:1937` ``) from being taken for prose
    and slipping through the class built to catch it.
    """
    head = text[:end]
    return (
        SYMBOL_RE.search(head) is not None
        or LINE_RE.search(head) is not None
        or LINK_PATH_RE.search(head) is not None
        or RECEIPT_CITATION_RE.search(head) is not None
    )


def scan_continuations(raw):
    """Return [(line, token)] for continuation tokens with no path restated.

    A continuation continues a citation that precedes it on the same line, and a
    citation is any of the four shapes `_cites_before` recognises -- including a
    `git:<commit>:path` receipt. What a receipt does NOT do is cover its
    neighbours: a bare `:1937` beside a receipt still restates a line number the
    reader cannot resolve and both grammars cannot see, so it is a finding
    whether or not a receipt shares the line. The readable, immovable form
    repeats the receipt (`git:<commit>:path#L1937`), and that token is not
    continuation-shaped at all -- which is why removing the old line-level
    receipt exemption costs the corpus nothing.
    """
    found = []
    for number, text in _live_lines(raw):
        for match in CONTINUATION_SPAN_RE.finditer(text):
            if not _cites_before(text, match.start()):
                continue
            found.append((number, match.group(0)))
        for match in LINK_CONTINUATION_RE.finditer(text):
            found.append((number, match.group(0)))
    return found


def extract(roots):
    """Scan the working tree of every corpus document."""
    symbols = {}
    lines = {}
    continuations = {}
    for doc in roots:
        raw = _read_text(os.path.join(REPO_ROOT, doc))
        symbols[doc], lines[doc] = scan_text(raw)
        continuations[doc] = scan_continuations(raw)
    return symbols, lines, continuations


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


def _card_entries(card):
    """The usable symbol entries of one batched context card.

    An entry is usable only when it carries all three things the gate compares:
    a name, a kind and a declaration line. A card that omits one is treated as
    silence for every id it might have covered, which sends those ids to the
    per-symbol resolver.
    """
    docs = card.get("docs") if isinstance(card, dict) else None
    symbols = docs.get("symbols") if isinstance(docs, dict) else None
    if not isinstance(symbols, list):
        return []
    usable = []
    for entry in symbols:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        kind = entry.get("kind")
        line = entry.get("line")
        if not isinstance(name, str) or not isinstance(kind, str):
            continue
        if not isinstance(line, int) or isinstance(line, bool):
            continue
        usable.append(
            {
                "name": name,
                "kind": kind,
                "line": line,
                "symbol_id": entry.get("symbol_id"),
            }
        )
    return usable


def _context_cards(repowise, paths):
    """{path: [entry]} from one batched `repowise context` call.

    Never raises. The prefilter is an optimisation, and a call that fails, times
    out or omits a requested target leaves those ids to the per-symbol resolver,
    which is the gate's authority (see RESOLUTION). That is also why an absent
    path is not read as a symbol's absence: repowise budgets its batched output
    and drops targets without saying so.
    """
    if not paths:
        return {}
    try:
        proc = subprocess.run(
            [repowise, "context"]
            + list(paths)
            + ["--include", "symbols", "--format", "json"],
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=RESOLVER_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError):
        return {}
    if proc.returncode != 0:
        return {}
    payload = _first_json_object(proc.stdout.decode("utf-8", "replace"))
    targets = payload.get("targets") if isinstance(payload, dict) else None
    if not isinstance(targets, dict):
        return {}
    cards = {}
    for path in paths:
        entries = _card_entries(targets.get(path))
        if entries:
            cards[path] = entries
    return cards


def batched_cards(repowise, paths):
    """{path: [entry]} over every cited path, in bounded parallel batches."""
    ordered = sorted(paths)
    batches = [
        ordered[index:index + CONTEXT_PATHS_PER_CALL]
        for index in range(0, len(ordered), CONTEXT_PATHS_PER_CALL)
    ]
    if not batches:
        return {}
    cards = {}
    with ThreadPoolExecutor(max_workers=min(RESOLVER_WORKERS, len(batches))) as pool:
        for answered in pool.map(lambda batch: _context_cards(repowise, batch), batches):
            cards.update(answered)
    return cards


def card_for(symbol_id, entries):
    """The card entry that positively identifies `symbol_id`, or None.

    A qualified citation must match the card's own symbol id: the card lists the
    members of every type in the file, and matching by leaf name would let it
    answer with another type's member -- precisely the confusion the containment
    check exists to catch. A plain citation matches by leaf name, and only when
    every entry carrying that name agrees about kind and line; a disagreement is
    handed to the per-symbol resolver, which is the authority.
    """
    parts = symbol_id.split("::")
    if len(parts) > 2:
        hits = [entry for entry in entries if entry.get("symbol_id") == symbol_id]
    else:
        hits = [entry for entry in entries if entry["name"] == parts[-1]]
    if not hits:
        return None
    first = hits[0]
    for other in hits[1:]:
        if (other["kind"], other["line"]) != (first["kind"], first["line"]):
            return None
    return first


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


def _card_answer(entry):
    """The answer a batched card carries, in the shape the checks consume."""
    return {
        "kind": entry["kind"],
        "line": entry["line"],
        "reason": None,
        "source": "batched card",
    }


def _payload_answer(payload, path_part):
    """The answer a per-symbol resolver payload carries."""
    bounds = _bounds(payload)
    return {
        "kind": payload.get("kind"),
        "line": None if bounds is None else bounds[0],
        "reason": verdict(payload, path_part),
        "source": "repowise symbol",
    }


def resolve_all(repowise, symbol_ids):
    """{symbol_id: payload} for every id, on a bounded thread pool.

    BLOCKED wins: when any id comes back operational (resolver absent, exit 2,
    unreadable answer) the run is BLOCKED, and the id reported is the first in
    sorted order rather than the first to finish, so the message is a function
    of the corpus too.
    """
    if not symbol_ids:
        return {}

    def one(symbol_id):
        try:
            return resolve(repowise, symbol_id)
        except Blocked as exc:
            return exc

    payloads = {}
    blocked = {}
    with ThreadPoolExecutor(max_workers=min(RESOLVER_WORKERS, len(symbol_ids))) as pool:
        for symbol_id, result in zip(symbol_ids, pool.map(one, symbol_ids)):
            if isinstance(result, Blocked):
                blocked[symbol_id] = result
            else:
                payloads[symbol_id] = result
    for symbol_id in symbol_ids:
        if symbol_id in blocked:
            raise blocked[symbol_id]
    return payloads


def _declaration_header(header):
    """(lines skipped, declaration text) for a block header.

    A block header starts at the previous brace boundary, so it carries the doc
    comments and attributes that precede the item. Those are documentation
    about the declaration, not the declaration, so they are skipped and the
    remaining text is whitespace-normalized.
    """
    skipped = 0
    depth = 0
    for line in header.splitlines():
        stripped = line.strip()
        if depth > 0:
            depth += stripped.count("[") - stripped.count("]")
            skipped += 1
            continue
        if not stripped or stripped.startswith("//"):
            skipped += 1
            continue
        if stripped.startswith("#[") or stripped.startswith("#!["):
            depth = max(0, stripped.count("[") - stripped.count("]"))
            skipped += 1
            continue
        break
    return skipped, " ".join(" ".join(header.split("\n")[skipped:]).split())


def _declared_type(header):
    """(declared type name, lines to its declaration) or (None, 0).

    `enum X`, `struct X`, `union X`, `trait X`, `impl X`, `impl<T> X<T>` and the
    trait-impl form `impl Trait for X` all declare a type; in the last form the
    right-hand type owns the members, so that is the answer. A body block
    (`match self`, `if let ...`) matches neither and declares nothing.
    """
    skipped, text = _declaration_header(header)
    match = _DECL_RE.match(text)
    if match is not None:
        return match.group(1), skipped
    match = _IMPL_RE.match(text)
    if match is None:
        return None, 0
    rest = match.group(1).strip()
    if rest.startswith("<"):
        depth = 0
        for index, char in enumerate(rest):
            if char == "<":
                depth += 1
            elif char == ">":
                depth -= 1
            if depth == 0:
                rest = rest[index + 1:].strip()
                break
        else:
            return None, 0
    if " for " in rest:
        rest = rest.rsplit(" for ", 1)[1].strip()
    match = _PATH_HEAD_RE.match(rest)
    return (match.group(1), skipped) if match is not None else (None, 0)


def _skip_char_literal(text, index):
    """Index just past a character literal, or past the quote of a lifetime.

    `'a` is a lifetime or loop label with no closing quote; a character literal
    has one and may carry an escape whose braces are not structure (`'\\u{7b}'`).
    """
    following = index + 1
    if following >= len(text):
        return len(text)
    if text[following] == "\\":
        if text.startswith("\\u{", following):
            close = text.find("}", following)
            index = len(text) if close < 0 else close + 1
        else:
            index = following + 2
        quote = text.find("'", index)
        return len(text) if quote < 0 else quote + 1
    if text.startswith("'", following + 1):
        return following + 2
    return following


def _block_header(brace_text, brace_line, statement_text, statement_line):
    """The reading of a block header that actually declares something.

    A declaration can follow a brace-less statement, and such a statement leaves
    no brace boundary behind: after `use super::{ ... };` or `const LIMIT: u8 =
    1;` the tightest boundary for the next `impl`/`struct` is the statement
    terminator. Reading only from the brace boundary yields a header like
    "; impl LogStore", which declares nothing, so the block is unattributable
    and every qualified citation into it is falsely rejected.

    A `;` can also sit INSIDE a declaration header -- a const-generic array
    length, `where [(); N]: Sized` -- where the tightest boundary amputates the
    declaration (`N]: Sized,`). The whole segment since the previous brace
    boundary is still a valid reading there, so it is kept as the fallback.
    Asking which reading yields a declaration is what keeps this a header
    reader rather than a statement parser: no statement grammar is modelled,
    and a block that declares nothing keeps its previous header verbatim (the
    enclosing-block text diagnostics quote).
    """
    for text, start in ((statement_text, statement_line), (brace_text, brace_line)):
        if _declared_type(text)[0] is not None:
            return text, start
    return brace_text, brace_line


@functools.lru_cache(maxsize=None)
def _brace_blocks(path):
    """Every brace-delimited block in `path`: [(header text, start line, end)].

    The header is the text since the previous block boundary, which is how
    `impl fmt::Display for ConnectError` and `pub enum ConnectError` are
    recovered without a Rust parser. Two boundaries count, because a block can
    follow either: a brace (`{` / `}`) or a statement terminator (`;`). See
    `_block_header` for why both readings exist and how they are chosen.
    Braces inside comments, string literals, raw strings, character literals
    and statement terminators inside those same literals are not structure and
    are skipped: a `"{"` in a format string would otherwise shift every
    enclosing-block reading below it. Cached because a document cites one file
    many times and the file is scanned only to answer line attribution.
    """
    text = _read_text(os.path.join(REPO_ROOT, path))
    length = len(text)
    blocks = []
    stack = []
    line = 1
    boundary = 0
    boundary_line = 1
    statement = 0
    statement_line = 1
    index = 0
    while index < length:
        char = text[index]
        if char == "\n":
            line += 1
            index += 1
        elif text.startswith("//", index):
            end = text.find("\n", index)
            index = length if end < 0 else end
        elif text.startswith("/*", index):
            depth = 1
            index += 2
            while index < length and depth:
                if text.startswith("/*", index):
                    depth += 1
                    index += 2
                elif text.startswith("*/", index):
                    depth -= 1
                    index += 2
                else:
                    line += text[index] == "\n"
                    index += 1
        elif char.isalpha() or char == "_":
            start = index
            while index < length and (text[index].isalnum() or text[index] == "_"):
                index += 1
            raw = text[start:index] in ("r", "br", "cr")
            if raw and index < length and text[index] in '#"':
                hashes = 0
                while index < length and text[index] == "#":
                    hashes += 1
                    index += 1
                if index < length and text[index] == '"':
                    end = text.find('"' + "#" * hashes, index + 1)
                    index = length if end < 0 else end + 1 + hashes
                    line += text.count("\n", start, index)
        elif char == '"':
            index += 1
            while index < length and text[index] != '"':
                if text[index] == "\\":
                    line += index + 1 < length and text[index + 1] == "\n"
                    index += 2
                    continue
                line += text[index] == "\n"
                index += 1
            index += 1
        elif char == "'":
            index = _skip_char_literal(text, index)
        elif char == "{":
            header, start = _block_header(
                text[boundary:index], boundary_line,
                text[statement:index], statement_line,
            )
            stack.append((header, start))
            index += 1
            boundary = statement = index
            boundary_line = statement_line = line
        elif char == "}":
            if stack:
                header, start = stack.pop()
                blocks.append((header, start, line))
            index += 1
            boundary = statement = index
            boundary_line = statement_line = line
        elif char == ";":
            index += 1
            statement = index
            statement_line = line
        else:
            index += 1
    return blocks


def _type_chain(path, line):
    """Declarations enclosing `line`, innermost first: [(start, name, end, header)]."""
    chain = []
    for header, start, end in _brace_blocks(path):
        name, skipped = _declared_type(header)
        declared = start + skipped
        if name is not None and declared <= line <= end:
            chain.append((declared, name, end, header))
    chain.sort(key=lambda entry: entry[0], reverse=True)
    return chain


def type_containment(path, line, symbol_id, prefixes):
    """None when `line` sits inside every cited type, else the finding.

    `prefixes` is [(qualifier, name)] outermost first. Matching runs innermost
    segment against the innermost enclosing declaration, so `path::A::B::b`
    must be enclosed by B inside A and cannot borrow A for a member of B.
    """
    chain = _type_chain(path, line)
    names = [entry[1] for entry in chain]
    cursor = 0
    for qualifier, name in reversed(prefixes):
        while cursor < len(names) and names[cursor] != name:
            cursor += 1
        if cursor < len(names):
            cursor += 1
            continue
        if not chain:
            return (
                "type-containment: %s: member line %d sits outside every "
                "declaration, so it is not a member of %s" % (symbol_id, line, qualifier)
            )
        enclosing = chain[0]
        return (
            "type-containment: %s: member line %d lies inside %s (%d-%d), "
            "not inside %s"
            % (
                symbol_id,
                line,
                _declaration_header(enclosing[3])[1],
                enclosing[0],
                enclosing[2],
                qualifier,
            )
        )
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
    symbols, lines, continuations = extract(roots)

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

    # Every id this run will ask about: each citation whose path exists, plus
    # every enclosing segment a qualified citation names (see TYPE CONTAINMENT).
    # One answer per distinct id -- the same memo the serial run kept -- except
    # that the expensive answers are fetched in bulk and in parallel (see
    # RESOLUTION), and a citation the batch did not positively identify is left
    # to the per-symbol resolver.
    resolvable = [
        symbol_id
        for symbol_id in unique_ids
        if os.path.exists(os.path.join(REPO_ROOT, symbol_id.split("::")[0]))
    ]
    wanted = set(resolvable)
    for symbol_id in resolvable:
        parts = symbol_id.split("::")
        for depth in range(2, len(parts)):
            wanted.add("::".join(parts[:depth]))
    resolve_ids = sorted(wanted)

    cards = batched_cards(repowise, {symbol_id.split("::")[0] for symbol_id in resolve_ids})
    answers = {}
    for symbol_id in resolve_ids:
        entry = card_for(symbol_id, cards.get(symbol_id.split("::")[0], []))
        if entry is not None:
            answers[symbol_id] = _card_answer(entry)
    payloads = resolve_all(
        repowise, [symbol_id for symbol_id in resolve_ids if symbol_id not in answers]
    )
    for symbol_id in resolve_ids:
        if symbol_id not in answers:
            answers[symbol_id] = _payload_answer(
                payloads[symbol_id], symbol_id.split("::")[0]
            )

    verified_ids = set()
    for symbol_id in unique_ids:
        parts = symbol_id.split("::")
        path_part = parts[0]
        if not os.path.exists(os.path.join(REPO_ROOT, path_part)):
            findings.append(
                "unknown path: %s (no such file in the checkout)" % path_part
            )
            continue
        # A qualified reference names a chain of constructs, and the leaf answer
        # alone cannot prove the chain: `path::A::b` and `path::C::b` return the
        # same payload when both types hold a `b`. Every enclosing segment is
        # resolved and verified on its own (see TYPE CONTAINMENT).
        prefixes = []
        reason = None
        for depth in range(2, len(parts)):
            qualifier = "::".join(parts[:depth])
            qualifier_answer = answers[qualifier]
            reason = qualifier_answer["reason"]
            if reason is not None:
                reason = "%s: %s" % (qualifier, reason)
                break
            if qualifier_answer["kind"] not in TYPE_LIKE_KINDS:
                reason = "%s: intermediate segment resolves to kind %r, not a type-like construct" % (
                    qualifier,
                    qualifier_answer["kind"],
                )
                break
            prefixes.append((qualifier, parts[depth - 1]))
        if reason is not None:
            findings.append("%s: %s" % (symbol_id, reason))
            continue
        leaf = answers[symbol_id]
        reason = leaf["reason"]
        if reason is not None:
            findings.append("%s: %s" % (symbol_id, reason))
            continue
        if prefixes:
            member_line = leaf["line"]
            if member_line is None:
                # Containment is the whole point of the multi-segment form: a
                # member the resolver places nowhere cannot be attributed, and
                # an unattributable citation is not a verified one.
                findings.append(
                    "type-containment: %s: the resolver reported no line for the "
                    "member, so its enclosing type cannot be checked" % symbol_id
                )
                continue
            reason = type_containment(path_part, member_line, symbol_id, prefixes)
            if reason is not None:
                findings.append(reason)
                continue
        verified_ids.add(symbol_id)

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

    # A continuation belongs to the citation before it, and a `git:<commit>:`
    # receipt on the line is one of those citations, never a waiver: a bare
    # `:NNN` beside a receipt is a line number the grammar cannot see, so it is
    # a finding whatever the lock state.
    for doc in roots:
        for number, token in continuations[doc]:
            findings.append(
                "%s:%d: continuation reference: %s continues a path named earlier "
                "and does not carry that path itself" % (doc, number, token)
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
