#!/usr/bin/env python3
"""Rust symbol-reference lint for the governing specification.

Scope: live `path.rs::Symbol` references in `docs/alumina-proxy.md` only. The
reference is checked against the Repowise index at HEAD. Non-Rust references,
links, anchors, line ranges and continuations are out of scope; other documents
are deliberately not mechanically checked. This is a lint, not a gate.

Exit contract:
  0  clean; last line is `REF-CHECK-OK <n>`.
  1  one or more findings; one `REF-CHECK-FINDING <text>` per line.
  2  BLOCKED: the lint could not run (Repowise absent, stale index,
     unreadable spec, resolver failure). Never reported as clean.
"""

from __future__ import annotations

import concurrent.futures
import json
import os
import re
import shutil
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPEC_DOC = "docs/alumina-proxy.md"
INDEX_STATE = os.path.join(REPO_ROOT, ".repowise", "state.json")

# A whole inline-code span that is exactly a Rust symbol reference. Anchoring
# on the backticks keeps a `git:<sha>:path` receipt out of scope.
REF_RE = re.compile(
    r"(?<!`)`((?:[A-Za-z0-9_][A-Za-z0-9_./-]*\.rs)::[A-Za-z_][A-Za-z0-9_:]*)`(?!`)"
)

RESOLVER_TIMEOUT_SECONDS = 60
RESOLVER_WORKERS = 16


class Blocked(Exception):
    """Operational failure: the lint did not run, so nothing was proven."""


def extract():
    """Sorted unique Rust symbol references in the governing specification."""
    path = os.path.join(REPO_ROOT, SPEC_DOC)
    try:
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
    except OSError as exc:
        raise Blocked("cannot read %s: %s" % (SPEC_DOC, exc)) from exc
    return sorted({match.group(1) for match in REF_RE.finditer(text)})


def _git(*args):
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=RESOLVER_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Blocked("git %s failed: %s" % (" ".join(args), exc)) from exc
    if proc.returncode != 0:
        raise Blocked("git %s failed: %s" % (" ".join(args), proc.stderr.strip()))
    return proc.stdout.strip()


def head_commit():
    return _git("rev-parse", "HEAD")


def indexed_commit():
    try:
        with open(INDEX_STATE, encoding="utf-8") as handle:
            state = json.load(handle)
    except (OSError, ValueError) as exc:
        raise Blocked("cannot read %s: %s" % (INDEX_STATE, exc)) from exc
    commit = state.get("last_sync_commit")
    if not isinstance(commit, str) or not commit:
        raise Blocked("no last_sync_commit in %s" % INDEX_STATE)
    return commit


def verdict(payload, path_part):
    """None when the payload verifies the reference, else a finding string."""
    if not isinstance(payload, dict):
        raise Blocked("resolver payload is not an object")
    if "error" in payload:
        detail = str(payload.get("error")).split(". ")[0].strip()
        return "unresolved symbol: %s (%s)" % (path_part, detail)
    if payload.get("verified") is not True:
        return "unverified symbol: %s (verified=%r)" % (path_part, payload.get("verified"))
    if payload.get("file") != path_part:
        return "resolver reported file=%r for %r" % (payload.get("file"), path_part)
    return None


def resolve(repowise, ref):
    """One `repowise symbol` call; returns a finding or None."""
    path_part = ref.split("::", 1)[0]
    try:
        proc = subprocess.run(
            [repowise, "symbol", ref, "--format", "json"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=RESOLVER_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise Blocked("resolver timed out for %s" % ref) from exc
    except OSError as exc:
        raise Blocked("resolver failed for %s: %s" % (ref, exc)) from exc
    if proc.returncode == 2:
        raise Blocked("resolver exited 2 for %s: %s" % (ref, proc.stderr.strip()))
    if proc.returncode != 0 and not proc.stdout.strip():
        return "unresolved symbol: %s (resolver exit %d)" % (ref, proc.returncode)
    try:
        payload = json.loads(proc.stdout)
    except ValueError as exc:
        raise Blocked("unreadable resolver answer for %s: %s" % (ref, exc)) from exc
    return verdict(payload, path_part)


def main():
    try:
        refs = extract()
        if not refs:
            print("REF-CHECK-OK 0")
            return 0

        repowise = shutil.which("repowise")
        if repowise is None:
            raise Blocked("repowise not on PATH (no live symbol resolver)")

        indexed = indexed_commit()
        head = head_commit()
        if indexed != head:
            raise Blocked(
                "stale symbol index: indexed_commit=%s head=%s (run repowise update)"
                % (indexed, head)
            )

        findings = []
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(RESOLVER_WORKERS, len(refs))
        ) as pool:
            for ref, finding in zip(refs, pool.map(lambda r: resolve(repowise, r), refs)):
                if finding is not None:
                    findings.append(finding)

        for finding in findings:
            print("REF-CHECK-FINDING %s" % finding)
        if findings:
            return 1
        print("REF-CHECK-OK %d" % len(refs))
        return 0
    except Blocked as exc:
        print("REF-CHECK-BLOCKED %s" % exc)
        return 2


if __name__ == "__main__":
    sys.exit(main())
