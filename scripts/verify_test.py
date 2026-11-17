#!/usr/bin/env python3
"""Focused tests for independent verification selectors; no real builds run."""

import ast
import collections
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parent.parent

GATE_NAMES = ("unsafe_surface_gate", "cfg_test_parentage_gate")


def extract_function(name):
    script = (ROOT / "scripts/verify.sh").read_text()
    match = re.search(rf"^{name}\(\) \{{\n.*?^\}}$", script, re.S | re.M)
    assert match is not None, f"function not found in scripts/verify.sh: {name}"
    return match.group(0)


def extract_gates():
    """The real gate bodies, text-extracted from scripts/verify.sh (the same
    precedent as test_dirty_agents_content_drift_is_detected): the tests drive
    the shipped decision logic, never a Python re-implementation of it."""
    return "\n\n".join(extract_function(name) for name in GATE_NAMES)


GATES = extract_gates()


def synthetic_identity_repo(temp):
    """A synthetic repo carrying every identity input and a git stub that
    answers the three reads a snapshot makes (HEAD, status, blob hashes). The
    tests drive the shipped `sh scripts/verify.sh identity ...` path; the
    predicate under test is never re-implemented in Python here."""
    repo, tools = temp / "repo", temp / "tools"
    (repo / "scripts").mkdir(parents=True)
    tools.mkdir()
    script = ROOT / "scripts/verify.sh"
    shutil.copyfile(script, repo / "scripts/verify.sh")
    prefix = script.read_text().split("# Keep snapshot locations", 1)[0]
    files = subprocess.check_output(
        ["sh", "-c", prefix + '\nprintf "%s\\n" "$IDENTITY_FILES"',
         "sh", "identity", "snapshot"], cwd=repo, text=True,
    ).split()
    for name in files:
        if name == "scripts/verify.sh":
            continue
        dest = repo / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(f"synthetic input: {name}\n")
    (repo / "scripts/cargo_config_probe.py").write_text('print("absent")\n')
    git = tools / "git"
    # The HEAD answer is a well-formed git object name because the compare types
    # that record: a stub value the writer could not produce would make every
    # synthetic pin fail for the wrong reason.
    git.write_text('''#!/bin/sh
case "$*" in
  'rev-parse --verify HEAD') printf '3f786850e387550fdab836ed7e6dc881de23001b\\n';;
  'status --porcelain') [ "${FIXTURE_STATUS_FAIL:-0}" = 0 ] || exit 42; printf ' M %s\\n' "$FIXTURE_INPUT";;
  'hash-object --stdin-paths')
    [ "${FIXTURE_BLOB_FAIL:-0}" = 0 ] || exit 43
    while IFS= read -r path; do shasum -a 256 "$path" | cut -d' ' -f1; done;;
  *) exit 1;;
esac
''')
    git.chmod(0o755)
    env = {"PATH": f"{tools}:{os.environ['PATH']}", "FIXTURE_INPUT": "AGENTS.md",
           "CARGO_HOME": str(temp / "cargo-home")}
    return repo, tools, env, files


def rewrite_column(path, index, value):
    """Replace one cell of every row in a witness record, keeping the key and
    the row width. Applied to BOTH snapshots it makes an ill-typed record that
    still compares equal, which is exactly the false-PASS shape a cell guard
    exists to refuse."""
    rows = []
    for line in path.read_text().splitlines():
        fields = line.split("\t")
        fields[index] = value
        rows.append("\t".join(fields))
    path.write_bytes(("\n".join(rows) + "\n").encode())


class Selectors(unittest.TestCase):
    def run_verify(self, *args, env=None, cwd=ROOT):
        return subprocess.run(
            ["sh", "scripts/verify.sh", *map(str, args)], cwd=cwd,
            env={**os.environ, **(env or {})}, text=True, capture_output=True,
        )

    def test_removed_selectors_reject(self):
        for scope in ("phase1", "phase1-fast", "phase1-slow"):
            result = self.run_verify("boundary", scope)
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)

    def test_missing_prerequisites_and_arguments_fail(self):
        env = {"PATH": "/usr/bin:/bin"}
        for args, marker in ((["supply-chain", "audit-deny"], "AUDIT-DENY-BLOCKED"),
                             (["fixtures", "boot"], "BOOT-FIXTURES-BLOCKED")):
            result = self.run_verify(*args, env=env)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(marker, result.stderr)
        for args in (("identity", "snapshot"), ("identity", "compare", "target"),
                     ("identity", "artifact"), ("host-mid", "union", "extra")):
            self.assertEqual(self.run_verify(*args).returncode, 2)

    def test_dirty_agents_content_drift_is_detected(self):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            repo, _tools, env, files = synthetic_identity_repo(temp)
            representatives = {"Cargo.toml", "src/main.rs", ".gitignore", "AGENTS.md",
                               "scripts/verify.sh", "scripts/verify_test.py",
                               "docs/qa-package/validate.sh", "docs/qa-package/validate_test.py"}
            self.assertTrue(representatives <= set(files))
            for name in ("AGENTS.md", "docs/qa-package/validate.sh", "docs/qa-package/validate_test.py"):
                path = repo / name
                baseline = path.read_bytes()
                path.write_bytes(baseline + b"\nfixture dirty one\n")
                env = {**env, "FIXTURE_INPUT": name}
                before, after = temp / "before", temp / "after"
                result = self.run_verify("identity", "snapshot", before, env=env, cwd=repo)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                hashed = {line.split(maxsplit=1)[1] for line in (before / "inputs.sha256").read_text().splitlines()}
                self.assertEqual(hashed, set(files))
                result = self.run_verify("identity", "snapshot", after, env=env, cwd=repo)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                result = self.run_verify("identity", "compare", before, after, env=env, cwd=repo)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                path.write_bytes(baseline + b"\nfixture dirty two\n")
                result = self.run_verify("identity", "snapshot", after, env=env, cwd=repo)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual((before / "status").read_text(), f" M {name}\n")
                self.assertEqual((before / "status").read_bytes(), (after / "status").read_bytes())
                result = self.run_verify("identity", "compare", before, after, env=env, cwd=repo)
                self.assertNotEqual(result.returncode, 0, name + result.stdout + result.stderr)
                self.assertIn("input hashes differ", result.stderr)
                path.write_bytes(baseline)
            path.unlink()
            result = self.run_verify("identity", "snapshot", temp / "missing", env=env, cwd=repo)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(f"identity input missing: {name}", result.stderr)
            path.write_bytes(baseline)
            result = self.run_verify("identity", "snapshot", temp / "bad-status",
                                     env={**env, "FIXTURE_STATUS_FAIL": "1"}, cwd=repo)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("git status exit 42", result.stderr)

    def test_source_and_artifact_identity(self):
        with tempfile.TemporaryDirectory() as temp:
            before, after = Path(temp) / "before", Path(temp) / "after"
            for path in (before, after):
                result = self.run_verify("identity", "snapshot", path)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            result = self.run_verify("identity", "compare", before, after)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            # A READABLE difference must reach the CHANGED class, so every
            # payload below is legal for its record's kind. An ill-typed record
            # is UNKNOWN, so pinning only the record line would let the terminal
            # class move while this test stayed green.
            for name, payload in (
                    ("head", b"1" * 40 + b"\n"),
                    ("status", b" M synthetic/other-input\n"),
                    ("env", b"hasher=fixture-other\n")):
                original = (after / name).read_bytes()
                self.assertNotEqual(original, payload, name)
                (after / name).write_bytes(payload)
                result = self.run_verify("identity", "compare", before, after)
                self.assertNotEqual(result.returncode, 0, name)
                self.assertIn("SOURCE-IDENTITY-CHANGED", result.stderr)
                self.assertIn("boundary inputs not stable", result.stderr)
                self.assertNotIn("SOURCE-IDENTITY-UNKNOWN", result.stderr)
                (after / name).write_bytes(original)
            # inputs.sha256 stays parseable and keeps its path set, so this is a
            # content difference the comparer can observe -- never an
            # unobservable record.
            original = (after / "inputs.sha256").read_bytes()
            digest, paths = original.split(maxsplit=1)
            self.assertEqual(len(digest), 64)
            other = b"0" * 64 if digest != b"0" * 64 else b"1" * 64
            (after / "inputs.sha256").write_bytes(other + b" " + paths)
            result = self.run_verify("identity", "compare", before, after)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("SOURCE-IDENTITY-CHANGED", result.stderr)
            self.assertIn("boundary inputs not stable", result.stderr)
            self.assertNotIn("SOURCE-IDENTITY-UNKNOWN", result.stderr)
            (after / "inputs.sha256").write_bytes(original)
            result = self.run_verify("identity", "compare", before, Path(temp) / "missing")
            self.assertNotEqual(result.returncode, 0)
            with tempfile.TemporaryDirectory(dir=ROOT, prefix=".receipt-executed-") as scratch:
                artifact = Path(scratch) / "artifact"
                artifact.write_bytes(b"receipt test artifact\n")
                result = self.run_verify("identity", "artifact", artifact)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                path_suffix = f"  {artifact}\n"
                self.assertTrue(result.stdout.endswith(path_suffix), result.stdout)
                label, digest = result.stdout.removesuffix(path_suffix).rsplit(" ", 1)
                self.assertEqual(label, "  artifact sha256")
                self.assertEqual(digest, hashlib.sha256(artifact.read_bytes()).hexdigest())
            result = self.run_verify("identity", "artifact", Path(temp) / "missing")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("ARTIFACT-IDENTITY FAIL", result.stderr)
            bad_hasher = Path(temp) / "sha256sum"
            bad_hasher.write_text("#!/bin/sh\nexit 42\n")
            bad_hasher.chmod(0o755)
            env = {"PATH": f"{temp}:{os.environ['PATH']}"}
            for args in (("identity", "snapshot", Path(temp) / "failed"),
                         ("identity", "artifact", ROOT / "Cargo.lock")):
                result = self.run_verify(*args, env=env)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("SOURCE-IDENTITY FAIL", result.stderr)

    def _identity_pair(self, temp):
        """Two snapshots of one synthetic repo, both must succeed first: a pin
        that starts from a failed snapshot is testing the harness, not the
        comparer."""
        repo, tools, env, _files = synthetic_identity_repo(temp)
        before, after = temp / "before", temp / "after"
        for snapshot in (before, after):
            result = self.run_verify("identity", "snapshot", snapshot,
                                     env=env, cwd=repo)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return repo, tools, env, before, after

    def _blob_sha(self, snapshot, name):
        for line in (snapshot / "inputs.blob").read_text().splitlines():
            path, sha = line.split("\t")
            if path == name:
                return sha
        self.fail(f"{name} absent from {snapshot}/inputs.blob")

    def _stat_tuple(self, snapshot, name):
        for line in (snapshot / "inputs.stat").read_text().splitlines():
            path, ino, size, mtime, ctime = line.split("\t")
            if path == name:
                return (ino, size, mtime, ctime)
        self.fail(f"{name} absent from {snapshot}/inputs.stat")

    def test_identity_compare_stable_on_untouched_pair(self):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            repo, _tools, env, _files = synthetic_identity_repo(temp)
            before, after = temp / "before", temp / "after"
            for snapshot in (before, after):
                result = self.run_verify("identity", "snapshot", snapshot, env=env, cwd=repo)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertTrue((before / "inputs.blob").is_file())
            self.assertTrue((before / "inputs.stat").is_file())
            result = self.run_verify("identity", "compare", before, after, env=env, cwd=repo)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("SOURCE-IDENTITY-STABLE-OK", result.stdout)

    def test_byte_identical_rewrite_is_refused_by_the_stat_witness(self):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            repo, _tools, env, _files = synthetic_identity_repo(temp)
            target = repo / "src/main.rs"
            before, after = temp / "before", temp / "after"
            result = self.run_verify("identity", "snapshot", before, env=env, cwd=repo)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            original = target.read_bytes()
            before_sha = self._blob_sha(before, "src/main.rs")
            before_stat = self._stat_tuple(before, "src/main.rs")
            # Same bytes, forced distinct mtime: neither the worktree sha256 nor
            # the git blob sha can see this rewrite; only the stat tuple can.
            target.write_bytes(original)
            forced = 1_000_000_000
            os.utime(target, ns=(forced, forced))
            result = self.run_verify("identity", "snapshot", after, env=env, cwd=repo)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(self._blob_sha(after, "src/main.rs"), before_sha)
            self.assertNotEqual(self._stat_tuple(after, "src/main.rs"), before_stat)
            for record in ("inputs.sha256", "inputs.blob"):
                self.assertEqual((before / record).read_bytes(),
                                 (after / record).read_bytes(), record)
            result = self.run_verify("identity", "compare", before, after, env=env, cwd=repo)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("SOURCE-IDENTITY-DRIFT-BYTE-IDENTICAL", result.stderr)
            self.assertIn("src/main.rs", result.stderr)
            self.assertIn(before_sha, result.stderr)
            self.assertIn("mtime_ns", result.stderr)

    def test_identity_compare_names_a_content_drift(self):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            repo, _tools, env, _files = synthetic_identity_repo(temp)
            target = repo / "src/main.rs"
            before, after = temp / "before", temp / "after"
            result = self.run_verify("identity", "snapshot", before, env=env, cwd=repo)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            before_sha = self._blob_sha(before, "src/main.rs")
            target.write_text("synthetic input: src/main.rs changed\n")
            result = self.run_verify("identity", "snapshot", after, env=env, cwd=repo)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            after_sha = self._blob_sha(after, "src/main.rs")
            self.assertNotEqual(after_sha, before_sha)
            result = self.run_verify("identity", "compare", before, after, env=env, cwd=repo)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("SOURCE-IDENTITY-DRIFT-CONTENT", result.stderr)
            self.assertIn("src/main.rs", result.stderr)
            self.assertIn(before_sha, result.stderr)
            self.assertIn(after_sha, result.stderr)

    def test_identity_compare_refuses_a_snapshot_without_the_witness(self):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            repo, _tools, env, _files = synthetic_identity_repo(temp)
            before, after = temp / "before", temp / "after"
            for snapshot in (before, after):
                result = self.run_verify("identity", "snapshot", snapshot, env=env, cwd=repo)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            for witness in ("inputs.blob", "inputs.stat"):
                saved = (after / witness).read_bytes()
                (after / witness).unlink()
                result = self.run_verify("identity", "compare", before, after,
                                         env=env, cwd=repo)
                self.assertNotEqual(result.returncode, 0, witness)
                self.assertIn("SOURCE-IDENTITY-UNKNOWN", result.stderr)
                self.assertIn(witness, result.stderr)
                (after / witness).write_bytes(saved)

    def test_identity_compare_refuses_an_emptied_witness(self):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            repo, _tools, env, _files = synthetic_identity_repo(temp)
            before, after = temp / "before", temp / "after"
            for snapshot in (before, after):
                result = self.run_verify("identity", "snapshot", snapshot, env=env, cwd=repo)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            witnesses = ("inputs.blob", "inputs.stat")
            saved = {(snapshot, witness): (snapshot / witness).read_bytes()
                     for snapshot in (before, after) for witness in witnesses}
            for snapshot in (before, after):
                for witness in witnesses:
                    (snapshot / witness).write_bytes(b"")
            # Zero rows on both sides must never compare equal: that was the
            # false PASS (exit 0, STABLE-OK) this test exists to keep closed.
            result = self.run_verify("identity", "compare", before, after,
                                     env=env, cwd=repo)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("SOURCE-IDENTITY-UNKNOWN", result.stderr)
            # The zero-row refusal is load-bearing for the message an operator
            # reads: without it this path degrades into the coverage refusal
            # ("misses inputs ..."), which the UNKNOWN token alone cannot tell
            # apart. load() reads before/inputs.blob first.
            self.assertIn("inputs.blob has zero rows", result.stderr)
            self.assertIn("boundary inputs not observable", result.stderr)
            self.assertNotIn("STABLE-OK", result.stdout + result.stderr)
            for (snapshot, witness), payload in saved.items():
                (snapshot / witness).write_bytes(payload)
            # One witness emptied in either snapshot is unobservable too, and
            # the refusal names the record that could not be read.
            for witness in witnesses:
                for target in (before, after):
                    payload = (target / witness).read_bytes()
                    (target / witness).write_bytes(b"")
                    result = self.run_verify("identity", "compare", before, after,
                                             env=env, cwd=repo)
                    self.assertNotEqual(result.returncode, 0, witness)
                    self.assertIn("SOURCE-IDENTITY-UNKNOWN", result.stderr)
                    self.assertIn(witness, result.stderr)
                    self.assertIn(f"{witness} has zero rows", result.stderr)
                    self.assertIn("boundary inputs not observable", result.stderr)
                    self.assertNotIn("STABLE-OK", result.stdout + result.stderr)
                    (target / witness).write_bytes(payload)

    def test_identity_compare_names_one_empty_witness_unknown_not_drift(self):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            repo, _tools, env, _files = synthetic_identity_repo(temp)
            before, after = temp / "before", temp / "after"
            for snapshot in (before, after):
                result = self.run_verify("identity", "snapshot", snapshot, env=env, cwd=repo)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            for witness in ("inputs.blob", "inputs.stat"):
                saved = (after / witness).read_bytes()
                (after / witness).write_bytes(b"")
                result = self.run_verify("identity", "compare", before, after,
                                         env=env, cwd=repo)
                self.assertNotEqual(result.returncode, 0, witness)
                self.assertIn("SOURCE-IDENTITY-UNKNOWN", result.stderr)
                # One side emptied is unobservable. DRIFT-CONTENT would assert
                # an input-set change that the witness never showed.
                self.assertNotIn("SOURCE-IDENTITY-DRIFT-CONTENT", result.stderr)
                self.assertNotIn("STABLE-OK", result.stdout + result.stderr)
                (after / witness).write_bytes(saved)

    def test_identity_compare_refuses_a_witness_that_drops_an_input(self):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            repo, _tools, env, _files = synthetic_identity_repo(temp)
            before, after = temp / "before", temp / "after"
            for snapshot in (before, after):
                result = self.run_verify("identity", "snapshot", snapshot, env=env, cwd=repo)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            saved = {witness: (after / witness).read_bytes()
                     for witness in ("inputs.blob", "inputs.stat")}
            rows = {witness: payload.splitlines(keepends=True)
                    for witness, payload in saved.items()}
            dropped = rows["inputs.stat"][0].split(b"\t")[0]
            self.assertIn(dropped, {row.split(b"\t")[0]
                                    for row in rows["inputs.blob"]})
            # Drop the SAME input from both witnesses, so the pair still covers
            # one another; only the snapshot's own content record still names
            # the input, and that is what the witness must be measured against.
            for witness, payload in rows.items():
                kept = [row for row in payload
                        if not row.startswith(dropped + b"\t")]
                self.assertEqual(len(kept), len(payload) - 1, witness)
                (after / witness).write_bytes(b"".join(kept))
            hashed = {line.split(maxsplit=1)[1]
                      for line in (after / "inputs.sha256").read_text().splitlines()}
            self.assertIn(dropped.decode(), hashed)
            result = self.run_verify("identity", "compare", before, after,
                                     env=env, cwd=repo)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("SOURCE-IDENTITY-UNKNOWN", result.stderr)
            self.assertIn(dropped.decode(), result.stderr)
            self.assertNotIn("SOURCE-IDENTITY-DRIFT-CONTENT", result.stderr)
            self.assertNotIn("STABLE-OK", result.stdout + result.stderr)
            for witness, payload in saved.items():
                (after / witness).write_bytes(payload)

    def test_identity_compare_refuses_an_unreadable_input_set(self):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            repo, _tools, env, _files = synthetic_identity_repo(temp)
            before, after = temp / "before", temp / "after"
            for snapshot in (before, after):
                result = self.run_verify("identity", "snapshot", snapshot, env=env, cwd=repo)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            saved = (after / "inputs.sha256").read_bytes()
            # The expected input set is the content record's own, so a record
            # that is empty or unparseable leaves the coverage claim
            # unobservable rather than satisfied.
            for unreadable in (b"", b"not-a-digest-and-path\n"):
                (after / "inputs.sha256").write_bytes(unreadable)
                result = self.run_verify("identity", "compare", before, after,
                                         env=env, cwd=repo)
                self.assertNotEqual(result.returncode, 0, unreadable)
                self.assertIn("SOURCE-IDENTITY-UNKNOWN", result.stderr)
                self.assertIn("inputs.sha256", result.stderr)
                self.assertIn("boundary inputs not observable", result.stderr)
                self.assertNotIn("SOURCE-IDENTITY-DRIFT-CONTENT", result.stderr)
                self.assertNotIn("STABLE-OK", result.stdout + result.stderr)
            (after / "inputs.sha256").write_bytes(saved)

    def test_identity_compare_names_a_missing_record_unknown(self):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            repo, _tools, env, _files = synthetic_identity_repo(temp)
            before, after = temp / "before", temp / "after"
            for snapshot in (before, after):
                result = self.run_verify("identity", "snapshot", snapshot, env=env, cwd=repo)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            for name in ("head", "status", "inputs.sha256", "env"):
                saved = (after / name).read_bytes()
                (after / name).unlink()
                result = self.run_verify("identity", "compare", before, after,
                                         env=env, cwd=repo)
                self.assertNotEqual(result.returncode, 0, name)
                self.assertIn("SOURCE-IDENTITY-UNKNOWN", result.stderr)
                self.assertIn(name, result.stderr)
                self.assertNotIn("SOURCE-IDENTITY-CHANGED", result.stderr)
                self.assertNotIn("STABLE-OK", result.stdout + result.stderr)
                (after / name).write_bytes(saved)

    def test_identity_compare_refuses_a_witness_row_with_no_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            repo, _tools, env, before, after = self._identity_pair(temp)
            # A key with no evidence: '<path><TAB>' (blob, width 2) and
            # '<path><TAB><TAB><TAB><TAB>' (stat, width 5). Two such rows compare
            # equal, so without the cell rule this pair certified STABLE-OK with
            # nothing observed.
            for witness in ("inputs.blob", "inputs.stat"):
                saved = {snapshot: (snapshot / witness).read_bytes()
                         for snapshot in (before, after)}
                for snapshot in (before, after):
                    rows = []
                    for line in (snapshot / witness).read_text().splitlines():
                        fields = line.split("\t")
                        rows.append(fields[0] + "\t" * (len(fields) - 1))
                    (snapshot / witness).write_bytes(
                        ("\n".join(rows) + "\n").encode())
                result = self.run_verify("identity", "compare", before, after,
                                         env=env, cwd=repo)
                self.assertNotEqual(result.returncode, 0, witness)
                self.assertIn("SOURCE-IDENTITY-UNKNOWN", result.stderr)
                # The refusal names the record and the row, so the operator can
                # find the row rather than re-derive which record failed.
                self.assertIn(witness, result.stderr)
                self.assertIn("line 1", result.stderr)
                self.assertIn("boundary inputs not observable", result.stderr)
                self.assertNotIn("SOURCE-IDENTITY-CHANGED", result.stderr)
                self.assertNotIn("STABLE-OK", result.stdout + result.stderr)
                for snapshot, payload in saved.items():
                    (snapshot / witness).write_bytes(payload)

    def test_identity_compare_refuses_an_untypable_stat_cell(self):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            repo, _tools, env, before, after = self._identity_pair(temp)
            saved = {snapshot: (snapshot / "inputs.stat").read_bytes()
                     for snapshot in (before, after)}
            # The stat writer renders %d: 'abc' is not an observation, and '007'
            # is not the rendering int() produces. Both sides carry the same
            # value, so a presence-only guard sees an equal tuple and certifies
            # the byte-identical detection the stat witness exists for.
            for payload in ("abc", "007"):
                for snapshot in (before, after):
                    rewrite_column(snapshot / "inputs.stat", 3, payload)
                result = self.run_verify("identity", "compare", before, after,
                                         env=env, cwd=repo)
                self.assertNotEqual(result.returncode, 0, payload)
                self.assertIn("SOURCE-IDENTITY-UNKNOWN", result.stderr)
                self.assertIn("inputs.stat", result.stderr)
                self.assertIn("boundary inputs not observable", result.stderr)
                self.assertNotIn("DRIFT-BYTE-IDENTICAL", result.stderr)
                self.assertNotIn("STABLE-OK", result.stdout + result.stderr)
            for snapshot, payload in saved.items():
                (snapshot / "inputs.stat").write_bytes(payload)

    def test_identity_compare_refuses_an_untypable_blob_name(self):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            repo, _tools, env, before, after = self._identity_pair(temp)
            saved = {snapshot: (snapshot / "inputs.blob").read_bytes()
                     for snapshot in (before, after)}
            # `git hash-object` emits a lowercase object name: 40 hex for a sha1
            # repository, 64 for a sha256 one. A short name, or upper case (which
            # git never prints), is not evidence about the input.
            for payload in ("deadbeef", "A" * 64):
                for snapshot in (before, after):
                    rewrite_column(snapshot / "inputs.blob", 1, payload)
                result = self.run_verify("identity", "compare", before, after,
                                         env=env, cwd=repo)
                self.assertNotEqual(result.returncode, 0, payload)
                self.assertIn("SOURCE-IDENTITY-UNKNOWN", result.stderr)
                self.assertIn("inputs.blob", result.stderr)
                self.assertIn("boundary inputs not observable", result.stderr)
                self.assertNotIn("SOURCE-IDENTITY-DRIFT-CONTENT", result.stderr)
                self.assertNotIn("STABLE-OK", result.stdout + result.stderr)
            for snapshot, payload in saved.items():
                (snapshot / "inputs.blob").write_bytes(payload)

    def test_identity_compare_refuses_a_head_that_is_not_one_git_object_name(self):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            repo, _tools, env, before, after = self._identity_pair(temp)
            saved = {snapshot: (snapshot / "head").read_bytes()
                     for snapshot in (before, after)}
            # The writer records `git rev-parse --verify HEAD`: one lowercase
            # object name and one newline. An empty file, prose, a truncated
            # name and an extra line are all records the comparer cannot
            # interpret, and none may be compared as if they were the same value.
            for payload in (b"", b"notasha\n", b"0" * 39 + b"\n",
                            b"0" * 40 + b"\n\n"):
                for snapshot in (before, after):
                    (snapshot / "head").write_bytes(payload)
                result = self.run_verify("identity", "compare", before, after,
                                         env=env, cwd=repo)
                self.assertNotEqual(result.returncode, 0, payload)
                self.assertIn("SOURCE-IDENTITY-UNKNOWN", result.stderr)
                self.assertIn("head", result.stderr)
                self.assertIn("boundary inputs not observable", result.stderr)
                self.assertNotIn("SOURCE-IDENTITY-CHANGED", result.stderr)
                self.assertNotIn("STABLE-OK", result.stdout + result.stderr)
            for snapshot, payload in saved.items():
                (snapshot / "head").write_bytes(payload)

    def test_identity_compare_refuses_an_empty_env_record(self):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            repo, _tools, env, before, after = self._identity_pair(temp)
            saved = {snapshot: (snapshot / "env").read_bytes()
                     for snapshot in (before, after)}
            # An env record carries its evidence in its bytes: two zero-byte
            # records are an empty claim, not an agreement about the build
            # environment.
            for snapshot in (before, after):
                (snapshot / "env").write_bytes(b"")
            result = self.run_verify("identity", "compare", before, after,
                                     env=env, cwd=repo)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("SOURCE-IDENTITY-UNKNOWN", result.stderr)
            self.assertIn("env empty", result.stderr)
            self.assertIn("boundary inputs not observable", result.stderr)
            self.assertNotIn("SOURCE-IDENTITY-CHANGED", result.stderr)
            self.assertNotIn("STABLE-OK", result.stdout + result.stderr)
            for snapshot, payload in saved.items():
                (snapshot / "env").write_bytes(payload)

    def test_identity_compare_accepts_an_empty_status_record(self):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            repo, _tools, env, before, after = self._identity_pair(temp)
            # The per-record emptiness rule is named, not a blanket "no empty
            # files" sweep: an empty status IS the clean-tree observation, so
            # refusing it would be a false UNKNOWN on correct input.
            for snapshot in (before, after):
                (snapshot / "status").write_bytes(b"")
            result = self.run_verify("identity", "compare", before, after,
                                     env=env, cwd=repo)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("SOURCE-IDENTITY-STABLE-OK", result.stdout)

    def test_identity_compare_refuses_a_witness_row_the_record_never_named(self):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            repo, _tools, env, before, after = self._identity_pair(temp)
            saved = (after / "inputs.blob").read_bytes()
            # A row the snapshot's own content record never named is invented
            # evidence: it must be refused by name, not diffed as a drift.
            (after / "inputs.blob").write_bytes(
                saved + b"invented/input\t" + b"0" * 64 + b"\n")
            result = self.run_verify("identity", "compare", before, after,
                                     env=env, cwd=repo)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("SOURCE-IDENTITY-UNKNOWN", result.stderr)
            self.assertIn("invented/input", result.stderr)
            self.assertIn("boundary inputs not observable", result.stderr)
            self.assertNotIn("SOURCE-IDENTITY-DRIFT-CONTENT", result.stderr)
            self.assertNotIn("STABLE-OK", result.stdout + result.stderr)
            (after / "inputs.blob").write_bytes(saved)

    def test_identity_compare_refuses_a_record_that_is_not_utf8(self):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            repo, _tools, env, before, after = self._identity_pair(temp)
            for name in ("inputs.blob", "inputs.stat", "inputs.sha256"):
                saved = (after / name).read_bytes()
                # A record that is not UTF-8 cannot be observed. An uncaught
                # decode error is a traceback that exits 1, which reads as drift.
                (after / name).write_bytes(b"\xff\xfe\x00not utf-8\n")
                result = self.run_verify("identity", "compare", before, after,
                                         env=env, cwd=repo)
                self.assertNotEqual(result.returncode, 0, name)
                self.assertIn("SOURCE-IDENTITY-UNKNOWN", result.stderr)
                self.assertIn(name, result.stderr)
                self.assertIn("boundary inputs not observable", result.stderr)
                self.assertNotIn("Traceback", result.stderr)
                self.assertNotIn("STABLE-OK", result.stdout + result.stderr)
                (after / name).write_bytes(saved)

    @unittest.skipIf(os.geteuid() == 0,
                     "root can read a mode-000 record; the unreadable shape is unavailable")
    def test_identity_compare_keeps_an_unreadable_record_unknown(self):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            repo, _tools, env, before, after = self._identity_pair(temp)
            record = after / "head"
            saved = record.read_bytes()
            record.chmod(0o000)
            try:
                result = self.run_verify("identity", "compare", before, after,
                                         env=env, cwd=repo)
            finally:
                record.chmod(0o644)
            self.assertEqual(record.read_bytes(), saved)
            # A record the comparer cannot read is unobservable: it is never a
            # CHANGED verdict about the value it was supposed to carry.
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("SOURCE-IDENTITY-UNKNOWN", result.stderr)
            self.assertIn("head", result.stderr)
            self.assertIn("boundary inputs not observable", result.stderr)
            self.assertNotIn("SOURCE-IDENTITY-CHANGED", result.stderr)
            self.assertNotIn("STABLE-OK", result.stdout + result.stderr)

    def _compare_path_tools(self, temp, name, missing):
        """A PATH holding only the compare path's prerequisites, minus one."""
        tools = temp / name
        tools.mkdir()
        for tool in ("sh", "cat", "cmp", "python3"):
            if tool in missing:
                continue
            found = shutil.which(tool)
            self.assertIsNotNone(found, tool)
            (tools / tool).symlink_to(found)
        return tools

    def test_identity_compare_keeps_a_cmp_failure_unknown(self):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            repo, _tools, env, before, after = self._identity_pair(temp)
            tools = self._compare_path_tools(temp, "tools-cmp-error", ())
            (tools / "cmp").unlink()
            # cmp refuses to read an operand (exit 2). That is an operational
            # failure about the probe, never a CHANGED verdict about the value.
            (tools / "cmp").write_text("#!/bin/sh\nexit 2\n")
            (tools / "cmp").chmod(0o755)
            result = self.run_verify("identity", "compare", before, after,
                                     env={**env, "PATH": str(tools)}, cwd=repo)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("SOURCE-IDENTITY-UNKNOWN", result.stderr)
            self.assertIn("boundary inputs not observable", result.stderr)
            self.assertNotIn("SOURCE-IDENTITY-CHANGED", result.stderr)
            self.assertNotIn("STABLE-OK", result.stdout + result.stderr)

    def test_identity_compare_keeps_an_absent_cmp_unknown(self):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            repo, _tools, env, before, after = self._identity_pair(temp)
            tools = self._compare_path_tools(temp, "tools-no-cmp", ("cmp",))
            result = self.run_verify("identity", "compare", before, after,
                                     env={**env, "PATH": str(tools)}, cwd=repo)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("SOURCE-IDENTITY-UNKNOWN", result.stderr)
            self.assertIn("boundary inputs not observable", result.stderr)
            self.assertNotIn("SOURCE-IDENTITY-CHANGED", result.stderr)
            self.assertNotIn("STABLE-OK", result.stdout + result.stderr)

    def test_identity_compare_keeps_an_absent_interpreter_unknown(self):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            repo, _tools, env, before, after = self._identity_pair(temp)
            tools = self._compare_path_tools(temp, "tools-no-python", ("python3",))
            # No interpreter means the witness was never examined: an absent
            # tool is unobservable, never a drift about the inputs themselves.
            result = self.run_verify("identity", "compare", before, after,
                                     env={**env, "PATH": str(tools)}, cwd=repo)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("SOURCE-IDENTITY-UNKNOWN", result.stderr)
            self.assertIn("python3", result.stderr)
            self.assertIn("boundary inputs not observable", result.stderr)
            self.assertNotIn("SOURCE-IDENTITY-CHANGED", result.stderr)
            self.assertNotIn("STABLE-OK", result.stdout + result.stderr)

    def test_snapshot_refuses_a_failed_witness_producer(self):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            repo, _tools, env, _files = synthetic_identity_repo(temp)
            result = self.run_verify("identity", "snapshot", temp / "blob-fail",
                                     env={**env, "FIXTURE_BLOB_FAIL": "1"}, cwd=repo)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("SOURCE-IDENTITY FAIL", result.stderr)
            self.assertIn("blob batch exit 43", result.stderr)
            shim = temp / "python3"
            shim.write_text("#!/bin/sh\nexit 44\n")
            shim.chmod(0o755)
            result = self.run_verify("identity", "snapshot", temp / "stat-fail",
                                     env={**env, "PATH": f"{temp}:{env['PATH']}"}, cwd=repo)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("SOURCE-IDENTITY FAIL", result.stderr)
            self.assertIn("stat pass failed", result.stderr)

    def test_snapshot_refuses_an_absent_python3(self):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            repo, tools, env, _files = synthetic_identity_repo(temp)
            for name in ("sh", "mkdir", "shasum", "sed", "sort", "paste", "wc", "rm", "cut"):
                found = shutil.which(name)
                self.assertIsNotNone(found, name)
                (tools / name).symlink_to(found)
            result = self.run_verify("identity", "snapshot", temp / "no-python3",
                                     env={**env, "PATH": str(tools)}, cwd=repo)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("SOURCE-IDENTITY FAIL", result.stderr)
            self.assertIn("python3 required", result.stderr)

    def test_audit_deny_pins_and_failures(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            for name, body in {
                "cargo-audit": 'printf "cargo-audit %s\\n" "${MOCK_AUDIT_VERSION:-0.22.1}"',
                "cargo-deny": 'printf "cargo-deny %s\\n" "${MOCK_DENY_VERSION:-0.19.4}"',
                "cargo": 'case "$1" in audit) exit "${AUDIT_EXIT:-0}";; deny) exit "${DENY_EXIT:-0}";; esac; exit 99',
            }.items():
                exe = path / name
                exe.write_text("#!/bin/sh\n" + body + "\n")
                exe.chmod(0o755)
            env = {"PATH": f"{path}:{os.environ['PATH']}"}
            result = self.run_verify("supply-chain", "audit-deny", env=env)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("AUDIT-DENY-OK", result.stdout)
            for setting, expected in (
                ("MOCK_AUDIT_VERSION", "cargo-audit version"),
                ("MOCK_DENY_VERSION", "cargo-deny version"),
                ("AUDIT_EXIT", "cargo audit exit 99"),
                ("DENY_EXIT", "cargo deny exit 99"),
            ):
                result = self.run_verify("supply-chain", "audit-deny", env={**env, setting: "99"})
                self.assertNotEqual(result.returncode, 0, setting)
                self.assertIn("AUDIT-DENY FAIL", result.stderr)
                self.assertIn(expected, result.stderr, setting)

    def test_mocked_host_mid_dispatch_and_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp) / "repo"
            (repo / "scripts").mkdir(parents=True)
            shutil.copyfile(ROOT / "scripts/verify.sh", repo / "scripts/verify.sh")
            podman = Path(temp) / "podman"
            podman.write_text('''#!/bin/sh
case "$3 $4" in
  "image inspect") printf 'sha256:test\\n';;
  "run --rm") [ "$ALT_NO_VOLUME" != 1 ] || [ -d "$PWD/target" ] || { echo 'missing target bind source' >&2; exit 1; }; printf '%s\\n' "$*" >> "$DISPATCH_LOG"; exit "${DISPATCH_EXIT:-0}";;
esac
''')
            podman.chmod(0o755)
            # The scan derives its witness-off root from `cargo metadata`; the
            # fixture repo carries no manifest, so the stub answers as cargo does
            # for this checkout (the dispatch plumbing, not Cargo, is under test).
            cargo = Path(temp) / "cargo"
            cargo.write_text(
                f"#!/bin/sh\nprintf '%s\\n' '{{\"target_directory\":\"{repo}/target\"}}'\n")
            cargo.chmod(0o755)
            log = Path(temp) / "calls"
            env = {"PATH": f"{temp}:{os.environ['PATH']}", "PODMAN_CONNECTION": "test",
                   "DISPATCH_LOG": str(log), "ALT_NO_VOLUME": "1"}
            result = self.run_verify("host-mid", "foundations", env=env, cwd=repo)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("sh scripts/verify.sh mid foundations", log.read_text())
            result = self.run_verify("host-mid", "foundations", env={**env, "DISPATCH_EXIT": "42"}, cwd=repo)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("LINUX-MID FAIL", result.stderr)
            result = self.run_verify("host-mid", "union", env=env, cwd=repo)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("ALT-COPY-SKIPPED", result.stderr)
            result = self.run_verify("host-mid", "union", env={**env, "ALT_NO_VOLUME": "0"}, cwd=repo)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("ALT-COPY-FAIL", result.stderr)
            self.assertEqual(self.run_verify("host-mid", "unknown", env=env, cwd=repo).returncode, 2)

    def gate_child_scan(self, temp, synthetic, env=None, metadata=None, cargo=None,
                        reject_wide_ps=False, restrict_path=False, repo_name="repo"):
        """Runs the shipped gate-child scan in a temp repo whose `ps` prints the
        real listing plus the planted lines: the real listing satisfies the
        scan's self-listing precondition, so only the planted lines are tested.
        `PWD` pins the logical checkout spelling; `pwd -P` supplies the physical
        one, so on a host whose temp root is a symlink both are covered.
        `repo_name` moves the checkout under a name carrying a separator.

        `cargo metadata` is stubbed as well, because the scan derives its
        witness-off build root from cargo: `metadata` is the JSON text the stub
        prints (default: a target_directory under the temp repo) and `cargo`
        replaces the stub outright to drive a failing or unusable producer. The
        stub also records every invocation in `cargo-calls.txt` and refuses any
        argv other than the scan's pinned one.
        `reject_wide_ps` makes the stub refuse every `-ww` form, so the scan
        falls back to a truncating listing form; `restrict_path` runs the scan
        with no PATH beyond the stubs (to exercise an absent prerequisite)."""
        repo, tools = temp / repo_name, temp / "tools"
        (repo / "scripts").mkdir(parents=True)
        tools.mkdir()
        shutil.copyfile(ROOT / "scripts/verify.sh", repo / "scripts/verify.sh")
        cat = shutil.which("cat")
        listing = temp / "synthetic-ps.txt"
        listing.write_text("".join(f"{line}\n" for line in synthetic))
        ps = tools / "ps"
        wide_guard = 'case "$*" in *-ww*) exit 1;; esac\n' if reject_wide_ps else ""
        # Absolute cat: the stubs stay usable when PATH holds nothing else.
        ps.write_text(f'#!/bin/sh\n{wide_guard}"{shutil.which("ps")}" -eo pid=,ppid=,args=\n"{cat}" "{listing}"\n')
        ps.chmod(0o755)
        metadata_path = temp / "metadata.json"
        # Compact JSON, i.e. cargo's own serde_json output shape (the scan reads
        # an exact `"target_directory":"` field, never a formatted document).
        metadata_path.write_text(metadata if metadata is not None
                                 else json.dumps({"target_directory": str(repo / "target")},
                                                 separators=(",", ":")))
        cargo_stub = tools / "cargo"
        cargo_calls = temp / "cargo-calls.txt"
        cargo_stub.write_text(cargo if cargo is not None else (
            "#!/bin/sh\n"
            f'printf \'%s\\n\' "$*" >> "{cargo_calls}"\n'
            'case "$*" in\n'
            '  "metadata --no-deps --format-version 1 --locked") ;;\n'
            '  *) echo "cargo stub: unexpected invocation: $*" >&2; exit 64 ;;\n'
            "esac\n"
            f'"{cat}" "{metadata_path}"\n'))
        cargo_stub.chmod(0o755)
        path = f"{tools}:{os.environ['PATH']}"
        if restrict_path:
            (tools / "sh").symlink_to(shutil.which("sh"))
            path = str(tools)
        result = self.run_verify(
            "gate-children", "scan", cwd=repo,
            env={"PATH": path, "PWD": str(repo), **(env or {})})
        return repo, result

    def test_gate_child_leak_under_the_alloc_witness_root_fails(self):
        # The witness-on gate binaries are built with --target-dir
        # $ALT_AW_TARGET_DIR, so an unscanned aw root reports a real leak clean.
        hash_dir, suffix = "0" * 16, "1" * 16
        name = f"main_thread_serving-{suffix}"
        for case in ("logical", "physical", "absolute"):
            with self.subTest(case), tempfile.TemporaryDirectory() as temp:
                temp = Path(temp)
                repo = temp / "repo"
                physical = Path(os.path.realpath(repo))
                if case == "absolute":
                    absolute = temp / "aw-absolute"
                    env = {"ALT_AW_TARGET_DIR": str(absolute)}
                    root = absolute / "debug/build/alumina"
                else:
                    env = {}
                    checkout = repo if case == "logical" else physical
                    root = checkout / "target/aw/debug/build/alumina"
                aw = root / hash_dir / "out" / name
                repo, result = self.gate_child_scan(temp, [f"991001 1 {aw}"], env=env)
                self.assertNotEqual(result.returncode, 0, case + result.stdout + result.stderr)
                self.assertIn("GATE-CHILD-LEAK-FAIL", result.stderr, case)
                self.assertIn(str(aw), result.stderr, case)

    def test_gate_child_scan_fails_closed_on_a_whitespace_build_root(self):
        # A value carrying a space is refused at the source, before composition:
        # the composed root is never built from an unbound value.
        with tempfile.TemporaryDirectory() as temp:
            _, result = self.gate_child_scan(
                Path(temp), [], env={"ALT_AW_TARGET_DIR": "aw root"})
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("GATE-CHILD-LEAK-UNKNOWN", result.stderr)
            self.assertIn("ALT_AW_TARGET_DIR contains whitespace", result.stderr)

    def test_gate_child_scan_binds_a_separator_in_the_knob_before_composition(self):
        # B1: a whitespace-carrying SOURCE value cannot become one root the
        # line-oriented listing can delimit, so it is refused at the value. The
        # defect this pins was a line-joined root list: a separator inside a
        # value fragmented it into whitespace-free pieces that each passed the
        # per-root check and named roots cargo never execs from.
        for label, value in (
            ("LF", "a\nb"),
            ("CR", "aw\rx"),
            ("tab", "aw\tx"),
            ("trailing-space", "aw "),
        ):
            with self.subTest(label), tempfile.TemporaryDirectory() as temp:
                _, result = self.gate_child_scan(
                    Path(temp), [], env={"ALT_AW_TARGET_DIR": value})
                self.assertNotEqual(result.returncode, 0,
                                    label + result.stdout + result.stderr)
                self.assertIn("GATE-CHILD-LEAK-UNKNOWN", result.stderr, label)
                self.assertIn("ALT_AW_TARGET_DIR contains whitespace",
                              result.stderr, label)
                self.assertNotIn("GATE-CHILD-LEAK-OK", result.stdout, label)

    def test_gate_child_scan_transports_roots_as_values_not_a_line_list(self):
        # B1 structural pin: the roots are carried as values (positional
        # parameters, then a per-root environment value) from composition to
        # matching. A line-joined intermediate is the representation that
        # reopened this defect class three times (trailing separator, `./`
        # prefix, LF), so the banned shapes are asserted absent and the value
        # transport present. A green behavioural pin alone cannot hold this:
        # the separator patch kept every behavioural test green.
        body = extract_function("assert_no_leaked_gate_children")
        for banned in ('printf "%s\\n", root',
                       'split(ENVIRON["GL_ROOTS"]',
                       "GL_ROOTS=",
                       "_gl_roots",
                       "<<EOF",
                       "eval "):
            self.assertNotIn(banned, body,
                             f"line-joined root transport is back: {banned}")
        for required in ("set --", 'for _gl_root in "$@"',
                         'GL_ROOT="$_gl_root"',
                         '${_gl_meta#"$_gl_checkout"/}'):
            self.assertIn(required, body,
                          f"root value transport is missing: {required}")

    def test_gate_child_scan_binds_the_metadata_answer_before_composition(self):
        # The same source binding applies to cargo's answer. A space survives
        # verbatim from CARGO_TARGET_DIR and is reachable, so it is bound at the
        # source; the escaping separators (LF, CR, TAB) are JSON-escaped by cargo
        # and already leave no readable value, which fails closed too.
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            document = ('{"target_directory":"' + str(temp / "repo" / "tar get")
                        + '"}\n')
            _, result = self.gate_child_scan(temp, [], metadata=document)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("GATE-CHILD-LEAK-UNKNOWN", result.stderr)
            self.assertIn("cargo metadata target_directory contains whitespace",
                          result.stderr)
            self.assertNotIn("GATE-CHILD-LEAK-OK", result.stdout)
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            document = ('{"target_directory":"' + str(temp / "repo" / "tar\nget")
                        + '"}\n')
            _, result = self.gate_child_scan(temp, [], metadata=document)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("GATE-CHILD-LEAK-UNKNOWN", result.stderr)
            self.assertNotIn("GATE-CHILD-LEAK-OK", result.stdout)

    def test_gate_child_scan_binds_a_checkout_spelling_before_composition(self):
        # A checkout spelling is a root source too: an LF in it fragments both
        # the witness-off and the witness-on root into clean-looking fragments.
        with tempfile.TemporaryDirectory() as temp:
            _, result = self.gate_child_scan(Path(temp), [], repo_name="re\npo")
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("GATE-CHILD-LEAK-UNKNOWN", result.stderr)
            self.assertIn("checkout spelling contains whitespace", result.stderr)
            self.assertNotIn("GATE-CHILD-LEAK-OK", result.stdout)

    def test_gate_child_scan_names_the_filesystem_root_refusal(self):
        # I2: '/' is a real value, so it is refused for its real reason. The
        # empty-component text would name a cause that is not the case.
        for label, env, metadata in (
            ("knob", {"ALT_AW_TARGET_DIR": "/"}, None),
            ("metadata", {}, '{"target_directory":"/"}\n'),
        ):
            with self.subTest(label), tempfile.TemporaryDirectory() as temp:
                _, result = self.gate_child_scan(
                    Path(temp), [], env=env, metadata=metadata)
                self.assertNotEqual(result.returncode, 0,
                                    label + result.stdout + result.stderr)
                self.assertIn("GATE-CHILD-LEAK-UNKNOWN", result.stderr, label)
                self.assertIn("is the filesystem root", result.stderr, label)
                self.assertIn("cannot be a build root", result.stderr, label)
                self.assertNotIn("empty, '.' or '..'", result.stderr, label)
                self.assertNotIn("is empty", result.stderr, label)

    def test_gate_child_scan_refuses_an_ambiguous_metadata_answer(self):
        # A1: last-wins lets a second key choose a root cargo never uses. The
        # answer is ambiguous, so it is refused rather than resolved by order.
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            repo = temp / "repo"
            document = ('{"target_directory":"' + str(repo / "target") + '",'
                        '"target_directory":"' + str(repo / "other") + '"}')
            _, result = self.gate_child_scan(temp, [], metadata=document)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("GATE-CHILD-LEAK-UNKNOWN", result.stderr)
            self.assertIn("more than once", result.stderr)
            self.assertIn("ambiguous", result.stderr)
            self.assertNotIn("GATE-CHILD-LEAK-OK", result.stdout)

    def test_gate_child_scan_pins_its_metadata_invocation(self):
        # A2: the derived root is only as good as the invocation that asked for
        # it, so the argv is pinned and a realistic cargo document (single-line
        # JSON, packages first, target_directory among later fields) is parsed to
        # the expected root.
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            repo = temp / "repo"
            document = json.dumps({
                "packages": [{
                    "name": "alumina",
                    "version": "0.1.0",
                    "id": f"path+file://{repo}#alumina",
                    "manifest_path": f"{repo}/Cargo.toml",
                    "targets": [{"kind": ["lib"], "name": "alumina"}],
                }],
                "workspace_members": [f"path+file://{repo}#alumina"],
                "workspace_default_members": [f"path+file://{repo}#alumina"],
                "resolve": None,
                "target_directory": str(repo / "target"),
                "version": 1,
                "workspace_root": str(repo),
                "metadata": None,
            }, separators=(",", ":"))
            _, result = self.gate_child_scan(temp, [], metadata=document)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn(f"{repo}/target/debug/build/alumina", result.stdout)
            self.assertEqual(
                (temp / "cargo-calls.txt").read_text().splitlines(),
                ["metadata --no-deps --format-version 1 --locked"])

    def test_gate_child_scan_ignores_non_matches_and_names_its_roots(self):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            repo = temp / "repo"
            inside = (repo / "target/aw/debug/build/alumina" / ("0" * 16) / "out"
                      / f"gate_child-{'1' * 16}")
            lines = [
                f"991003 1 /bin/sh -c cc -o {inside}",  # the path only among the args
                f"991004 4242 {inside}",                # argv0 inside a root, not reparented
                f"991005 1 /usr/bin/sleep 30",          # reparented, outside every root
            ]
            repo, result = self.gate_child_scan(temp, lines)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("GATE-CHILD-LEAK-OK", result.stdout)
            for checkout in {str(repo), os.path.realpath(repo)}:
                for room in ("target", "target/aw"):
                    self.assertIn(f"{checkout}/{room}/debug/build/alumina", result.stdout)

    def test_gate_child_scan_follows_cargo_to_a_relocated_target_directory(self):
        # F2: CARGO_TARGET_DIR (or a config-file build.target-dir) vacates
        # <checkout>/target, and a hardcoded witness-off root then scans a
        # directory nothing builds into: a real orphan reports clean.
        hash_dir, suffix = "0" * 16, "1" * 16
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            relocated = temp / "relocated"
            orphan = relocated / "debug/build/alumina" / hash_dir / "out" / f"gate_child-{suffix}"
            _, result = self.gate_child_scan(
                temp, [f"991010 1 {orphan}"],
                metadata=json.dumps({"target_directory": str(relocated)},
                                    separators=(",", ":")),
                env={"CARGO_TARGET_DIR": str(relocated)})
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("GATE-CHILD-LEAK-FAIL", result.stderr)
            self.assertIn(str(orphan), result.stderr)

    def test_gate_child_scan_normalises_a_trailing_slash_knob(self):
        # F1: cargo execs from <c>/target/aw/debug/... — Path push-join never
        # repeats a separator — so a literal concatenation scanned
        # <c>/target/aw//debug/... and reported a real orphan clean.
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            repo = temp / "repo"
            orphan = (repo / "target/aw/debug/build/alumina" / ("0" * 16) / "out"
                      / f"gate_child-{'1' * 16}")
            _, result = self.gate_child_scan(temp, [f"991011 1 {orphan}"],
                                             env={"ALT_AW_TARGET_DIR": "target/aw/"})
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("GATE-CHILD-LEAK-FAIL", result.stderr)
            self.assertIn(str(orphan), result.stderr)

    def test_gate_child_scan_refuses_an_unprovable_knob_spelling(self):
        # A spelling the scan cannot prove it can match is refused, never
        # guessed at: an OK line over a root cargo may not exec from is the
        # defect class the derived roots exist to remove.
        for spelling in ("", "./target/aw", "a/../aw", "target//aw"):
            with self.subTest(spelling=spelling), tempfile.TemporaryDirectory() as temp:
                _, result = self.gate_child_scan(
                    Path(temp), [], env={"ALT_AW_TARGET_DIR": spelling})
                self.assertNotEqual(result.returncode, 0,
                                    spelling + result.stdout + result.stderr)
                self.assertIn("GATE-CHILD-LEAK-UNKNOWN", result.stderr, spelling)
                self.assertIn(f"ALT_AW_TARGET_DIR='{spelling}'", result.stderr, spelling)

    def test_gate_child_scan_refuses_an_unusable_metadata_answer(self):
        # The witness-off root has one authority: cargo's own answer. A failing
        # producer, a missing field, an empty value and a JSON-escaped (hence
        # unreadable) path all leave the root underived — UNKNOWN, never a
        # silent fallback to <checkout>/target.
        for label, kwargs in (
            ("producer-failed", {"cargo": "#!/bin/sh\nexit 1\n"}),
            ("field-missing", {"metadata": "{}\n"}),
            ("value-empty", {"metadata": '{"target_directory":""}\n'}),
            ("value-escaped", {"metadata": '{"target_directory":"/tmp/a\\\\b"}\n'}),
        ):
            with self.subTest(label), tempfile.TemporaryDirectory() as temp:
                _, result = self.gate_child_scan(Path(temp), [], **kwargs)
                self.assertNotEqual(result.returncode, 0,
                                    label + result.stdout + result.stderr)
                self.assertIn("GATE-CHILD-LEAK-UNKNOWN", result.stderr, label)
                self.assertIn("target_directory", result.stderr, label)

    def test_gate_child_scan_normalises_a_trailing_slash_metadata_answer(self):
        # Measured cargo behaviour: target_directory is reported verbatim, so
        # CARGO_TARGET_DIR=relocated/ answers "<c>/relocated/". Composing that
        # literally would scan "<c>/relocated//debug/..." and report a real
        # orphan clean. The metadata root deliberately lies OUTSIDE
        # <checkout>/target and <checkout>/target/aw: a test whose root lies
        # inside them also passes against the hardcoded-root scan, so it pins
        # nothing (it was green on 0754829 for exactly that reason).
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            repo = temp / "repo"
            relocated = repo / "relocated"
            orphan = (relocated / "debug/build/alumina" / ("0" * 16) / "out"
                      / f"gate_child-{'1' * 16}")
            _, result = self.gate_child_scan(
                temp, [f"991012 1 {orphan}"],
                metadata='{"target_directory":"' + str(relocated) + '/"}\n',
                env={"CARGO_TARGET_DIR": "relocated/"})
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("GATE-CHILD-LEAK-FAIL", result.stderr)
            self.assertIn(str(orphan), result.stderr)

    def test_gate_child_scan_refuses_a_non_canonical_metadata_answer(self):
        # A './' component survives in cargo's answer, so the scan cannot prove
        # which argv[0] cargo execs from it: refused, never guessed at.
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp) / "repo"
            _, result = self.gate_child_scan(
                Path(temp), [],
                metadata='{"target_directory":"' + str(repo) + '/./target"}\n')
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("GATE-CHILD-LEAK-UNKNOWN", result.stderr)
            self.assertIn("cargo metadata target_directory=", result.stderr)

    def test_gate_child_scan_marks_an_absent_root_in_its_ok_line(self):
        # A root that does not exist (a legitimate pre-build state, or a
        # mis-spelling) must be visible in the receipt rather than implied.
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            repo = temp / "repo"
            (repo / "target/debug/build/alumina").mkdir(parents=True)
            _, result = self.gate_child_scan(temp, [])
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn(f"{repo}/target/debug/build/alumina", result.stdout)
            self.assertNotIn(f"{repo}/target/debug/build/alumina (absent)", result.stdout)
            self.assertIn(f"{repo}/target/aw/debug/build/alumina (absent)", result.stdout)

    def test_gate_child_scan_notes_a_truncating_listing_form(self):
        # F4 residual: busybox `ps` accepts no -ww form, and a truncated argv[0]
        # makes a real leak look matchless. The scan must not fail closed on the
        # portable fallback (it would red every busybox host), so it records the
        # residual in the receipt instead of hiding it.
        with tempfile.TemporaryDirectory() as temp:
            _, result = self.gate_child_scan(Path(temp), [], reject_wide_ps=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("GATE-CHILD-LEAK-OK", result.stdout)
            self.assertIn("GATE-CHILD-LEAK-NOTE", result.stderr)

    def test_gate_child_scan_without_awk_fails_closed(self):
        # F6: the scan's helpers run under `set -eu`, so a missing awk must still
        # produce a named UNKNOWN verdict rather than a bare abort with no
        # observation verdict at all.
        with tempfile.TemporaryDirectory() as temp:
            _, result = self.gate_child_scan(Path(temp), [], restrict_path=True)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("GATE-CHILD-LEAK-UNKNOWN", result.stderr)
            self.assertIn("awk", result.stderr)

    def test_fixture_artifact_provenance_across_connections(self):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            repo, tools = temp / "repo", temp / "tools"
            (repo / "scripts").mkdir(parents=True)
            (repo / "target/release").mkdir(parents=True)
            (repo / "target").chmod(0o700)
            tools.mkdir()
            for name in ("verify.sh", "fixture_metadata_probe.py"):
                shutil.copyfile(ROOT / "scripts" / name, repo / "scripts" / name)
            release = repo / "target/release/alumina"
            release.write_bytes(b"production")
            release.chmod(0o755)
            for name, content in (("rootless", b"fresh variant"), ("rootful", b"stale plausible variant")):
                volume = temp / name / "fixture-facts/release/alumina"
                volume.parent.mkdir(parents=True)
                volume.write_bytes(content)
                volume.chmod(0o755)
            podman = tools / "podman"
            podman.write_text('''#!/usr/bin/env python3
import hashlib, os, pathlib, shutil, subprocess, sys
a = sys.argv[1:]; conn = a[1]; cmd = a[2:]; base = pathlib.Path(os.environ["MOCK_BASE"])
root = pathlib.Path.cwd(); variant = root / "target/fixture-facts/release/alumina"
if cmd[:2] == ["image", "inspect"]: print("sha256:mock"); sys.exit(0)
if cmd[0] != "run": sys.exit(0)
script = cmd[cmd.index("-c") + 1]
# The variant build is identified by its dispatch content (the repo carries no
# toolchain pin, so no selector is available as the discriminator).
if '--features fixture-facts' in script and '--target-dir target/fixture-facts' in script:
    if os.environ.get("ALT_NO_VOLUME") == "1":
        variant.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(base / "rootless/fixture-facts/release/alumina", variant)
    sys.exit(0)
if 'cp "/t/$REL"' in script:
    variant.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(base / "rootless/fixture-facts/release/alumina", variant)
    print(hashlib.sha256(variant.read_bytes()).hexdigest()); sys.exit(0)
mounts = [cmd[i + 1] for i, v in enumerate(cmd[:-1]) if v == "-v"]
mounted = base / conn / "fixture-facts/release/alumina" if any(":/app/target:" in m for m in mounts) else variant
file_mount = next((m for m in mounts if m.endswith(":/fixture-alumina:ro,Z")), None)
if file_mount: mounted = pathlib.Path(file_mount.removesuffix(":/fixture-alumina:ro,Z"))
if conn == "rootful":
    assert str(root) + ":/app:ro,Z" in mounts
    assert cmd[cmd.index("--security-opt") + 1] == "no-new-privileges"
    assert cmd[cmd.index("--cap-add") + 1] == "NET_ADMIN" and cmd[cmd.index("--user") + 1] == "0:0"
    fault = os.environ.get("MOCK_FAULT")
    if fault == "digest": variant.write_bytes(b"tampered")
    if fault == "missing": variant.unlink()
    if fault == "setid": variant.chmod(0o4755)
expected = cmd[-1]
if "fixture_metadata_probe.py" in script:
    probe = next(line for line in script.splitlines() if "python3 /app/scripts/fixture_metadata_probe.py" in line)
    probe = probe.replace("/app/scripts/fixture_metadata_probe.py", str(root / "scripts/fixture_metadata_probe.py"))
    if conn == "rootful" and os.environ.get("MOCK_FAULT") == "probe":
        probe = probe.replace("fixture_metadata_probe.py", "missing_probe.py")
    probe = probe.replace("/fixture-alumina", str(mounted))
    check = subprocess.run(["sh", "-c", "set -eu\\n" + probe + "\\nprintf PROBE-OK", "--", expected], capture_output=True, text=True)
    if check.returncode: sys.stderr.write(check.stderr); sys.exit(check.returncode)
else:
    sys.stderr.write("missing per-fixture provenance probe\\n"); sys.exit(99)
if "setpriv" not in script and "mkdir -p /work" not in script:
    print("security.capability=absent"); sys.exit(0)
if not file_mount and (root / "target").stat().st_mode & 0o077 == 0:
    sys.stderr.write("uid 65534 cannot traverse target directory\\n"); sys.exit(99)
with open(base / "executed", "a") as log: log.write(conn + " " + mounted.read_text() + "\\n")
if "pid=$!" in script:
    print('level=info kind=startup_final status="terminated"\\nlevel=info kind=shutdown_final status="drained"\\nFIXTURE-POSITIVE-SUPERVISED: reaped child rc=0')
    sys.stderr.write('kernel-facts: ruid=65534 euid=65534 suid=65534 fsuid=65534 cap_eff=0 cap_prm=0 cap_amb=0 no_new_privs=1\\nalumina: warning: resolver 127.0.0.1 has no FQDN (IP#fqdn) metadata; plain DNS over port 53 only — the DoT (853) SNI/SAN identity surface is unavailable\\n'); sys.exit(0)
if conn == "rootful": facts, error = "65534 euid=65534 suid=65534 fsuid=65534 cap_eff=1000 cap_prm=1000 cap_amb=1000 no_new_privs=1", "non-empty effective capability set"
elif "--security-opt" not in cmd: facts, error = "65534 euid=65534 suid=65534 fsuid=65534 cap_eff=0 cap_prm=0 cap_amb=0 no_new_privs=0", "no_new_privs not set"
else: facts, error = "0 euid=0 suid=0 fsuid=0 cap_eff=800405fb cap_prm=800405fb cap_amb=0 no_new_privs=1", "process has a root UID (real/effective/saved/filesystem)"
sys.stderr.write("kernel-facts: ruid=" + facts + "\\nalumina: prerequisite failure: " + error + "\\n"); sys.exit(78)
''')
            podman.chmod(0o755)
            env = {"PATH": f"{tools}:{os.environ['PATH']}", "MOCK_BASE": str(temp),
                   "PODMAN_CONNECTION": "rootless", "PODMAN_ROOT_CONNECTION": "rootful"}
            for no_volume in ("0", "1"):
                log = temp / "executed"
                log.unlink(missing_ok=True)
                result = self.run_verify("fixtures", "boot", env={**env, "ALT_NO_VOLUME": no_volume}, cwd=repo)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(log.read_text().splitlines(), ["rootless fresh variant"] * 3 + ["rootful fresh variant"])
                for fault, marker in (("digest", "digest-mismatch"), ("missing", "stat-error"), ("setid", "setid"), ("probe", "can't open file")):
                    log.unlink()
                    result = self.run_verify("fixtures", "boot", env={**env, "ALT_NO_VOLUME": no_volume, "MOCK_FAULT": fault}, cwd=repo)
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn(marker, result.stdout + result.stderr)
                    self.assertNotIn("rootful", log.read_text())


class GateIntegrity(unittest.TestCase):
    def run_gate(self, repo, gate, env=None):
        (repo / "gate.sh").write_text(GATES + f"\n\n{gate}\n")
        return subprocess.run(
            ["sh", "gate.sh"], cwd=repo, text=True, capture_output=True,
            env={**os.environ, **(env or {})},
        )

    def sandbox(self, temp):
        repo, outside = Path(temp) / "repo", Path(temp) / "outside"
        (repo / "src").mkdir(parents=True)
        outside.mkdir()
        return repo, outside

    def test_symlinked_unsafe_source_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            repo, outside = self.sandbox(temp)
            (outside / "probe.rs").write_text(
                "fn probe() { unsafe { core::hint::unreachable_unchecked() } }\n")
            (repo / "src/probe_unsafe.rs").symlink_to(outside / "probe.rs")
            result = self.run_gate(repo, "unsafe_surface_gate")
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("UNSAFE-SURFACE-FAIL", result.stderr)
            self.assertIn("src/probe_unsafe.rs", result.stderr)

    def test_symlinked_clean_source_passes_and_scratch_roots_are_pruned(self):
        with tempfile.TemporaryDirectory() as temp:
            repo, outside = self.sandbox(temp)
            (outside / "clean.rs").write_text("pub fn clean() {}\n")
            (repo / "src/lib.rs").write_text("pub mod probe_clean;\n")
            (repo / "src/probe_clean.rs").symlink_to(outside / "clean.rs")
            for pruned in ("target", ".ooda"):
                (repo / pruned).mkdir()
                (repo / pruned / "planted.rs").write_text("fn planted() { unsafe {} }\n")
            nested_target = repo / "scripts/probe/build/target"
            nested_target.mkdir(parents=True)
            (nested_target / "planted.rs").write_text("fn planted() { unsafe {} }\n")
            result = self.run_gate(repo, "unsafe_surface_gate")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("UNSAFE-SURFACE-OK", result.stdout)

    def test_non_src_crate_source_stays_in_scan_universe(self):
        with tempfile.TemporaryDirectory() as temp:
            repo, _ = self.sandbox(temp)
            probe = repo / "scripts/probe"
            probe.mkdir(parents=True)
            (probe / "main.rs").write_text("fn main() { unsafe {} }\n")
            result = self.run_gate(repo, "unsafe_surface_gate")
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("scripts/probe/main.rs", result.stderr)

    def test_empty_scan_universe_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            repo, _ = self.sandbox(temp)
            result = self.run_gate(repo, "unsafe_surface_gate")
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("UNSAFE-SURFACE-SCAN-FAIL", result.stderr)

    def test_unsafe_scan_producer_error_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            repo, _ = self.sandbox(temp)
            (repo / "src/lib.rs").write_text("pub fn ok() {}\n")
            tools = Path(temp) / "tools"
            tools.mkdir()
            rg = tools / "rg"
            rg.write_text("#!/bin/sh\nexit 2\n")
            rg.chmod(0o755)
            result = self.run_gate(repo, "unsafe_surface_gate",
                                   env={"PATH": f"{tools}:{os.environ['PATH']}"})
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("UNSAFE-SURFACE-SCAN-FAIL", result.stderr)

    def test_grep_fallback_reads_an_explicit_symlink_path(self):
        with tempfile.TemporaryDirectory() as temp:
            repo, outside = self.sandbox(temp)
            (outside / "evil.rs").write_text("fn evil() { unsafe {} }\n")
            (repo / "src/linked.rs").symlink_to(outside / "evil.rs")
            tools = Path(temp) / "tools"
            tools.mkdir()
            for name in ("find", "sed", "grep", "awk", "dirname", "basename", "mktemp", "xargs"):
                target = shutil.which(name)
                self.assertIsNotNone(target, name)
                (tools / name).symlink_to(target)
            result = self.run_gate(repo, "unsafe_surface_gate", env={"PATH": f"{tools}:/bin"})
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("UNSAFE-SURFACE-FAIL", result.stderr)
            self.assertIn("src/linked.rs", result.stderr)

    def test_symlinked_test_module_with_cfg_test_parent_passes(self):
        with tempfile.TemporaryDirectory() as temp:
            repo, outside = self.sandbox(temp)
            (repo / "src/log").mkdir()
            (repo / "src/log/mod.rs").write_text("#[cfg(test)]\nmod tests;\n")
            (outside / "log_tests.rs").write_text("fn helper() { unsafe {} }\n")
            (repo / "src/log/tests.rs").symlink_to(outside / "log_tests.rs")
            for gate, marker in (("cfg_test_parentage_gate", "CFG-TEST-PARENTAGE-OK"),
                                 ("unsafe_surface_gate", "UNSAFE-SURFACE-OK")):
                result = self.run_gate(repo, gate)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn(marker, result.stdout)

    def test_two_line_form_with_blank_line_and_pub_crate_passes(self):
        with tempfile.TemporaryDirectory() as temp:
            repo, _ = self.sandbox(temp)
            (repo / "src/log").mkdir()
            (repo / "src/log/mod.rs").write_text("#[cfg(test)]\n\npub(crate) mod dot_tests;\n")
            (repo / "src/log/dot_tests.rs").write_text("fn t() {}\n")
            result = self.run_gate(repo, "cfg_test_parentage_gate")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("CFG-TEST-PARENTAGE-OK", result.stdout)

    def test_symlinked_test_module_with_non_test_parent_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            repo, outside = self.sandbox(temp)
            (repo / "src/log").mkdir()
            (repo / "src/log/mod.rs").write_text('#[cfg(feature = "probe")]\nmod tests;\n')
            (outside / "log_tests.rs").write_text("fn helper() {}\n")
            (repo / "src/log/tests.rs").symlink_to(outside / "log_tests.rs")
            result = self.run_gate(repo, "cfg_test_parentage_gate")
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("CFG-TEST-PARENTAGE-FAIL", result.stderr)
            self.assertIn("src/log/tests.rs", result.stderr)

    def test_second_non_cfg_test_declaration_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            repo, _ = self.sandbox(temp)
            (repo / "src/log").mkdir()
            (repo / "src/log/mod.rs").write_text(
                '#[cfg(test)]\nmod tests;\n\n#[cfg(feature = "probe")] mod tests;\n')
            (repo / "src/log/tests.rs").write_text("fn t() {}\n")
            result = self.run_gate(repo, "cfg_test_parentage_gate")
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("CFG-TEST-PARENTAGE-FAIL", result.stderr)

    def test_trailing_comment_cannot_attribute_a_declaration(self):
        with tempfile.TemporaryDirectory() as temp:
            repo, _ = self.sandbox(temp)
            (repo / "src/log").mkdir()
            (repo / "src/log/mod.rs").write_text(
                '#[cfg(test)]\nmod tests;\n\n'
                '#[cfg(feature = "probe")] mod tests; // #[cfg(test)]\n')
            (repo / "src/log/tests.rs").write_text("fn t() {}\n")
            result = self.run_gate(repo, "cfg_test_parentage_gate")
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("CFG-TEST-PARENTAGE-FAIL", result.stderr)

    def test_trailing_comment_on_attribute_line_cannot_attribute(self):
        with tempfile.TemporaryDirectory() as temp:
            repo, _ = self.sandbox(temp)
            (repo / "src/log").mkdir()
            (repo / "src/log/mod.rs").write_text(
                '#[cfg(test)]\nmod tests;\n\n'
                '#[cfg(feature = "probe")] // #[cfg(test)]\nmod tests;\n')
            (repo / "src/log/tests.rs").write_text("fn t() {}\n")
            result = self.run_gate(repo, "cfg_test_parentage_gate")
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("CFG-TEST-PARENTAGE-FAIL", result.stderr)

    def test_genuine_cfg_test_after_a_non_test_attribute_stays_green(self):
        with tempfile.TemporaryDirectory() as temp:
            repo, _ = self.sandbox(temp)
            (repo / "src/log").mkdir()
            (repo / "src/log/mod.rs").write_text(
                '#[cfg(feature = "probe")]\n#[cfg(test)]\nmod tests;\n')
            (repo / "src/log/tests.rs").write_text("fn t() {}\n")
            result = self.run_gate(repo, "cfg_test_parentage_gate")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("CFG-TEST-PARENTAGE-OK", result.stdout)

    def test_whitespace_path_with_resolving_fragments_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            repo, _ = self.sandbox(temp)
            (repo / "src/my evil.rs").write_text("fn evil() { unsafe {} }\n")
            (repo / "src/my").write_text("")
            (repo / "evil.rs").write_text("")
            result = self.run_gate(repo, "unsafe_surface_gate")
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("UNSAFE-SURFACE-SCAN-FAIL", result.stderr)

    def test_whitespace_path_without_fragments_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            repo, _ = self.sandbox(temp)
            (repo / "src/my evil.rs").write_text("fn evil() { unsafe {} }\n")
            result = self.run_gate(repo, "unsafe_surface_gate")
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("UNSAFE-SURFACE-SCAN-FAIL", result.stderr)

    def test_non_regular_enumerated_path_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            repo, _ = self.sandbox(temp)
            (repo / "src/device.rs").symlink_to("/dev/null")
            result = self.run_gate(repo, "unsafe_surface_gate")
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("UNSAFE-SURFACE-SCAN-FAIL", result.stderr)

    def test_grep_fallback_producer_error_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            repo, _ = self.sandbox(temp)
            (repo / "src/lib.rs").write_text("pub fn ok() {}\n")
            tools = Path(temp) / "tools"
            tools.mkdir()
            grep = tools / "grep"
            grep.write_text("#!/bin/sh\nexit 2\n")
            grep.chmod(0o755)
            for name in ("find", "mktemp", "xargs"):
                target = shutil.which(name)
                self.assertIsNotNone(target, name)
                (tools / name).symlink_to(target)
            result = self.run_gate(repo, "unsafe_surface_gate", env={"PATH": f"{tools}:/bin"})
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("UNSAFE-SURFACE-SCAN-FAIL", result.stderr)

    def test_ambiguous_parent_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            repo, _ = self.sandbox(temp)
            (repo / "src/log").mkdir()
            (repo / "src/log.rs").write_text("#[cfg(test)]\nmod tests;\n")
            (repo / "src/log/mod.rs").write_text("#[cfg(test)]\nmod tests;\n")
            (repo / "src/log/tests.rs").write_text("fn t() {}\n")
            result = self.run_gate(repo, "cfg_test_parentage_gate")
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("ambiguous parent", result.stderr)

    def test_pub_mod_masking_declaration_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            repo, _ = self.sandbox(temp)
            (repo / "src/log").mkdir()
            (repo / "src/log/mod.rs").write_text(
                '#[cfg(test)]\nmod tests;\n\npub mod tests;\n')
            (repo / "src/log/tests.rs").write_text("fn t() {}\n")
            result = self.run_gate(repo, "cfg_test_parentage_gate")
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("CFG-TEST-PARENTAGE-FAIL", result.stderr)

    def test_pub_super_masking_declaration_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            repo, _ = self.sandbox(temp)
            (repo / "src/log").mkdir()
            (repo / "src/log/mod.rs").write_text(
                '#[cfg(test)]\nmod tests;\n\npub(super) mod tests;\n')
            (repo / "src/log/tests.rs").write_text("fn t() {}\n")
            result = self.run_gate(repo, "cfg_test_parentage_gate")
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("CFG-TEST-PARENTAGE-FAIL", result.stderr)

    def test_attributed_phantom_in_block_comment_cannot_mask_pub_declaration(self):
        with tempfile.TemporaryDirectory() as temp:
            repo, _ = self.sandbox(temp)
            (repo / "src/log").mkdir()
            (repo / "src/log/mod.rs").write_text(
                '/*\n#[cfg(test)]\nmod tests;\n*/\npub mod tests;\n')
            (repo / "src/log/tests.rs").write_text("fn t() {}\n")
            result = self.run_gate(repo, "cfg_test_parentage_gate")
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("CFG-TEST-PARENTAGE-FAIL", result.stderr)

    def test_cfg_test_anywhere_in_leading_attribute_prefix_passes(self):
        with tempfile.TemporaryDirectory() as temp:
            repo, _ = self.sandbox(temp)
            (repo / "src/log").mkdir()
            (repo / "src/log/mod.rs").write_text(
                '#[cfg(feature = "probe")] #[cfg(test)] mod tests;\n')
            (repo / "src/log/tests.rs").write_text("fn t() {}\n")
            result = self.run_gate(repo, "cfg_test_parentage_gate")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("CFG-TEST-PARENTAGE-OK", result.stdout)

    def test_attributed_single_line_visibility_forms_pass(self):
        for declaration in (
                "#[cfg(test)] mod tests;",
                "#[cfg(test)] pub(crate) mod tests;",
                "#[cfg(test)] pub(super) mod tests;",
                "#[cfg(test)] pub(in crate::log) mod tests;"):
            with tempfile.TemporaryDirectory() as temp:
                repo, _ = self.sandbox(temp)
                (repo / "src/log").mkdir()
                (repo / "src/log/mod.rs").write_text(declaration + "\n")
                (repo / "src/log/tests.rs").write_text("fn t() {}\n")
                result = self.run_gate(repo, "cfg_test_parentage_gate")
                self.assertEqual(result.returncode, 0,
                                 declaration + result.stdout + result.stderr)
                self.assertIn("CFG-TEST-PARENTAGE-OK", result.stdout)


# --- D8: the shutdown no-admission witness ------------------------------------
# The shipped scripts/e2e_shutdown.py reads E2E_TARGET at import; the value only
# names an in-container binary path and no case is executed here.
def load_shutdown_witness():
    saved = os.environ.get("E2E_TARGET")
    os.environ["E2E_TARGET"] = "witness-test-target"
    try:
        spec = importlib.util.spec_from_file_location(
            "e2e_shutdown_under_test", ROOT / "scripts/e2e_shutdown.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        if saved is None:
            del os.environ["E2E_TARGET"]
        else:
            os.environ["E2E_TARGET"] = saved
    return module


class FakeChild:
    """The reaped-child surface the witness touches (kill + wait only)."""

    def __init__(self):
        self.kills = 0
        self.reaps = 0

    def kill(self):
        self.kills += 1

    def wait(self, timeout=None):
        self.reaps += 1
        return -15


class ShutdownWitness(unittest.TestCase):
    """D8: a post-signal no-admission sample must classify exactly ONE probe,
    and a reachable observation is TERMINAL for the sample. Re-probing after a
    reachable connect lets a later refusal overwrite an observed admission and
    greens a case that admitted a client after the signal.

    The decision logic executed is the shipped module itself, never a Python
    re-implementation."""

    def setUp(self):
        self.mod = load_shutdown_witness()
        self.shipped_settle = self.mod.SIGNAL_SETTLE
        # The settle is a real-time delay whose existence and bounds are pinned
        # separately; the behavioural pins below run without it so they exercise
        # the sampling decision, not the wall clock.
        self.mod.SIGNAL_SETTLE = 0.0
        self.mod.FAILURES.clear()
        self.probes = []

    def probe_sequence(self, *observations):
        """Serve the given classified observations, repeating the last one so a
        looping witness cannot starve on the sequence."""
        sequence = list(observations)

        def probe():
            self.probes.append(1)
            return sequence[min(len(self.probes), len(sequence)) - 1]

        self.mod.connect_probe = probe

    def sample(self, name="WITNESS", seconds=1.0):
        out = io.StringIO()
        proc = FakeChild()
        deadline = time.monotonic() + seconds
        with contextlib.redirect_stdout(out):
            ok = self.mod.probe_refused_sampled(deadline, name, proc)
        return ok, proc, out.getvalue()

    def sample_no_bind(self, name="WITNESS-SAMPLE"):
        out = io.StringIO()
        proc = FakeChild()
        with contextlib.redirect_stdout(out):
            ok = self.mod.sample_no_bind(name, proc)
        return ok, proc, out.getvalue()

    def test_a_reachable_observation_is_terminal_for_the_sample(self):
        # The next probe would be an authoritative refusal: the pre-fix witness
        # re-probed through sample_no_bind, forgot the admission and continued.
        self.probe_sequence(("reachable", None), ("refused", None))
        ok, proc, out = self.sample()
        self.assertFalse(ok, out)
        self.assertEqual(len(self.probes), 1,
                         f"a reachable observation must never be re-probed; probes={len(self.probes)}")
        self.assertIn("listener bound at a sampled probe point", out)
        self.assertEqual(self.mod.FAILURES, ["WITNESS"])
        self.assertGreaterEqual(proc.kills, 1, "the admitting child must be reaped")
        self.assertGreaterEqual(proc.reaps, 1)

    def test_an_operational_error_is_terminal_and_indeterminate(self):
        self.probe_sequence(("error", OSError(24, "Too many open files")),
                            ("refused", None))
        ok, proc, out = self.sample()
        self.assertFalse(ok, out)
        self.assertEqual(len(self.probes), 1,
                         f"an operational error must never be re-probed; probes={len(self.probes)}")
        self.assertIn("indeterminate, not absence", out)
        self.assertEqual(self.mod.FAILURES, ["WITNESS"])

    def test_the_interval_is_sampled_until_the_deadline(self):
        self.probe_sequence(("refused", None))
        ok, proc, out = self.sample(seconds=0.4)
        self.assertTrue(ok, out)
        self.assertGreaterEqual(len(self.probes), 2,
                                "the post-signal interval, not one instant, must be sampled")
        self.assertEqual(self.mod.FAILURES, [])
        self.assertEqual((proc.kills, proc.reaps), (0, 0))

    def test_the_settle_exists_and_stays_inside_every_sampling_window(self):
        self.assertGreater(self.shipped_settle, 0.0,
                           "the settle must exist: SIGTERM observation is asynchronous")
        # The bound that matters is the sampling deadline at both call sites
        # (t0+2.0 and t0+2.5), not the 8 s grace: a settle that ate the window
        # would starve the samples and red a correct candidate.
        self.assertLess(self.shipped_settle, 0.5,
                        "the settle must leave the sampling window intact")

    def test_a_deadline_inside_the_settle_is_an_observation_gap(self):
        self.mod.SIGNAL_SETTLE = 0.2
        self.probe_sequence(("refused", None))
        ok, _, out = self.sample(seconds=0.01)
        self.assertFalse(ok, out)
        self.assertIn("observation gap, not a pass", out)
        self.assertEqual(len(self.probes), 0, "the settle must not be a re-probe")

    def test_one_sample_classifies_one_probe(self):
        # Property pin for the shared judgement owner (green pre- and post-fix):
        # sample_no_bind never re-probes after a non-refusal.
        self.probe_sequence(("reachable", None), ("refused", None))
        ok, proc, out = self.sample_no_bind()
        self.assertFalse(ok, out)
        self.assertEqual(len(self.probes), 1)
        self.assertIn("listener bound at a sampled probe point", out)

    def test_a_held_open_listener_fails_and_a_closed_port_certifies(self):
        # Real-IO plant/revert pair: a listener held open is the violating
        # shape; the identical witness must fail it and then certify the closed
        # port after the plant is removed.
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", 0))
            listener.listen(8)
            self.mod.PROXY = ("127.0.0.1", listener.getsockname()[1])
            ok, _, out = self.sample(name="WITNESS-PLANT")
            self.assertFalse(ok, out)
            self.assertIn("listener bound at a sampled probe point", out)
            self.assertEqual(self.mod.FAILURES, ["WITNESS-PLANT"])
        finally:
            listener.close()
        self.mod.FAILURES.clear()
        ok, _, out = self.sample(name="WITNESS-REVERT", seconds=0.15)
        self.assertTrue(ok, out)
        self.assertEqual(self.mod.FAILURES, [])


def extract_untracked_allowlist_default():
    """The shipped allowlist line, so the tests exercise the real default and
    can supply a non-empty list for the prefix-semantics pins."""
    match = re.search(r'^E2E_UNTRACKED_ALLOW="([^"]*)"$',
                      (ROOT / "scripts/verify.sh").read_text(), re.M)
    assert match is not None, "E2E_UNTRACKED_ALLOW default not found in scripts/verify.sh"
    return match


class E2EReceiptInputs(unittest.TestCase):
    """D7: the E2E source receipt must bind the built binary to the candidate
    it was built from. `git diff HEAD` cannot see untracked files, so a checkout
    carrying an untracked Cargo input (a root `build.rs`, a `.cargo/config.toml`,
    a new module) can build a different binary under the same receipt. The
    receipt's untracked coverage is exactly what the pinned (tracked) .gitignore
    rules admit: an ignored path is outside it by construction. The bodies
    executed are text-extracted from scripts/verify.sh (never a Python
    re-implementation), and each receipt field is still produced by the shipped
    sha256_digest owner."""

    RECEIPT_BODIES = ("sha256_digest", "e2e_untracked_input_guard",
                      "e2e_receipt_fields")

    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        self.temp = Path(self._temp.name)
        self.repo = self.temp / "repo"
        (self.repo / "scripts").mkdir(parents=True)
        shutil.copyfile(ROOT / "scripts/verify.sh", self.repo / "scripts/verify.sh")
        (self.repo / ".gitignore").write_text("target/\n")
        (self.repo / "Cargo.toml").write_text('[package]\nname = "probe"\n')
        (self.repo / "scripts/e2e_shutdown.py").write_text("# harness\n")
        (self.repo / "scripts/e2e_shutdown.sh").write_text("# harness\n")
        self.git("init", "-q", "--template=")
        self.git("add", "-A")
        self.git("-c", "user.email=probe@example.invalid", "-c", "user.name=probe",
                 "commit", "-qm", "base")
        self.head = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=self.repo, text=True).strip()

    def git_env(self):
        """Hermetic git: the developer's global/system config and any inherited
        GIT_* repository override must not decide what the guard observes (an
        inherited core.excludesFile or GIT_DIR could hide a planted input and
        turn a real pin into a false red)."""
        env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull,
               "GIT_CONFIG_SYSTEM": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
        for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE",
                     "GIT_OBJECT_DIRECTORY", "GIT_CEILING_DIRECTORIES"):
            env.pop(name, None)
        env.pop("GIT_CONFIG_COUNT", None)
        for name in [k for k in env
                     if k.startswith("GIT_CONFIG_KEY_") or k.startswith("GIT_CONFIG_VALUE_")]:
            env.pop(name, None)
        return env

    def git(self, *args):
        subprocess.run(["git", *args], cwd=self.repo, check=True,
                       capture_output=True, env=self.git_env())

    def receipt_script(self, allow=None):
        allow_line = (extract_untracked_allowlist_default().group(0) if allow is None
                      else f'E2E_UNTRACKED_ALLOW="{allow}"')
        bodies = "\n\n".join(extract_function(name)
                             for name in self.RECEIPT_BODIES)
        driver = self.temp / "receipt.sh"
        # set -eu: the driver runs the shipped bodies under the interpreter
        # options scripts/verify.sh itself uses.
        driver.write_text(
            "set -eu\n" + bodies + "\n\n" + allow_line + '\nTGT="$PWD/target"\nmkdir -p "$TGT"\n'
            "e2e_receipt_fields relay scripts/e2e_shutdown.py scripts/e2e_shutdown.sh\n")
        return driver

    def run_receipt(self, cwd=None, allow=None, extra_env=None):
        return subprocess.run(
            ["sh", str(self.receipt_script(allow))], cwd=cwd or self.repo,
            text=True, capture_output=True, env={**self.git_env(), **(extra_env or {})})

    def test_the_shipped_allowlist_names_only_the_local_index_cache(self):
        self.assertEqual(extract_untracked_allowlist_default().group(1), ".repowise/",
                         "an allowlist entry is a visible reviewed bypass, never a convenience")
        for entry in extract_untracked_allowlist_default().group(1).split():
            self.assertTrue(entry.endswith("/"), f"allowlist entry is not a directory prefix: {entry}")

    def test_the_guard_is_wired_into_the_shared_receipt_owner(self):
        # Every sampling point (pre-build, post-build, post-harness) inherits the
        # guard only because it lives in e2e_receipt_fields itself; a later
        # removal of that call would otherwise leave every behavioural pin green.
        self.assertIn('e2e_untracked_input_guard "$_gate"',
                      extract_function("e2e_receipt_fields"))

    def test_a_clean_tree_is_certified(self):
        result = self.run_receipt()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        fields = result.stdout.split()
        self.assertEqual(len(fields), 5, result.stdout)
        self.assertEqual(fields[0], self.head, "the receipt must still bind HEAD")
        self.assertNotIn("BLOCKED", result.stderr)

    def test_an_untracked_build_input_is_refused(self):
        (self.repo / "build.rs").write_text("fn main() {\n    println!(\"cargo:rerun-if-changed=src\");\n}\n")
        result = self.run_receipt()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("E2E-relay-BLOCKED", result.stderr)
        self.assertIn("build.rs", result.stderr)
        # revert the plant: the same receipt certifies the clean checkout again
        (self.repo / "build.rs").unlink()
        again = self.run_receipt()
        self.assertEqual(again.returncode, 0, again.stdout + again.stderr)

    def test_a_local_ignore_entry_cannot_hide_a_build_input(self):
        # `--exclude-standard` would honour .git/info/exclude and certify this
        # checkout with an untracked, Cargo-consumed build.rs.
        (self.repo / ".git/info").mkdir(parents=True, exist_ok=True)
        (self.repo / ".git/info/exclude").write_text("build.rs\n")
        (self.repo / "build.rs").write_text("fn main() {}\n")
        result = self.run_receipt()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("build.rs", result.stderr)

    def test_gitignored_build_artifacts_do_not_refuse_the_receipt(self):
        (self.repo / "target").mkdir()
        (self.repo / "target/artifact").write_text("generated\n")
        result = self.run_receipt()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_the_allowlist_excuses_only_the_named_generated_artifact(self):
        (self.repo / "generated").mkdir()
        (self.repo / "generated/facts.txt").write_text("generated\n")
        allowed = self.run_receipt(allow="generated/")
        self.assertEqual(allowed.returncode, 0, allowed.stdout + allowed.stderr)
        (self.repo / "build.rs").write_text("fn main() {}\n")
        refused = self.run_receipt(allow="generated/")
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("build.rs", refused.stderr)
        self.assertNotIn("generated/facts.txt", refused.stderr)

    def test_a_path_prefix_does_not_excuse_a_lookalike_sibling(self):
        (self.repo / "generated-evil").mkdir()
        (self.repo / "generated-evil/build.rs").write_text("fn main() {}\n")
        result = self.run_receipt(allow="generated/")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("generated-evil/build.rs", result.stderr)

    @unittest.skipIf(os.geteuid() == 0,
                     "root can read a mode-000 directory; the diagnostic shape is unavailable")
    def test_a_producer_diagnostic_on_exit_zero_is_a_blocked_observation(self):
        # git reports an unreadable directory as a WARNING and leaves its
        # contents out of the list, so an exit-0 diagnostic is an incomplete
        # universe - never a clean observation (the pre-fix shape certified it).
        opaque = self.repo / "opaque"
        opaque.mkdir()
        (opaque / "build.rs").write_text("fn main() {}\n")
        opaque.chmod(0o000)
        try:
            result = self.run_receipt()
        finally:
            opaque.chmod(0o755)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("observation incomplete, not a receipt", result.stderr)

    def test_an_unobservable_untracked_universe_fails_closed(self):
        # no work tree: the producer fails, so the receipt must not certify
        plain = self.temp / "plain"
        (plain / "scripts").mkdir(parents=True)
        (plain / "scripts/e2e_shutdown.py").write_text("# harness\n")
        (plain / "scripts/e2e_shutdown.sh").write_text("# harness\n")
        result = self.run_receipt(cwd=plain)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("untracked-input observation failed", result.stderr)

    def test_an_external_diff_driver_cannot_hide_a_tracked_edit(self):
        clean = self.run_receipt().stdout.split()
        (self.repo / "Cargo.toml").write_text('[package]\nname = "probe"\nversion = "0.9.9"\n')
        silent = shutil.which("true")
        self.assertIsNotNone(silent)
        dirty = self.run_receipt(extra_env={"GIT_EXTERNAL_DIFF": silent}).stdout.split()
        self.assertEqual(dirty[0], clean[0])
        self.assertNotEqual(dirty[1], clean[1],
                            "an external diff driver must not blank the receipt's diff field")

    def test_a_tracked_modification_still_changes_the_receipt(self):
        clean = self.run_receipt().stdout.split()
        (self.repo / "Cargo.toml").write_text('[package]\nname = "probe"\nversion = "0.2.0"\n')
        dirty = self.run_receipt().stdout.split()
        self.assertEqual(dirty[0], clean[0], "HEAD is unchanged by a worktree edit")
        self.assertNotEqual(dirty[1], clean[1],
                            "the tracked dirty diff must still be receipt-carried")


def extract_budget_default():
    """The shipped budget line, so the tests pin the constant the gate actually
    runs with rather than a copy of it."""
    match = re.search(r"^GATE_SUITE_BUDGET_SECS=.*$",
                      (ROOT / "scripts/verify.sh").read_text(), re.M)
    assert match is not None, "GATE_SUITE_BUDGET_SECS default not found in scripts/verify.sh"
    return match


def suite_knob_names(body=None):
    """Every GATE_SUITE_* constant the shipped helper reads, taken from the
    helper's own text: the driver is handed exactly the assignments for these
    names, so a knob the helper resolves from cannot be missing from the
    harness (L3)."""
    body = extract_function("bounded_suite") if body is None else body
    names = set(re.findall(r"GATE_SUITE_[A-Z_]+", body))
    assert names, "bounded_suite reads no GATE_SUITE_* constant"
    return names


def shipped_knob_lines(text=None):
    """The shipped top-level assignment lines for those constants, in file order
    (the order the resolution depends on: floor and ceiling before the value).

    Exactly one UNINDENTED assignment per name is allowed. A second assignment --
    at top level or inside a function body -- would leave every value pin reading
    a line the gate does not resolve from, so the shadow is refused here rather
    than staying invisible (L3)."""
    names = suite_knob_names()
    text = (ROOT / "scripts/verify.sh").read_text() if text is None else text
    found = {name: [] for name in names}
    order = []
    for line in text.splitlines():
        match = re.match(r"^([ \t]*)([A-Z_][A-Z0-9_]*)=", line)
        if match is None or match.group(2) not in found:
            continue
        found[match.group(2)].append((match.group(1), line))
        order.append(line)
    for name in sorted(found):
        hits = found[name]
        assert len(hits) == 1, (
            f"{name} must have exactly ONE assignment in scripts/verify.sh; a shadow "
            f"assignment leaves the value pins reading a line the helper does not "
            f"resolve from -- found {len(hits)}: {[hit[1] for hit in hits]}")
        assert hits[0][0] == "", (
            f"{name} is assigned inside a function body, not at top level: {hits[0][1]}")
    return order


def shipped_min_stack():
    """The stack size the shipped default resolves to, read out of the floor line
    itself: a second declaration of the number here would pin nothing."""
    floor = next(line for line in shipped_knob_lines()
                 if line.startswith("GATE_SUITE_MIN_STACK_FLOOR="))
    value = floor.split("=", 1)[1].strip('"')
    assert value.isdigit(), f"stack floor is not a byte count: {value}"
    return value


def bounded_suite_source():
    """The shipped declaration writer and the shipped helper, in the order the
    real script defines them.

    The helper calls `_bs_declare` on every return path, so a driver carrying the
    helper without the writer does not test a channel at all: it exits with
    'command not found' under `set -e`. One helper here keeps that pairing true
    for both drivers."""
    return (extract_function("_bs_declare") + "\n\n"
            + extract_function("bounded_suite"))


class BoundedSuite(unittest.TestCase):
    """Every lib-suite invocation runs under the shipped `bounded_suite` owner,
    text-extracted from scripts/verify.sh (never a Python re-implementation):
    libtest has no timeout, so a wedged suite is otherwise indistinguishable
    from a slow one and consumes the whole window.

    A stub wrapper stands in for `timeout`/`gtimeout` to drive each exit path;
    the stub records its own argv, so the portable `-s KILL` form and the budget
    are pinned as the shipped helper passes them, and it echoes its own
    `$RUST_MIN_STACK`, so the stack budget is proven observed by the child it
    wraps rather than asserted from the helper's source text."""

    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        self.temp = Path(self._temp.name)
        self.tools = self.temp / "tools"
        self.tools.mkdir()
        # The per-run channel's own prerequisites, reached exactly as InnerTest
        # reaches them (see the note there): a directory of real utilities beside
        # the stub directory, never a widened PATH.
        self.util = self.temp / "util"
        self.util.mkdir()
        for name in ("mktemp", "cp", "rm"):
            found = shutil.which(name)
            self.assertIsNotNone(found,
                                 f"{name} is a prerequisite of the per-run channel")
            (self.util / name).symlink_to(found)
        self.calls = self.temp / "calls"
        self.stack_seen = self.temp / "stack-seen"
        self.declared = self.temp / "declared"
        # The driver is every shipped knob assignment the helper reads (in file
        # order) plus the shipped source, under the interpreter options
        # scripts/verify.sh itself runs with.
        self.driver = self.temp / "bounded.sh"
        self.driver.write_text(
            "set -eu\n" + "\n".join(shipped_knob_lines()) + "\n\n"
            + bounded_suite_source() + '\n\nbounded_suite "$@"\n')

    # The shipped reader's shape: one declaration path per run, exported BEFORE
    # the call and read AFTER it. `$DECLARED` stands in for the mktemp file
    # inner_test creates, so what is left at that path is the declaration the
    # helper's own process wrote.
    READER = ('GATE_SUITE_DECLARATION_FILE="$DECLARED"\n'
              'export GATE_SUITE_DECLARATION_FILE\n'
              '_rc=0\n'
              'bounded_suite "$@" || _rc=$?\n'
              'exit "$_rc"\n')

    def declared_driver(self, name="declared.sh", body=None):
        """The shipped source plus a call, then the shipped declaration left at
        the path the caller exported: the channel is read after the call, exactly
        as the shipped reader reads it, so a helper that writes nothing is
        observable here as an empty (or absent) file."""
        path = self.temp / name
        path.write_text(
            "set -eu\n" + "\n".join(shipped_knob_lines()) + "\n\n"
            + bounded_suite_source() + "\n\n"
            + (body if body is not None else self.READER))
        return path

    def stub(self, name, rc):
        path = self.tools / name
        path.write_text('#!/bin/sh\n'
                        'printf "%s\\n" "$*" >> "$CALLS"\n'
                        'printf "%s\\n" "${RUST_MIN_STACK-<unset>}" > "$STACK_SEEN"\n'
                        f'exit {rc}\n')
        path.chmod(0o755)

    def run_bounded(self, *args, env=None, driver=None):
        # Absolute interpreter: the stub cases run with a PATH that shadows
        # every wrapper, so `sh` must not be resolved through it. The stack
        # knobs are scrubbed from the host environment so a developer's export
        # cannot stand in for the shipped default.
        inherited = {key: value for key, value in os.environ.items()
                     if key not in ("GATE_SUITE_BUDGET_SECS", "GATE_SUITE_MIN_STACK",
                                    "RUST_MIN_STACK", "GATE_SUITE_DECLARATION_FILE")}
        return subprocess.run(
            [shutil.which("sh") or "/bin/sh",
             str(driver or self.driver), *map(str, args)],
            cwd=self.temp, text=True, capture_output=True,
            env={**inherited, "CALLS": str(self.calls),
                 "STACK_SEEN": str(self.stack_seen),
                 "DECLARED": str(self.declared), **(env or {})})

    def scoped_path(self, *directories):
        """The stub directories searched FIRST, then the driver's own utilities --
        the shape InnerTest's reader uses, and nothing is resolved from the host
        PATH."""
        return ":".join([*(str(directory) for directory in directories),
                         str(self.util)])

    def describe(self, result):
        """The observed behaviour, so a refusal assertion reports what actually
        happened (including a wrapper argv the helper should never have
        assembled) rather than only that a number differed."""
        calls = (self.calls.read_text().strip() if self.calls.exists()
                 else "<wrapper never invoked>")
        return (f"wrapper argv: {calls}\n"
                f"exit: {result.returncode}\n"
                f"stdout: {result.stdout}stderr: {result.stderr}")

    def test_an_absent_wrapper_fails_closed(self):
        result = self.run_bounded("suite", env={"PATH": str(self.tools)})
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("GATE-SUITE-TIMEOUT-UNKNOWN", result.stderr)

    def test_a_timed_out_suite_is_labelled_and_fails(self):
        self.stub("timeout", 124)
        result = self.run_bounded("suite", env={"PATH": str(self.tools)})
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("GATE-SUITE-TIMEOUT-FAIL", result.stderr)
        self.assertIn("GATE-SUITE-BOUND", result.stdout)
        self.assertEqual(self.calls.read_text().strip(), "-s KILL 600 suite")

    def test_a_sigkilled_suite_reports_the_137_status_as_a_timeout(self):
        # 137 is what a `-s KILL` wrapper returns for a KILLed child (measured on
        # GNU coreutils); its own stub makes the arm reachable on any host, so
        # dropping 137 from the case cannot pass here.
        self.stub("timeout", 137)
        result = self.run_bounded("suite", env={"PATH": str(self.tools)})
        self.assertEqual(result.returncode, 137, self.describe(result))
        self.assertIn("GATE-SUITE-TIMEOUT-FAIL", result.stderr)

    def test_a_green_suite_passes(self):
        self.stub("timeout", 0)
        result = self.run_bounded("suite", env={"PATH": str(self.tools)})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("GATE-SUITE-TIMEOUT", result.stderr)

    def test_a_genuine_test_failure_passes_through_unchanged(self):
        self.stub("timeout", 101)
        result = self.run_bounded("suite", env={"PATH": str(self.tools)})
        self.assertEqual(result.returncode, 101, result.stdout + result.stderr)
        self.assertNotIn("GATE-SUITE-TIMEOUT", result.stdout + result.stderr)

    def test_gtimeout_is_the_fallback_spelling(self):
        self.stub("gtimeout", 0)
        result = self.run_bounded("suite", env={"PATH": str(self.tools)})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.calls.read_text().strip(), "-s KILL 600 suite")

    def test_the_shipped_bound_stops_a_long_suite(self):
        if shutil.which("timeout") is None and shutil.which("gtimeout") is None:
            self.skipTest("no timeout wrapper on this test host; the absence path "
                          "is covered as fail-closed above")
        started = time.monotonic()
        result = self.run_bounded("sleep", 30, env={"GATE_SUITE_BUDGET_SECS": "1"})
        elapsed = time.monotonic() - started
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("GATE-SUITE-TIMEOUT-FAIL", result.stderr)
        self.assertLess(elapsed, 10, f"the bound did not stop the suite: {elapsed:.1f}s")

    def test_the_budget_and_the_portable_kill_form_are_pinned(self):
        # The `${VAR-600}` spelling (no colon) is load-bearing: unset must take
        # the default, while an explicitly EMPTY value must stay empty and be
        # refused below. `:-` would silently turn empty into the default, so a
        # knob set to nothing would run at 600 s with no refusal to record.
        self.assertIn('GATE_SUITE_BUDGET_SECS="${GATE_SUITE_BUDGET_SECS-600}"',
                      extract_budget_default().group(0))
        body = extract_function("bounded_suite")
        self.assertIn('-s KILL "$_bs_budget_secs" "$@"', body)
        self.assertNotIn("-k ", body)

    def assert_budget_refused(self, value):
        """A refused budget is refused BEFORE the wrapper: no argv assembled, no
        GATE-SUITE-BOUND line, nothing executed. A stub that would exit 0 stands
        in, so nothing but the refusal can produce a non-zero status here."""
        self.stub("timeout", 0)
        self.stub("gtimeout", 0)
        result = self.run_bounded("suite", env={"PATH": str(self.tools),
                                                "GATE_SUITE_BUDGET_SECS": value})
        note = self.describe(result)
        self.assertNotEqual(result.returncode, 0, note)
        self.assertIn("GATE-SUITE-TIMEOUT-UNKNOWN", result.stderr, note)
        self.assertNotIn("GATE-SUITE-BOUND", result.stdout, note)
        self.assertFalse(self.calls.exists(),
                         f"the wrapper ran despite a refused budget {value!r}: {note}")

    def test_a_zero_budget_is_refused_before_the_wrapper(self):
        # A wrapper's duration 0 is "no limit" (BSD `man timeout`: "The special
        # duration, zero, signifies no limit"; GNU behaves the same), so a zero
        # budget is an absent bound, not a tight one - and the receipt line must
        # never affirm a bound of 0.
        self.assert_budget_refused("0")
        self.assert_budget_refused("00")
        self.assert_budget_refused("0000")

    def test_an_empty_or_non_numeric_budget_is_refused_before_the_wrapper(self):
        self.assert_budget_refused("")
        for value in ("-600", "+600", "600.0", "600s", " 600", "600 ", "6e2",
                      "0x258", "six hundred", "600 601"):
            self.assert_budget_refused(value)

    def test_an_unset_budget_resolves_to_the_shipped_default(self):
        # No GATE_SUITE_BUDGET_SECS in the environment at all: the shipped
        # default is what the wrapper is handed, and no refusal marker appears.
        self.stub("timeout", 0)
        result = self.run_bounded("suite", env={"PATH": str(self.tools)})
        self.assertEqual(result.returncode, 0, self.describe(result))
        self.assertEqual(self.calls.read_text().strip(), "-s KILL 600 suite")
        self.assertNotIn("GATE-SUITE-TIMEOUT", result.stderr)

    def test_a_leading_zero_budget_is_accepted_as_its_value(self):
        # "0600" is the same bound as "600"; it is accepted and handed over as
        # 600, so no parser can read it as octal 384 or as zero.
        self.stub("timeout", 0)
        result = self.run_bounded("suite", env={"PATH": str(self.tools),
                                                "GATE_SUITE_BUDGET_SECS": "0600"})
        self.assertEqual(result.returncode, 0, self.describe(result))
        self.assertEqual(self.calls.read_text().strip(), "-s KILL 600 suite")

    def test_the_child_observes_the_shipped_stack_budget(self):
        self.stub("timeout", 0)
        result = self.run_bounded("suite", env={"PATH": str(self.tools)})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        shipped = shipped_min_stack()
        self.assertEqual(self.stack_seen.read_text().strip(), shipped,
                         "the wrapped child did not inherit the shipped RUST_MIN_STACK")
        self.assertIn(f"RUST_MIN_STACK={shipped}", result.stdout)

    def test_a_second_stack_assignment_cannot_hide_from_the_pins(self):
        # L3: the extraction refuses a duplicate or function-body assignment, so
        # a shadow value cannot sit in verify.sh unseen by every pin above.
        text = (ROOT / "scripts/verify.sh").read_text()
        shadowed = text.replace("bounded_suite() {\n",
                                "bounded_suite() {\n    GATE_SUITE_MIN_STACK=1048576\n", 1)
        self.assertNotEqual(shadowed, text)
        with self.assertRaises(AssertionError):
            shipped_knob_lines(shadowed)
        duplicate = text.replace(
            'GATE_SUITE_MIN_STACK="${GATE_SUITE_MIN_STACK-${RUST_MIN_STACK-$GATE_SUITE_MIN_STACK_FLOOR}}"',
            'GATE_SUITE_MIN_STACK="${GATE_SUITE_MIN_STACK-${RUST_MIN_STACK-$GATE_SUITE_MIN_STACK_FLOOR}}"\n'
            'GATE_SUITE_MIN_STACK=1048576', 1)
        self.assertNotEqual(duplicate, text)
        with self.assertRaises(AssertionError):
            shipped_knob_lines(duplicate)

    def test_every_shipped_suite_knob_reaches_the_driver(self):
        # L3: the driver carries every shipped assignment the helper reads, so a
        # value the gate resolves from cannot be missing from the harness -- and
        # it carries no third one the helper never reads.
        driver = self.driver.read_text()
        knobs = shipped_knob_lines()
        self.assertTrue(knobs)
        for line in knobs:
            self.assertIn(line + "\n", driver)
        assignments = [line for line in driver.splitlines()
                       if re.match(r"^[ \t]*GATE_SUITE_[A-Z_]+=", line)]
        self.assertEqual(assignments, knobs,
                         "the driver carries a GATE_SUITE_* assignment the shipped "
                         "helper does not resolve from")

    def test_the_floor_is_the_documented_magnitude(self):
        # L2: a floor pinned only to itself stays green when it is lowered, and
        # lowering it toward the 2 MiB default re-creates the exit-101 class this
        # increment exists to kill. The documented magnitude is a literal here.
        self.assertEqual(shipped_min_stack(), "16777216")

    def assert_stack_refused(self, value=None, env=None):
        """A refused stack budget is refused BEFORE the wrapper is resolved: no
        argv assembled, no GATE-SUITE-BOUND line, nothing executed. A stub that
        would exit 0 stands in, so nothing but the refusal can produce a non-zero
        status here, and the stub's log is compared against its pre-call state
        because an accepted case in the same test may already have logged one."""
        self.stub("timeout", 0)
        supplied = {"PATH": str(self.tools), **(env or {})}
        if value is not None:
            supplied["GATE_SUITE_MIN_STACK"] = value
        before = self.calls.read_text() if self.calls.exists() else None
        result = self.run_bounded("suite", env=supplied)
        note = self.describe(result)
        self.assertNotEqual(result.returncode, 0, note)
        self.assertIn("GATE-SUITE-STACK-UNKNOWN", result.stderr, note)
        self.assertNotIn("GATE-SUITE-BOUND", result.stdout, note)
        after = self.calls.read_text() if self.calls.exists() else None
        self.assertEqual(after, before,
                         f"the timeout wrapper ran despite a refused stack budget "
                         f"{supplied!r}: {note}")

    def test_an_empty_stack_budget_fails_closed_before_the_wrapper(self):
        self.assert_stack_refused("")

    def test_an_under_floor_or_non_numeric_stack_budget_is_refused(self):
        self.assert_stack_refused("1048576")
        self.assert_stack_refused("16M")

    def test_a_numeral_no_shell_can_compare_is_refused_before_the_comparison(self):
        # L1: `[ x -lt y ]` on an unrepresentable numeral is an arithmetic error,
        # and the error takes the false branch -- the value was exported and std
        # fell back to its 2 MiB default with no marker. The digit ceiling is
        # checked before any comparison, so the refusal is the stack marker and
        # the stub wrapper is never invoked.
        self.assert_stack_refused("12345678901234567890")
        self.assert_stack_refused("9223372036854775808")
        self.assert_stack_refused("9" * 40)
        self.assert_stack_refused(env={"RUST_MIN_STACK": "12345678901234567890"})

    def test_a_leading_zero_stack_budget_is_compared_by_its_value(self):
        # Leading zeros carry no value: they are stripped before the digit
        # ceiling, so a padded numeral is neither refused as over-long nor read
        # as octal.
        self.stub("timeout", 0)
        result = self.run_bounded("suite", env={"PATH": str(self.tools),
                                                "GATE_SUITE_MIN_STACK": "00000016777216"})
        self.assertEqual(result.returncode, 0, self.describe(result))
        self.assertEqual(self.stack_seen.read_text().strip(), "16777216")
        self.assert_stack_refused("0000000001048576")

    def test_the_documented_spelling_is_honoured(self):
        # B2: RUST_MIN_STACK is the spelling every document teaches. It is an
        # input the helper honours, not an ambient variable it overwrites.
        self.stub("timeout", 0)
        result = self.run_bounded("suite", env={"PATH": str(self.tools),
                                                "RUST_MIN_STACK": "33554432"})
        self.assertEqual(result.returncode, 0, self.describe(result))
        self.assertEqual(self.stack_seen.read_text().strip(), "33554432",
                         "the documented RUST_MIN_STACK was replaced, not honoured")
        self.assertIn("RUST_MIN_STACK=33554432", result.stdout)

    def test_the_documented_spelling_is_refused_below_the_floor(self):
        # B2: honouring the documented spelling is not weakening the floor. An
        # under-floor RUST_MIN_STACK is REFUSED, never silently clamped up to the
        # floor and run -- a clamp would resurrect the 22144 class exactly as
        # silently as the overwrite did.
        self.assert_stack_refused(env={"RUST_MIN_STACK": "1048576"})
        self.assert_stack_refused(env={"RUST_MIN_STACK": "0001048576"})

    def test_an_empty_documented_spelling_fails_closed(self):
        # The resolution is non-colon at BOTH levels: an explicitly empty value is
        # a refusal at either level, never a fall-through to the next one.
        self.assert_stack_refused(env={"RUST_MIN_STACK": ""})
        self.assert_stack_refused("", env={"RUST_MIN_STACK": "33554432"})

    def test_the_gate_knob_takes_precedence_over_the_documented_spelling(self):
        self.stub("timeout", 0)
        result = self.run_bounded("suite", env={"PATH": str(self.tools),
                                                "GATE_SUITE_MIN_STACK": "33554432",
                                                "RUST_MIN_STACK": "1048576"})
        self.assertEqual(result.returncode, 0, self.describe(result))
        self.assertEqual(self.stack_seen.read_text().strip(), "33554432",
                         "the gate knob must win over RUST_MIN_STACK")

    # The helper's own run is DECLARED on a separate channel, not encoded in the
    # status it returns: the wrapped command owns that status, so no number can
    # carry a refusal. The channel is the declaration FILE, so it survives the
    # helper running in a subshell.
    REFUSALS = (
        ("stack non-numeric", {"GATE_SUITE_MIN_STACK": "16M"},
         "refused:stack-unknown"),
        ("stack over the digit ceiling", {"GATE_SUITE_MIN_STACK": "9" * 19},
         "refused:stack-unknown"),
        ("stack below the floor", {"GATE_SUITE_MIN_STACK": "1048576"},
         "refused:stack-unknown"),
        ("budget non-numeric", {"GATE_SUITE_BUDGET_SECS": "600s"},
         "refused:budget-unknown"),
        ("budget of zero", {"GATE_SUITE_BUDGET_SECS": "0"},
         "refused:budget-unknown"),
        ("no wrapper on PATH", {"PATH": "tools"}, "refused:wrapper-absent"),
    )

    def declared_after(self):
        return (self.declared.read_text().strip()
                if self.declared.exists() else "<no declaration file was written>")

    def test_every_refusal_path_declares_the_refused_check(self):
        """SIX refusal paths, and each one declares itself BY NAME.

        Five would satisfy every message-level assertion in this file while
        leaving one refusal indistinguishable from a wrapped status -- the
        defect B1 names. The status stays 1 on every path (unchanged, and the
        same number a wrapped command returns), so the declaration is the only
        thing that distinguishes them."""
        for name, env, expected in self.REFUSALS:
            with self.subTest(refusal=name):
                self.calls.unlink(missing_ok=True)
                self.declared.unlink(missing_ok=True)
                result = self.run_bounded("suite", env=env,
                                          driver=self.declared_driver())
                note = self.describe(result)
                self.assertEqual(result.returncode, 1, note)
                self.assertEqual(self.declared_after(), expected, note)
                self.assertFalse(self.calls.exists(),
                                 f"the wrapper ran on a refused {name}: {note}")

    def test_a_green_run_declares_ok(self):
        # `ok` means "the helper's own run is sound", not "the command passed":
        # that is the reading the reader's 101 and operational arms depend on.
        self.stub("timeout", 0)
        result = self.run_bounded("suite", env={"PATH": str(self.tools)},
                                  driver=self.declared_driver())
        note = self.describe(result)
        self.assertEqual(result.returncode, 0, note)
        self.assertEqual(self.declared_after(), "ok", note)

    def test_a_killed_run_declares_the_kill_and_not_a_refusal(self):
        # 124 and 137 are the only statuses the helper itself labels a kill, so
        # it is the party that can say "I killed it" -- and it says so.
        self.stub("timeout", 137)
        result = self.run_bounded("suite", env={"PATH": str(self.tools)},
                                  driver=self.declared_driver())
        note = self.describe(result)
        self.assertEqual(result.returncode, 137, note)
        self.assertEqual(self.declared_after(), "killed", note)
        self.assertIn("GATE-SUITE-TIMEOUT-FAIL", result.stderr, note)

    def test_a_wrapped_failure_declares_ok_and_never_a_refusal(self):
        # The wrapped command's own status must leave the declaration at `ok`: a
        # refusal would let this run read as a budget fact nobody observed, and
        # an inherited declaration would let it read as the previous run's.
        self.stub("timeout", 101)
        result = self.run_bounded("suite", env={"PATH": str(self.tools)},
                                  driver=self.declared_driver())
        note = self.describe(result)
        self.assertEqual(result.returncode, 101, note)
        self.assertEqual(self.declared_after(), "ok", note)

    def test_each_run_gets_its_own_declaration_file(self):
        """A stale declaration is the failure mode a per-process assertion cannot
        see: two calls in ONE shell, a refusal then a green run. The per-run file
        makes it true by construction -- each run writes only its own file -- so
        the pin is the two DISTINCT paths and the second file's own content."""
        self.stub("timeout", 0)
        driver = self.declared_driver("per-run.sh", body=(
            '_shipped_stack="$GATE_SUITE_MIN_STACK"\n'
            'GATE_SUITE_MIN_STACK=16M\n'
            '_first=$(mktemp "$DECLARED_DIR/one.XXXXXX")\n'
            'printf "%s\\n" "$_first" > "$DECLARED_FIRST_NAME"\n'
            'GATE_SUITE_DECLARATION_FILE="$_first"\n'
            'export GATE_SUITE_DECLARATION_FILE\n'
            'bounded_suite suite || :\n'
            'cp "$_first" "$DECLARED_REFUSED"\n'
            'rm -f "$_first"\n'
            'GATE_SUITE_MIN_STACK="$_shipped_stack"\n'
            '_second=$(mktemp "$DECLARED_DIR/two.XXXXXX")\n'
            'printf "%s\\n" "$_second" > "$DECLARED_SECOND_NAME"\n'
            'GATE_SUITE_DECLARATION_FILE="$_second"\n'
            'export GATE_SUITE_DECLARATION_FILE\n'
            'bounded_suite suite || :\n'
            'cp "$_second" "$DECLARED_LATER"\n'
            'rm -f "$_second"\n'
            'exit 0\n'))
        refused = self.temp / "refused"
        later = self.temp / "later"
        first_name = self.temp / "first-name"
        second_name = self.temp / "second-name"
        result = self.run_bounded(env={"PATH": self.scoped_path(self.tools),
                                       "DECLARED_DIR": str(self.temp),
                                       "DECLARED_REFUSED": str(refused),
                                       "DECLARED_LATER": str(later),
                                       "DECLARED_FIRST_NAME": str(first_name),
                                       "DECLARED_SECOND_NAME": str(second_name)},
                                  driver=driver)
        note = self.describe(result)
        self.assertEqual(result.returncode, 0, note)
        self.assertEqual(refused.read_text().strip(), "refused:stack-unknown", note)
        self.assertEqual(later.read_text().strip(), "ok",
                         "the refusal survived into a later green run in the same "
                         "shell: " + note)
        self.assertNotEqual(first_name.read_text().strip(),
                            second_name.read_text().strip(),
                            "both runs declared into ONE file, so the second run's "
                            "content cannot be a fact about the second run: " + note)

    def test_without_a_declaration_path_the_helper_writes_nothing(self):
        """The path is the caller's to export. Unset or empty, the helper does
        not attempt a write at all -- an announcement here would be the failed
        write this test is looking for the absence of."""
        self.stub("timeout", 0)
        driver = self.declared_driver("unset.sh", body=(
            '[ -z "${GATE_SUITE_DECLARATION_FILE-}" ] || {\n'
            '    echo "PATH-WAS-SET: $GATE_SUITE_DECLARATION_FILE" >&2\n'
            '    exit 9\n'
            '}\n'
            'bounded_suite "$@"\n'))
        result = self.run_bounded("suite", env={"PATH": str(self.tools),
                                                "GATE_SUITE_DECLARATION_FILE": ""},
                                  driver=driver)
        note = self.describe(result)
        self.assertEqual(result.returncode, 0, note)
        self.assertNotIn("PATH-WAS-SET", result.stderr, note)
        self.assertNotIn("GATE-SUITE-DECLARATION-UNKNOWN", result.stderr, note)

    def test_a_failed_declaration_write_is_announced_and_never_changes_the_status(self):
        # `set -e` must never turn a channel failure into a suite failure, and a
        # silent channel is the failure mode this file exists to remove: the
        # write is announced and the status is the wrapped command's.
        self.stub("timeout", 0)
        unwritable = self.temp / "no-such-dir" / "declared"
        result = self.run_bounded("suite", env={"PATH": str(self.tools),
                                                "DECLARED": str(unwritable)},
                                  driver=self.declared_driver())
        note = self.describe(result)
        self.assertEqual(result.returncode, 0, note)
        self.assertIn("GATE-SUITE-DECLARATION-UNKNOWN", result.stderr, note)
        self.assertFalse(unwritable.exists(), note)

    def test_every_lib_suite_call_site_goes_through_the_bound(self):
        for name in ("mid_union", "mid_full"):
            lib_lines = [line.strip() for line in extract_function(name).splitlines()
                         if "--lib" in line]
            self.assertEqual(len(lib_lines), 2, name)
            for line in lib_lines:
                self.assertTrue(line.startswith("bounded_suite cargo atest"),
                                f"{name} runs a lib suite unbounded: {line}")
                self.assertNotIn("RUST_MIN_STACK=", line,
                                 f"{name} carries the stack budget at the call site; "
                                 f"the helper owns it: {line}")


class InnerTest(unittest.TestCase):
    """The seventh `cargo atest` site: `inner test <target>` is an argument to
    the shipped `bounded_suite`, not a second stack owner with its own prefix.

    The fastest loop is where the 22144 class costs most (a lib surface run at a
    smaller host default dies at libtest exit 101 with no failing test), so the
    pin drives the shipped `inner_test` body against a stub `cargo` and a stub
    `timeout` on PATH: the wrapper hands the command over, and the cargo child's
    own environment shows the floor it actually ran at.

    The declaration channel is a FILE per run, so these tests can also see it:
    the wrapper stub records the path and its mode while the run is in flight,
    TMPDIR points at a scratch directory, and every exit path must leave that
    directory empty."""

    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        self.temp = Path(self._temp.name)
        self.tools = self.temp / "tools"
        self.tools.mkdir()
        self.calls = self.temp / "cargo-calls"
        self.stack_seen = self.temp / "stack-seen"
        self.wrapper_calls = self.temp / "wrapper-calls"
        self.declaration_path = self.temp / "declaration-path"
        self.declaration_mode = self.temp / "declaration-mode"
        self.scratch = self.temp / "tmp"
        self.scratch.mkdir()
        # The reader's own prerequisites are not what these tests vary -- the
        # wrapper's presence is. So they are reached through a directory of real
        # utilities placed BESIDE the stub directory, never by widening PATH to
        # /usr/bin: a host `timeout` on PATH would resurrect the wrapper a case
        # meant to withhold and silently defeat the absent-wrapper refusal, while
        # `mktemp`, `cat`, `rm` and `stat` here behave exactly as in a real run.
        self.util = self.temp / "util"
        self.util.mkdir()
        for name in ("mktemp", "cat", "rm", "stat"):
            found = shutil.which(name)
            self.assertIsNotNone(found, f"{name} is a prerequisite of this reader")
            (self.util / name).symlink_to(found)
        self.stub("cargo",
                  'printf "%s\\n" "$*" >> "$CARGO_CALLS"\n'
                  'printf "%s\\n" "${RUST_MIN_STACK-<unset>}" > "$STACK_SEEN"\n'
                  'exit "${CARGO_RC-0}"\n')
        # The wrapper records the argv the helper assembled, then hands the
        # command over, so the cargo stub runs as the wrapper's child exactly as
        # a real suite would. It also records the declaration path it inherited
        # and that file's mode WHILE IT EXISTS -- the reader removes it after the
        # run, so the mode can only be observed from inside the run. Both `stat`
        # spellings are supported: GNU `-c %a` first, BSD `-f %Lp` second.
        self.stub("timeout",
                  'printf "%s\\n" "$*" >> "$WRAPPER_CALLS"\n'
                  'printf "%s\\n" "${GATE_SUITE_DECLARATION_FILE-<unset>}" '
                  '> "$DECLARATION_PATH"\n'
                  'if [ -n "${GATE_SUITE_DECLARATION_FILE-}" ]; then\n'
                  '    stat -c %a "$GATE_SUITE_DECLARATION_FILE" 2>/dev/null '
                  '|| stat -f %Lp "$GATE_SUITE_DECLARATION_FILE" 2>/dev/null\n'
                  'fi > "$DECLARATION_MODE"\n'
                  'shift 3\n'
                  'exec "$@"\n')
        # A PATH carrying the cargo stub but no wrapper at all: the
        # absent-wrapper refusal is reachable even where the host has one.
        self.cargo_only = self.temp / "cargo-only"
        self.cargo_only.mkdir()
        self.stub("cargo",
                  'printf "%s\\n" "$*" >> "$CARGO_CALLS"\n'
                  'printf "%s\\n" "${RUST_MIN_STACK-<unset>}" > "$STACK_SEEN"\n'
                  'exit "${CARGO_RC-0}"\n', directory=self.cargo_only)
        self.driver = self.write_driver("inner.sh", extract_function("inner_test"))

    def stub(self, name, body, directory=None):
        path = (directory or self.tools) / name
        path.write_text("#!/bin/sh\n" + body)
        path.chmod(0o755)

    def write_driver(self, name, inner_body):
        """Every shipped knob assignment the helper reads, the shipped source,
        then the shipped `inner_test` body under the interpreter options
        scripts/verify.sh itself runs with."""
        path = self.temp / name
        path.write_text(
            "set -eu\n" + "\n".join(shipped_knob_lines()) + "\n\n"
            + bounded_suite_source() + "\n\n" + inner_body
            + '\n\ninner_test "$@"\n')
        return path

    def run_inner(self, *args, env=None, driver=None):
        inherited = {key: value for key, value in os.environ.items()
                     if key not in ("GATE_SUITE_BUDGET_SECS", "GATE_SUITE_MIN_STACK",
                                    "RUST_MIN_STACK", "GATE_SUITE_DECLARATION_FILE",
                                    "TMPDIR")}
        return subprocess.run(
            [shutil.which("sh") or "/bin/sh",
             str(driver or self.driver), *map(str, args)],
            cwd=self.temp, text=True, capture_output=True,
            env={**inherited, "PATH": self.scoped_path(self.tools),
                 "CARGO_CALLS": str(self.calls),
                 "STACK_SEEN": str(self.stack_seen),
                 "WRAPPER_CALLS": str(self.wrapper_calls),
                 "DECLARATION_PATH": str(self.declaration_path),
                 "DECLARATION_MODE": str(self.declaration_mode),
                 "TMPDIR": str(self.scratch), **(env or {})})

    def scoped_path(self, *directories):
        """The stub directories searched FIRST, then the reader's own utilities.
        The host PATH is absent, so a wrapper this run means to withhold stays
        withheld."""
        return ":".join([*(str(directory) for directory in directories),
                         str(self.util)])

    def describe(self, result):
        calls = (self.calls.read_text().strip() if self.calls.exists()
                 else "<cargo never invoked>")
        wrapper = (self.wrapper_calls.read_text().strip()
                   if self.wrapper_calls.exists() else "<wrapper never invoked>")
        return (f"cargo argv: {calls}\nwrapper argv: {wrapper}\n"
                f"exit: {result.returncode}\n"
                f"stdout: {result.stdout}stderr: {result.stderr}")

    def test_the_target_is_an_argument_to_the_bound_helper(self):
        body = extract_function("inner_test")
        self.assertEqual(body.count("bounded_suite cargo atest"), 1, body)
        bare = [line.strip() for line in body.splitlines()
                if line.strip().startswith("cargo atest")]
        self.assertEqual(bare, [], f"inner_test still runs a bare cargo atest: {bare}")

    def test_the_target_runs_at_the_shipped_stack_floor(self):
        result = self.run_inner("foundations")
        note = self.describe(result)
        self.assertEqual(result.returncode, 0, note)
        self.assertIn("INNER-TEST-OK: foundations", result.stdout, note)
        self.assertNotIn("INNER-TEST-BUDGET-REFUSED", result.stderr, note)
        self.assertNotIn("INNER-TEST-OPERATIONAL-FAIL", result.stderr, note)
        self.assertNotIn("INNER-TEST-HOST-INCOMPATIBLE-OR-FAIL", result.stderr, note)
        shipped = shipped_min_stack()
        self.assertEqual(self.stack_seen.read_text().strip(), shipped, note)
        self.assertIn(f"RUST_MIN_STACK={shipped}", result.stdout, note)
        self.assertEqual(self.calls.read_text().strip(),
                         "atest -p alumina --locked --test foundations", note)
        # The budget wraps the cargo invocation from this site too, in the
        # shipped portable form the helper owns.
        self.assertEqual(self.wrapper_calls.read_text().strip(),
                         "-s KILL 600 cargo atest -p alumina --locked "
                         "--test foundations", note)

    def test_an_under_floor_budget_is_refused_and_never_misattributed(self):
        result = self.run_inner("foundations", env={"GATE_SUITE_MIN_STACK": "1048576"})
        note = self.describe(result)
        # The status is UNCHANGED (1, the same number a wrapped command returns)
        # and the report comes from the helper's declaration instead: that is the
        # whole point of the channel, so both halves are pinned together.
        self.assertEqual(result.returncode, 1, note)
        self.assertIn("GATE-SUITE-STACK-UNKNOWN", result.stderr, note)
        self.assertIn("INNER-TEST-BUDGET-REFUSED", result.stderr, note)
        self.assertIn("declared 'stack-unknown'", result.stderr, note)
        self.assertNotIn("INNER-TEST-HOST-INCOMPATIBLE-OR-FAIL", result.stderr, note)
        self.assertNotIn("INNER-TEST-OPERATIONAL-FAIL", result.stderr, note)
        self.assertFalse(self.calls.exists(),
                         f"cargo ran under a refused stack budget: {note}")
        self.assertFalse(self.wrapper_calls.exists(),
                         f"the wrapper was resolved under a refused stack budget: {note}")

    def test_every_refusal_path_reaches_the_reader_as_the_budget(self):
        """All six refusal paths, end to end through the shipped reader.

        Each case names the marker the helper prints for that refusal; cargo and
        the wrapper must both stay uninvoked, so nothing but the refusal itself
        can produce this classification -- and the status stays 1 throughout."""
        cases = (
            ("stack non-numeric", {"GATE_SUITE_MIN_STACK": "16M"},
             "GATE-SUITE-STACK-UNKNOWN"),
            ("stack over the digit ceiling", {"GATE_SUITE_MIN_STACK": "9" * 19},
             "GATE-SUITE-STACK-UNKNOWN"),
            ("stack below the floor", {"GATE_SUITE_MIN_STACK": "1048576"},
             "GATE-SUITE-STACK-UNKNOWN"),
            ("budget non-numeric", {"GATE_SUITE_BUDGET_SECS": "600s"},
             "GATE-SUITE-TIMEOUT-UNKNOWN"),
            ("budget of zero", {"GATE_SUITE_BUDGET_SECS": "0"},
             "GATE-SUITE-TIMEOUT-UNKNOWN"),
            ("no wrapper on PATH", {"PATH": self.scoped_path(self.cargo_only)},
             "GATE-SUITE-TIMEOUT-UNKNOWN"),
        )
        for name, env, marker in cases:
            with self.subTest(refusal=name):
                # Each case must prove cargo was never invoked by itself; a
                # previous subTest's log would otherwise stand in for it.
                self.calls.unlink(missing_ok=True)
                self.wrapper_calls.unlink(missing_ok=True)
                result = self.run_inner("foundations", env=env)
                note = self.describe(result)
                self.assertEqual(result.returncode, 1, note)
                self.assertIn(marker, result.stderr, note)
                self.assertIn("INNER-TEST-BUDGET-REFUSED", result.stderr, note)
                self.assertIn("declared '", result.stderr, note)
                self.assertNotIn("INNER-TEST-TIMEOUT-FAIL", result.stderr, note)
                self.assertNotIn("INNER-TEST-HOST-INCOMPATIBLE-OR-FAIL",
                                 result.stderr, note)
                self.assertNotIn("INNER-TEST-OPERATIONAL-FAIL", result.stderr, note)
                self.assertFalse(self.calls.exists(),
                                 f"cargo ran under a refused {name}: {note}")
                self.assertFalse(self.wrapper_calls.exists(),
                                 f"the wrapper ran under a refused {name}: {note}")

    def test_a_wrapped_status_is_never_read_as_a_refusal_or_an_assertion(self):
        """The pass-through partition: a status the WRAPPED command returned is
        never reported as a refusal or as an assertion verdict. 1 is the case
        that mattered -- it is both a wrapped command's generic failure and what
        the helper used to return -- and 2/125/126/127 are ordinary wrapper and
        shell failures that used to land in the assertion arm. 2 and 126 carry
        the old ambiguity exactly: the tool triage read both as "a test binary
        ran" and 2 as the shell's own misuse status."""
        for status in (1, 2, 125, 126, 127):
            with self.subTest(wrapped=status):
                result = self.run_inner("foundations", env={"CARGO_RC": str(status)})
                note = self.describe(result)
                self.assertEqual(result.returncode, status, note)
                self.assertIn("INNER-TEST-OPERATIONAL-FAIL", result.stderr, note)
                self.assertNotIn("INNER-TEST-BUDGET-REFUSED", result.stderr, note)
                self.assertNotIn("INNER-TEST-TIMEOUT-FAIL", result.stderr, note)
                self.assertNotIn("INNER-TEST-HOST-INCOMPATIBLE-OR-FAIL",
                                 result.stderr, note)

    def test_a_killed_run_reports_the_budget_not_an_assertion(self):
        result = self.run_inner("foundations", env={"CARGO_RC": "124"})
        note = self.describe(result)
        self.assertEqual(result.returncode, 124, note)
        self.assertIn("INNER-TEST-TIMEOUT-FAIL", result.stderr, note)
        self.assertIn("declared 'killed'", result.stderr, note)
        self.assertNotIn("INNER-TEST-HOST-INCOMPATIBLE-OR-FAIL", result.stderr, note)
        self.assertNotIn("INNER-TEST-BUDGET-REFUSED", result.stderr, note)
        self.assertNotIn("INNER-TEST-OPERATIONAL-FAIL", result.stderr, note)

    def test_a_genuine_failing_assertion_still_points_at_the_mid_tier(self):
        result = self.run_inner("foundations", env={"CARGO_RC": "101"})
        note = self.describe(result)
        self.assertEqual(result.returncode, 101, note)
        self.assertIn("INNER-TEST-HOST-INCOMPATIBLE-OR-FAIL", result.stderr, note)
        self.assertIn("verify.sh mid", result.stderr, note)
        self.assertNotIn("INNER-TEST-BUDGET-REFUSED", result.stderr, note)
        self.assertNotIn("INNER-TEST-OPERATIONAL-FAIL", result.stderr, note)

    def test_the_assertion_arm_is_pinned_by_plant_not_by_a3cce49(self):
        """101 is the ONE status this triage keeps from the old code, so it
        cannot be red on a3cce49 -- the honest falsification is a plant: move the
        arm and 101 falls into the operational class, which is exactly the
        regression (an assertion verdict turned into an unknown) this pin
        exists to refuse."""
        shipped_body = extract_function("inner_test")
        planted_body = shipped_body.replace("\n                101)\n",
                                            "\n                100)\n", 1)
        self.assertNotEqual(planted_body, shipped_body,
                            "the shipped reader has no 101 arm to plant against")
        planted = self.write_driver("planted-101.sh", planted_body)
        result = self.run_inner("foundations", env={"CARGO_RC": "101"},
                                driver=planted)
        note = self.describe(result)
        self.assertEqual(result.returncode, 101, note)
        self.assertIn("INNER-TEST-OPERATIONAL-FAIL", result.stderr,
                      "the plant did not move the 101 arm, so the pin proves "
                      "nothing: " + note)

    def test_a_bare_cargo_atest_call_turns_the_stack_pin_red(self):
        # Plant: the routing removed, every other shipped line intact. The same
        # driver then runs cargo with no helper, so the cargo child's
        # RUST_MIN_STACK is unset and no declaration is written at all -- the pin
        # is behavioural, not a textual match on the call site, and the missing
        # declaration is reported as UNKNOWN rather than as a pass.
        shipped_body = extract_function("inner_test")
        planted_body = shipped_body.replace(
            "if bounded_suite cargo atest $_run_args; then",
            "if cargo atest $_run_args; then", 1)
        self.assertNotEqual(planted_body, shipped_body)
        planted = self.write_driver("planted.sh", planted_body)
        result = self.run_inner("foundations", driver=planted)
        note = self.describe(result)
        self.assertEqual(self.stack_seen.read_text().strip(), "<unset>",
                         "the plant still ran at a stack budget; the pin proves "
                         "nothing: " + note)
        self.assertIn("INNER-TEST-UNKNOWN", result.stderr, note)
        self.assertNotIn("INNER-TEST-OK", result.stdout + result.stderr, note)

    # --- the declaration channel is a file the running process writes --------

    def test_a_blocked_declaration_channel_refuses_before_any_run(self):
        """A channel that cannot be created is its own refusal: no suite run
        starts without somewhere to report it, so cargo and the wrapper both stay
        uninvoked and nothing is claimed. It is NOT a budget fact -- no check was
        refused, so the reader must not report one. Both shapes are pinned: an
        `mktemp` that runs and fails, and one that is absent altogether."""
        failing = self.temp / "mktemp-fails"
        failing.mkdir()
        self.stub("mktemp", "exit 1\n", directory=failing)
        for name, path in (
                ("mktemp fails", self.scoped_path(failing, self.tools)),
                ("mktemp absent", str(self.tools))):
            with self.subTest(channel=name):
                # Neither log may survive a previous subTest, so each shape
                # proves cargo and the wrapper stayed uninvoked by itself.
                self.calls.unlink(missing_ok=True)
                self.wrapper_calls.unlink(missing_ok=True)
                result = self.run_inner("foundations", env={"PATH": path})
                note = self.describe(result)
                self.assertEqual(result.returncode, 1, note)
                self.assertIn("INNER-TEST-CHANNEL-BLOCKED", result.stderr, note)
                self.assertFalse(self.calls.exists(),
                                 f"cargo ran without a declaration channel "
                                 f"({name}): {note}")
                self.assertFalse(self.wrapper_calls.exists(),
                                 f"the wrapper ran without a declaration channel "
                                 f"({name}): {note}")
                self.assertNotIn("INNER-TEST-OK", result.stdout + result.stderr, note)
                self.assertNotIn("INNER-TEST-BUDGET-REFUSED", result.stderr, note)

    def test_a_pipeline_call_site_still_reports_the_refusal(self):
        """The seam: the helper runs in a subshell here, so a shell-variable
        declaration dies with that subshell and the reader is left with its
        operational arm -- over a run that never started. The file is written by
        the process that ran, so the refusal arrives anyway, and the piped status
        (0) cannot be read as a pass."""
        shipped_body = extract_function("inner_test")
        planted_body = shipped_body.replace(
            "if bounded_suite cargo atest $_run_args; then",
            "if bounded_suite cargo atest $_run_args | cat; then", 1)
        self.assertNotEqual(planted_body, shipped_body,
                            "the shipped reader has no single-line helper call to "
                            "pipe")
        planted = self.write_driver("planted-pipeline.sh", planted_body)
        result = self.run_inner("foundations",
                                env={"GATE_SUITE_MIN_STACK": "1048576"},
                                driver=planted)
        note = self.describe(result)
        self.assertIn("INNER-TEST-BUDGET-REFUSED", result.stderr, note)
        self.assertIn("declared 'stack-unknown'", result.stderr, note)
        self.assertIn("INNER-TEST-STATUS-CONTRADICTS-DECLARATION", result.stderr,
                      "the piped status 0 was not named as impossible against a "
                      "refusal: " + note)
        self.assertNotIn("INNER-TEST-OK", result.stdout + result.stderr, note)
        self.assertNotIn("INNER-TEST-OPERATIONAL-FAIL", result.stderr, note)
        self.assertFalse(self.calls.exists(),
                         f"cargo ran under a refused stack budget: {note}")
        self.assertFalse(self.wrapper_calls.exists(),
                         f"the wrapper ran under a refused stack budget: {note}")
        # The same plant on a green run is still a pass, so the test above shows
        # the channel carries the refusal rather than refusing everything.
        self.calls.unlink(missing_ok=True)
        self.wrapper_calls.unlink(missing_ok=True)
        green = self.run_inner("foundations", driver=planted)
        self.assertIn("INNER-TEST-OK: foundations", green.stdout,
                      self.describe(green))

    def test_a_missing_or_garbled_declaration_is_unknown_and_never_ok(self):
        """Every shape that is not a recognised declaration is UNKNOWN: a green
        status with nothing behind it is exactly the false PASS this channel
        replaced, so it must neither read as OK nor exit 0."""
        shipped_body = extract_function("inner_test")
        reader = ('_itr_declared=$(cat "$_it_declaration" 2>/dev/null) '
                  '|| _itr_declared=""')
        self.assertIn(reader, shipped_body,
                      "the shipped reader does not read the declaration file")
        # (a) absent: the reader exports no path, so the helper writes nothing
        # and the per-run file stays empty.
        absent_body = shipped_body.replace(
            'GATE_SUITE_DECLARATION_FILE="$_it_declaration"',
            'GATE_SUITE_DECLARATION_FILE=""', 1)
        self.assertNotEqual(absent_body, shipped_body)
        cases = [("absent", absent_body)]
        for value in ("gibberish", "refused:"):
            garbled_body = shipped_body.replace(
                reader, f'_itr_declared="{value}"', 1)
            self.assertNotEqual(garbled_body, shipped_body)
            cases.append((value, garbled_body))
        for name, body in cases:
            with self.subTest(declaration=name):
                planted = self.write_driver(f"planted-{name}.sh", body)
                result = self.run_inner("foundations", driver=planted)
                note = self.describe(result)
                self.assertIn("INNER-TEST-UNKNOWN", result.stderr, note)
                self.assertNotIn("INNER-TEST-OK", result.stdout + result.stderr,
                                 note)
                self.assertNotEqual(result.returncode, 0,
                                    f"a run whose declaration was {name} exited "
                                    f"0, which is a false PASS: {note}")

    def test_the_declaration_file_is_private_and_removed_on_every_exit_path(self):
        """One fresh file per run, mode 0600 while the run is in flight, and gone
        afterwards -- including the refusal, kill, wrapped-failure and unknown
        paths, so no run can leave a declaration for the next one to read."""
        reader = ('_itr_declared=$(cat "$_it_declaration" 2>/dev/null) '
                  '|| _itr_declared=""')
        shipped_body = extract_function("inner_test")
        unknown = self.write_driver(
            "planted-unknown-cleanup.sh",
            shipped_body.replace(reader, '_itr_declared="gibberish"', 1))
        for name, env, driver in (
                ("green", {}, None),
                ("wrapped failure", {"CARGO_RC": "1"}, None),
                ("killed", {"CARGO_RC": "124"}, None),
                ("refused", {"GATE_SUITE_MIN_STACK": "1048576"}, None),
                ("unknown", {}, unknown)):
            with self.subTest(exit_path=name):
                for path in (self.declaration_path, self.declaration_mode):
                    path.unlink(missing_ok=True)
                result = self.run_inner("foundations", env=env, driver=driver)
                note = self.describe(result)
                self.assertEqual(
                    sorted(path.name for path in self.scratch.iterdir()), [],
                    f"the {name} path left a declaration file behind: {note}")
                if name == "refused":
                    # No wrapper ran, so no mode was observed; the isolation
                    # above is the whole claim there.
                    continue
                recorded = self.declaration_path.read_text().strip()
                self.assertTrue(recorded.startswith(str(self.scratch)),
                                f"the declaration file was not created under "
                                f"TMPDIR: {note}")
                self.assertEqual(self.declaration_mode.read_text().strip(), "600",
                                 f"the declaration file was not private while the "
                                 f"run was in flight: {note}")


BOUNDED_SUITE_TOKEN = re.compile(r"\bbounded_suite\b")
# The shell words that admit the command after them as a command in the CURRENT
# shell. `then`/`else`/`do` open a compound body, `{ ; }` groups in this shell,
# and `time`/`command` prefix a command without a child shell; `env FOO=1` and a
# bare assignment do not appear, because those do change what the command word
# is. Every entry here is a spelling that costs the declaration nothing.
CURRENT_SHELL_KEYWORDS = ("", "if", "elif", "then", "else", "while", "until",
                          "do", "!", "{", "time", "command")
CALL_WORD = "bounded_suite"
NESTED_SHELL = re.compile(r"\b(?:sh|bash|zsh|dash|ksh)\s+-c\b")
# A here-document's body is read by a child shell (or by a consumer that never
# evaluates it), never by the shell that parses the script, so a call written
# there cannot declare anything that survives to this reader.
HEREDOC_OPENER = re.compile(
    r"<<-?\s*(?:'([A-Za-z_][A-Za-z0-9_]*)'|\"([A-Za-z_][A-Za-z0-9_]*)\""
    r"|([A-Za-z_][A-Za-z0-9_]*))")
# `&`, `&&`, `||`, `;` and `;;` each terminate a command and introduce the one
# that follows, so the text after the last one is the region that decides the
# command word: `true & bounded_suite ...` runs the helper in this shell. A
# `pattern)` case arm introduces its body the same way, so the closing paren of
# an arm is an introducer and the arm body stays a current-shell call.
INTRODUCER = re.compile(r"&&|\|\||;;|;&|[&|;)]")


def quote_states(line):
    """Per-character shell quoting: 'plain', 'single' or 'double'.

    A backslash escapes the next character outside single quotes, so the
    escaped character keeps the current state instead of opening a quote. The
    scanner needs this because an operator inside quotes is literal text, while
    `$(` and a backtick still execute inside double quotes."""
    states = []
    state = "plain"
    escaped = False
    for character in line:
        if escaped:
            states.append(state)
            escaped = False
            continue
        if state == "plain":
            if character == "\\":
                states.append(state)
                escaped = True
                continue
            if character in "'\"":
                state = "single" if character == "'" else "double"
                states.append(state)
                continue
        elif state == "single":
            if character == "'":
                state = "plain"
                states.append(state)
                continue
        else:
            if character == "\\":
                states.append(state)
                escaped = True
                continue
            if character == '"':
                state = "plain"
                states.append(state)
                continue
        states.append(state)
    return states


def command_word(line, at):
    """The command-word region before a call, after the last introducer."""
    states = quote_states(line)
    cut = 0
    for match in INTRODUCER.finditer(line, 0, at):
        if states[match.start()] not in ("single", "double"):
            cut = match.end()
    return line[cut:at].strip()


def lossy_call_shape(line, at):
    """The shape name for a call whose declaration dies with a child shell.

    This is the ordered HAZARD layer, and it runs before every allowance: a
    diagnostic on an `echo`/`printf` line must never filter a raw span out of
    the scan. `$(` and a backtick execute even inside double quotes, so only
    single quotes excuse them; an operator inside either quote is literal text.
    A bare `&` is a FORWARD terminator, so it is read where it appears rather
    than only at end of line."""
    states = quote_states(line)
    for index in range(at):
        if states[index] == "single":
            continue
        if line.startswith("$(", index):
            return "command substitution"
        if line[index] == "`":
            return "backticks"
    if NESTED_SHELL.search(line[:at]):
        return "nested shell"
    if command_word(line, at).startswith("("):
        return "subshell"
    for index in range(at + len(CALL_WORD), len(line)):
        if states[index] in ("single", "double"):
            continue
        character = line[index]
        previous = line[index - 1] if index else ""
        following = line[index + 1] if index + 1 < len(line) else ""
        # The call's own command span ends at its first terminator, so a later
        # command on the same line cannot decide this call's fate.
        if character == "&" and previous == ">":
            continue                     # `>&2` is a redirection, not a job
        if character == "&" and following == ">":
            continue                     # `&>` is a redirection too
        if character == ";":
            return None                  # the call's command ends in this shell
        if character == "&" and following == "&":
            return None                  # `&&` introduces a separate command
        if character == "&":
            return "background"
        if character == "|" and following == "|":
            return None                  # `||` introduces a separate command
        if character == "|":
            return "pipeline"
    return None


def heredoc_body_lines(text):
    """The 1-based line numbers that hold a here-document body."""
    bodies, pending = set(), []
    for number, line in enumerate(text.splitlines(), 1):
        if pending:
            bodies.add(number)
            if line.strip() == pending[0]:
                pending.pop(0)
            continue
        for match in HEREDOC_OPENER.finditer(line):
            pending.append(next(group for group in match.groups() if group))
    return bodies


def quote_span_shape(line, at):
    """The shape of a quote opened at `at`.

    A quote opens a span whose contents are read by whoever the opening line
    hands them to, so `sh -c '` names the nested shell and a lone quote names a
    string no shell evaluates. The line that closes the span never decides."""
    return "nested shell" if NESTED_SHELL.search(line[:at]) else "quoted string"


def step_quotes(segment, quote, escaped):
    """The quoting state after one physical line, and whether its newline is removed.

    POSIX removes an unquoted backslash-newline before tokenizing, and the
    escaped newline inside double quotes goes with it, but a backslash inside
    single quotes is literal text: the join decision needs the quote a line is
    written in, not just its last character."""
    removed = False
    for character in segment:
        was_escaped = escaped
        escaped = removed = False
        if was_escaped:
            continue
        if quote == "single":
            if character == "'":
                quote = ""
            continue
        if character == "\\":
            escaped = removed = True
            continue
        if character == "'" and quote != "double":
            quote = "single"
        elif character == '"':
            quote = "" if quote == "double" else "double"
    return quote, escaped, removed


def joined_command_units(text, bodies):
    """(first physical line, its stripped text, joined text) per command unit.

    POSIX removes an unquoted backslash-newline before the shell tokenizes, so
    `bounded_suite ... \\` followed by `| cat` is ONE command whose pipeline is
    written on the second physical line; a line-local scan can never see the
    operator that decides that call. A unit therefore spans the physical lines
    a continuation joins, while every entry keeps the FIRST physical line and
    its stripped text, so a join never renumbers a report.

    A here-document body is body text, not a continuation: verify.sh:2386 ends
    in a backslash inside an ALTCF body, and joining it would rename every line
    after it. Bodies are enumerated on physical lines and are neither joined nor
    joined into. A comment line is a barrier for the same reason -- its text is
    not code, so it opens no unit and is never scanned for a call."""
    lines = text.splitlines()
    units = []
    quote, escaped = "", False
    number = 0
    while number < len(lines):
        first = number + 1
        number += 1
        stripped = lines[first - 1].strip()
        if first in bodies or stripped.startswith("#"):
            units.append((first, stripped, lines[first - 1]))
            continue
        parts = [lines[first - 1]]
        while True:
            quote, escaped, removed = step_quotes(parts[-1], quote, escaped)
            following = number + 1
            if (not removed or following > len(lines) or following in bodies
                    or lines[number].strip().startswith("#")):
                break
            parts.append(lines[number])
            number += 1
            escaped = False             # the removed newline was the escaped character
        escaped = False                 # a trailing backslash escapes no character
        units.append((first, stripped,
                      "".join(part[:-1] for part in parts[:-1]) + parts[-1]))
    return units


def carried_span_shapes(units, bodies):
    """Per unit, the shape of the span still open from an earlier unit.

    A quote, `$(` or backtick that survives the newline reads its contents in a
    child shell -- or in no shell at all -- so a call written there can never
    declare anything this reader sees. The span state is therefore carried
    across the unit loop, the way here-document bodies are precomputed. A
    here-document body and a comment line are not code, so they neither open
    nor carry a span. The innermost span wins, and it is named by the unit that
    opened it."""
    carried = []
    spans = []                          # innermost last: kind, shape, unit, depth
    for number, stripped, joined in units:
        shapes = [None] * len(joined)
        carried.append(shapes)
        if number in bodies or stripped.startswith("#"):
            continue
        escaped = False
        for index, character in enumerate(joined):
            for _kind, shape, opened, _depth in reversed(spans):
                if opened < number:
                    shapes[index] = shape
                    break
            if escaped:
                escaped = False
                continue
            kind = spans[-1][0] if spans else ""
            if kind == "single":
                if character == "'":
                    spans.pop()
                continue
            if kind == "double":
                if character == "\\":
                    escaped = True
                elif character == '"':
                    spans.pop()
                elif joined.startswith("$(", index):
                    spans.append(["substitution", "command substitution", number, 0])
                elif character == "`":
                    spans.append(["backticks", "backticks", number, 0])
                continue
            if kind == "backticks":
                if character == "`":
                    spans.pop()
                continue
            if kind == "substitution":
                if character == "(":
                    spans[-1][3] += 1
                elif character == ")":
                    spans[-1][3] -= 1
                    if spans[-1][3] == 0:
                        spans.pop()
                continue
            if character == "\\":
                escaped = True
            elif joined.startswith("$(", index):
                spans.append(["substitution", "command substitution", number, 0])
            elif character == "`":
                spans.append(["backticks", "backticks", number, 0])
            elif character in "'\"":
                spans.append(["single" if character == "'" else "double",
                              quote_span_shape(joined, index), number, 0])
    return carried


def lint_bounded_suite_call_sites(text):
    """The lint entry point: (accepted, warnings) for every call site in a script.

    LINT SEMANTICS: it may warn, it may not certify. A hazard it names is worth
    reading; a clean report is NOT evidence that the declaration survives, because
    the property (which shell ran the helper) is dynamic and this is text. The
    declaration itself is carried in a file the running process writes, so no
    caller's correctness depends on this report -- including the shipped script's.
    """
    accepted, refused = scan_bounded_suite_call_sites(text)
    return accepted, refused


def scan_bounded_suite_call_sites(text):
    """(accepted, refused) for every `bounded_suite` occurrence in a script.

    A call written in a child shell cannot declare anything to a reader in this
    one, so the interesting question is which shell runs it. This classifier
    answers that from the text, which is why it can only ever be a lint: the file
    channel is what actually survives a subshell call site.

    The hazard layer runs FIRST and the diagnostic allowance is applied only to
    what survives it, so an allowance can never act as a line filter over a raw
    span. Every occurrence is examined, not just the first, because a second call
    on a known unit is exactly where a lossy shape hides.

    The scan unit is the shell command unit, not the physical line: POSIX
    removes an unquoted backslash-newline before tokenizing, so an operator
    written on a continuation line still decides the call. A span opened on an
    earlier unit is carried into the columns it still covers, so neither a
    newline nor a join can launder a child shell into the current one.

    Each entry is `(line_number, shape, line)`, where the line number is the
    FIRST physical line of the unit and the text is that line's stripped text,
    never the joined text. Refusals name the line and the shape; accepted
    entries carry the shape too, so a report has something readable to say."""
    accepted, refused = [], []
    bodies = heredoc_body_lines(text)
    units = joined_command_units(text, bodies)
    carried = carried_span_shapes(units, bodies)
    for (number, stripped, joined), shapes in zip(units, carried):
        if stripped.startswith("#") or stripped.startswith("bounded_suite() {"):
            continue
        if number in bodies:
            for _match in BOUNDED_SUITE_TOKEN.finditer(joined):
                refused.append((number, "heredoc body", stripped))
            continue
        for match in BOUNDED_SUITE_TOKEN.finditer(joined):
            shape = shapes[match.start()]
            if shape is not None:
                refused.append((number, shape, stripped))
                continue
            shape = lossy_call_shape(joined, match.start())
            if shape is not None:
                refused.append((number, shape, stripped))
                continue
            if stripped.startswith(("echo ", "printf ")):
                continue
            if command_word(joined, match.start()) not in CURRENT_SHELL_KEYWORDS:
                refused.append((number, "not a current-shell command word", stripped))
                continue
            accepted.append((number, "current-shell call", stripped))
    return accepted, refused


class CallSiteLint(unittest.TestCase):
    """LINT: it may warn, it may not certify.

    This layer used to be a named pin: `ChannelSoundness` claimed to prove every
    call site ran the helper in the current shell, so a subshell call could not
    lose the declaration silently. It could -- three adversarial rounds found a
    new blind spot each time (an echo-prefixed line, a trailing `&`, a
    continuation line), because the property is DYNAMIC and the analysis was
    textual. The declaration is now a file the running process writes, so no test
    here needs to be right about the shell: what remains is a lint over the call
    sites, reported for a reader.

    What still holds as a test is the lint's OWN shape-naming: every shape it
    claims to recognise is planted here, and a classifier change that stops
    naming one turns its plant red. Nothing in this class may fail because
    scripts/verify.sh contains a hazard -- that is a warning for a reader, not a
    gate."""

    # A hazard-free baseline the plant tests build on. The shipped script is the
    # lint's SUBJECT, never a plant's baseline: a test here must not be able to
    # fail on a hazard that lives in scripts/verify.sh.
    BASELINE = ("#!/bin/sh\n"
                "bounded_suite cargo atest -p alumina --lib\n")

    def shipped(self):
        return (ROOT / "scripts/verify.sh").read_text()

    def planted(self, plant):
        """The baseline with one plant appended, and the plant's line number."""
        text = self.BASELINE.rstrip("\n")
        return text + "\n" + plant + "\n", len(text.splitlines()) + 1

    def test_the_shipped_report_names_a_line_and_a_shape_for_every_warning(self):
        """Report quality only: a warning a reader cannot act on is noise, so
        every one carries a 1-based line number, a shape name and the text of
        the line it is about. The list itself is NOT asserted empty -- a hazard
        in scripts/verify.sh is not this layer's verdict to fail."""
        _accepted, warnings = lint_bounded_suite_call_sites(self.shipped())
        for entry in warnings:
            self.assertEqual(len(entry), 3,
                             f"a warning is not (line, shape, line): {entry}")
            number, shape, line = entry
            self.assertIsInstance(number, int, f"warning carries no line: {entry}")
            self.assertGreaterEqual(number, 1, f"warning line is not 1-based: {entry}")
            self.assertIsInstance(shape, str, f"warning names no shape: {entry}")
            self.assertTrue(shape.strip(), f"warning names an empty shape: {entry}")
            self.assertIsInstance(line, str, f"warning carries no line text: {entry}")

    def test_the_shipped_path_reports_a_planted_hazard_readably(self):
        """The same report, on the real document: a legal-or-lossy call appended
        to scripts/verify.sh is named at its own line with its own shape. This is
        what a reader gets; it is not a verdict on what was already there."""
        text = self.shipped()
        first_planted = len(text.splitlines()) + 1
        _accepted, warnings = lint_bounded_suite_call_sites(
            text + "\n" + "bounded_suite cargo atest -p alumina --lib | cat\n")
        planted = [entry for entry in warnings if entry[0] >= first_planted]
        self.assertEqual([shape for _, shape, _ in planted], ["pipeline"])
        self.assertIn("bounded_suite cargo atest", planted[0][2])

    # One line per shape, each carrying the anchored spelling so the count stays
    # constant and only the shape check can catch it.
    PLANTS = (
        ("command substitution",
         'x=$(bounded_suite cargo atest -p alumina --lib)'),
        ("backticks",
         'x=`bounded_suite cargo atest -p alumina --lib`'),
        ("pipeline",
         'bounded_suite cargo atest -p alumina --lib | cat'),
        ("nested shell",
         "sh -c 'bounded_suite cargo atest -p alumina --lib'"),
        ("subshell",
         '( bounded_suite cargo atest -p alumina --lib )'),
        ("background",
         'bounded_suite cargo atest -p alumina --lib &'),
        ("not a current-shell command word",
         'env FOO=1 bounded_suite cargo atest -p alumina --lib'),
    )

    def test_each_lossy_shape_is_named_by_the_lint(self):
        """A lint that cannot name the shape it claims to know is decoration, so
        every shape is planted here and must be named. This is a test of the
        classifier, not of any script it is run over."""
        for expected, planted in self.PLANTS:
            with self.subTest(shape=expected):
                text, first_planted = self.planted(planted)
                accepted, warnings = lint_bounded_suite_call_sites(text)
                self.assertEqual(
                    [(number, shape) for number, shape, _ in warnings],
                    [(first_planted, expected)],
                    f"the planted {expected} line was not named: {warnings}")
                self.assertNotIn(planted, [line for _, _, line in accepted])

    # The permanent probes: the three forms that were accepted in silence plus
    # the second call on an already-known line. The current-shell call a
    # separator introduces is the green case in the test below.
    SILENT_ACCEPTS = (
        ("heredoc body",
         "sh <<'PLANT'\nbounded_suite cargo atest -p alumina --lib\nPLANT"),
        ("background",
         "bounded_suite cargo atest -p alumina --lib & wait"),
        ("background",
         'echo done; bounded_suite "$@" &'),
        ("background",
         "bounded_suite cargo atest -p alumina --lib; "
         "bounded_suite cargo atest -p alumina --lib & wait"),
    )

    def test_the_hazard_layer_runs_before_every_diagnostic_allowance(self):
        """Red on 47df36a for all four: the allowance was a line filter, the
        here-document body read as a current-shell line, `&` was only read at
        end of line, and only the first call on a line was examined."""
        for expected, planted in self.SILENT_ACCEPTS:
            with self.subTest(shape=expected, plant=planted):
                document, first_planted = self.planted(planted)
                _accepted, refused = scan_bounded_suite_call_sites(document)
                self.assertEqual(
                    [shape for _, shape, _ in refused], [expected],
                    f"the permanent {expected} probe was not refused: {refused}")
                number, _shape, line = refused[0]
                self.assertGreaterEqual(number, first_planted,
                                        "the refusal named no planted line")
                self.assertIn(line, planted,
                              "the refusal named a line other than the probe's")

    def test_a_separator_introduces_the_call_that_follows_it(self):
        """Red on 47df36a: the introducer was read as part of the command word,
        so a legitimate `true & bounded_suite ...` was refused as lossy."""
        call = "bounded_suite cargo atest -p alumina --lib"
        for introducer in ("&", "&&", "||", ";", ";;"):
            with self.subTest(introducer=introducer):
                document, first_planted = self.planted(f"true {introducer} {call}")
                accepted, refused = scan_bounded_suite_call_sites(document)
                self.assertEqual(
                    refused, [],
                    f"`{introducer}` introduces the call that follows it, so "
                    f"nothing is lossy here: {refused}")
                planted = [entry for entry in accepted
                           if entry[0] >= first_planted]
                self.assertEqual(
                    planted,
                    [(first_planted, "current-shell call",
                      f"true {introducer} {call}")],
                    "the introduced call is not an accepted call site")
        # The forward terminator stays a refusal: it is the same separator, but
        # after the call it backgrounds it.
        document, first_planted = self.planted(call + " &")
        _accepted, refused = scan_bounded_suite_call_sites(document)
        self.assertEqual([shape for _, shape, _ in refused], ["background"],
                         f"a trailing `&` still backgrounds the call: {refused}")
        self.assertEqual(refused[0][0], first_planted)

    CALL = "bounded_suite cargo atest -p alumina --lib"

    # A span that opens on one line and closes on another is still the child
    # shell's, so the scan state has to survive the newline. The three executing
    # forms plus a plain quoted string, which no shell evaluates at all.
    CROSS_LINE_SPANS = (
        ("command substitution",
         f"x=$(\n  {CALL}\n)"),
        ("backticks",
         f"x=`\n  {CALL}\n`"),
        ("nested shell",
         f"sh -c '\n  {CALL}\n'"),
        ("quoted string",
         f"x='\n  {CALL}\n'"),
    )

    def test_a_span_open_across_lines_carries_its_child_shell_shape(self):
        """Red on bfe63d7 for all four: the scan state was rebuilt on every
        line, so a `$(`, a backtick, a `sh -c '` and a plain quote opened on
        line 1 all left the line-2 token reading as a current-shell call."""
        for expected, probe in self.CROSS_LINE_SPANS:
            with self.subTest(shape=expected, probe=probe):
                accepted, refused = scan_bounded_suite_call_sites(probe + "\n")
                self.assertEqual(accepted, [],
                                 "a call inside a carried span was accepted")
                self.assertEqual(
                    refused, [(2, expected, self.CALL)],
                    f"the carried {expected} span was not named at line 2: "
                    f"{refused}")

    def test_a_case_arm_body_is_a_current_shell_call(self):
        """Red on bfe63d7: the `foundations)` arm pattern stayed in the command
        word, so a legitimate case arm was refused as a lossy shape."""
        probe = f'case "$1" in\n  foundations) {self.CALL} ;;\nesac\n'
        accepted, refused = scan_bounded_suite_call_sites(probe)
        self.assertEqual(refused, [])
        self.assertEqual(accepted, [(2, "current-shell call",
                                     f"foundations) {self.CALL} ;;")])

    def test_a_call_outside_every_carried_span_stays_a_current_shell_site(self):
        """The carried layer must widen the hazard set, never filter lines: a
        plain call, a `&&`-introduced call and a backslash-continued call all
        stay accepted, while a trailing `&` is still the `background` refusal."""
        for probe in (self.CALL, f"true && {self.CALL}",
                      f"{self.CALL} \\\n  -p alumina --lib"):
            with self.subTest(probe=probe):
                accepted, refused = scan_bounded_suite_call_sites(probe + "\n")
                self.assertEqual(refused, [])
                self.assertEqual(accepted, [(1, "current-shell call",
                                             probe.splitlines()[0])])
        accepted, refused = scan_bounded_suite_call_sites(f"{self.CALL} &\n")
        self.assertEqual(accepted, [])
        self.assertEqual([shape for _, shape, _ in refused], ["background"])

    # POSIX removes an unquoted backslash-newline before the shell tokenizes,
    # so an operator written on the continuation line still terminates the
    # call's command span. The refusal names the unit's FIRST physical line.
    CONTINUATION_HAZARDS = (
        ("pipeline", f"{CALL} \\\n  | cat"),
        ("background", f"{CALL} \\\n  & wait"),
    )

    def test_a_continuation_cannot_hide_the_operator_on_the_next_line(self):
        """Red on 976b2f2 for both: the command span ended at the backslash, so
        the `|` and the `&` written on the continuation line were never read."""
        for expected, probe in self.CONTINUATION_HAZARDS:
            with self.subTest(shape=expected, probe=probe):
                accepted, refused = scan_bounded_suite_call_sites(probe + "\n")
                self.assertEqual(accepted, [],
                                 "the operator on the continuation line was "
                                 "not read at all")
                self.assertEqual(
                    refused, [(1, expected, f"{self.CALL} \\")],
                    "the refusal must name the joined unit's first physical "
                    f"line: {refused}")

    def test_a_joined_unit_reports_its_first_physical_line(self):
        """Convention, pinned because a join is where renumbering would hide:
        the call is written on physical line 2, and the unit reports line 1."""
        probe = f"true \\\n  && {self.CALL}"
        accepted, refused = scan_bounded_suite_call_sites(probe + "\n")
        self.assertEqual(refused, [])
        self.assertEqual(accepted, [(1, "current-shell call", "true \\")])

    # Every shell word that admits the command after it as a command in the
    # CURRENT shell. None of them is a shape the declaration can be lost to.
    KEYWORD_INTRODUCERS = (
        f"if true; then {CALL}; fi",
        f"if false; then true; else {CALL}; fi",
        f"for x in a; do {CALL}; done",
        f"{{ {CALL} ; }}",
        f"time {CALL}",
        f"command {CALL}",
    )

    def test_every_shell_word_that_admits_a_command_admits_the_call(self):
        """Red on 976b2f2 for all six: `then`, `else`, `do`, `{`, `time` and
        `command` each introduce a command that runs in this shell, so the
        keyword set -- not the call -- was the incomplete part."""
        for probe in self.KEYWORD_INTRODUCERS:
            with self.subTest(probe=probe):
                accepted, refused = scan_bounded_suite_call_sites(probe + "\n")
                self.assertEqual(refused, [],
                                 "a shell word that admits a command is not a "
                                 f"lossy shape: {refused}")
                self.assertEqual(accepted, [(1, "current-shell call", probe)])

    def test_an_unanchored_current_shell_call_is_accepted_and_named(self):
        """`bounded_suite "$@"` is a legitimate current-shell call that no shape
        check can object to, and nothing counts it any more: the lint names it as
        accepted at its own line, which is all a lint owes a reader."""
        text = self.BASELINE.rstrip("\n") + '\nbounded_suite "$@"\n'
        accepted, warnings = lint_bounded_suite_call_sites(text)
        self.assertEqual(warnings, [],
                         f"a current-shell call is not a warning: {warnings}")
        self.assertEqual([entry[1:] for entry in accepted],
                         [("current-shell call", "bounded_suite cargo atest -p alumina --lib"),
                          ("current-shell call", 'bounded_suite "$@"')])


class IdentityEnvRecord(unittest.TestCase):
    """L5: the declared-env record must name the stack input the helper actually
    resolves from, so a snapshot can never describe a knob nothing reads -- and it
    must record an explicitly empty value as empty, because empty is the spelling
    that is refused rather than defaulted."""

    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        self.temp = Path(self._temp.name)
        # The shipped function under the interpreter options scripts/verify.sh
        # runs with, plus the one caller-set variable it reads.
        self.driver = self.temp / "declared.sh"
        self.driver.write_text(
            "set -eu\n"
            'config_home="${CARGO_HOME:-$HOME/.cargo}"\n'
            + extract_function("identity_snapshot_env_declared")
            + "\n\nidentity_snapshot_env_declared\n")

    def render(self, env=None):
        inherited = {key: value for key, value in os.environ.items()
                     if key not in ("GATE_SUITE_MIN_STACK", "RUST_MIN_STACK")}
        result = subprocess.run(
            [shutil.which("sh") or "/bin/sh", str(self.driver)],
            cwd=self.temp, text=True, capture_output=True,
            env={**inherited, **(env or {})})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result.stdout.splitlines()

    def test_the_record_names_the_knob_the_helper_reads(self):
        # The helper resolves from GATE_SUITE_MIN_STACK (defaulted from the
        # documented RUST_MIN_STACK), so a record naming only the documented
        # spelling describes a variable nothing in this script consumes.
        self.assertIn("GATE_SUITE_MIN_STACK", extract_function("bounded_suite"))
        lines = self.render({"GATE_SUITE_MIN_STACK": "33554432"})
        self.assertIn("gate_suite_min_stack=33554432", lines)
        self.assertIn("rust_min_stack=<unset>", lines)

    def test_an_empty_knob_is_recorded_as_empty_not_absent(self):
        # `:-` folds the refused spelling into <unset>, so the one value a
        # snapshot most needs to show would read as an untaken default.
        self.assertIn("gate_suite_min_stack=", self.render({"GATE_SUITE_MIN_STACK": ""}))
        self.assertIn("rust_min_stack=", self.render({"RUST_MIN_STACK": ""}))


# --- A2: discovery completeness ----------------------------------------------
# A test that is defined but never collected runs nothing and proves nothing:
# a green-on-parent test pins nothing, and a recorded "Ran N" that is smaller
# than the definitions is not a count of them. The harness therefore compares
# what the source defines against what the loader collected, before any test
# runs, and refuses the run naming the difference.
def iter_suite_tests(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from iter_suite_tests(item)
        else:
            yield item


def collected_test_ids(suite):
    """Every collected test in the loader's own identity: `Class.method` counts."""
    return collections.Counter(
        f"{type(test).__name__}.{test._testMethodName}"
        for test in iter_suite_tests(suite))


def ast_test_definitions(source):
    """Class-scope `def test*` definitions as a `Class.method` multiset.

    Returns `(defined, non_collectable)`. `defined` counts definitions, not
    distinct names: a second `def test_x` in the same class shadows the first,
    so two definitions must produce two collected tests. `non_collectable` names
    the definitions whose class is not a `unittest.TestCase` subclass: they are
    test-shaped definitions the loader can never run, and are reported by name
    rather than silently matched against a set. String literals are out of scope
    because the source is parsed as an AST."""
    tree = ast.parse(source)
    classes = [node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]
    bases = {
        node.name: [base.attr if isinstance(base, ast.Attribute)
                    else getattr(base, "id", "")
                    for base in node.bases]
        for node in classes
    }

    def is_test_case(name, seen=()):
        if name in seen:
            return False
        for base in bases.get(name, ()):
            if base == "TestCase" or is_test_case(base, seen + (name,)):
                return True
        return False

    defined = collections.Counter()
    non_collectable = set()
    for node in classes:
        test_case = is_test_case(node.name)
        for item in node.body:
            if (isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and item.name.startswith("test")):
                name = f"{node.name}.{item.name}"
                defined[name] += 1
                if not test_case:
                    non_collectable.add(name)
    return defined, non_collectable


def undiscovered_test_ids(defined, non_collectable, collected):
    """Pure: every definition the run cannot execute, named with its counts.

    `defined` and `collected` are `Class.method` multisets; `non_collectable`
    names the definitions in a class the loader cannot collect. Counts are
    compared, so N definitions require N collected tests."""
    gaps = []
    for name, count in sorted(defined.items()):
        found = collected.get(name, 0)
        if name in non_collectable:
            gaps.append(f"{name} (defined {count}, collected {found}; the class "
                        "is not a unittest.TestCase subclass, so the definition "
                        "cannot run)")
        elif found != count:
            gaps.append(f"{name} (defined {count}, collected {found})")
    for name, count in sorted(collected.items()):
        if name not in defined:
            gaps.append(f"{name} (defined 0, collected {count})")
    return gaps


class DiscoveryCompletenessLoader(unittest.TestLoader):
    """Loads exactly as `unittest` does, but first refuses a suite smaller than
    the definitions. The comparison uses an unfiltered load, so `-k` still
    narrows the run without tripping the guard."""

    def loadTestsFromModule(self, module, *args, **kwargs):
        suite = super().loadTestsFromModule(module, *args, **kwargs)
        source = (Path(module.__file__).read_text()
                  if getattr(module, "__file__", None) else "")
        patterns = getattr(self, "testNamePatterns", None)
        self.testNamePatterns = None
        try:
            complete = super().loadTestsFromModule(module, *args, **kwargs)
        finally:
            self.testNamePatterns = patterns
        defined, non_collectable = ast_test_definitions(source)
        missing = undiscovered_test_ids(defined, non_collectable,
                                        collected_test_ids(complete))
        if missing:
            print("DISCOVERY-INCOMPLETE: defined in the source but not collected "
                  f"({len(missing)}): " + "; ".join(missing), file=sys.stderr)
            raise SystemExit(1)
        return suite


class DiscoveryCompleteness(unittest.TestCase):
    """The guard's own pins: the pure comparison, the AST reader, and the
    shipped module's definitions against a real unfiltered load."""

    def test_the_pure_comparison_names_every_uncollected_definition(self):
        defined = collections.Counter(
            {"Alpha.test_one": 2, "Beta.test_three": 1, "Gamma.test_four": 1})
        collected = collections.Counter({"Alpha.test_one": 1})
        self.assertEqual(
            undiscovered_test_ids(defined, {"Gamma.test_four"}, collected),
            ["Alpha.test_one (defined 2, collected 1)",
             "Beta.test_three (defined 1, collected 0)",
             "Gamma.test_four (defined 1, collected 0; the class is not a "
             "unittest.TestCase subclass, so the definition cannot run)"])
        self.assertEqual(undiscovered_test_ids(defined, set(), defined), [])
        self.assertEqual(
            undiscovered_test_ids(collections.Counter({"A.test_x": 1}),
                                  set(),
                                  collections.Counter({"A.test_x": 2})),
            ["A.test_x (defined 1, collected 2)"])

    def test_the_ast_reader_counts_definitions_and_flags_non_test_case_classes(self):
        source = (
            "import unittest\n"
            "class Samples(unittest.TestCase):\n"
            "    def test_one(self):\n        pass\n"
            "    def test_one(self):\n        pass\n"
            "    def helper(self):\n        pass\n"
            "class Derived(Samples):\n"
            "    def test_two(self):\n        pass\n"
            "class Other:\n"
            "    def test_not_a_case(self):\n        pass\n"
            "literal = 'def test_in_a_string(self): pass'\n")
        defined, non_collectable = ast_test_definitions(source)
        self.assertEqual(dict(defined),
                         {"Samples.test_one": 2,
                          "Derived.test_two": 1,
                          "Other.test_not_a_case": 1})
        self.assertEqual(non_collectable, {"Other.test_not_a_case"})
        self.assertNotIn("literal.test_in_a_string", defined)

    def test_the_shipped_harness_collects_every_definition(self):
        defined, non_collectable = ast_test_definitions(Path(__file__).read_text())
        complete = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
        self.assertGreater(sum(defined.values()), 0)
        self.assertEqual(undiscovered_test_ids(defined, non_collectable,
                                              collected_test_ids(complete)), [])
        self.assertEqual(sum(defined.values()), sum(collected_test_ids(complete).values()))


if __name__ == "__main__":
    # unittest's own argument handling, so `-k <pattern>` filters for real: a
    # hand-rolled loader here silently ignored it and ran the whole suite. The
    # loader fails the run when the collected suite is smaller than the source.
    unittest.main(module=sys.modules[__name__],
                  testLoader=DiscoveryCompletenessLoader())
