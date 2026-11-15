#!/usr/bin/env python3
"""Offline regression tests for scripts/ref_check.py, the docs symbol gate.

WHY THIS EXISTS
  ref_check.py owns a three-valued outcome (clean / finding / BLOCKED), a
  hand-rolled Rust brace lexer and a Markdown fence state machine, and it is the
  only detector of the `path::Symbol` grammar. Its contract is pinned here so
  the gate's correctness outlives the session that wrote it — otherwise the
  docs gate's test surface would be one session deep.

THE SEAMS A CASE OWNS
  The fixture copies the SHIPPED scripts/ref_check.py to <tmp>/repo/scripts/,
  so REPO_ROOT resolves to the fixture; the corpus is the fixture's own
  DOCSLINK_ROOTS line; index freshness is the fixture's `.repowise/state.json`;
  and a fake `repowise` on PATH answers per symbol id from a JSON table the case
  writes. That is how each case chooses a verified answer, an error payload or
  an exit status. No network, no real index, no real `.repowise/`.

  Cases 12-14 exercise type containment and the literal/comment traps through
  the shipped lexer reading fixture Rust sources, so the containment path is
  proven without the index.
"""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
REF_CHECK = ROOT / "scripts/ref_check.py"

FAKE_REPOWISE = '''#!{python}
import json, os, sys
symbol = sys.argv[2]
log = os.environ.get("REF_CHECK_FAKE_LOG")
if log:
    with open(log, "a", encoding="utf-8") as handle:
        handle.write(symbol + "\\n")
entry = json.load(open(os.environ["REF_CHECK_FAKE_TABLE"], encoding="utf-8")).get(symbol)
if entry is None:
    sys.stdout.write(json.dumps({{"error": "no such symbol: %s. Not in the index." % symbol}}))
    sys.exit(1)
sys.stdout.write(entry.get("stdout", ""))
sys.stderr.write(entry.get("stderr", ""))
sys.exit(entry.get("exit", 0))
'''


def verified(path, line, end=None, kind="struct"):
    """A resolver answer for a construct that verifies, at a reported line."""
    return {"stdout": json.dumps({
        "verified": True, "file": path, "kind": kind,
        "start_line": line, "end_line": line if end is None else end})}


def git_env():
    """Hermetic git: the developer's global config must not decide the fixture.

    An inherited GIT_DIR or core.excludesFile would bind the gate to another
    repository and turn a real pin into a false green.
    """
    env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull,
           "GIT_CONFIG_SYSTEM": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
    for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE",
                 "GIT_OBJECT_DIRECTORY", "GIT_CEILING_DIRECTORIES",
                 "GIT_CONFIG_COUNT"):
        env.pop(name, None)
    for name in [k for k in env
                 if k.startswith("GIT_CONFIG_KEY_") or k.startswith("GIT_CONFIG_VALUE_")]:
        env.pop(name, None)
    return env


class RefCheck(unittest.TestCase):
    """One temp repository per case: one corpus, one index key, one fake resolver."""

    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        self.temp = Path(self._temp.name)
        self.repo = self.temp / "repo"
        self.tools = self.temp / "tools"
        self.bare = self.temp / "bare"
        (self.repo / "scripts").mkdir(parents=True)
        self.tools.mkdir()
        self.bare.mkdir()
        shutil.copyfile(REF_CHECK, self.repo / "scripts/ref_check.py")
        git = shutil.which("git")
        self.assertIsNotNone(git, "git is required to build the fixture")
        (self.bare / "git").symlink_to(git)
        self.roots = ["docs/a.md"]
        self.write_verify_sh()
        self.write("docs/a.md", "Prose without any references.\n")
        self.table = {}
        self.log = self.temp / "resolver-calls"
        self.git("init", "-q", "--template=")
        self.commit("base")
        self.head = self.rev("HEAD")
        self.write_state(self.head)

    # -- fixture construction --------------------------------------------------
    def write(self, name, text):
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def write_verify_sh(self, body=None):
        text = body if body is not None else (
            "#!/bin/sh\n# fixture harness: the gate reads only DOCSLINK_ROOTS\n"
            'DOCSLINK_ROOTS="%s"\n' % " ".join(self.roots))
        (self.repo / "scripts/verify.sh").write_text(text)

    def write_state(self, commit):
        self.write(".repowise/state.json", json.dumps({"last_sync_commit": commit}) + "\n")

    def git(self, *args):
        subprocess.run(["git", *args], cwd=self.repo, check=True,
                       capture_output=True, env=git_env())

    def rev(self, name):
        return subprocess.check_output(["git", "rev-parse", name], cwd=self.repo,
                                       text=True, env=git_env()).strip()

    def commit(self, message):
        self.git("add", "-A")
        self.git("-c", "user.email=probe@example.invalid", "-c", "user.name=probe",
                 "commit", "-qm", message, "--allow-empty")

    # -- execution -------------------------------------------------------------
    def run_ref_check(self, path=None):
        """Run the shipped gate as a subprocess; the fake resolver is on PATH.

        `path` replaces PATH entirely, which is how a case withholds repowise.
        """
        fake = self.tools / "repowise"
        fake.write_text(FAKE_REPOWISE.format(python=sys.executable))
        fake.chmod(0o755)
        table = self.temp / "resolver-table.json"
        table.write_text(json.dumps(self.table))
        env = {**git_env(),
               "PATH": path if path is not None else f"{self.tools}:{os.environ['PATH']}",
               "REF_CHECK_FAKE_TABLE": str(table),
               "REF_CHECK_FAKE_LOG": str(self.log)}
        return subprocess.run(
            [sys.executable, str(self.repo / "scripts/ref_check.py")],
            cwd=self.repo, env=env, text=True, capture_output=True)

    def calls(self):
        return self.log.read_text().split() if self.log.exists() else []

    def assert_exit(self, result, expected, marker=None):
        self.assertEqual(result.returncode, expected,
                         "exit %d, want %d\n%s%s"
                         % (result.returncode, expected, result.stdout, result.stderr))
        if marker is not None:
            self.assertIn(marker, result.stdout + result.stderr)

    # -- 1-8: the exit contract ------------------------------------------------
    def test_1_clean_corpus_is_clean_with_a_citation_count(self):
        self.write("src/lib.rs", "pub struct Alpha {\n    pub value: u8,\n}\n")
        self.write("docs/a.md", "See src/lib.rs::Alpha for the shape.\n")
        self.commit("corpus")
        self.write_state(self.rev("HEAD"))
        self.table = {"src/lib.rs::Alpha": verified("src/lib.rs", 1, 3)}
        result = self.run_ref_check()
        self.assert_exit(result, 0, "REF-CHECK-OK")
        self.assertEqual(result.stdout.strip().splitlines()[-1], "REF-CHECK-OK 1")
        self.assertEqual(self.calls(), ["src/lib.rs::Alpha"])

    def test_2_unresolvable_symbol_is_a_finding_with_the_resolver_reason(self):
        self.write("docs/a.md", "See src/lib.rs::Missing.\n")
        self.commit("corpus")
        self.write_state(self.rev("HEAD"))
        self.write("src/lib.rs", "pub struct Alpha {}\n")
        result = self.run_ref_check()
        self.assert_exit(result, 1, "REF-CHECK-FINDING")
        self.assertIn("unresolved symbol: no such symbol: src/lib.rs::Missing",
                      result.stdout)
        self.assertNotIn("REF-CHECK-BLOCKED", result.stdout)

    def test_3_unknown_path_is_a_finding_and_never_reaches_the_resolver(self):
        self.write("docs/a.md", "See src/ghost.rs::Ghost.\n")
        self.commit("corpus")
        self.write_state(self.rev("HEAD"))
        result = self.run_ref_check()
        self.assert_exit(result, 1, "REF-CHECK-FINDING")
        self.assertIn("unknown path: src/ghost.rs", result.stdout)
        self.assertEqual(self.calls(), [], "an absent path needs no resolver answer")

    def test_4_stale_index_blocks_and_names_both_commits(self):
        self.write_state("0" * 40)
        result = self.run_ref_check()
        self.assert_exit(result, 2, "REF-CHECK-BLOCKED")
        self.assertIn("stale symbol index", result.stdout)
        self.assertIn("indexed_commit=" + "0" * 40, result.stdout)
        self.assertIn("head=" + self.head, result.stdout)

    def test_5_absent_repowise_blocks_rather_than_reporting_clean(self):
        result = self.run_ref_check(path=str(self.bare))
        self.assert_exit(result, 2, "REF-CHECK-BLOCKED")
        self.assertIn("repowise not on PATH", result.stdout)
        self.assertNotIn("REF-CHECK-OK", result.stdout)

    def test_6_unparseable_or_missing_roots_block(self):
        for body, marker in (
                ("#!/bin/sh\n# no roots assignment at all\n", "DOCSLINK_ROOTS not found"),
                ('#!/bin/sh\nDOCSLINK_ROOTS=""\n', "DOCSLINK_ROOTS is empty"),
                ('#!/bin/sh\nDOCSLINK_ROOTS="docs/a.md"\nDOCSLINK_ROOTS="docs/b.md"\n',
                 "defined 2 times"),
                ('#!/bin/sh\nDOCSLINK_ROOTS = "docs/a.md"\n', "DOCSLINK_ROOTS not found"),
        ):
            self.write_verify_sh(body)
            result = self.run_ref_check()
            self.assert_exit(result, 2, "REF-CHECK-BLOCKED")
            self.assertIn(marker, result.stdout, body)

    def test_7_resolver_exit_two_or_more_blocks_even_with_a_plausible_payload(self):
        self.write("src/lib.rs", "pub struct Alpha {}\n")
        self.write("docs/a.md", "See src/lib.rs::Alpha.\n")
        self.commit("corpus")
        self.write_state(self.rev("HEAD"))
        self.table = {"src/lib.rs::Alpha": {
            **verified("src/lib.rs", 1, 1), "exit": 2, "stderr": "resolver exploded\n"}}
        result = self.run_ref_check()
        self.assert_exit(result, 2, "REF-CHECK-BLOCKED")
        self.assertIn("resolver exit 2", result.stdout)
        self.assertNotIn("REF-CHECK-FINDING", result.stdout)

    def test_8_resolver_exit_one_with_an_error_payload_is_a_finding(self):
        self.write("src/lib.rs", "pub struct Alpha {}\n")
        self.write("docs/a.md", "See src/lib.rs::Alpha.\n")
        self.commit("corpus")
        self.write_state(self.rev("HEAD"))
        self.table = {"src/lib.rs::Alpha": {
            "stdout": json.dumps({"error": "not found in the index."}), "exit": 1}}
        result = self.run_ref_check()
        self.assert_exit(result, 1, "REF-CHECK-FINDING")
        self.assertIn("unresolved symbol: not found in the index", result.stdout)
        self.assertNotIn("REF-CHECK-BLOCKED", result.stdout)

    # -- 9: exemptions are structural -----------------------------------------
    def test_9_fenced_blocks_and_git_receipts_are_exempt(self):
        receipt = "git:1812405b5c9130a170d1e00988b2a77d80d86e3d:"
        self.write("docs/a.md", (
            "Prose.\n"
            "\n"
            "```rust\n"
            "src/lib.rs::Ghost\n"
            "src/lib.rs:12\n"
            "```\n"
            "\n"
            "A receipt: %ssrc/lib.rs::Ghost and %ssrc/lib.rs:77\n"
            % (receipt, receipt)))
        self.commit("corpus")
        self.write_state(self.rev("HEAD"))
        result = self.run_ref_check()
        self.assert_exit(result, 0, "REF-CHECK-OK 0")
        self.assertEqual(self.calls(), [], "exempt text must not reach the resolver")

    # -- 10-11: the ratchet ----------------------------------------------------
    def test_10_a_locked_document_that_regains_a_line_reference_is_a_finding(self):
        # HEAD carries the document without line references, so it is locked.
        self.assert_exit(self.run_ref_check(), 0, "REF-CHECK-OK 0")
        self.write("docs/a.md", "Prose.\n\nSee src/lib.rs:12 for details.\n")
        result = self.run_ref_check()
        self.assert_exit(result, 1, "REF-CHECK-FINDING")
        self.assertIn("ratchet violation: locked document regained line reference "
                      "src/lib.rs:12", result.stdout)

    def test_11_a_document_already_carrying_line_references_at_head_is_not_locked(self):
        self.write("docs/a.md", "Prose.\n\nSee src/lib.rs:12 for details.\n")
        self.commit("legacy corpus")
        self.write_state(self.rev("HEAD"))
        result = self.run_ref_check()
        self.assert_exit(result, 0, "REF-CHECK-OK 0")
        self.assertNotIn("ratchet violation", result.stdout)

    # -- 12-13: type containment ----------------------------------------------
    def fixture_types(self):
        """Write two types holding a same-named member; return both member lines."""
        source = self.write("src/fixture.rs", (
            "pub struct TypeA {\n"
            "    pub member: u8,\n"
            "}\n"
            "\n"
            "pub struct TypeB {\n"
            "    pub member: u8,\n"
            "}\n"))
        members = [number + 1
                   for number, line in enumerate(source.read_text().splitlines())
                   if line == "    pub member: u8,"]
        self.assertEqual(len(members), 2, "the fixture needs both same-named members")
        return members

    def test_12_a_same_named_member_of_another_type_is_a_containment_finding(self):
        member_a, member_b = self.fixture_types()
        self.write("docs/a.md", "See src/fixture.rs::TypeA::member.\n")
        self.commit("corpus")
        self.write_state(self.rev("HEAD"))
        self.table = {
            "src/fixture.rs::TypeA": verified("src/fixture.rs", 1, 3),
            # The resolver returns a `member`: same file, same leaf name, but the
            # member of TypeB. Only containment separates the two.
            "src/fixture.rs::TypeA::member": verified("src/fixture.rs", member_b,
                                                     kind="field"),
        }
        self.assertNotEqual(member_a, member_b)
        result = self.run_ref_check()
        self.assert_exit(result, 1, "REF-CHECK-FINDING")
        self.assertIn("type-containment: src/fixture.rs::TypeA::member", result.stdout)
        self.assertIn("not inside src/fixture.rs::TypeA", result.stdout)

    def test_13_a_member_inside_its_cited_type_passes(self):
        _, member_b = self.fixture_types()
        self.write("docs/a.md", "See src/fixture.rs::TypeB::member.\n")
        self.commit("corpus")
        self.write_state(self.rev("HEAD"))
        self.table = {
            "src/fixture.rs::TypeB": verified("src/fixture.rs", 5, 7),
            "src/fixture.rs::TypeB::member": verified("src/fixture.rs", member_b,
                                                     kind="field"),
        }
        result = self.run_ref_check()
        self.assert_exit(result, 0, "REF-CHECK-OK 1")
        self.assertNotIn("type-containment", result.stdout)

    # -- 14: literal and comment traps ----------------------------------------
    def test_14_braces_in_literals_and_comments_do_not_shift_attribution(self):
        # Every trap the lexer must skip: a brace in a char literal, a lifetime,
        # a raw string, a block comment, and a brace in a normal string. The last
        # one sits immediately before a closing brace, so a lexer that reads it as
        # structure loses the enclosing `impl` and mis-attributes the member.
        source = self.write("src/traps.rs", (
            "// a line comment holding braces { } is not structure\n"
            "pub struct TrapsCase {\n"
            "    pub member: u8,\n"
            "}\n"
            "\n"
            "impl TrapsCase {\n"
            "    pub fn inner(&self) -> u8 {\n"
            "        self.member\n"
            "    }\n"
            "\n"
            "    pub fn char_brace() -> char {\n"
            "        '{'\n"
            "    }\n"
            "\n"
            "    pub fn lifetime<'a>(value: &'a u8) -> &'a u8 {\n"
            "        value\n"
            "    }\n"
            "\n"
            "    pub fn raw_brace() -> &'static str {\n"
            '        r#"{"#\n'
            "    }\n"
            "\n"
            "    pub fn comment_braces() {\n"
            "        /* { } */\n"
            "    }\n"
            "\n"
            "    pub fn string_brace() -> &'static str {\n"
            '        "{"\n'
            "    }\n"
            "}\n"))
        lines = source.read_text().splitlines()
        member = lines.index("        self.member") + 1
        self.write("docs/a.md", "See src/traps.rs::TrapsCase::inner.\n")
        self.commit("corpus")
        self.write_state(self.rev("HEAD"))
        self.table = {
            "src/traps.rs::TrapsCase": verified("src/traps.rs", 2, 4),
            "src/traps.rs::TrapsCase::inner": verified("src/traps.rs", member,
                                                       kind="function"),
        }
        result = self.run_ref_check()
        self.assert_exit(result, 0, "REF-CHECK-OK 1")
        self.assertNotIn("type-containment", result.stdout)

    # -- 15-17: statement-terminator boundaries -------------------------------
    # A declaration can follow a brace-less statement. Measured defect (P1.11):
    # `use super::{ ... };` leaves no brace boundary, so the next impl was read
    # as `; impl LogStore`, declared nothing, and every qualified citation into
    # it was rejected as "sits outside every declaration".
    def test_15_an_impl_after_a_use_group_is_attributable(self):
        source = self.write("src/logstore.rs", (
            "use super::{\n"
            "    Cursor, LOG_RETRY, LogStore,\n"
            "};\n"
            "\n"
            "impl LogStore {\n"
            "    pub fn drain_sink(&mut self) {\n"
            "        self.queued = 0;\n"
            "    }\n"
            "}\n"))
        lines = source.read_text().splitlines()
        member = lines.index("        self.queued = 0;") + 1
        self.write("docs/a.md", "See src/logstore.rs::LogStore::drain_sink.\n")
        self.commit("corpus")
        self.write_state(self.rev("HEAD"))
        self.table = {
            "src/logstore.rs::LogStore": verified("src/logstore.rs", 5, 9, kind="impl"),
            "src/logstore.rs::LogStore::drain_sink": verified(
                "src/logstore.rs", member, kind="function"),
        }
        result = self.run_ref_check()
        self.assert_exit(result, 0, "REF-CHECK-OK 1")
        self.assertNotIn("type-containment", result.stdout)

    def test_16_a_struct_and_an_enum_after_a_const_statement_are_attributable(self):
        source = self.write("src/window.rs", (
            "const LIMIT: usize = 8;\n"
            "\n"
            "pub struct Window {\n"
            "    pub member: u8,\n"
            "}\n"
            "\n"
            "pub enum Mode {\n"
            "    Idle,\n"
            "}\n"))
        lines = source.read_text().splitlines()
        field = lines.index("    pub member: u8,") + 1
        variant = lines.index("    Idle,") + 1
        self.write("docs/a.md", (
            "See src/window.rs::Window::member and src/window.rs::Mode::Idle.\n"))
        self.commit("corpus")
        self.write_state(self.rev("HEAD"))
        self.table = {
            "src/window.rs::Window": verified("src/window.rs", 3, 5),
            "src/window.rs::Window::member": verified("src/window.rs", field, kind="field"),
            "src/window.rs::Mode": verified("src/window.rs", 7, 9, kind="enum"),
            "src/window.rs::Mode::Idle": verified("src/window.rs", variant, kind="enum"),
        }
        result = self.run_ref_check()
        self.assert_exit(result, 0, "REF-CHECK-OK 2")
        self.assertNotIn("type-containment", result.stdout)

    def test_17_a_statement_terminator_inside_a_header_does_not_amputate_it(self):
        # `[(); N]` carries a `;` before the opening brace. A boundary reader
        # that trusted only the last terminator would keep "N]: Sized," and lose
        # the declaration entirely, so the whole segment must stay readable.
        source = self.write("src/holder.rs", (
            "pub struct Holder<const N: usize>\n"
            "where\n"
            "    [(); N]: Sized,\n"
            "{\n"
            "    pub member: u8,\n"
            "}\n"))
        lines = source.read_text().splitlines()
        field = lines.index("    pub member: u8,") + 1
        self.write("docs/a.md", "See src/holder.rs::Holder::member.\n")
        self.commit("corpus")
        self.write_state(self.rev("HEAD"))
        self.table = {
            "src/holder.rs::Holder": verified("src/holder.rs", 1, 6),
            "src/holder.rs::Holder::member": verified("src/holder.rs", field, kind="field"),
        }
        result = self.run_ref_check()
        self.assert_exit(result, 0, "REF-CHECK-OK 1")
        self.assertNotIn("type-containment", result.stdout)

    # -- 18-23: continuations must carry their own path ----------------------
    # LINE_RE needs a path prefix, so `:1937` standing in for a path named
    # earlier is invisible to both the resolver check and the ratchet. A
    # citation precedes it, but a citation is not a waiver: shape is what
    # separates a continuation from a port or a clock time, and a `git:<commit>:`
    # receipt is itself one of the citations.
    def test_18_an_orphaned_span_continuation_is_a_finding(self):
        self.write("src/lib.rs", "pub struct Alpha {}\n")
        self.write("docs/a.md", "See src/lib.rs::Alpha, then `:42` for the body.\n")
        self.commit("corpus")
        self.write_state(self.rev("HEAD"))
        self.table = {"src/lib.rs::Alpha": verified("src/lib.rs", 1, 1)}
        result = self.run_ref_check()
        self.assert_exit(result, 1, "REF-CHECK-FINDING")
        self.assertIn("continuation reference: `:42`", result.stdout)

    def test_19_a_link_target_with_a_line_number_outside_the_link_is_a_finding(self):
        self.write("src/lib.rs", "pub struct Alpha {}\n")
        self.write("docs/a.md", "See [lib](../src/lib.rs):12 for the shape.\n")
        self.commit("corpus")
        self.write_state(self.rev("HEAD"))
        result = self.run_ref_check()
        self.assert_exit(result, 1, "REF-CHECK-FINDING")
        self.assertIn("continuation reference: [lib](../src/lib.rs):12", result.stdout)

    def test_20_ports_times_and_ranges_in_prose_do_not_fire(self):
        self.write("docs/a.md", (
            "The listener binds :8080 and `:443` for TLS; the log rotates at 12:30.\n"))
        self.commit("corpus")
        self.write_state(self.rev("HEAD"))
        result = self.run_ref_check()
        self.assert_exit(result, 0, "REF-CHECK-OK 0")
        self.assertNotIn("continuation reference", result.stdout)

    def test_21_a_receipt_on_the_line_does_not_cover_a_bare_continuation(self):
        # The receipt names ONE path and ONE line. The bare `:1937` beside it
        # continues a path the reader has to infer and no grammar checks, so the
        # document has regained a line number. This is the shape the class was
        # added for, and it must not be exempted by a receipt sharing its line:
        # the receipt covers its own path, never the token next to it.
        receipt = "git:1812405b5c9130a170d1e00988b2a77d80d86e3d:"
        self.write("docs/a.md", (
            "See `%ssrc/log.rs#L1850`, `:1937` for the labels.\n" % receipt))
        self.commit("corpus")
        self.write_state(self.rev("HEAD"))
        result = self.run_ref_check()
        self.assert_exit(result, 1, "REF-CHECK-FINDING")
        self.assertIn("continuation reference: `:1937`", result.stdout)

    def test_22_the_exact_pre_fix_spec_shape_is_a_finding(self):
        # docs/alumina-proxy.md carried this token pair four times before the
        # migration (`:1937`/`:1951` after the log.rs receipt, `:1694`/`:1700`
        # after startup_dns.rs). Pinned verbatim: a regression to it, or a
        # receipt exemption readmitted to the class, must fail here.
        sha = "5486a6f0a1b2c3d4e5f60718293a4b5c6d7e8f90"
        self.write("docs/a.md", (
            "The log slot receipt is `git:%s:src/log.rs#L1850`, `:1937`.\n" % sha))
        self.commit("corpus")
        self.write_state(self.rev("HEAD"))
        result = self.run_ref_check()
        self.assert_exit(result, 1, "REF-CHECK-FINDING")
        self.assertIn("continuation reference: `:1937`", result.stdout)

    def test_23_a_continuation_that_repeats_its_receipt_stays_clean(self):
        # The migrated form: every token carries its own sha, path and line, so
        # nothing has to be inferred and nothing is continuation-shaped. This is
        # the shape the four spec tokens now use, and dropping the receipt
        # exemption must not turn it into a false positive.
        sha = "5486a6f0a1b2c3d4e5f60718293a4b5c6d7e8f90"
        self.write("docs/a.md", (
            "The log slot receipt is `git:%s:src/log.rs#L1850`, "
            "`git:%s:src/log.rs#L1937`.\n" % (sha, sha)))
        self.commit("corpus")
        self.write_state(self.rev("HEAD"))
        result = self.run_ref_check()
        self.assert_exit(result, 0, "REF-CHECK-OK 0")
        self.assertNotIn("continuation reference", result.stdout)


if __name__ == "__main__":
    unittest.main()
