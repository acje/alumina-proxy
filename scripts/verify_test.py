#!/usr/bin/env python3
"""Focused tests for independent verification selectors; no real builds run."""

import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent

GATE_NAMES = ("unsafe_surface_gate", "cfg_test_parentage_gate")


def extract_gates():
    """The real gate bodies, text-extracted from scripts/verify.sh (the same
    precedent as test_dirty_agents_content_drift_is_detected): the tests drive
    the shipped decision logic, never a Python re-implementation of it."""
    script = (ROOT / "scripts/verify.sh").read_text()
    bodies = []
    for name in GATE_NAMES:
        match = re.search(rf"^{name}\(\) \{{\n.*?^\}}$", script, re.S | re.M)
        assert match is not None, f"gate function not found in scripts/verify.sh: {name}"
        bodies.append(match.group(0))
    return "\n\n".join(bodies)


GATES = extract_gates()


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
            representatives = {"Cargo.toml", "src/main.rs", ".gitignore", "AGENTS.md",
                               "scripts/verify.sh", "scripts/verify_test.py",
                               "docs/qa-package/validate.sh", "docs/qa-package/validate_test.py"}
            self.assertTrue(representatives <= set(files))
            for name in files:
                if name == "scripts/verify.sh":
                    continue
                dest = repo / name
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text(f"synthetic input: {name}\n")
            (repo / "scripts/cargo_config_probe.py").write_text('print("absent")\n')
            git = tools / "git"
            git.write_text('''#!/bin/sh
case "$*" in
  'rev-parse --verify HEAD') printf 'fixture-head\\n';;
  'status --porcelain') [ "${FIXTURE_STATUS_FAIL:-0}" = 0 ] || exit 42; printf ' M %s\\n' "$FIXTURE_INPUT";;
  *) exit 1;;
esac
''')
            git.chmod(0o755)
            for name in ("AGENTS.md", "docs/qa-package/validate.sh", "docs/qa-package/validate_test.py"):
                path = repo / name
                baseline = path.read_bytes()
                path.write_bytes(baseline + b"\nfixture dirty one\n")
                env = {"PATH": f"{tools}:{os.environ['PATH']}", "FIXTURE_INPUT": name,
                       "CARGO_HOME": str(temp / "cargo-home")}
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
            for name in ("head", "status", "inputs.sha256", "env"):
                original = (after / name).read_bytes()
                (after / name).write_bytes(b"changed\n")
                result = self.run_verify("identity", "compare", before, after)
                self.assertNotEqual(result.returncode, 0, name)
                self.assertIn("SOURCE-IDENTITY-CHANGED", result.stderr)
                (after / name).write_bytes(original)
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

    def test_audit_deny_pins_and_failures(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            for name, body in {
                "cargo-audit": 'printf "cargo-audit %s\\n" "${MOCK_AUDIT_VERSION:-0.22.1}"',
                "cargo-deny": 'printf "cargo-deny %s\\n" "${MOCK_DENY_VERSION:-0.19.4}"',
                "cargo": 'case "$2" in audit) exit "${AUDIT_EXIT:-0}";; deny) exit "${DENY_EXIT:-0}";; esac; exit 99',
            }.items():
                exe = path / name
                exe.write_text("#!/bin/sh\n" + body + "\n")
                exe.chmod(0o755)
            env = {"PATH": f"{path}:{os.environ['PATH']}"}
            result = self.run_verify("supply-chain", "audit-deny", env=env)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("AUDIT-DENY-OK", result.stdout)
            for setting in ("MOCK_AUDIT_VERSION", "MOCK_DENY_VERSION", "AUDIT_EXIT", "DENY_EXIT"):
                result = self.run_verify("supply-chain", "audit-deny", env={**env, setting: "99"})
                self.assertNotEqual(result.returncode, 0, setting)
                self.assertIn("AUDIT-DENY FAIL", result.stderr)

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
if 'cargo +' in script:
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
            result = self.run_gate(repo, "unsafe_surface_gate")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("UNSAFE-SURFACE-OK", result.stdout)

    def test_non_src_bench_source_stays_in_scan_universe(self):
        with tempfile.TemporaryDirectory() as temp:
            repo, _ = self.sandbox(temp)
            bench = repo / "scripts/bench/echo-backend/src"
            bench.mkdir(parents=True)
            (bench / "main.rs").write_text("fn main() { unsafe {} }\n")
            result = self.run_gate(repo, "unsafe_surface_gate")
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("scripts/bench/echo-backend/src/main.rs", result.stderr)

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
            for name in ("find", "sed", "grep", "awk", "dirname", "basename"):
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


if __name__ == "__main__":
    unittest.main()
