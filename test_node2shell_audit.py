"""Offline regressions for verdict, identity, evidence, exposure and transport boundaries."""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("node_audit", Path(__file__).with_name("node2shell-audit.py"))
audit = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = audit
spec.loader.exec_module(audit)
EMPTY = {"schema": 1}
SHA = hashlib.sha256(b"fixture").hexdigest()


def build(version="24.22.1", **kwargs):
    row = {"sha256": SHA, "kind": "node", "decoder": "bundled", "node_version": version, "source": "synthetic test fixture"}
    row.update(kwargs)
    return {"schema": 1, "builds": [row]}


def inventory(path="/srv/node", kind="node"):
    return {"schema": 1, "coverage_confirmed": True, "scope": "test deployment",
            "runtimes": [{"label": "test", "kind": kind, "path": path}]}


def record(status="PATCHED", kind="node", path="/srv/node", pid=10, **extra):
    row = {"status": status, "kind": kind, "path": path, "pid": pid, "restart_needed": False,
           "cve_results": {cve: {"status": status, "detail": "synthetic fixture", "sources": []}
                           for cve in audit.artifact_cves(kind)}}
    row.update(extra)
    return row


class VersionsAndEvidence(unittest.TestCase):
    def test_release_boundaries(self):
        for affected, fixed, newer in (("22.23.3", "22.23.4", "22.24.0"),
                                       ("24.22.0", "24.22.1", "24.23.0"),
                                       ("26.12.0", "26.12.1", "26.13.0")):
            with self.subTest(branch=fixed):
                self.assertEqual(audit.upstream_status(affected), "AFFECTED")
                self.assertEqual(audit.upstream_status(fixed), "PATCHED")
                self.assertEqual(audit.upstream_status(newer), "PATCHED")

    def test_uncovered_or_nonstandard_versions_are_unknown(self):
        for version in ("20.99.0", "18.20.8", "25.1.0", "27.0.0", "28.0.0", "24.22.1-rc.1",
                        "v24.22.1", "24.22.1+vendor", "24.022.1", "24.22", "", "garbage"):
            with self.subTest(version=version):
                self.assertEqual(audit.upstream_status(version), "UNKNOWN")

    def test_no_execution_during_file_assessment(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "node"
            path.write_bytes(b"fixture")
            with patch.object(audit, "command", side_effect=AssertionError("must not execute")):
                report = audit.audit_local(inventory(str(path)), build(), files=True)
        self.assertEqual(report["verdict"], "PATCHED")
        self.assertEqual(report["assessment_scope"], "installed-files-only")

    def test_changed_bytes_do_not_use_build_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "node"
            path.write_bytes(b"different")
            with patch.object(audit, "package_metadata", side_effect=audit.AuditError("unowned")):
                row = audit.inspect_file({"path": str(path), "kind": "node"}, None, build())
        self.assertEqual(row["status"], "UNKNOWN")

    def test_explicit_backport_can_cover_eol(self):
        proof = build()
        row = proof["builds"][0]
        del row["node_version"]
        row.update(status="PATCHED", cves=list(audit.CVES))
        audit.validate_config(None, proof)
        result = record("UNKNOWN")
        audit.assess_file(result, {"sha256": SHA}, None, proof)
        self.assertEqual(result["status"], "PATCHED")

    def test_external_linkage_is_not_itself_patch_evidence(self):
        proof = build()
        row = proof["builds"][0]
        del row["node_version"]
        row["decoder"] = "external"
        audit.validate_config(None, proof)
        result = record("UNKNOWN")
        audit.assess_file(result, {"sha256": SHA}, None, proof)
        self.assertEqual((result["status"], result["decoder"]), ("UNKNOWN", "external"))

    def test_rejects_wrong_kind(self):
        with self.assertRaisesRegex(audit.AuditError, "kind mismatch"):
            audit.assess_file(record("UNKNOWN", kind="brotli"), {"sha256": SHA}, None, build())

    def test_bad_build_evidence_rejected(self):
        mutations = ({"sha256": "bad"}, {"kind": "php"}, {"source": ""}, {"decoder": "guessed"},
                     {"node_version": 24}, {"status": "PATCHED", "cves": []}, {"extra": True})
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(audit.AuditError):
                audit.validate_config(None, build(**mutation))

    def test_duplicate_evidence_rejected(self):
        proof = build()
        proof["builds"] *= 2
        with self.assertRaisesRegex(audit.AuditError, "Duplicate"):
            audit.validate_config(None, proof)

    def test_inventory_requires_explicit_coverage_and_paths(self):
        for field, value in (("coverage_confirmed", False), ("coverage_confirmed", "true"),
                             ("scope", ""), ("runtimes", []), ("schema", True)):
            config = inventory()
            config[field] = value
            with self.subTest(field=field), self.assertRaises(audit.AuditError):
                audit.validate_config(config, EMPTY)
        for path in ("node", "-node", "//host/node", "\\\\host\\node", "/node\n", "C:\\node.exe:stream"):
            with self.subTest(path=path), self.assertRaises(audit.AuditError):
                audit.validate_config(inventory(path), EMPTY)

    def test_unreviewed_exposure_cannot_be_marked_reachable(self):
        config = inventory()
        config["runtimes"][0]["exposure"] = {audit.BROTLI_CVE: {"reachability": "reachable"}}
        with self.assertRaises(audit.AuditError):
            audit.validate_config(config, EMPTY)


class VerdictsAndDecoders(unittest.TestCase):
    def test_clearance_requires_every_artifact_and_coverage(self):
        cases = (([], [], "UNKNOWN"), ([record()], [], "PATCHED"),
                 ([record()], ["hidden namespace"], "UNKNOWN"),
                 ([record(), record("UNKNOWN")], [], "UNKNOWN"),
                 ([record(restart_needed=True)], [], "UNKNOWN"),
                 ([record("AFFECTED"), record("UNKNOWN")], ["coverage gap"], "AFFECTED"))
        for rows, issues, expected in cases:
            with self.subTest(expected=expected, rows=rows):
                self.assertEqual(audit.finish(rows, issues)["verdict"], expected)

    def test_external_decoder_follows_actual_same_process_component(self):
        for status in ("PATCHED", "AFFECTED", "UNKNOWN"):
            rows = [record("UNKNOWN", decoder="external"),
                    record("UNKNOWN", kind="libnode", path="/lib/libnode.so", decoder="external"),
                    record(status, kind="brotli", path="/lib/libbrotlidec.so")]
            with patch.object(audit.sys, "platform", "linux"):
                audit.resolve_decoders(rows)
            self.assertEqual([r["cve_results"][audit.BROTLI_CVE]["status"] for r in rows], [status] * 3)
            self.assertEqual(rows[0]["status"], "AFFECTED" if status == "AFFECTED" else "UNKNOWN")
            self.assertEqual(rows[0]["cve_results"]["CVE-2026-105482"]["status"], "UNKNOWN")

    def test_external_decoder_cannot_borrow_another_pid(self):
        rows = [record("UNKNOWN", decoder="external"), record(kind="brotli", pid=20)]
        audit.resolve_decoders(rows)
        self.assertEqual(rows[0]["status"], "UNKNOWN")

    def test_external_installed_files_do_not_prove_linkage(self):
        rows = [record("UNKNOWN", pid=0, decoder="external"), record(kind="brotli", pid=0)]
        audit.resolve_decoders(rows)
        self.assertEqual(rows[0]["status"], "UNKNOWN")

    def test_replaced_decoder_blocks_clearance(self):
        rows = [record("UNKNOWN", decoder="external"), record(kind="brotli", restart_needed=True)]
        with patch.object(audit.sys, "platform", "linux"):
            audit.resolve_decoders(rows)
        self.assertEqual(rows[0]["status"], "UNKNOWN")
        self.assertTrue(rows[0]["restart_needed"])

    def test_windows_decoder_does_not_clear_loaded_image(self):
        rows = [record("UNKNOWN", decoder="external"), record(kind="brotli")]
        with patch.object(audit.sys, "platform", "win32"):
            audit.resolve_decoders(rows)
        self.assertEqual(rows[0]["status"], "UNKNOWN")

    def test_bundled_libnode_can_supply_decoder(self):
        rows = [record("UNKNOWN", decoder="external"), record("AFFECTED", kind="libnode")]
        with patch.object(audit.sys, "platform", "linux"):
            audit.resolve_decoders(rows)
        self.assertEqual(rows[0]["status"], "AFFECTED")

    def test_exposure_is_independent_and_never_proves_rce(self):
        config = inventory()
        entry = config["runtimes"][0]
        for status, exposure, expected in (("AFFECTED", "reachable", "POTENTIALLY_EXPLOITABLE"),
                                           ("AFFECTED", "not_observed", "NOT_ESTABLISHED"),
                                           ("UNKNOWN", "reachable", "NOT_ESTABLISHED"),
                                           ("PATCHED", "reachable", "NOT_ESTABLISHED")):
            entry["exposure"] = {audit.BROTLI_CVE: {"reachability": exposure, "source": "review ticket"}}
            rows = [record(status)]
            audit.attach_exposure(rows, config)
            self.assertEqual(rows[0]["exploitability"], expected)
            self.assertEqual(rows[0]["status"], status)

    def test_inactive_file_does_not_get_live_exposure_priority(self):
        config = inventory()
        config["runtimes"][0]["exposure"] = {audit.BROTLI_CVE: {"reachability": "reachable", "source": "review"}}
        rows = [record("AFFECTED", pid=0)]
        audit.attach_exposure(rows, config)
        self.assertEqual(rows[0]["exploitability"], "NOT_ESTABLISHED")

    def test_missing_and_extra_runtime_and_access_error_are_retained(self):
        runtime = audit.Runtime(10, "node", "/extra/node", "/proc/10/exe", "1")
        with patch.object(audit, "discover", return_value=([runtime], ["PID access denied"])), \
                patch.object(audit, "inspect_runtime", return_value=record(path=runtime.path)):
            report = audit.audit_local(inventory(), EMPTY)
        self.assertEqual(report["verdict"], "UNKNOWN")
        self.assertEqual({d["code"] for d in report["diagnostics"]},
                         {"DISCOVERY_INCOMPLETE", "EXPECTED_RUNTIME_MISSING", "UNEXPECTED_RUNTIME"})

    def test_no_inventory_never_clears_host(self):
        with patch.object(audit, "discover", return_value=([audit.Runtime(10, "node", "/srv/node", "", "1")], [])), \
                patch.object(audit, "inspect_runtime", return_value=record()):
            self.assertEqual(audit.audit_local(None, EMPTY)["verdict"], "UNKNOWN")

    def test_windows_keeps_installed_file_separate(self):
        runtime = audit.Runtime(10, "node", "C:\\node.exe", "C:\\node.exe", "1")
        with patch.object(audit.sys, "platform", "win32"), \
                patch.object(audit, "inspect_file", return_value=record("AFFECTED", detail="fixture", diagnostics=[])):
            row = audit.inspect_runtime(runtime, None, EMPTY)
        self.assertEqual((row["status"], row["file_status"]), ("UNKNOWN", "AFFECTED"))


class PackageEvidence(unittest.TestCase):
    def test_debian_decoder_threshold_is_exact_and_no_derivative_inheritance(self):
        package = {"manager": "dpkg", "package": "libbrotli1"}
        for release, fixed in (("12", "1.0.9-2+deb12u1"), ("13", "1.1.0-2+deb13u1")):
            self.assertEqual(audit.fixed_rule(package, ("debian", release), EMPTY, "brotli")["fixed_version"], fixed)
        for distro, kind in ((("ubuntu", "24.04"), "brotli"), (("debian", "14"), "brotli"), (("debian", "13"), "node")):
            with self.assertRaises(audit.AuditError):
                audit.fixed_rule(package, distro, EMPTY, kind)

    def test_debian_node_defers_only_after_checksum(self):
        package = {"manager": "dpkg", "package": "nodejs", "version": "20.19.2+dfsg-1+deb13u3",
                   "algorithm": "sha256", "digest": SHA}
        row = record("UNKNOWN")
        with patch.object(audit, "package_metadata", return_value=package):
            audit.assess_file(row, {"sha256": SHA}, ("debian", "13"), EMPTY)
            self.assertEqual(row["decoder"], "external")
            with self.assertRaisesRegex(audit.AuditError, "differs"):
                audit.assess_file(record("UNKNOWN"), {"sha256": "0" * 64}, ("debian", "13"), EMPTY)

    def test_vendor_rule_requires_correct_rpm_stream_vendor_arch(self):
        rule = {"os_id": "rhel", "os_version": "9.8", "manager": "rpm", "package": "nodejs",
                "kind": "node", "decoder": "bundled", "fixed_version": "1:24.22.1-1.el9",
                "cves": list(audit.CVES), "sources": ["https://example.org/advisory"],
                "arch": "x86_64", "vendor": "Red Hat, Inc.", "module": "nodejs:24:fixture"}
        proof = {"schema": 1, "vendor_fixes": [rule]}
        audit.validate_config(None, proof)
        package = {k: rule[k] for k in ("manager", "package", "arch", "vendor", "module")}
        self.assertEqual(audit.fixed_rule(package, ("rhel", "9.8"), proof, "node"), rule)
        for field in ("arch", "vendor", "module"):
            changed = dict(package, **{field: "wrong"})
            with self.assertRaises(audit.AuditError):
                audit.fixed_rule(changed, ("rhel", "9.8"), proof, "node")

    def test_native_comparator_result_and_errors(self):
        cases = (("dpkg", 0, "", "PATCHED"), ("dpkg", 1, "", "AFFECTED"),
                 ("apk", 0, "<", "AFFECTED"), ("apk", 0, ">", "PATCHED"),
                 ("pacman", 0, "-4", "AFFECTED"), ("pacman", 0, "0", "PATCHED"),
                 ("rpm", 0, "-1", "AFFECTED"), ("rpm", 0, "1", "PATCHED"))
        for manager, rc, output, expected in cases:
            with patch.object(audit, "system_tool", side_effect=lambda x: x), \
                    patch.object(audit, "command", return_value=subprocess.CompletedProcess([], rc, output, "")):
                self.assertEqual(audit.package_status({"manager": manager, "version": "1.0"}, "1.1"), expected)
        with patch.object(audit, "system_tool", side_effect=lambda x: x), \
                patch.object(audit, "command", return_value=subprocess.CompletedProcess([], 2, "", "")), \
                self.assertRaises(audit.AuditError):
            audit.package_status({"manager": "dpkg", "version": "1"}, "2")

    def test_rpm_version_cannot_inject_macro(self):
        with self.assertRaises(audit.AuditError), patch.object(audit, "command") as command:
            audit.package_status({"manager": "rpm", "version": '%{lua:os.execute("bad")}'}, "1")
        command.assert_not_called()


class IdentityAndDiscovery(unittest.TestCase):
    def simulate_linux(self, foreign=False, denied=False, executable="/usr/bin/node"):
        with patch.object(audit.sys, "platform", "linux"), \
                patch.object(Path, "iterdir", return_value=iter([Path("/proc/101"), Path("/proc/102")])), \
                patch.object(audit, "start_time", return_value="100"), \
                patch.object(audit.os, "readlink", return_value=executable), \
                patch.object(audit.os, "stat", return_value=SimpleNamespace(st_dev=1, st_ino=5)), \
                patch.object(audit.os, "makedev", return_value=2049, create=True), \
                patch.object(Path, "read_text", side_effect=PermissionError("denied") if denied else None,
                             return_value="1000-2000 r-xp 0 08:01 88 /usr/lib/libbrotlidec.so.1\n"), \
                patch.object(audit, "same_namespace", return_value=not foreign):
            return audit.discover(None)

    def test_linux_all_workers_and_decoder_mappings(self):
        runs, issues = self.simulate_linux()
        self.assertEqual(len(runs), 4)
        self.assertEqual({r.kind for r in runs}, {"node", "brotli"})
        self.assertEqual(issues, [])

    def test_linux_foreign_namespace_is_coverage_gap(self):
        runs, issues = self.simulate_linux(foreign=True)
        self.assertEqual(runs, [])
        self.assertEqual(len(issues), 2)

    def test_linux_unreadable_mappings_are_not_clearance(self):
        runs, issues = self.simulate_linux(denied=True)
        self.assertEqual(runs, [])
        self.assertEqual(len(issues), 2)

    def test_linux_unrelated_brotli_consumer_is_not_node(self):
        self.assertEqual(self.simulate_linux(executable="/usr/bin/browser"), ([], []))

    def test_component_names(self):
        for path in ("/lib/libbrotlidec.so.1.1.0", "/opt/lib/libbrotlidec.1.dylib", "C:\\x\\brotlidec.dll"):
            self.assertEqual(audit.module_kind(path), "brotli")
        for path in ("/lib/libnode.so.115", "C:\\x\\node.dll", "/lib/libnode.115.dylib"):
            self.assertEqual(audit.module_kind(path), "libnode")
        for path in ("/lib/libbrotlienc.so", "/lib/libbrotlicommon.so", "/tmp/libnode.so.bak"):
            self.assertIsNone(audit.module_kind(path))

    def test_windows_names_and_explicit_renamed_node(self):
        snapshot = {"processes": [{"pid": 10, "start": "1", "path": "C:\\app\\worker.exe", "modules": []}], "issues": []}
        with patch.object(audit, "powershell_json", return_value=snapshot):
            runs, _ = audit.discover_windows(inventory("c:\\APP\\WORKER.EXE"))
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0].kind, "node")

    def test_windows_unrelated_brotli_consumers_are_not_node(self):
        snapshot = {"processes": [{"pid": 10, "start": "1", "path": "C:\\browser.exe",
                                   "modules": [{"path": "C:\\brotlidec.dll"}]}], "issues": []}
        with patch.object(audit, "powershell_json", return_value=snapshot):
            self.assertEqual(audit.discover_windows(None)[0], [])

    def test_windows_embedded_libnode_is_discovered(self):
        snapshot = {"processes": [{"pid": 10, "start": "1", "path": "C:\\worker.exe",
                                   "modules": [{"path": "C:\\node.dll"}, {"path": "C:\\brotlidec.dll"}]}], "issues": []}
        with patch.object(audit, "powershell_json", return_value=snapshot):
            runs, _ = audit.discover_windows(None)
        self.assertEqual({r.kind for r in runs}, {"libnode", "brotli"})

    def test_hash_checks_discovery_identity_and_pid_reuse(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "node"
            path.write_bytes(b"fixture")
            info = path.stat()
            runtime = audit.Runtime(10, "node", str(path), str(path), "start", device=info.st_dev, inode=info.st_ino)
            with patch.object(audit.sys, "platform", "linux"), patch.object(audit, "same_namespace", return_value=True), \
                    patch.object(audit, "start_time", return_value="start"):
                self.assertEqual(audit.hash_runtime(runtime)[0]["sha256"], SHA)
                runtime.inode += 1
                with self.assertRaisesRegex(audit.AuditError, "discovered"):
                    audit.hash_runtime(runtime)
            with patch.object(audit.sys, "platform", "linux"), patch.object(audit, "start_time", return_value="reused"), \
                    self.assertRaisesRegex(audit.AuditError, "reused"):
                audit.hash_runtime(runtime)

    def test_hash_rejects_namespace_change(self):
        runtime = audit.Runtime(10, "node", "/node", "/proc/10/exe", "1")
        with patch.object(audit.sys, "platform", "linux"), patch.object(audit, "start_time", return_value="1"), \
                patch.object(audit, "same_namespace", return_value=False), self.assertRaisesRegex(audit.AuditError, "namespace"):
            audit.hash_runtime(runtime)

    def test_draft_never_confirms_coverage(self):
        with patch.object(audit, "discover", return_value=([audit.Runtime(1, "node", "/node", "", "1")], ["hidden process"])):
            report = audit.draft_inventory()
        self.assertFalse(report["draft_inventory"]["coverage_confirmed"])
        self.assertEqual(report["exit_status"], 2)
        self.assertIn("hidden process", report["draft_inventory"]["discovery_issues"])


class TransportAndCLI(unittest.TestCase):
    def test_transferred_source_fingerprint_is_verified(self):
        result = audit.finish([record()], [])
        result["token"] = "nonce"
        result["metadata"]["tool_sha256"] = "0" * 64
        result["metadata"]["evidence_sha256"] = audit.report_metadata(None, EMPTY)["evidence_sha256"]
        with patch.object(audit, "remote_program", return_value=("nonce", "source")), \
                patch.object(audit, "command", return_value=subprocess.CompletedProcess([], 0, json.dumps(result), "")):
            report = audit.run_remote(["ssh"], "ssh", "host", None, EMPTY)
        self.assertEqual(report["verdict"], "UNKNOWN")
        self.assertIn("fingerprints", report["issues"][0])

    def test_remote_roundtrip_runs_transferred_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "node"
            path.write_bytes(b"fixture")
            token, program = audit.remote_program(inventory(str(path)), build(), files=True)
            result = subprocess.run([sys.executable, "-"], input=program, text=True, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(audit.valid_remote_result(json.loads(result.stdout), token, result.returncode))

    def test_remote_rejects_forged_envelopes(self):
        result = audit.finish([record()], [])
        result["token"] = "nonce"
        self.assertTrue(audit.valid_remote_result(result, "nonce", 0))
        for field, value in (("token", "wrong"), ("completed", False), ("verdict", "AFFECTED"),
                             ("exit_status", 1), ("cves", []), ("runtimes", []), ("issues", ["hidden"]),
                             ("diagnostics", [{}])):
            changed = copy.deepcopy(result)
            changed[field] = value
            self.assertFalse(audit.valid_remote_result(changed, "nonce", 0), field)

    def test_transport_failure_is_unknown(self):
        with patch.object(audit, "command", return_value=subprocess.CompletedProcess([], 255, "", "unreachable")):
            result = audit.run_remote(["ssh"], "ssh", "host", None, EMPTY)
        self.assertEqual(result["verdict"], "UNKNOWN")
        self.assertIn("unreachable", result["issues"][-1])

    def test_safe_ssh_and_container_arguments(self):
        with patch.object(audit, "system_tool", side_effect=lambda x: x), patch.object(audit, "run_remote") as run:
            audit.audit_ssh("auditor@host", True, None, EMPTY, python="/opt/Python tools/python3")
            args = run.call_args.args[0]
            self.assertIn("StrictHostKeyChecking=yes", args)
            self.assertEqual(args[-1], "/usr/bin/sudo -n -- '/opt/Python tools/python3' -")
            audit.audit_container("service-1", "docker", None, EMPTY)
            self.assertEqual(run.call_args.args[0], ["docker", "exec", "-i", "service-1", "/usr/bin/python3", "-"])
        for host in ("-oProxyCommand=bad", "host;bad", "host\nother"):
            with self.assertRaises(audit.AuditError):
                audit.audit_ssh(host, False, None, EMPTY)

    def test_windows_ssh_requires_absolute_executable(self):
        with self.assertRaises(audit.AuditError):
            audit.audit_ssh("host", False, None, EMPTY, remote_os="windows", python="python")

    def test_cli_invalid_options_fail_closed(self):
        for args in (("--files",), ("--sudo",), ("--remote-python", "/python"),
                     ("--draft-inventory", "--evidence", "missing")):
            with contextlib.redirect_stdout(io.StringIO()) as out:
                code = audit.main([*args, "--json"])
            self.assertEqual(code, 2)
            self.assertEqual(json.loads(out.getvalue())["reports"][0]["verdict"], "UNKNOWN")

    def test_json_config_is_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_bytes(b" " * (audit.MAX_CONFIG + 1))
            with self.assertRaisesRegex(audit.AuditError, "1 MiB"):
                audit.load_json(path)

    def test_probe_is_opt_in_hint_only_and_environment_is_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ("node.exe" if sys.platform == "win32" else "node")
            path.write_bytes(b"fixture")
            with patch.object(audit, "command", return_value=subprocess.CompletedProcess([], 0, "v24.22.0\n", "")) as execute:
                result = audit.audit_probe(str(path))
            self.assertEqual(execute.call_args.args[0], [str(path), "--version"])
        self.assertEqual(result["verdict"], "UNKNOWN")
        self.assertEqual(result["version_hints"][0]["upstream_comparison"], "AFFECTED")
        with patch.object(audit.sys, "platform", "linux"), patch.dict(os.environ, {"NODE_OPTIONS": "--require evil.js"}), \
                patch.object(audit.subprocess, "run") as run:
            audit.command(["/usr/bin/node", "--version"])
        self.assertNotIn("NODE_OPTIONS", run.call_args.kwargs["env"])


if __name__ == "__main__":
    unittest.main()
