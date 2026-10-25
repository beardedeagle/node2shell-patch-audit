"""Regressions for independent CVE coverage and incomplete patch evidence."""
import copy
import unittest
from unittest.mock import patch

from test_node2shell_audit import EMPTY, SHA, audit, build, inventory, record


class AdvisoryScopeTests(unittest.TestCase):
    def test_guidance_does_not_apply_versioned_guides_to_other_releases(self):
        for distro, applicable in (("rhel", "9.7"), ("amzn", "2023"), ("sles", "15.7")):
            with self.subTest(distro=distro):
                self.assertEqual(audit.diagnostic("AFFECTED", "fixture", (distro, applicable))["guidance"],
                                 [audit.ADVISORY, audit.GUIDANCE[distro]])
                self.assertEqual(audit.diagnostic("AFFECTED", "fixture", (distro, "other"))["guidance"],
                                 [audit.ADVISORY])

    def test_all_ten_advisory_cves_and_branch_exclusions(self):
        cves = {"CVE-2026-105481", "CVE-2026-105482", "CVE-2026-105483", "CVE-2026-106069",
                "CVE-2026-106070", "CVE-2026-106071", "CVE-2026-106072", "CVE-2026-106073",
                "CVE-2026-106074", "CVE-2026-111497"}
        self.assertEqual(set(audit.CVES), cves)
        for old, fixed, excluded in (
            ("22.23.3", "22.23.4", {"CVE-2026-105483", "CVE-2026-106070", "CVE-2026-106071"}),
            ("24.22.0", "24.22.1", {"CVE-2026-106070", "CVE-2026-106071"}),
            ("26.12.0", "26.12.1", set()),
        ):
            for version, status in ((old, "AFFECTED"), (fixed, "PATCHED")):
                with self.subTest(version=version):
                    self.assertEqual(audit.upstream_cves(version),
                                     {cve: "NOT_AFFECTED" if cve in excluded else status for cve in cves})
        self.assertEqual(set(audit.upstream_cves("20.99.0").values()), {"UNKNOWN"})

    def test_brotli_only_fix_cannot_clear_other_node_cves(self):
        proof = build()
        del proof["builds"][0]["node_version"]
        proof["builds"][0].update(status="PATCHED", cves=[audit.BROTLI_CVE])
        audit.validate_config(None, proof)
        row = record("UNKNOWN")
        audit.assess_file(row, {"sha256": SHA}, None, proof)
        self.assertEqual(row["cve_results"][audit.BROTLI_CVE]["status"], "PATCHED")
        self.assertEqual(row["cve_results"]["CVE-2026-105482"]["status"], "UNKNOWN")
        self.assertEqual(audit.finish([row], [])["verdict"], "UNKNOWN")

    def test_standalone_brotli_does_not_clear_the_whole_advisory(self):
        result = audit.finish([record(kind="brotli", pid=0)], [])
        self.assertEqual(result["cve_summary"][audit.BROTLI_CVE], "PATCHED")
        self.assertEqual(result["cve_summary"]["CVE-2026-106074"], "UNKNOWN")
        self.assertEqual(result["verdict"], "UNKNOWN")

    def test_external_brotli_never_overwrites_core_cve_evidence(self):
        for version, core_status in (("24.22.0", "AFFECTED"), ("24.22.1", "PATCHED")):
            for decoder_status in ("AFFECTED", "PATCHED", "UNKNOWN"):
                with self.subTest(version=version, decoder=decoder_status):
                    row = record("UNKNOWN")
                    proof = build(version, decoder="external")
                    audit.validate_config(None, proof)
                    audit.assess_file(row, {"sha256": SHA}, None, proof)
                    self.assertEqual(row["cve_results"][audit.BROTLI_CVE]["status"], "UNKNOWN")
                    with patch.object(audit.sys, "platform", "linux"):
                        audit.resolve_decoders([row, record(decoder_status, kind="brotli", path="/lib/brotli")])
                    self.assertEqual(row["cve_results"]["CVE-2026-105482"]["status"], core_status)
                    self.assertEqual(row["cve_results"][audit.BROTLI_CVE]["status"], decoder_status)
                    expected = "AFFECTED" if "AFFECTED" in (core_status, decoder_status) else decoder_status
                    self.assertEqual(row["status"], expected)

    def test_exposure_must_match_the_affected_cve(self):
        row = record()
        audit.set_cve_result(row, "CVE-2026-105482", "AFFECTED", "fixture")
        config = inventory()
        config["runtimes"][0]["exposure"] = {
            audit.BROTLI_CVE: {"reachability": "reachable", "source": "Brotli-only review"}}
        audit.attach_exposure([row], config)
        self.assertEqual(row["exploitability"], "NOT_ESTABLISHED")
        config["runtimes"][0]["exposure"]["CVE-2026-105482"] = {
            "reachability": "reachable", "source": "DNS allowlist review"}
        audit.attach_exposure([row], config)
        self.assertEqual(row["exploitability"], "POTENTIALLY_EXPLOITABLE")
        self.assertEqual(row["cve_results"][audit.BROTLI_CVE]["exploitability"], "NOT_ESTABLISHED")

    def test_decoder_evidence_cannot_claim_node_core_fixes(self):
        for kind, decoder, cves in (("brotli", None, ["CVE-2026-105482"]),
                                    ("node", "external", [audit.BROTLI_CVE]),
                                    ("node", "bundled", [audit.BROTLI_CVE, audit.BROTLI_CVE])):
            proof = build(kind=kind, status="PATCHED", cves=cves)
            del proof["builds"][0]["node_version"]
            if decoder is None:
                del proof["builds"][0]["decoder"]
            else:
                proof["builds"][0]["decoder"] = decoder
            with self.subTest(kind=kind, cves=cves), self.assertRaises(audit.AuditError):
                audit.validate_config(None, proof)

    def test_distinct_vendor_cve_thresholds_remain_independent(self):
        base = {"os_id": "ubuntu", "os_version": "26.04", "manager": "dpkg", "package": "nodejs",
                "kind": "node", "decoder": "external", "sources": ["https://example.org/synthetic-advisory"]}
        proof = {"schema": 1, "vendor_fixes": [
            dict(base, cves=["CVE-2026-105482"], fixed_version="2"),
            dict(base, cves=["CVE-2026-106074"], fixed_version="3")]}
        audit.validate_config(None, proof)
        package = {"manager": "dpkg", "package": "nodejs", "version": "2", "algorithm": "sha256", "digest": SHA}
        row = record("UNKNOWN")
        with patch.object(audit, "package_metadata", return_value=package), \
                patch.object(audit, "package_status", side_effect=lambda p, fixed: "PATCHED" if fixed == "2" else "AFFECTED"):
            audit.assess_file(row, {"sha256": SHA}, ("ubuntu", "26.04"), proof)
        self.assertEqual(row["cve_results"]["CVE-2026-105482"]["status"], "PATCHED")
        self.assertEqual(row["cve_results"]["CVE-2026-106074"]["status"], "AFFECTED")
        self.assertEqual(row["cve_results"][audit.BROTLI_CVE]["status"], "UNKNOWN")
        self.assertEqual(row["status"], "AFFECTED")
        proof["vendor_fixes"][1]["cves"] = ["CVE-2026-105482"]
        with self.assertRaisesRegex(audit.AuditError, "Duplicate"):
            audit.validate_config(None, proof)

    def test_missing_or_forged_remote_cve_results_are_rejected(self):
        result = audit.finish([record()], [])
        result["token"] = "nonce"
        self.assertTrue(audit.valid_remote_result(result, "nonce", 0))
        for mode in ("missing", "summary", "contradiction"):
            altered = copy.deepcopy(result)
            if mode == "missing":
                del altered["runtimes"][0]["cve_results"]["CVE-2026-106074"]
            elif mode == "summary":
                altered["cve_summary"]["CVE-2026-106074"] = "AFFECTED"
            else:
                altered["runtimes"][0]["cve_results"]["CVE-2026-106074"]["status"] = "AFFECTED"
            with self.subTest(mode=mode):
                self.assertFalse(audit.valid_remote_result(altered, "nonce", 0))

    def test_windows_per_cve_file_evidence_stays_separate(self):
        runtime = audit.Runtime(10, "node", "C:\\node.exe", "C:\\node.exe", "1")
        with patch.object(audit.sys, "platform", "win32"), \
                patch.object(audit, "inspect_file", return_value=record("AFFECTED", detail="fixture", diagnostics=[])):
            row = audit.inspect_runtime(runtime, None, EMPTY)
        self.assertEqual({r["status"] for r in row["file_cve_results"].values()}, {"AFFECTED"})
        self.assertEqual({r["status"] for r in row["cve_results"].values()}, {"UNKNOWN"})
        self.assertEqual(audit.finish([row], [])["verdict"], "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
