"""Exercise real distro package metadata, checksum and version comparison.

Requires an installed dpkg-owned /usr/bin/node from the nodejs package.
Rules below are synthetic test assertions, not vulnerability advisories.
Does not execute Node or modify installed files.
"""
import subprocess

from test_node2shell_audit import audit, inventory


def main():
    path = "/usr/bin/node"
    package = audit.package_metadata(path)
    installed = subprocess.check_output(
        [audit.system_tool("dpkg-query"), "-W", "-f=${Version}", "--", "nodejs"], text=True).strip()
    assert package["manager"] == "dpkg" and package["package"] == "nodejs", package
    assert package["version"] == installed, package
    hashes = audit.hash_file(path)
    assert package["algorithm"] == "md5" and hashes["md5"] == package["digest"], package
    distro = audit.os_release()
    cve = "CVE-2026-105482"
    rule = {"os_id": distro[0], "os_version": distro[1], "manager": "dpkg",
            "package": "nodejs", "kind": "node", "decoder": "external",
            "fixed_version": installed, "cves": [cve],
            "sources": ["https://example.invalid/synthetic-package-integration-test"]}
    proof = {"schema": 1, "vendor_fixes": [rule]}
    config = inventory(path)
    config["scope"] = "Synthetic dpkg integration assertions; not a vulnerability assessment"
    newer = installed + "+node2shelltest1"
    subprocess.run([audit.system_tool("dpkg"), "--compare-versions", installed, "lt", newer], check=True)

    for threshold, expected, verdict in ((installed, "PATCHED", "UNKNOWN"), (newer, "AFFECTED", "AFFECTED")):
        rule["fixed_version"] = threshold
        report = audit.audit_local(config, proof, files=True)
        row, = report["runtimes"]
        assert row["manager"] == "dpkg" and row["package"] == "nodejs", row
        assert row["package_version"] == installed and row["sha256"] == hashes["sha256"], row
        assert row["cve_results"][cve]["status"] == expected, row
        assert row["cve_results"][cve]["sources"] == rule["sources"], row
        assert all(result["status"] == "UNKNOWN" for key, result in row["cve_results"].items() if key != cve), row
        assert report["verdict"] == verdict, report

    rule["os_version"] += "-different"
    report = audit.audit_local(config, proof, files=True)
    assert report["verdict"] == "UNKNOWN", report
    assert report["runtimes"][0]["cve_results"][cve]["status"] == "UNKNOWN", report
    print(f"PASS dpkg {distro[0]} {distro[1]}: nodejs {installed}; real ownership, checksum, "
          "equal/newer thresholds, partial CVE coverage and exact OS scope. Rules were synthetic.")


if __name__ == "__main__":
    main()
