"""Verify an official native Node release with a temporary idle worker; no network listeners."""
import argparse
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

import release_evidence
from test_node2shell_audit import audit, inventory


def verified_binary(version, root):
    """Download a native test runtime and verify its bytes before execution."""
    system = {"darwin": "darwin", "linux": "linux", "win32": "win"}[sys.platform]
    arch = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "x64", "amd64": "x64"}[platform.machine().lower()]
    target = system + "-" + arch
    proof = release_evidence.release_evidence(version, target)
    audit.validate_config(None, proof)
    prefix = f"node-v{version}-{target}"
    filename = prefix + (".zip" if system == "win" else ".tar.gz")
    binary = root / ("node.exe" if system == "win" else "node")
    with tempfile.TemporaryFile() as stream:
        release_evidence.download(f"https://nodejs.org/dist/v{version}/{filename}", stream, release_evidence.LIMIT)
        archive = zipfile.ZipFile(stream) if system == "win" else tarfile.open(fileobj=stream, mode="r:gz")
        with archive:
            name = prefix + ("/node.exe" if system == "win" else "/bin/node")
            member = archive.open(name) if system == "win" else archive.extractfile(name)
            with member, binary.open("wb") as output:
                shutil.copyfileobj(release_evidence.BoundedReader(member), output)
        assert audit.hash_file(str(binary))["sha256"] == proof["builds"][0]["sha256"]
        binary.chmod(0o700)
    return binary, proof, target


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--expect", required=True, choices=("AFFECTED", "PATCHED"),
                        help="Expected verdict from independent advisory evidence")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as directory:
        binary, proof, target = verified_binary(args.version, Path(directory).resolve())
        config = inventory(str(binary))
        expected = args.expect
        report = audit.audit_local(config, proof, files=True)
        assert report["verdict"] == expected, report
        exclusions = {"22": {"CVE-2026-105483", "CVE-2026-106070", "CVE-2026-106071"},
                      "24": {"CVE-2026-106070", "CVE-2026-106071"}, "26": set()}
        expected_cves = {cve: "NOT_AFFECTED" if cve in exclusions[args.version.split(".")[0]] else expected
                         for cve in audit.CVES}
        assert report["cve_summary"] == expected_cves, report
        environment = {"PATH": os.defpath}
        if sys.platform == "win32":
            environment["SystemRoot"] = str(audit.windows_system_directory().parent)
        process = subprocess.Popen([str(binary), "--eval", 'console.log("ready"); setInterval(() => {}, 1000)'],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=environment)
        try:
            assert process.stdout.readline().strip() == "ready", process.stderr.read(1000)
            runs, issues = audit.discover(config)
            own = [run for run in runs if run.pid == process.pid and run.kind == "node"]
            assert own, issues
            row = audit.inspect_runtime(own[0], None, proof)
            if sys.platform == "win32":
                assert row["status"] == "UNKNOWN" and row["file_status"] == expected, row
                assert {cve: result["status"] for cve, result in row["file_cve_results"].items()} == expected_cves, row
                assert all(result["status"] == "UNKNOWN" for result in row["cve_results"].values()), row
            else:
                assert row["status"] == expected, row
                assert {cve: result["status"] for cve, result in row["cve_results"].items()} == expected_cves, row
            print(f"Official Node {args.version} {target}: installed={expected}; running={row['status']}")
        finally:
            process.terminate()
            process.wait(timeout=10)
            process.stdout.close()
            process.stderr.close()


if __name__ == "__main__":
    main()
