"""Native identity checks using disposable fixtures, never vulnerable Brotli input."""
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from test_node2shell_audit import audit, inventory


def main():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory).resolve()
        if sys.platform == "win32":
            binary = Path(sys.executable).resolve()
            command = [str(binary), "-u", "-c", "import time; print('ready'); time.sleep(60)"]
            config = inventory(str(binary))
            proof = {"schema": 1, "builds": [{"kind": "node", "sha256": audit.hash_file(str(binary))["sha256"],
                                               "decoder": "bundled", "node_version": "24.22.1",
                                               "source": "Synthetic Python stand-in; not actual Node evidence"}]}
        else:
            # Rosetta injects Node flags into executables named "node"; inventory this fixture explicitly.
            binary = root / "node2shell-fixture"
            library = root / ("libbrotlidec.dylib" if sys.platform == "darwin" else "libbrotlidec.so.1")
            (root / "decoder.c").write_text("int fixture_decoder(void) { return 42; }\n")
            (root / "worker.c").write_text('#include <dlfcn.h>\n#include <stdio.h>\n#include <unistd.h>\n'
                                          'int main(int argc, char **argv) {\n'
                                          'if (argc != 2 || !dlopen(argv[1], RTLD_NOW)) return 1;\n'
                                          'puts("ready"); fflush(stdout); for (;;) pause(); }\n')
            shared = ["-dynamiclib"] if sys.platform == "darwin" else ["-shared", "-fPIC"]
            subprocess.run(["cc", *shared, str(root / "decoder.c"), "-o", str(library)], check=True, timeout=30)
            subprocess.run(["cc", str(root / "worker.c"), "-o", str(binary), "-ldl"], check=True, timeout=30)
            config = inventory(str(binary))
            config["runtimes"].append({"label": "fixture decoder", "kind": "brotli", "path": str(library)})
            proof = {"schema": 1, "builds": [
                {"kind": "node", "sha256": audit.hash_file(str(binary))["sha256"], "decoder": "external",
                 "node_version": "24.22.1",
                 "source": "Synthetic native fixture; external dlopen dependency"},
                {"kind": "brotli", "sha256": audit.hash_file(str(library))["sha256"], "status": "PATCHED",
                 "cves": [audit.BROTLI_CVE], "source": "Synthetic shared library; not actual Brotli evidence"}]}
            command = [str(binary), str(library)]
        audit.validate_config(config, proof)
        process = subprocess.Popen(command, stdout=subprocess.PIPE, text=True)
        try:
            assert process.stdout.readline().strip() == "ready"
            runs, issues = audit.discover(config)
            own = [run for run in runs if run.pid == process.pid]
            expected_kinds = {"node"} if sys.platform == "win32" else {"node", "brotli"}
            assert {run.kind for run in own} == expected_kinds, (own, issues)
            records = [audit.inspect_runtime(run, None, proof) for run in own]
            audit.resolve_decoders(records)
            if sys.platform == "win32":
                assert all(row["status"] == "UNKNOWN" and row["file_status"] == "PATCHED" for row in records), records
            else:
                assert all(row["status"] == "PATCHED" for row in records), records
                node = next(run for run in own if run.kind == "node")
                os.rename(binary, str(binary) + ".old")
                binary.write_bytes(b"replacement")
                if sys.platform == "darwin":
                    changed = audit.inspect_runtime(node, None, proof)
                    assert changed["status"] == "UNKNOWN" and changed["restart_needed"], changed
                else:
                    assert audit.hash_runtime(node)[1] is True
            print(f"Native {sys.platform} discovery, artifact identity and decoder checks passed (synthetic fixtures).")
        finally:
            process.terminate()
            process.wait(timeout=10)
            process.stdout.close()


if __name__ == "__main__":
    main()
