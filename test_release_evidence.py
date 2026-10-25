import hashlib
import io
import tarfile
import unittest
import zipfile
from unittest.mock import patch

import release_evidence as release
import verify_release
from test_node2shell_audit import audit, build


def tar_archive(names):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        for name, data, link in names:
            item = tarfile.TarInfo(name)
            item.size = len(data)
            if link:
                item.type = tarfile.SYMTYPE
                item.linkname = "/outside"
            archive.addfile(item, io.BytesIO(data))
    stream.seek(0)
    return stream


class ReleaseTests(unittest.TestCase):
    def test_tar_reads_only_expected_artifact_without_extraction(self):
        archive = tar_archive([("release/bin/node", b"node fixture", False), ("../../outside", b"ignored", False)])
        self.assertEqual(release.artifact_digest(archive, "release"), hashlib.sha256(b"node fixture").hexdigest())

    def test_duplicate_missing_and_linked_artifacts_rejected(self):
        target = ("release/bin/node", b"node", False)
        for names in ([], [target, target], [("release/bin/node", b"", True)]):
            with self.assertRaises(ValueError):
                release.artifact_digest(tar_archive(names), "release")

    def test_zip_reads_windows_artifact(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("release/node.exe", b"windows node")
        stream.seek(0)
        self.assertEqual(release.artifact_digest(stream, "release", True), hashlib.sha256(b"windows node").hexdigest())

    def test_expansion_is_bounded(self):
        archive = tar_archive([("release/bin/node", b"x" * 100, False)])
        with patch.object(release, "LIMIT", 50), self.assertRaises(ValueError):
            release.artifact_digest(archive, "release")

    def test_release_inputs_cannot_change_host_or_path(self):
        for version in ("24.22.1/../../bad", "27.0.0", "v24.22.1", "24.22.1-rc.1"):
            with self.assertRaises(ValueError), patch.object(release, "download") as download:
                release.release_evidence(version, "linux-x64")
            download.assert_not_called()

    def test_manifest_and_archive_must_agree(self):
        def download(url, stream, limit):
            stream.write(b"0" * 64 + b"  node-v24.22.1-linux-x64.tar.gz\n")
            stream.seek(0)
            return "1" * 64
        with patch.object(release, "download", side_effect=download), self.assertRaisesRegex(ValueError, "checksum mismatch"):
            release.release_evidence("24.22.1", "linux-x64")

    def test_native_verifier_catches_a_wrong_classifier_verdict(self):
        def download(url, stream, limit):
            filename = url.rsplit("/", 1)[1]
            if filename.endswith(".zip"):
                with zipfile.ZipFile(stream, "w") as archive:
                    archive.writestr(filename[:-4] + "/node.exe", b"fixture")
            else:
                stream.write(tar_archive([(filename[:-7] + "/bin/node", b"fixture", False)]).getvalue())
            stream.seek(0)

        for machine, arch in (("ARM64", "arm64"), ("AMD64", "x64"), ("aarch64", "arm64"), ("x86_64", "x64")):
            with self.subTest(machine=machine), \
                    patch.object(verify_release.platform, "machine", return_value=machine), \
                    patch.object(verify_release.sys, "argv", ["verify_release.py", "--version", "24.22.0",
                                                              "--expect", "AFFECTED"]), \
                    patch.object(release, "release_evidence", return_value=build("24.22.0")) as proof, \
                    patch.object(release, "download", side_effect=download), \
                    patch.object(audit, "upstream_status", return_value="PATCHED"), \
                    patch.object(verify_release.subprocess, "Popen") as launch:
                with self.assertRaisesRegex(AssertionError, "PATCHED"):
                    verify_release.main()
                self.assertTrue(proof.call_args.args[1].endswith("-" + arch))
                launch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
