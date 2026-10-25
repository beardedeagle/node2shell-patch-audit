"""Package and file identity regressions retained from the shared audit design."""
import base64
import gzip
import hashlib
import io
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from test_node2shell_audit import audit


class OSReleaseTests(unittest.TestCase):
    def test_version_fields_preserve_spec_punctuation_and_case(self):
        for field in ('VERSION_ID', 'VERSION_CODENAME'):
            for quote in ('', "'", '"'):
                data = 'NAME="Test OS + GNU/Linux"\nID=testos\n' + field + '=' + quote + '1.2+Build~rc1^20261025' + quote + '\n'
                with self.subTest(field=field, quote=quote), \
                        patch.object(Path, 'is_file', return_value=True), \
                        patch.object(Path, 'read_text', return_value=data):
                    self.assertEqual(audit.os_release(), ('testos', '1.2+Build~rc1^20261025'))

    def test_malformed_identity_fields_cannot_select_fallback_rules(self):
        for line in ('ID="debian', "ID=debian'", 'ID="debian\'',
                     'ID="debian+other"', 'VERSION_ID="12', 'VERSION_ID=12/other'):
            data = 'ID=debian\nVERSION_CODENAME=bookworm\n' + line + '\n'
            with self.subTest(line=line), patch.object(Path, 'is_file', return_value=True), \
                    patch.object(Path, 'read_text', return_value=data), self.assertRaises(audit.AuditError):
                audit.os_release()


class PackageAndFileTests(unittest.TestCase):
    def test_alpine_checksum_is_file_specific(self):
        checksum = "Q1" + base64.b64encode(bytes.fromhex("ab" * 20)).decode()
        database = f"P:nodejs\nV:24.22.1-r0\nF:usr/bin\nR:nodejs-other\nZ:{checksum}\nR:nodejs\nZ:{checksum}\n"
        with patch.object(Path, "open", side_effect=lambda *args, **kwargs: io.StringIO(database)):
            result = audit.apk_metadata("/usr/bin/nodejs")
            self.assertEqual(result["digest"], "ab" * 20)
            self.assertEqual(result["version"], "24.22.1-r0")
            with self.assertRaises(audit.AuditError):
                audit.apk_metadata("/usr/bin/node")
        with patch.object(Path, "open", return_value=io.StringIO(database.replace("Q1", "Q9"))):
            with self.assertRaises(audit.AuditError):
                audit.apk_metadata("/usr/bin/nodejs")

    def test_alpine_stream_preserves_boundaries_and_rejects_duplicate_owners(self):
        checksum = "Q1" + base64.b64encode(bytes.fromhex("ab" * 20)).decode()
        record = f"P:nodejs\nV:24.22.1-r0\nF:usr/bin\nR:nodejs\nZ:{checksum}"
        cases = ((record, None),
                 (record + "\n\n" + record.replace("P:nodejs", "P:other"), "No unique APK"),
                 (record + f"\n\nF:usr/bin\nR:nodejs\nZ:{checksum}", "Invalid APK"))
        for database, error in cases:
            with self.subTest(error=error), io.StringIO(database) as stream, \
                    patch.object(Path, "open", return_value=stream), \
                    patch.object(stream, "read", side_effect=AssertionError("Database must be streamed")):
                if error:
                    with self.assertRaisesRegex(audit.AuditError, error):
                        audit.apk_metadata("/usr/bin/nodejs")
                else:
                    self.assertEqual(audit.apk_metadata("/usr/bin/nodejs")["package"], "nodejs")

    def test_pacman_uses_owned_package_mtree_digest(self):
        replies = [subprocess.CompletedProcess([], 0, "node\n", ""),
                   subprocess.CompletedProcess([], 0, "node 24.22.1-1\n", "")]
        mtree = "#mtree\n/set type=file\n./usr/bin/node type=file sha256digest=" + "a" * 64 + "\n"
        with patch.object(audit, "system_tool", return_value="/usr/bin/pacman"), \
                patch.object(audit, "command", side_effect=replies), \
                patch.object(gzip, "open", return_value=io.StringIO(mtree)):
            self.assertEqual(audit.pacman_metadata("/usr/bin/node")["digest"], "a" * 64)

    def test_hash_stream_rejects_mid_read_metadata_changes(self):
        with tempfile.TemporaryFile() as stream:
            stream.write(b"test runtime")
            stream.flush()
            info = audit.os.fstat(stream.fileno())
            fields = {key: getattr(info, key) for key in ("st_size", "st_mtime_ns", "st_ctime_ns")}
            for key in fields:
                stream.seek(0)
                changed = SimpleNamespace(**dict(fields, **{key: fields[key] + 1}))
                with self.subTest(field=key), \
                        patch.object(audit.os, "fstat", side_effect=[info, changed]), \
                        self.assertRaisesRegex(audit.AuditError, "File changed while hashing"):
                    audit.hash_stream(stream)

    def test_file_hash_uses_consistent_handle_metadata_but_rejects_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "node"
            path.write_bytes(b"test")
            with path.open("rb") as stream:
                info = audit.os.fstat(stream.fileno())
            fields = {key: getattr(info, key) for key in (
                "st_mode", "st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")}
            # Python on Windows can expose creation time via stat and change time via fstat.
            with patch.object(audit.os, "stat", return_value=SimpleNamespace(**dict(fields, st_ctime_ns=0))):
                self.assertEqual(audit.hash_file(str(path))["sha256"], hashlib.sha256(b"test").hexdigest())
            replacement = SimpleNamespace(**dict(fields, st_ino=info.st_ino + 1))
            with patch.object(audit.os, "fstat", side_effect=[info, info, replacement]), \
                    self.assertRaisesRegex(audit.AuditError, "pathname changed"):
                audit.hash_file(str(path))

    def test_dpkg_owner_version_and_checksum_are_preserved(self):
        for path in ('/usr/sbin/nodejs8.3', '/.node/bin/node'):
            for prefix in ('', './'):
                replies = [subprocess.CompletedProcess([], 0, 'nodejs: ' + path + '\n', ''),
                           subprocess.CompletedProcess([], 0, "nodejs\t24.22.0-0ubuntu0.24.04.13\tinstalled\n", "")]
                with self.subTest(path=path, prefix=prefix), \
                        patch.object(audit, "system_tool", return_value="/usr/bin/dpkg-query"), \
                        patch.object(audit, "command", side_effect=replies), \
                        patch.object(Path, "is_file", return_value=True), \
                        patch.object(Path, "read_text", return_value='a'*32 + '  ' + prefix + path[1:] + '\n'):
                    package = audit.dpkg_metadata(path)
                self.assertEqual(package["version"], "24.22.0-0ubuntu0.24.04.13")
                self.assertEqual(package["digest"], "a"*32)

    def test_dpkg_does_not_accept_other_file_from_pattern_match(self):
        with patch.object(audit, "system_tool", return_value="/usr/bin/dpkg-query"), \
                patch.object(audit, "command", return_value=subprocess.CompletedProcess([], 0, "nodejs: /other/file\n", "")), \
                self.assertRaises(audit.AuditError):
            audit.dpkg_metadata("/usr/sbin/nodejs8.3")

    def test_rpm_epoch_release_and_digest(self):
        replies = [subprocess.CompletedProcess([], 0, "nodejs\t1\t24.22.0\t2.el9\t8\n", ""),
                   subprocess.CompletedProcess([], 0, "/usr/sbin/nodejs\t" + "b"*64 + "\n", ""),
                   subprocess.CompletedProcess([], 0, "x86_64\tRed Hat, Inc.\n", ""),
                   subprocess.CompletedProcess([], 0, "(none)", "")]
        with patch.object(audit, "system_tool", return_value="/usr/bin/rpm"), \
                patch.object(audit, "command", side_effect=replies):
            package = audit.rpm_metadata("/usr/sbin/nodejs")
        self.assertEqual(package["version"], "1:24.22.0-2.el9")
        self.assertEqual(package["algorithm"], "sha256")
        self.assertEqual(package["digest"], "b"*64)

    def test_unknown_rpm_digest_fails_closed(self):
        with patch.object(audit, "system_tool", return_value="/usr/bin/rpm"), \
                patch.object(audit, "command", return_value=subprocess.CompletedProcess([], 0, "nodejs\t0\t24.22.0\t2.el9\t999\n", "")), \
                self.assertRaises(audit.AuditError):
            audit.rpm_metadata("/usr/sbin/nodejs")
