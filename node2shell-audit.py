#!/usr/bin/env python3
"""Read-only artifact audit for the ten CVEs in Node's October 2026 advisory."""
import argparse
import base64
import ctypes
import errno
import gzip
import hashlib
import json
import ntpath
import os
import platform
import re
import secrets
import shlex
import stat
import subprocess
import sys
import zlib
from contextlib import ExitStack
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath

BROTLI_CVE = "CVE-2026-111497"
# Branch scope is from the October advisory, not inferred from changelog omissions.
CVE_BRANCHES = {
    "CVE-2026-105482": (22, 24, 26),
    "CVE-2026-105483": (24, 26),
    "CVE-2026-106069": (22, 24, 26),
    BROTLI_CVE: (22, 24, 26),
    "CVE-2026-105481": (22, 24, 26),
    "CVE-2026-106072": (22, 24, 26),
    "CVE-2026-106074": (22, 24, 26),
    "CVE-2026-106070": (26,),
    "CVE-2026-106071": (26,),
    "CVE-2026-106073": (22, 24, 26),
}
CVES = tuple(CVE_BRANCHES)
BASELINES = {22: (22, 23, 4), 24: (24, 22, 1), 26: (26, 12, 1)}
KINDS = {"node", "libnode", "brotli"}
MODULE_KINDS = {"libnode", "brotli"}
MANAGERS = {"dpkg", "rpm", "apk", "pacman"}
MAX_CONFIG = 1024 * 1024
TOOL_VERSION = "1.0.0"
ADVISORY = "https://nodejs.org/en/blog/vulnerability/october-2026-security-releases"
DEBIAN_BROTLI_ADVISORY = "https://security-tracker.debian.org/tracker/CVE-2026-111497"
GUIDANCE = {
    "debian": "https://www.debian.org/doc/manuals/debian-handbook/sect.regular-upgrades.en.html",
    "ubuntu": "https://ubuntu.com/server/docs/how-to/software/package-management/",
    "rhel": "https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/managing_and_monitoring_security_updates/index",
    "rocky": "https://docs.rockylinux.org/guides/package_management/dnf_package_manager/",
    "almalinux": "https://wiki.almalinux.org/documentation/errata.html",
    "fedora": "https://dnf5.readthedocs.io/en/latest/commands/upgrade.8.html",
    "ol": "https://docs.oracle.com/en/operating-systems/oracle-linux/software-management/sfw-mgmt-UpdateSoftwareonEnterpriseLinux.html",
    "amzn": "https://docs.aws.amazon.com/linux/al2023/ug/security-inplace-update.html",
    "sles": "https://documentation.suse.com/sles/15-SP7/html/SLES-all/cha-onlineupdate-you.html",
    "alpine": "https://docs.alpinelinux.org/user-handbook/0.1a/Working/apk.html#_upgrading_packages",
    "arch": "https://wiki.archlinux.org/title/System_maintenance",
    "nixos": "https://wiki.nixos.org/wiki/Updating_NixOS",
    "gentoo": "https://wiki.gentoo.org/wiki/Upgrading_Gentoo",
    "slackware": "https://docs.slackware.com/slackware:slackpkg",
    "darwin": "https://github.com/nodejs/node#verifying-binaries",
    "win32": "https://github.com/nodejs/node#verifying-binaries",
}
NEXT_STEPS = {
    "ACCESS_DENIED": "Obtain read access to the process/file and rerun.",
    "FILE_MISSING": "Check inventory and deployment; inspect inactive files separately.",
    "FILE_CHANGED": "Recheck artifact identity; restart or replace stale workers, then re-audit.",
    "PROCESS_CHANGED": "Rerun against a stable process identity.",
    "EVIDENCE_MISSING": "Supply trusted SHA-256 build provenance or exact vendor evidence.",
    "EVIDENCE_MISMATCH": "Investigate the mismatch; obtain evidence for the actual artifact.",
    "VENDOR_RULE_MISSING": "Supply a rule for this exact OS, release, package and CVE.",
    "VERSION_UNSUPPORTED": "Use a supported fixed build or provide verified backport evidence.",
    "LOADED_IMAGE_UNVERIFIED": "Use --files for installed files; that cannot clear Windows loaded images.",
    "RESTART_REQUIRED": "Restart or replace the deployment using its normal procedure, then re-audit.",
    "AFFECTED": "Update the affected Node/Brotli artifact, restart its consumers and re-audit.",
    "INVENTORY_UNCONFIRMED": "Review all deployments and supply a confirmed inventory.",
    "EXPECTED_RUNTIME_MISSING": "Check the expected service/namespace; inspect inactive files separately.",
    "UNEXPECTED_RUNTIME": "Identify the artifact and include it in the reviewed inventory.",
    "DISCOVERY_INCOMPLETE": "Resolve process access or namespace restrictions and rerun within the deployment.",
    "NO_RUNTIME_FOUND": "Confirm namespace and inventory; use --files for inactive deployments.",
    "TRANSPORT_FAILED": "Check SSH/container access, target Python path and transport errors.",
    "OBSERVATION_ONLY": "Collect verified artifact and application-exposure evidence.",
    "INSPECTION_FAILED": "Resolve the inspection error and rerun; do not clear this deployment.",
    "DECODER_UNRESOLVED": "Identify and verify the actual loaded Brotli decoder and libnode artifacts.",
}

class AuditError(Exception):
    """Audit failure with a stable diagnostic code."""

    def __init__(self, message, code="INSPECTION_FAILED"):
        """Initialize an audit failure.

        Args:
            message (str): Human-readable failure detail.
            code (str): Key in NEXT_STEPS identifying the unresolved condition.
        """
        super().__init__(message)
        self.code = code


def command(argv, timeout=15, data=None):
    """Fixed system utilities, or a binary explicitly selected with --probe-node."""
    environment = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
    if sys.platform == "win32":
        directory = windows_system_directory()
        environment = {"SystemRoot": str(directory.parent), "PATH": str(directory),
                       "TEMP": os.environ.get("TEMP", str(directory.parent / "Temp"))}
        if Path(argv[0]).name.lower() == "ssh.exe":
            for key in ("USERPROFILE", "HOMEDRIVE", "HOMEPATH"):
                if key in os.environ:
                    environment[key] = os.environ[key]
    if Path(argv[0]).name == "ssh" and "SSH_AUTH_SOCK" in os.environ:
        environment["SSH_AUTH_SOCK"] = os.environ["SSH_AUTH_SOCK"]
    if Path(argv[0]).name in ("docker", "podman"):
        environment["HOME"] = str(Path.home())
        for key in ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "DOCKER_TLS_VERIFY",
                    "DOCKER_CERT_PATH", "CONTAINER_HOST", "CONTAINER_CONNECTION", "XDG_RUNTIME_DIR"):
            if key in os.environ:
                environment[key] = os.environ[key]
    try:
        return subprocess.run(argv, input=data, text=True, capture_output=True,
                              timeout=timeout, check=False,
                              env=environment, encoding="utf-8", errors="replace")
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AuditError("Command failed or timed out: " + argv[0]) from exc


def windows_system_directory():
    import ctypes
    buffer = ctypes.create_unicode_buffer(32768)
    size = ctypes.windll.kernel32.GetSystemDirectoryW(buffer, len(buffer))
    require(0 < size < len(buffer), "Cannot locate Windows system directory")
    return Path(buffer.value)


def system_tool(name):
    if sys.platform == "win32":
        relative = {"powershell": "WindowsPowerShell/v1.0/powershell.exe",
                    "ssh": "OpenSSH/ssh.exe"}.get(name)
        require(relative is not None, "Unsupported Windows utility: " + name)
        path = windows_system_directory() / relative
        require(path.is_file(), "Missing Windows system utility: " + name)
        return str(path)
    directories = ("/usr/bin", "/bin", "/usr/sbin", "/sbin")
    if name in ("docker", "podman"):
        directories += ("/usr/local/bin", "/opt/homebrew/bin")
    owners = {0}
    if name in ("docker", "podman") and os.getuid() == os.geteuid():
        owners.add(os.getuid())
    for directory in directories:
        path = Path(directory) / name
        try:
            info = path.stat()
            if (stat.S_ISREG(info.st_mode) and info.st_uid in owners
                    and not info.st_mode & 0o022 and os.access(path, os.X_OK)):
                return str(path)
        except OSError:
            continue
    raise AuditError("Missing trusted system utility: " + name)


def load_json(path):
    with open(path, "rb") as stream:
        data = stream.read(MAX_CONFIG + 1)
    if len(data) > MAX_CONFIG:
        raise AuditError("Configuration exceeds 1 MiB")
    return json.loads(data)


def require(condition, message, code="INSPECTION_FAILED"):
    """Enforce an audit precondition.

    Args:
        condition (bool): Whether the required invariant holds.
        message (str): Failure detail.
        code (str): Stable diagnostic code.

    Raises:
        AuditError: The condition is false.
    """
    if not condition:
        raise AuditError(message, code)


def diagnostic(code, detail, distro=None, manager=None):
    """Describe a finding without changing its patch verdict.

    Args:
        code (str): Stable NEXT_STEPS key.
        detail (str): Finding detail; treated as data in text and JSON output.
        distro (tuple[str, str] | None): Audited OS ID and release.
        manager (str | None): Artifact package manager, when known.

    Returns:
        dict: Code, detail, next step and applicable update guidance URLs.
    """
    guide = GUIDANCE.get(distro[0] if distro else sys.platform)
    # Versioned vendor guides apply only to their documented product release.
    if distro and ((distro[0] == "rhel" and distro[1].split(".")[0] != "9")
                   or (distro[0] == "amzn" and distro[1] != "2023")
                   or (distro[0] == "sles" and distro[1] != "15.7")):
        guide = None
    return {"code": code, "detail": detail, "next_step": NEXT_STEPS[code],
            "guidance": [ADVISORY, guide] if guide else [ADVISORY]}


def error_diagnostic(error, distro=None, manager=None):
    """Convert an inspection error into an actionable diagnostic.

    Args:
        error (Exception): Inspection or validation error.
        distro (tuple[str, str] | None): Audited OS ID and release.
        manager (str | None): Package manager already identified for the artifact.

    Returns:
        dict: Diagnostic retaining the original error detail.
    """
    code = error.code if isinstance(error, AuditError) else "INSPECTION_FAILED"
    if isinstance(error, PermissionError):
        code = "ACCESS_DENIED"
    elif isinstance(error, FileNotFoundError):
        code = "FILE_MISSING"
    return diagnostic(code, str(error), distro, manager)


def artifact_cves(kind):
    return (BROTLI_CVE,) if kind == "brotli" else CVES


def unknown_cves(kind, detail="No verified evidence for this CVE"):
    return {cve: {"status": "UNKNOWN", "detail": detail, "sources": []} for cve in artifact_cves(kind)}


def combine_statuses(statuses):
    statuses = list(statuses)
    if "AFFECTED" in statuses:
        return "AFFECTED"
    if not statuses or any(s not in ("PATCHED", "NOT_AFFECTED") for s in statuses):
        return "UNKNOWN"
    return "NOT_AFFECTED" if all(s == "NOT_AFFECTED" for s in statuses) else "PATCHED"


def refresh_assessment(record):
    results = record.setdefault("cve_results", unknown_cves(record["kind"]))
    status = combine_statuses(results.get(cve, {}).get("status", "UNKNOWN") for cve in artifact_cves(record["kind"]))
    record["status"] = "PATCHED" if status == "NOT_AFFECTED" else status


def set_cve_result(record, cve, status, detail, sources=()):
    record.setdefault("cve_results", unknown_cves(record["kind"]))[cve] = {
        "status": status, "detail": detail, "sources": list(sources)}
    refresh_assessment(record)


def summarize_cves(records):
    summary = {}
    for cve in CVES:
        statuses = []
        for row in records:
            if cve not in artifact_cves(row["kind"]):
                continue
            status = row.get("cve_results", {}).get(cve, {}).get("status", "UNKNOWN")
            statuses.append("UNKNOWN" if row["restart_needed"] and status == "PATCHED" else status)
        summary[cve] = combine_statuses(statuses)
    return summary


def explain_record(record, distro):
    """Attach unresolved conditions and restart guidance to an artifact record.

    Args:
        record (dict): Artifact assessment, updated in place.
        distro (tuple[str, str] | None): Audited OS ID and release.

    Returns:
        dict: The record with additive diagnostics; status remains unchanged.
    """
    refresh_assessment(record)
    findings = record.setdefault("diagnostics", [])
    if not findings and record["status"] != "PATCHED":
        code = "AFFECTED" if record["status"] == "AFFECTED" else (
            "VERSION_UNSUPPORTED" if "node_version" in record else "INSPECTION_FAILED")
        findings.append(diagnostic(code, record.get("detail", ""), distro, record.get("manager")))
    if record.get("restart_needed"):
        findings.append(diagnostic("RESTART_REQUIRED", "Running file was removed or replaced", distro, record.get("manager")))
    return record


def report_metadata(inventory=None, evidence=None):
    """Record the audited host and fingerprints of the supplied JSON documents.

    Args:
        inventory (dict | None): Parsed inventory, including its scope assertion.
        evidence (dict | None): Parsed evidence, including imported advisory rows.

    Returns:
        dict: UTC report time, tool identity, target OS/architecture and SHA-256
        fingerprints of canonical JSON; raw inputs are not retained.
    """
    def fingerprint(value):
        return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                         allow_nan=False).encode()).hexdigest() if value is not None else None
    try:
        distro = os_release()
    except (OSError, AuditError):
        distro = None
    source_hash = globals().get("AUDIT_SOURCE_SHA256")
    if source_hash is None and "__file__" in globals():
        try:
            source_hash = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        except OSError:
            source_hash = None
    return {"timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "tool_version": TOOL_VERSION, "tool_sha256": source_hash,
            "target": {"platform": sys.platform, "os_release": list(distro) if distro else None,
                       "os_version": platform.mac_ver()[0] if sys.platform == "darwin" else platform.version(),
                       "architecture": platform.machine()},
            "inventory_sha256": fingerprint(inventory), "evidence_sha256": fingerprint(evidence)}


def absolute_path(value):
    return bool(isinstance(value, str) and not any(ord(c) < 32 for c in value)
            and not value.startswith(("//", "\\\\"))
            and (value.startswith("/") or
                 (PureWindowsPath(value).is_absolute() and re.match(r"^[A-Za-z]:", value)
                  and ":" not in value[2:])))


def path_key(value):
    return ntpath.normcase(ntpath.normpath(value)) if re.match(r"^[A-Za-z]:", value) else value


def os_release():
    # Parse the two simple fields without sourcing a shell file.
    values = {}
    path = Path("/etc/os-release")
    if not path.is_file():
        path = Path("/usr/lib/os-release")
    for line in path.read_text().splitlines():
        match = re.fullmatch(r'(ID|VERSION_ID|VERSION_CODENAME)=["\']?([A-Za-z0-9._-]+)["\']?', line)
        if match:
            values[match[1]] = match[2]
    require("ID" in values, "Cannot determine OS release")
    return values["ID"], values.get("VERSION_ID", values.get("VERSION_CODENAME", "rolling"))


def start_time(pid):
    return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]


def same_namespace(pid):
    remote = os.stat(f"/proc/{pid}/ns/mnt")
    local = os.stat("/proc/self/ns/mnt")
    return ((remote.st_dev, remote.st_ino) == (local.st_dev, local.st_ino) and
            os.stat(f"/proc/{pid}/root").st_ino == os.stat("/").st_ino and
            os.stat(f"/proc/{pid}/root").st_dev == os.stat("/").st_dev)


def proc_path(raw):
    deleted = raw.endswith(" (deleted)")
    if deleted:
        raw = raw[:-10]
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), raw), deleted


@dataclass
class Runtime:
    pid: int
    kind: str
    path: str
    live_path: str
    start: str
    deleted: bool = False
    device: int = 0
    inode: int = 0


def powershell_json(script, data):
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    result = command([system_tool("powershell"), "-NoLogo", "-NoProfile", "-NonInteractive",
                      "-EncodedCommand", encoded], timeout=120, data=json.dumps(data))
    require(result.returncode == 0, "Windows inspection failed: " + result.stderr[:1000])
    return json.loads(result.stdout.lstrip("\ufeff"))


class MacOSProcesses:
    """Read process identities and mapped vnodes through libproc."""

    class BSDInfo(ctypes.Structure):
        _fields_ = [(name, ctypes.c_uint32) for name in (
            "flags", "status", "xstatus", "pid", "ppid", "uid", "gid", "ruid",
            "rgid", "svuid", "svgid", "reserved")]
        _fields_ += [("comm", ctypes.c_char * 16), ("name", ctypes.c_char * 32)]
        _fields_ += [(name, ctypes.c_uint32) for name in ("nfiles", "pgid", "jobc", "tdev", "tpgid")]
        _fields_ += [("nice", ctypes.c_int32), ("seconds", ctypes.c_uint64), ("microseconds", ctypes.c_uint64)]

    class RegionInfo(ctypes.Structure):
        _fields_ = [(name, ctypes.c_uint32) for name in ("protection", "max_protection", "inheritance", "flags")]
        _fields_ += [("offset", ctypes.c_uint64)]
        _fields_ += [(name, ctypes.c_uint32) for name in (
            "behavior", "wired", "tag", "resident", "private_shared", "swapped", "dirty",
            "references", "shadow_depth", "share_mode", "private", "shared", "object_id", "depth")]
        _fields_ += [("address", ctypes.c_uint64), ("size", ctypes.c_uint64)]

    class VnodeStat(ctypes.Structure):
        _fields_ = [("device", ctypes.c_uint32), ("mode", ctypes.c_uint16), ("nlink", ctypes.c_uint16),
                    ("inode", ctypes.c_uint64), ("uid", ctypes.c_uint32), ("gid", ctypes.c_uint32)]
        _fields_ += [(name, ctypes.c_int64) for name in (
            "atime", "atime_ns", "mtime", "mtime_ns", "ctime", "ctime_ns",
            "birthtime", "birthtime_ns", "size", "blocks")]
        _fields_ += [("blocksize", ctypes.c_int32), ("flags", ctypes.c_uint32),
                    ("generation", ctypes.c_uint32), ("rdevice", ctypes.c_uint32),
                    ("reserved", ctypes.c_int64 * 2)]

    def __init__(self):
        class RegionPath(ctypes.Structure):
            _fields_ = [("region", MacOSProcesses.RegionInfo), ("stat", MacOSProcesses.VnodeStat),
                        ("type", ctypes.c_int), ("padding", ctypes.c_int),
                        ("fsid", ctypes.c_int32 * 2), ("path", ctypes.c_char * 1024)]
        self.region_type = RegionPath
        self.lib = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        self.lib.proc_listallpids.argtypes = [ctypes.c_void_p, ctypes.c_int]
        self.lib.proc_listallpids.restype = ctypes.c_int
        self.lib.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
        self.lib.proc_pidinfo.restype = ctypes.c_int
        self.lib.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
        self.lib.proc_pidpath.restype = ctypes.c_int

    def pids(self):
        for _ in range(3):
            count = self.lib.proc_listallpids(None, 0)
            require(0 < count < 1000000, "Cannot enumerate macOS processes")
            buffer = (ctypes.c_int * (count + 128))()
            used = self.lib.proc_listallpids(buffer, ctypes.sizeof(buffer))
            require(used > 0, "Cannot enumerate macOS processes")
            if used < len(buffer):
                return sorted(set(pid for pid in buffer[:used] if pid > 0))
        raise AuditError("macOS process list kept growing during enumeration")

    def info(self, pid, flavor, data, address=0):
        ctypes.set_errno(0)
        size = self.lib.proc_pidinfo(pid, flavor, address, ctypes.byref(data), ctypes.sizeof(data))
        if size <= 0:
            code = ctypes.get_errno() or errno.EIO
            raise OSError(code, os.strerror(code))
        require(size == ctypes.sizeof(data), "Incomplete macOS process information")
        return data

    def identity(self, pid):
        data = self.info(pid, 3, self.BSDInfo())  # PROC_PIDTBSDINFO
        require(data.pid == pid, "macOS process identity mismatch")
        if data.status == 5:  # SZOMB
            raise ProcessLookupError(errno.ESRCH, "Process is a zombie")
        return f"{data.seconds}:{data.microseconds}"

    def executable(self, pid):
        buffer = ctypes.create_string_buffer(4096)
        ctypes.set_errno(0)
        size = self.lib.proc_pidpath(pid, buffer, len(buffer))
        if size <= 0:
            code = ctypes.get_errno() or errno.EIO
            raise OSError(code, os.strerror(code))
        path = os.fsdecode(buffer.value)
        require(absolute_path(path), "Invalid macOS executable path")
        return path

    def mappings(self, pid):
        address, mappings = 0, {}
        for index in range(100000):
            try:
                data = self.info(pid, 8, self.region_type(), address)  # PROC_PIDREGIONPATHINFO
            except OSError as exc:
                if exc.errno == errno.EINVAL and index:
                    return list(mappings.values())
                raise
            end = data.region.address + data.region.size
            require(data.region.address >= address and end > address and end < 2 ** 64,
                    "Invalid macOS memory region")
            address = end
            path = os.fsdecode(data.path)
            if path:
                require(absolute_path(path), "Invalid macOS mapped-file path")
                row = {"path": path, "device": data.stat.device, "inode": data.stat.inode,
                       "nlink": data.stat.nlink}
                key = path, row["device"], row["inode"]
                mappings[key] = row
        raise AuditError("macOS memory-region limit exceeded")


def hash_macos_runtime(runtime):
    api = MacOSProcesses()
    require(api.identity(runtime.pid) == runtime.start, "Process exited or PID was reused", "PROCESS_CHANGED")
    require(runtime.inode > 0 and not runtime.deleted, "Running macOS file has no readable vnode identity")
    with open(runtime.live_path, "rb") as stream:
        before = os.fstat(stream.fileno())
        require((before.st_dev, before.st_ino) == (runtime.device, runtime.inode),
                "macOS pathname no longer identifies the running mapping; restart and re-audit", "FILE_CHANGED")
        hashes, info = hash_stream(stream)
        mappings = api.mappings(runtime.pid)
        require(any((row["device"], row["inode"]) == (info.st_dev, info.st_ino) for row in mappings),
                "macOS mapping changed during inspection", "PROCESS_CHANGED")
        require(api.identity(runtime.pid) == runtime.start, "Process exited or PID was reused", "PROCESS_CHANGED")
        after = os.fstat(stream.fileno())
        require((info.st_size, info.st_mtime_ns, info.st_ctime_ns) ==
                (after.st_size, after.st_mtime_ns, after.st_ctime_ns), "Running file changed during inspection", "FILE_CHANGED")
    try:
        current = os.stat(runtime.path)
        restart = (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino)
    except FileNotFoundError:
        restart = True
    return hashes, restart


def hash_stream(stream):
    info = os.fstat(stream.fileno())
    require(stat.S_ISREG(info.st_mode), "Image is not a regular file")
    hashes = {name: hashlib.new(name, usedforsecurity=False)
              for name in ("md5", "sha1", "sha256", "sha384", "sha512")}
    for block in iter(lambda: stream.read(1024 * 1024), b""):
        for digest in hashes.values():
            digest.update(block)
    after = os.fstat(stream.fileno())
    require((info.st_size, info.st_mtime_ns, info.st_ctime_ns) ==
            (after.st_size, after.st_mtime_ns, after.st_ctime_ns), "File changed while hashing", "FILE_CHANGED")
    return {name: digest.hexdigest() for name, digest in hashes.items()}, info


def hash_file(path):
    """Hash a stable installed file without executing it.

    Args:
        path (str): Absolute path on this host.

    Returns:
        dict[str, str]: File digests keyed by algorithm name.

    Raises:
        AuditError: The path is invalid, non-regular or changes while hashing.
        OSError: The file is missing or cannot be inspected.
    """
    require(absolute_path(path) and Path(path).is_absolute(), "File path must be absolute on this host")
    require(stat.S_ISREG(os.stat(path).st_mode), "File is not a regular file: " + path)
    with open(path, "rb") as stream:
        hashes, info = hash_stream(stream)
        # Windows stat/fstat can disagree on ctime semantics; compare open handles.
        with open(path, "rb") as current_stream:
            current = os.fstat(current_stream.fileno())
        require((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) ==
                (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns, current.st_ctime_ns),
                "File pathname changed while hashing", "FILE_CHANGED")
    return hashes


def hash_runtime(runtime):
    if sys.platform == "darwin":
        return hash_macos_runtime(runtime)
    require(start_time(runtime.pid) == runtime.start, "Process exited or PID was reused", "PROCESS_CHANGED")
    require(same_namespace(runtime.pid), "Process changed mount/root namespace", "PROCESS_CHANGED")
    with ExitStack() as stack:
        try:
            stream = stack.enter_context(open(runtime.live_path, "rb"))
        except OSError as exc:
            # map_files may need extra capabilities. A pathname is acceptable only
            # when its device/inode proves it is the file in the inspected mapping.
            require(runtime.kind in MODULE_KINDS and not runtime.deleted,
                    "Cannot read the running file", error_diagnostic(exc)["code"])
            stream = stack.enter_context(open(runtime.path, "rb"))
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode), "Running image is not a regular file")
        require(runtime.inode > 0 and (info.st_dev, info.st_ino) == (runtime.device, runtime.inode),
                "File no longer identifies the discovered executable/mapping", "FILE_CHANGED")
        hashes, info = hash_stream(stream)
    require(start_time(runtime.pid) == runtime.start, "Process exited or PID was reused", "PROCESS_CHANGED")
    require(same_namespace(runtime.pid), "Process changed mount/root namespace", "PROCESS_CHANGED")
    if runtime.kind in MODULE_KINDS:
        mapped = False
        for line in Path(f"/proc/{runtime.pid}/maps").read_text().splitlines():
            fields = line.split(None, 5)
            if len(fields) == 6:
                device = os.makedev(*(int(part, 16) for part in fields[3].split(":")))
                if (device, int(fields[4])) == (info.st_dev, info.st_ino):
                    mapped = True
        require(mapped, "Node.js module mapping changed during inspection", "PROCESS_CHANGED")
    else:
        current = os.stat(runtime.live_path)
        require((current.st_dev, current.st_ino) == (info.st_dev, info.st_ino),
                "Process executable changed during inspection", "PROCESS_CHANGED")
    restart = runtime.deleted
    try:
        disk = os.stat(runtime.path)
        restart |= (disk.st_dev, disk.st_ino) != (info.st_dev, info.st_ino)
    except FileNotFoundError:
        restart = True
    return hashes, restart


def dpkg_metadata(path):
    tool = system_tool("dpkg-query")
    result = command([tool, "-S", "--", path])
    owners = set()
    for line in result.stdout.splitlines():
        owner, sep, owned_path = line.partition(": ")
        if sep and owned_path == path:
            owners.add(owner)
    require(result.returncode == 0 and len(owners) == 1, "No unique dpkg owner for runtime")
    owner = owners.pop()
    require(re.fullmatch(r"[a-z0-9][a-z0-9+.-]*(?::[a-z0-9]+)?", owner), "Invalid package owner")
    result = command([tool, "-W", "-f=${binary:Package}\t${Version}\t${db:Status-Status}\n", "--", owner])
    fields = result.stdout.strip().split("\t")
    require(result.returncode == 0 and len(fields) == 3 and fields[2] == "installed",
            "Package is not fully installed")
    package, version, _ = fields
    require(re.fullmatch(r"[a-z0-9][a-z0-9+.-]*(?::[a-z0-9]+)?", package), "Invalid package name")
    checksum = None
    for name in dict.fromkeys((package, owner, package.split(":")[0])):
        manifest = Path("/var/lib/dpkg/info") / (name + ".md5sums")
        if not manifest.is_file():
            continue
        for line in manifest.read_text().splitlines():
            parts = line.split(None, 1)
            if len(parts) == 2 and "/" + parts[1].lstrip("./") == path:
                require(re.fullmatch(r"[0-9a-f]{32}", parts[0]), "Invalid package checksum")
                checksum = parts[0]
    require(checksum is not None, "Package has no checksum for the running file")
    return {"manager": "dpkg", "package": package.split(":")[0], "version": version,
            "algorithm": "md5", "digest": checksum}


def rpm_metadata(path):
    tool = system_tool("rpm")
    result = command([tool, "-qf", "--qf",
                      "%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{FILEDIGESTALGO}\n", "--", path])
    fields = result.stdout.strip().split("\t")
    require(result.returncode == 0 and len(fields) == 5, "No unique RPM owner for runtime")
    package, epoch, version, release, algorithm = fields
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9+._-]*", package), "Invalid RPM name")
    require(epoch.isdigit(), "Cannot determine RPM epoch")
    algorithm = {"1": "md5", "2": "sha1", "8": "sha256", "9": "sha384", "10": "sha512"}.get(algorithm)
    require(algorithm is not None, "Unsupported RPM file digest algorithm")
    result = command([tool, "-qf", "--qf", "[%{FILENAMES}\t%{FILEDIGESTS}\n]", "--", path])
    digests = [line.split("\t")[1] for line in result.stdout.splitlines()
               if line.startswith(path + "\t") and len(line.split("\t")) == 2]
    require(result.returncode == 0 and len(digests) == 1 and
            re.fullmatch(r"[0-9a-f]+", digests[0]), "No unique RPM file checksum")
    identity = command([tool, "-qf", "--qf", "%{ARCH}\t%{VENDOR}\n", "--", path])
    identity_fields = identity.stdout.strip().split("\t")
    require(identity.returncode == 0 and len(identity_fields) == 2, "Cannot determine RPM architecture/vendor")
    arch, vendor = identity_fields
    module_query = command([tool, "-qf", "--qf", "%{MODULARITYLABEL}", "--", path])
    module = module_query.stdout.strip() if module_query.returncode == 0 else None
    return {"manager": "rpm", "package": package, "version": f"{epoch}:{version}-{release}",
            "algorithm": algorithm, "digest": digests[0], "arch": arch,
            "module": "" if module == "(none)" else module, "vendor": vendor}


def apk_metadata(path):
    matches = []
    with Path("/lib/apk/db/installed").open() as stream:
        name = version = directory = filename = None
        for line in stream:
            line = line.rstrip("\r\n")
            if not line:
                name = version = directory = filename = None
                continue
            key, sep, value = line.partition(":")
            if not sep:
                continue
            if key == "P":
                name = value
            elif key == "V":
                version = value
            elif key == "F":
                directory, filename = value, None
            elif key == "R":
                filename = value
            elif key == "Z" and directory is not None and filename is not None:
                if "/" + "/".join(filter(None, (directory, filename))) != path:
                    continue
                require(value.startswith("Q1"), "Unsupported APK checksum encoding")
                digest = base64.b64decode(value[2:], validate=True)
                require(len(digest) == 20 and name and version, "Invalid APK file checksum")
                matches.append({"manager": "apk", "package": name, "version": version,
                                "algorithm": "sha1", "digest": digest.hex()})
    require(len(matches) == 1, "No unique APK file checksum; use build evidence")
    return matches[0]


def pacman_metadata(path):
    result = command([system_tool("pacman"), "-Qoq", "--", path])
    owners = result.stdout.splitlines()
    require(result.returncode == 0 and len(owners) == 1
            and re.fullmatch(r"[A-Za-z0-9@_+][A-Za-z0-9@_.+-]*", owners[0]),
            "No unique pacman owner for file")
    package = owners[0]
    result = command([system_tool("pacman"), "-Q", "--", package])
    parts = result.stdout.split()
    require(result.returncode == 0 and len(parts) == 2 and parts[0] == package
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+:~^_-]*", parts[1]),
            "Cannot determine pacman package version")
    version = parts[1]
    manifest = Path("/var/lib/pacman/local") / (package + "-" + version) / "mtree"
    matches = []
    with gzip.open(manifest, "rt") as stream:
        for line in stream:
            fields = line.split()
            if not fields or not fields[0].startswith("./"):
                continue
            name = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), fields[0][1:])
            if name == path:
                digests = [v[len("sha256digest="):] for v in fields[1:] if v.startswith("sha256digest=")]
                require(len(digests) == 1 and re.fullmatch(r"[0-9a-f]{64}", digests[0]),
                        "No SHA-256 for file in pacman mtree")
                matches.extend(digests)
    require(len(matches) == 1, "No unique pacman file checksum; use build evidence")
    return {"manager": "pacman", "package": package, "version": version,
            "algorithm": "sha256", "digest": matches[0]}


def package_status(package, fixed):
    if package["manager"] == "dpkg":
        result = command([system_tool("dpkg"), "--compare-versions", package["version"], "ge", fixed])
        require(result.returncode in (0, 1), "Package version comparison failed")
        return "PATCHED" if result.returncode == 0 else "AFFECTED"
    # Constrained values cannot inject Lua, RPM macros, or shell syntax.
    for value in (package["version"], fixed):
        require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+:~^_-]*", value), "Invalid package version")
    if package["manager"] == "apk":
        result = command([system_tool("apk"), "version", "-t", package["version"], fixed])
        require(result.returncode == 0 and result.stdout.strip() in ("<", "=", ">"),
                "APK version comparison failed")
        return "AFFECTED" if result.stdout.strip() == "<" else "PATCHED"
    if package["manager"] == "pacman":
        result = command([system_tool("vercmp"), package["version"], fixed])
        require(result.returncode == 0 and re.fullmatch(r"-?[0-9]+", result.stdout.strip()),
                "pacman version comparison failed")
        return "AFFECTED" if int(result.stdout.strip()) < 0 else "PATCHED"
    require(package["manager"] == "rpm", "Unsupported version comparison")
    expression = '%{lua:print(rpm.vercmp("' + package["version"] + '","' + fixed + '"))}'
    result = command([system_tool("rpm"), "--eval", expression])
    require(result.returncode == 0 and result.stdout.strip() in ("-1", "0", "1"),
            "RPM version comparison unavailable")
    return "AFFECTED" if result.stdout.strip() == "-1" else "PATCHED"


def inspect_runtime(runtime, distro, evidence):
    """Assess a discovered artifact while preserving running-image uncertainty.

    Args:
        runtime (Runtime): Discovered process or module identity.
        distro (tuple[str, str] | None): Target OS ID and release.
        evidence (dict): Validated vendor and build evidence.

    Returns:
        dict: Status, restart flag, retained evidence and actionable diagnostics.
        Inspection failures remain UNKNOWN instead of clearing the artifact.
    """
    record = {"pid": runtime.pid, "kind": runtime.kind, "path": runtime.path,
              "status": "UNKNOWN", "restart_needed": runtime.deleted}
    try:
        if sys.platform == "win32":
            record.update(inspect_file({"kind": runtime.kind, "path": runtime.path}, distro, evidence))
            record.update(pid=runtime.pid, assessment_scope="observed-file")
            record["file_status"] = record["status"]
            record["file_cve_results"] = record["cve_results"]
            record["cve_results"] = unknown_cves(runtime.kind, "Windows loaded-image identity is unverified")
            record["status"] = "UNKNOWN"
            record["detail"] += "; Windows module paths do not prove loaded-image identity; file status is separate"
            record["diagnostics"].append(diagnostic("LOADED_IMAGE_UNVERIFIED", record["detail"], distro))
            return record
        if sys.platform == "darwin" and runtime.inode:
            try:
                current = os.stat(runtime.path)
                record["restart_needed"] |= (current.st_dev, current.st_ino) != (runtime.device, runtime.inode)
            except FileNotFoundError:
                record["restart_needed"] = True
        hashes, restart = hash_runtime(runtime)
        record.update(sha256=hashes["sha256"], restart_needed=restart)
        assess_file(record, hashes, distro, evidence)
    except (AuditError, OSError, ValueError, IndexError, EOFError, zlib.error) as exc:
        record["detail"] = str(exc)
        record["diagnostics"] = [error_diagnostic(exc, distro, record.get("manager"))]
    return explain_record(record, distro)


def inspect_file(item, distro, evidence):
    """Assess an installed file without asserting running-process coverage.

    Args:
        item (dict): Inventory kind and absolute file path.
        distro (tuple[str, str] | None): Target OS ID and release.
        evidence (dict): Validated operator evidence.

    Returns:
        dict: Installed-file verdict, evidence and unresolved-condition diagnostics.
    """
    record = {"pid": 0, "kind": item["kind"], "path": item["path"], "status": "UNKNOWN",
              "restart_needed": False, "assessment_scope": "installed-file"}
    try:
        assess_file(record, hash_file(item["path"]), distro, evidence)
    except (AuditError, OSError, ValueError, IndexError, EOFError, zlib.error) as exc:
        record["detail"] = str(exc)
        record["diagnostics"] = [error_diagnostic(exc, distro, record.get("manager"))]
    if sys.platform == "win32" and record["status"] == "UNKNOWN":
        try:
            record["version_hint"] = powershell_json(r'''
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$path = [Console]::In.ReadToEnd() | ConvertFrom-Json
$info = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($path)
@{product_version=$info.ProductVersion; file_version=$info.FileVersion} | ConvertTo-Json -Compress
''', item["path"])
        except (AuditError, OSError, ValueError) as exc:
            record["detail"] += "; Windows version resource unavailable: " + str(exc)
    return explain_record(record, distro)


def finish(records, issues, mode="local", scope=None, diagnostics=None, metadata=None):
    """Summarize assessments without changing the established exit-code rules.

    Args:
        records (list[dict]): Artifact assessments.
        issues (list[str]): Coverage or inspection failures preventing clearance.
        mode (str): Local audit or transport/observation method.
        scope (str | None): Operator-supplied deployment scope.
        diagnostics (list[dict] | None): Structured explanations of report issues.
        metadata (dict | None): Target/input identity captured by the caller.

    Returns:
        dict: Schema-1 report with additive diagnostics and metadata.
    """
    summary = summarize_cves(records)
    if "AFFECTED" in summary.values():
        status = 1
    elif (not records or issues or "UNKNOWN" in summary.values()
          or any(row["status"] != "PATCHED" or row["restart_needed"] for row in records)):
        status = 2
    else:
        status = 0
    if diagnostics is None:
        code = "TRANSPORT_FAILED" if mode in ("ssh", "container") else (
            "OBSERVATION_ONLY" if mode != "local" else "DISCOVERY_INCOMPLETE")
        diagnostics = [diagnostic(code, issue) for issue in issues]
    if not records and not diagnostics:
        diagnostics = [diagnostic("NO_RUNTIME_FOUND", "No runtime artifacts were assessed")]
    metadata = metadata if metadata is not None else report_metadata()
    metadata["host_role"] = "audit-target" if mode == "local" else "controller"
    return {"schema": 1, "completed": True, "mode": mode, "scope": scope,
            "cves": list(CVES), "cve_summary": summary,
            "verdict": {0: "PATCHED", 1: "AFFECTED", 2: "UNKNOWN"}[status],
            "exit_status": status, "runtimes": records, "issues": issues,
            "diagnostics": diagnostics, "metadata": metadata}


def draft_inventory():
    """Discover candidate inventory paths without asserting deployment coverage.

    Returns:
        dict: UNKNOWN audit report containing an unconfirmed inventory draft.
        Discovery errors are retained; inactive and hidden runtimes need review.
    """
    try:
        runtimes, issues = discover(None)
    except (AuditError, OSError) as exc:
        runtimes, issues = [], [str(exc)]
    key = os.path.realpath if sys.platform == "darwin" else path_key
    paths = {(run.kind, key(run.path)): run.path for run in runtimes}
    draft = {"schema": 1, "scope": "REVIEW deployment scope", "coverage_confirmed": False,
             "runtimes": [{"label": kind + " " + path, "kind": kind, "path": path}
                          for (kind, _), path in sorted(paths.items())],
             "discovery_issues": issues,
             "review_required": "Add inactive, renamed and hidden deployments; confirm scope and coverage before auditing."}
    report = finish([], issues + ["Draft inventory requires operator review"],
                    diagnostics=[diagnostic("INVENTORY_UNCONFIRMED", draft["review_required"])] +
                    [diagnostic("DISCOVERY_INCOMPLETE", issue) for issue in issues])
    draft["metadata"] = report["metadata"]
    report["draft_inventory"] = draft
    return report


def remote_main(payload):
    try:
        require(sys.version_info >= (3, 9), "Python 3.9+ is required")
        result = draft_inventory() if payload.get("draft", False) else audit_local(
            payload["inventory"], payload["evidence"], payload.get("files", False))
    except (AuditError, OSError, ValueError, TypeError, EOFError, zlib.error) as exc:
        result = finish([], ["Remote audit failed: " + str(exc)], diagnostics=[error_diagnostic(exc)])
    result["token"] = payload["token"]
    print(json.dumps(result))
    return result["exit_status"]


def valid_remote_result(result, token, rc):
    """Check a remote envelope before trusting its verdict or rendering findings.

    Args:
        result (object): Decoded remote JSON.
        token (str): Expected per-run result token.
        rc (int): Transport process exit status.

    Returns:
        bool: Whether identity, field types, verdict and exit status are consistent.
    """
    if not isinstance(result, dict) or result.get("token") != token:
        return False
    if result.get("schema") != 1 or result.get("completed") is not True:
        return False
    if result.get("cves") != list(CVES) or result.get("mode") != "local":
        return False
    records, issues = result.get("runtimes"), result.get("issues")
    if not isinstance(records, list) or not isinstance(issues, list) or not all(isinstance(x, str) for x in issues):
        return False
    if not valid_diagnostics(result.get("diagnostics", [])):
        return False
    metadata = result.get("metadata")
    if (not isinstance(metadata, dict) or not isinstance(metadata.get("target"), dict)
            or not isinstance(metadata.get("timestamp_utc"), str)
            or not isinstance(metadata.get("tool_version"), str)
            or not isinstance(metadata.get("tool_sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", metadata["tool_sha256"])):
        return False
    for row in records:
        if (not isinstance(row, dict) or row.get("status") not in ("PATCHED", "AFFECTED", "UNKNOWN")
                or type(row.get("restart_needed")) is not bool or type(row.get("pid")) is not int
                or not isinstance(row.get("kind"), str) or row["kind"] not in KINDS
                or not isinstance(row.get("path"), str)
                or not valid_diagnostics(row.get("diagnostics", []))):
            return False
        if not valid_cve_results(row.get("cve_results"), row["kind"]):
            return False
        status = combine_statuses(r["status"] for r in row["cve_results"].values())
        if row["status"] != ("PATCHED" if status == "NOT_AFFECTED" else status):
            return False
        if "file_status" in row or "file_cve_results" in row:
            if (not valid_cve_results(row.get("file_cve_results"), row["kind"])
                    or row["pid"] <= 0 or any(r["status"] != "UNKNOWN" for r in row["cve_results"].values())):
                return False
            status = combine_statuses(r["status"] for r in row["file_cve_results"].values())
            if row.get("file_status") != ("PATCHED" if status == "NOT_AFFECTED" else status):
                return False
    expected = finish(records, issues)
    return (rc == result.get("exit_status") == expected["exit_status"]
            and result.get("verdict") == expected["verdict"] and result.get("cve_summary") == expected["cve_summary"])


def valid_cve_results(value, kind):
    return (isinstance(value, dict) and set(value) == set(artifact_cves(kind)) and all(
        isinstance(row, dict) and row.get("status") in ("PATCHED", "AFFECTED", "UNKNOWN", "NOT_AFFECTED")
        and isinstance(row.get("detail"), str) and isinstance(row.get("sources"), list)
        and all(isinstance(source, str) for source in row["sources"]) for row in value.values()))


def valid_diagnostics(value):
    """Validate remote findings before rendering their fields.

    Args:
        value (object): Untrusted decoded JSON diagnostics value.

    Returns:
        bool: Whether all entries have known codes and safely renderable fields.
    """
    return isinstance(value, list) and all(
        isinstance(row, dict) and isinstance(row.get("code"), str) and row["code"] in NEXT_STEPS
        and isinstance(row.get("detail"), str) and isinstance(row.get("next_step"), str)
        and isinstance(row.get("guidance"), list)
        and all(isinstance(url, str) and url.startswith("https://") for url in row["guidance"])
        for row in value)


def remote_program(inventory, evidence, files=False, draft=False):
    """Serialize this script and configuration for an authenticated transport.

    Args:
        inventory (dict | None): Target inventory.
        evidence (dict): Target evidence.
        files (bool): Select installed-file assessment.
        draft (bool): Discover an unconfirmed inventory instead of assessing files.

    Returns:
        tuple[str, str]: Per-run result token and Python source sent over stdin.

    Raises:
        OSError: This script cannot be read for transfer.
    """
    token = secrets.token_hex(24)
    payload = {"token": token, "inventory": inventory, "evidence": evidence, "files": files, "draft": draft}
    source_bytes = Path(__file__).read_bytes()
    source = source_bytes.decode("utf-8")
    # repr embeds data as Python string literals; no target/config enters shell code.
    source_hash = hashlib.sha256(source_bytes).hexdigest()
    program = "import json\nns={'__name__':'node2shell_remote','AUDIT_SOURCE_SHA256':" + repr(source_hash) + "}\n"
    program += "exec(compile(" + ascii(source) + ",'<audit>','exec'),ns)\n"
    program += "raise SystemExit(ns['remote_main'](json.loads(" + repr(json.dumps(payload)) + ")))\n"
    return token, program


def run_remote(argv, mode, target, inventory, evidence, files=False, draft=False):
    """Run and validate one remote audit or inventory export.

    Args:
        argv (list[str]): Trusted utility and validated transport arguments.
        mode (str): SSH or container transport name.
        target (str): Validated target identifier.
        inventory (dict | None): Target inventory.
        evidence (dict): Target evidence.
        files (bool): Select installed-file assessment.
        draft (bool): Request an unconfirmed inventory draft.

    Returns:
        dict: Validated target report, or an UNKNOWN transport-failure report.
    """
    token, program = remote_program(inventory, evidence, files, draft)
    run = None
    try:
        run = command(argv, timeout=120, data=program)
        result = json.loads(run.stdout)
        require(valid_remote_result(result, token, run.returncode), "Remote result missing, incomplete, or inconsistent")
        expected_metadata = report_metadata(inventory, evidence)
        require(all(result["metadata"].get(key) == expected_metadata[key]
                    for key in ("tool_sha256", "inventory_sha256", "evidence_sha256")) if not draft
                else result["metadata"].get("tool_sha256") == expected_metadata["tool_sha256"],
                "Remote tool/input fingerprints differ from this request")
        result.pop("token")
        require(result.get("assessment_scope") == ("installed-files-only" if files else None),
                "Remote result has the wrong assessment scope")
        if draft:
            candidate = result.get("draft_inventory")
            require(isinstance(candidate, dict) and candidate.get("coverage_confirmed") is False
                    and isinstance(candidate.get("runtimes"), list) and result["exit_status"] == 2,
                    "Remote inventory draft missing or incorrectly confirmed")
        result["mode"] = mode
        result["target"] = target
        return result
    except (AuditError, ValueError, TypeError) as exc:
        result = finish([], [mode + "/setup/audit failure: " + str(exc)], mode)
        if run is not None:
            result["issues"].append(f"Transport exit {run.returncode}; stderr: {run.stderr.strip()[:2000]}")
        result["target"] = target
        return result


def audit_ssh(host, sudo, inventory, evidence, files=False, remote_os="linux", python=None, draft=False):
    require(re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.@:\[\]-]*", host), "Invalid SSH destination")
    if remote_os == "windows":
        require(not sudo, "--sudo is not supported for Windows SSH")
        require(absolute_path(python) and re.match(r"^[A-Za-z]:", python)
                and python.lower().endswith(".exe"), "Windows SSH requires --remote-python with an absolute .exe path")
        script = "$source=[Console]::In.ReadToEnd(); $source | & '" + python.replace("'", "''") + "' -; exit $LASTEXITCODE"
        remote = "powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand " + base64.b64encode(script.encode("utf-16le")).decode("ascii")
    else:
        python = python or "/usr/bin/python3"
        require(absolute_path(python) and python.startswith("/"), "Remote Python must be an absolute POSIX path")
        remote = shlex.quote(python) + " -"
        if sudo:
            remote = "/usr/bin/sudo -n -- " + remote
    return run_remote([system_tool("ssh"), "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
                       "-o", "StrictHostKeyChecking=yes", "--", host, remote], "ssh", host, inventory, evidence, files, draft)


def audit_container(container, engine, inventory, evidence, files=False, python=None, draft=False):
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", container), "Invalid container name or ID")
    require(engine in ("docker", "podman"), "Unsupported container engine")
    python = python or "/usr/bin/python3"
    require(absolute_path(python) and python.startswith("/"), "Container Python must be an absolute POSIX path")
    return run_remote([system_tool(engine), "exec", "-i", container, python, "-"],
                      "container", container, inventory, evidence, files, draft)


def upstream_status(version):
    match = re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", version)
    if not match:
        return "UNKNOWN"
    parts = tuple(map(int, match.groups()))
    fixed = BASELINES.get(parts[0])
    if fixed is None:
        return "UNKNOWN"
    return "PATCHED" if parts >= fixed else "AFFECTED"


def upstream_cves(version):
    status = upstream_status(version)
    if status == "UNKNOWN":
        return {cve: "UNKNOWN" for cve in CVES}
    major = int(version.split(".")[0])
    return {cve: status if major in branches else "NOT_AFFECTED" for cve, branches in CVE_BRANCHES.items()}


def valid_cve_scope(value, kind, external=False):
    allowed = set(artifact_cves(kind)) - ({BROTLI_CVE} if external else set())
    return (isinstance(value, list) and bool(value) and all(isinstance(cve, str) and cve in allowed for cve in value)
            and len(value) == len(set(value)))


def validate_config(inventory, evidence):
    if inventory is not None:
        require(isinstance(inventory, dict) and type(inventory.get("schema")) is int
                and inventory["schema"] == 1, "Inventory must have schema=1")
        require(inventory.get("coverage_confirmed") is True
                and isinstance(inventory.get("scope"), str) and inventory["scope"].strip(),
                "Inventory requires scope and coverage_confirmed=true", "INVENTORY_UNCONFIRMED")
        require(isinstance(inventory.get("runtimes"), list) and inventory["runtimes"],
                "Inventory must contain expected artifacts")
        seen = set()
        for row in inventory["runtimes"]:
            require(isinstance(row, dict) and isinstance(row.get("kind"), str)
                    and row["kind"] in KINDS and absolute_path(row.get("path"))
                    and isinstance(row.get("label"), str) and row["label"].strip(),
                    "Each inventory artifact needs label, kind and absolute path")
            key = row["kind"], path_key(row["path"])
            require(key not in seen, "Duplicate inventory artifact")
            seen.add(key)
            exposure = row.get("exposure")
            if exposure is not None:
                require(isinstance(exposure, dict) and set(exposure) <= set(artifact_cves(row["kind"])),
                        "Exposure must be keyed by applicable CVE")
                for review in exposure.values():
                    require(isinstance(review, dict)
                            and review.get("reachability") in ("reachable", "not_observed", "unknown")
                            and isinstance(review.get("source"), str) and review["source"].strip(),
                            "Each CVE exposure needs reachability and a review source")
    require(isinstance(evidence, dict) and type(evidence.get("schema")) is int
            and evidence["schema"] == 1, "Evidence must have schema=1")
    require(set(evidence) <= {"schema", "builds", "vendor_fixes"}, "Unknown evidence field")
    for field in ("builds", "vendor_fixes"):
        require(isinstance(evidence.get(field, []), list), "Invalid evidence list: " + field)
    seen = set()
    for row in evidence.get("builds", []):
        require(isinstance(row, dict) and isinstance(row.get("sha256"), str)
                and re.fullmatch(r"[0-9a-f]{64}", row["sha256"]), "Invalid build SHA-256")
        require(isinstance(row.get("kind"), str) and row["kind"] in KINDS
                and isinstance(row.get("source"), str) and row["source"].strip(),
                "Build needs artifact kind and trusted source")
        require(row["sha256"] not in seen, "Duplicate build SHA-256")
        seen.add(row["sha256"])
        require(set(row) <= {"sha256", "kind", "source", "decoder", "node_version", "status", "cves"},
                "Unknown build field")
        if row["kind"] != "brotli":
            require(row.get("decoder") in ("bundled", "external"),
                    "Node/libnode evidence must establish bundled or external decoder linkage")
        else:
            require("decoder" not in row and "node_version" not in row, "Brotli needs CVE-specific evidence")
        external = row.get("decoder") == "external"
        if "status" in row:
            require(row["status"] in ("PATCHED", "AFFECTED")
                    and valid_cve_scope(row.get("cves"), row["kind"], external)
                    and "node_version" not in row, "Explicit build status needs applicable CVEs and no version rule")
        elif "node_version" in row or not external:
            require(row["kind"] != "brotli" and isinstance(row.get("node_version"), str)
                    and "cves" not in row, "Bundled Node build needs node_version or explicit CVE status")
        else:
            require("cves" not in row, "CVE coverage needs an explicit status")
    seen = set()
    for row in evidence.get("vendor_fixes", []):
        require(isinstance(row, dict), "Invalid vendor rule")
        for field in ("os_id", "os_version", "package", "fixed_version"):
            require(isinstance(row.get(field), str)
                    and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+:~^_-]*", row[field]),
                    "Invalid vendor field: " + field)
        require(isinstance(row.get("manager"), str) and row["manager"] in MANAGERS
                and isinstance(row.get("kind"), str) and row["kind"] in KINDS
                and valid_cve_scope(row.get("cves"), row["kind"], row.get("decoder") == "external"),
                "Vendor rule needs manager, kind and applicable CVEs")
        require(isinstance(row.get("sources"), list) and row["sources"]
                and all(isinstance(url, str) and url.startswith("https://") for url in row["sources"]),
                "Vendor rule needs HTTPS advisory sources")
        require((row["kind"] == "brotli" and "decoder" not in row)
                or (row["kind"] != "brotli" and row.get("decoder") in ("bundled", "external")),
                "Node package rules must establish decoder linkage")
        if row["manager"] == "rpm":
            require(all(isinstance(row.get(field), str) for field in ("arch", "vendor", "module"))
                    and row["arch"] and row["vendor"], "RPM rules require exact arch, vendor and module label")
        key = tuple(row[k] for k in ("os_id", "os_version", "manager", "package", "kind"))
        key += tuple(row.get(k) for k in ("arch", "vendor", "module"))
        for cve in row["cves"]:
            require((key, cve) not in seen, "Duplicate vendor rule for CVE")
            seen.add((key, cve))
        for other in evidence.get("vendor_fixes", []):
            if (isinstance(other, dict) and other.get("kind") == row["kind"] != "brotli"
                    and all(other.get(k) == row.get(k) for k in
                            ("os_id", "os_version", "manager", "package", "arch", "vendor", "module"))):
                require(other.get("decoder") == row.get("decoder"), "Conflicting vendor decoder linkage")


def executable_kind(path):
    name = ntpath.basename(path).lower()
    return "node" if re.fullmatch(r"(?:node|nodejs)(?:[0-9]+)?(?:\.exe)?", name) else None


def module_kind(path):
    name = ntpath.basename(path).lower()
    if re.fullmatch(r"(?:lib)?brotlidec(?:[-.][0-9]+)*(?:\.so(?:\.[0-9]+)*|\.dylib|\.dll)", name):
        return "brotli"
    if re.fullmatch(r"(?:lib)?node(?:[-.][0-9]+)*(?:\.so(?:\.[0-9]+)*|\.dylib|\.dll)", name):
        return "libnode"
    return None


def discover(inventory):
    if sys.platform == "win32":
        return discover_windows(inventory)
    if sys.platform == "darwin":
        return discover_macos(inventory)
    require(sys.platform.startswith("linux"), "Process discovery supports Linux, macOS and Windows; use --files elsewhere")
    expected = {row["path"]: row["kind"] for row in (inventory or {}).get("runtimes", [])}
    pids = sorted(int(p.name) for p in Path("/proc").iterdir() if p.name.isdigit())
    require(pids, "No visible processes")
    runtimes, issues = [], []
    for pid in pids:
        try:
            started = start_time(pid)
            try:
                exe, deleted = proc_path(os.readlink(f"/proc/{pid}/exe"))
            except FileNotFoundError:
                if not Path(f"/proc/{pid}/cmdline").read_bytes():
                    continue
                raise
            kind = expected.get(exe) or executable_kind(exe)
            info = os.stat(f"/proc/{pid}/exe")
            found = [Runtime(pid, kind, exe, f"/proc/{pid}/exe", started, deleted,
                             info.st_dev, info.st_ino)] if kind else []
            modules = []
            for line in Path(f"/proc/{pid}/maps").read_text().splitlines():
                fields = line.split(None, 5)
                if len(fields) != 6:
                    continue
                path, removed = proc_path(fields[5])
                module = expected.get(path) or module_kind(path)
                if module not in MODULE_KINDS:
                    continue
                device = os.makedev(*(int(part, 16) for part in fields[3].split(":")))
                if not any(r.path == path for r in modules):
                    modules.append(Runtime(pid, module, path, f"/proc/{pid}/map_files/{fields[0]}",
                                           started, removed, device, int(fields[4])))
            if kind or any(r.kind == "libnode" or r.path in expected for r in modules):
                found.extend(modules)
            if not found:
                continue
            require(same_namespace(pid), f"PID {pid}: different mount/root namespace; audit inside it")
            require(start_time(pid) == started, f"PID {pid}: process changed during discovery")
            runtimes.extend(found)
        except FileNotFoundError:
            if Path(f"/proc/{pid}").exists():
                issues.append(f"PID {pid}: incomplete process inspection")
        except (OSError, ValueError, IndexError, AuditError) as exc:
            issues.append(f"PID {pid}: executable/module inspection incomplete: {exc}")
    return runtimes, issues


WINDOWS_DISCOVERY = r'''
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$expected = [Console]::In.ReadToEnd() | ConvertFrom-Json
$processes = @(); $issues = @()
foreach ($process in @(Get-Process)) {
    if ($process.Id -in @(0, 4, $PID)) { continue }
    try {
        $started = $process.StartTime.ToUniversalTime().Ticks.ToString()
        $path = $process.MainModule.FileName
        if (-not $path) { throw 'Executable path unavailable' }
        $modules = @()
        foreach ($module in @($process.Modules)) {
            if ($module.ModuleName -match '^(lib)?(node|brotlidec)([-.][0-9]+)*\.(dll|so)$' -or
                $module.FileName -in $expected) { $modules += @{path=$module.FileName} }
        }
        $current = Get-Process -Id $process.Id
        if ($current.StartTime.ToUniversalTime().Ticks.ToString() -ne $started) { throw 'PID reused' }
        $processes += @{pid=$process.Id; start=$started; path=$path; modules=$modules}
    } catch { $issues += "PID $($process.Id): cannot inspect executable/modules: $($_.Exception.Message)" }
}
@{processes=$processes; issues=$issues} | ConvertTo-Json -Depth 6 -Compress
'''


def discover_windows(inventory):
    expected = {path_key(row["path"]): row["kind"] for row in (inventory or {}).get("runtimes", [])}
    snapshot = powershell_json(WINDOWS_DISCOVERY, list(expected))
    require(isinstance(snapshot, dict) and isinstance(snapshot.get("processes"), list)
            and isinstance(snapshot.get("issues"), list)
            and all(isinstance(x, str) for x in snapshot["issues"]), "Malformed Windows snapshot")
    runtimes = []
    for process in snapshot["processes"]:
        require(isinstance(process, dict) and type(process.get("pid")) is int and process["pid"] > 0
                and absolute_path(process.get("path")) and isinstance(process.get("start"), str)
                and isinstance(process.get("modules"), list), "Malformed Windows process")
        path = process["path"]
        kind = expected.get(path_key(path)) or executable_kind(path)
        found = [Runtime(process["pid"], kind, path, path, process["start"])] if kind else []
        modules = []
        for module in process["modules"]:
            require(isinstance(module, dict) and absolute_path(module.get("path")), "Malformed Windows module")
            path = module["path"]
            component = expected.get(path_key(path)) or module_kind(path)
            if component in MODULE_KINDS and not any(path_key(r.path) == path_key(path) for r in modules):
                modules.append(Runtime(process["pid"], component, path, path, process["start"]))
        if kind or any(r.kind == "libnode" or path_key(r.path) in expected for r in modules):
            found.extend(modules)
        runtimes.extend(found)
    return runtimes, snapshot["issues"]


def discover_macos(inventory):
    api = MacOSProcesses()
    expected = {os.path.realpath(row["path"]): row["kind"] for row in (inventory or {}).get("runtimes", [])}
    runtimes, issues = [], []
    for pid in api.pids():
        try:
            started = api.identity(pid)
            exe = api.executable(pid)
            kind = expected.get(os.path.realpath(exe)) or executable_kind(exe)
            mappings = api.mappings(pid)
            found, modules = [], []
            for item in mappings:
                path = item["path"]
                component = expected.get(os.path.realpath(path)) or module_kind(path)
                if path == exe and kind:
                    component = kind
                if component:
                    row = Runtime(pid, component, path, path, started, item["nlink"] == 0,
                                  item["device"], item["inode"])
                    (found if path == exe else modules).append(row)
            if kind or any(r.kind == "libnode" or os.path.realpath(r.path) in expected for r in modules):
                found.extend(modules)
            if kind and not any(r.path == exe for r in found):
                found.append(Runtime(pid, kind, exe, exe, started))
                issues.append(f"PID {pid}: executable mapping unavailable")
            require(api.identity(pid) == started, "Process changed during discovery")
            runtimes.extend(found)
        except ProcessLookupError:
            continue
        except (OSError, AuditError) as exc:
            issues.append(f"PID {pid}: macOS inspection incomplete: {exc}")
    return runtimes, issues


def package_metadata(path):
    require(sys.platform.startswith("linux"), "Use SHA-256 build evidence on this platform", "EVIDENCE_MISSING")
    if Path("/var/lib/dpkg/status").is_file():
        return dpkg_metadata(path)
    if Path("/lib/apk/db/installed").is_file():
        return apk_metadata(path)
    if Path("/var/lib/pacman/local").is_dir():
        return pacman_metadata(path)
    if any(Path(p).is_dir() for p in ("/var/lib/rpm", "/usr/lib/sysimage/rpm")):
        return rpm_metadata(path)
    raise AuditError("No supported package database; use SHA-256 build provenance", "EVIDENCE_MISSING")


def fixed_rule(package, distro, evidence, kind, cve=BROTLI_CVE):
    for rule in evidence.get("vendor_fixes", []):
        if cve not in rule["cves"]:
            continue
        if (rule["os_id"], rule["os_version"], rule["manager"], rule["package"], rule["kind"]) != (
                *distro, package["manager"], package["package"], kind):
            continue
        if package["manager"] == "rpm" and any(rule[k] != package.get(k) for k in ("arch", "vendor", "module")):
            continue
        return rule
    if (cve == BROTLI_CVE and kind == "brotli" and distro[0] == "debian" and package["manager"] == "dpkg"
            and package["package"] == "libbrotli1" and distro[1] in ("12", "13")):
        return {"fixed_version": {"12": "1.0.9-2+deb12u1", "13": "1.1.0-2+deb13u1"}[distro[1]],
                "sources": [DEBIAN_BROTLI_ADVISORY], "verified_at": "2026-10-24"}
    raise AuditError("No exact vendor advisory rule for " + cve, "VENDOR_RULE_MISSING")


def assess_file(record, hashes, distro, evidence):
    record["cve_results"] = unknown_cves(record["kind"])
    record["sha256"] = hashes["sha256"]
    build = next((row for row in evidence.get("builds", []) if row["sha256"] == hashes["sha256"]), None)
    if build:
        require(build["kind"] == record["kind"], "Build evidence artifact kind mismatch", "EVIDENCE_MISMATCH")
        record.update(source=build["source"], detail="SHA-256 matches operator-trusted build provenance")
        if build.get("decoder") == "external":
            record.update(decoder="external", detail="Build provenance delegates decoding to a loaded library")
        if "node_version" in build:
            record["node_version"] = build["node_version"]
            for cve, status in upstream_cves(build["node_version"]).items():
                if cve != BROTLI_CVE or build.get("decoder") != "external":
                    set_cve_result(record, cve, status, "Trusted build matches upstream advisory branch scope",
                                   [build["source"], ADVISORY])
        elif "status" in build:
            for cve in build["cves"]:
                set_cve_result(record, cve, build["status"], "Explicit CVE evidence for these artifact bytes", [build["source"]])
        refresh_assessment(record)
        return
    package = package_metadata(record["path"])
    record.update(package=package["package"], package_version=package["version"], manager=package["manager"])
    require(hashes[package["algorithm"]] == package["digest"],
            "File differs from installed package checksum", "EVIDENCE_MISMATCH")
    require(distro is not None, "OS release unavailable for vendor comparison")
    # Debian's advisory explicitly identifies these Node branches as using system Brotli.
    if (distro[0] == "debian" and package["manager"] == "dpkg"
            and record["kind"] in ("node", "libnode")
            and ((distro[1] == "12" and package["package"] in ("nodejs", "libnode108")
                  and package["version"].startswith("18."))
                 or (distro[1] == "13" and package["package"] in ("nodejs", "libnode115")
                     and package["version"].startswith("20.")))):
        record.update(decoder="external", source=DEBIAN_BROTLI_ADVISORY,
                      detail="Verified Debian artifact uses system Brotli; loaded decoder must be assessed")
    rules = {}
    for cve in artifact_cves(record["kind"]):
        try:
            rule = fixed_rule(package, distro, evidence, record["kind"], cve)
            if record["kind"] != "brotli":
                require(record.get("decoder", rule["decoder"]) == rule["decoder"], "Vendor linkage contradicts build evidence")
                record["decoder"] = rule["decoder"]
            rules[cve] = rule
        except AuditError as exc:
            set_cve_result(record, cve, "UNKNOWN", str(exc))
    for cve, rule in rules.items():
        if cve == BROTLI_CVE and record.get("decoder") == "external":
            continue
        try:
            status = package_status(package, rule["fixed_version"])
            set_cve_result(record, cve, status, "File checksum and vendor scope match; fixed package " + rule["fixed_version"],
                           rule["sources"])
        except AuditError as exc:
            set_cve_result(record, cve, "UNKNOWN", str(exc), rule["sources"])
    record["detail"] = "Package identity verified; each CVE requires its own applicable vendor evidence"
    refresh_assessment(record)


def resolve_decoders(records):
    for kind in ("libnode", "node"):
        for row in records:
            if row["kind"] != kind or row.get("decoder") != "external":
                continue
            dependencies = [r for r in records if r["pid"] == row["pid"] and r is not row
                            and (r["kind"] == "brotli" or (kind == "node" and r["kind"] == "libnode"))]
            if row["pid"] <= 0 or sys.platform == "win32" or not dependencies:
                set_cve_result(row, BROTLI_CVE, "UNKNOWN", "No verified loaded decoder identity")
                row["diagnostics"] = [diagnostic("DECODER_UNRESOLVED", "No verified loaded decoder identity")]
                continue
            row["decoder_artifacts"] = [r["path"] for r in dependencies]
            statuses = []
            sources = []
            for dependency in dependencies:
                result = dependency.get("cve_results", {}).get(BROTLI_CVE, {})
                status = result.get("status", "UNKNOWN")
                statuses.append("UNKNOWN" if dependency["restart_needed"] and status == "PATCHED" else status)
                sources.extend(result.get("sources", []))
            set_cve_result(row, BROTLI_CVE, combine_statuses(statuses),
                           "Brotli assessment follows same-process library evidence", list(dict.fromkeys(sources)))
            row["restart_needed"] |= any(r["restart_needed"] for r in dependencies)
            row["detail"] = "External Brotli assessed separately from Node's other CVEs"
            row["diagnostics"] = []
            explain_record(row, None)


def attach_exposure(records, inventory):
    key = os.path.realpath if sys.platform == "darwin" else path_key
    configured = {(r["kind"], key(r["path"])): r for r in (inventory or {}).get("runtimes", [])}
    for row in records:
        entry = configured.get((row["kind"], key(row["path"])), {})
        row["label"] = entry.get("label", row["path"])
        row["exposure"] = entry.get("exposure", {})
        for cve, result in row["cve_results"].items():
            review = row["exposure"].get(cve, {"reachability": "unknown", "source": "Not reviewed"})
            result["exposure"] = review
            result["exploitability"] = ("POTENTIALLY_EXPLOITABLE" if row["pid"] > 0 and result["status"] == "AFFECTED"
                                        and review["reachability"] == "reachable" else "NOT_ESTABLISHED")
        row["exploitability"] = ("POTENTIALLY_EXPLOITABLE" if any(
            result["exploitability"] == "POTENTIALLY_EXPLOITABLE" for result in row["cve_results"].values()) else "NOT_ESTABLISHED")


def audit_local(inventory, evidence, files=False):
    validate_config(inventory, evidence)
    metadata = report_metadata(inventory, evidence)
    key = os.path.realpath if sys.platform == "darwin" else path_key
    if inventory:
        keys = {(r["kind"], key(r["path"])) for r in inventory["runtimes"]}
        require(len(keys) == len(inventory["runtimes"]), "Duplicate inventory path aliases")
    try:
        distro = os_release()
    except (OSError, AuditError):
        distro = None
    if files:
        require(inventory is not None, "--files requires inventory")
        records = [inspect_file(row, distro, evidence) for row in inventory["runtimes"]]
        attach_exposure(records, inventory)
        report = finish(records, [], scope=inventory["scope"], metadata=metadata)
        report["assessment_scope"] = "installed-files-only"
        report["limitations"] = ["Installed-file evidence does not establish loaded images or live exploitability"]
        return report
    try:
        runtimes, issues = discover(inventory)
    except (OSError, AuditError) as exc:
        return finish([], [str(exc)], diagnostics=[error_diagnostic(exc)], metadata=metadata)
    diagnostics = [diagnostic("DISCOVERY_INCOMPLETE", issue) for issue in issues]
    if inventory is None:
        issues.append("No confirmed inventory: discovery cannot prove deployment coverage")
        diagnostics.append(diagnostic("INVENTORY_UNCONFIRMED", issues[-1]))
    else:
        expected = {(r["kind"], key(r["path"])) for r in inventory["runtimes"]}
        observed = {(r.kind, key(r.path)) for r in runtimes}
        for code, entries in (("EXPECTED_RUNTIME_MISSING", expected - observed),
                              ("UNEXPECTED_RUNTIME", observed - expected)):
            for kind, path in sorted(entries):
                issues.append(f"{code}: {kind} {path}")
                diagnostics.append(diagnostic(code, issues[-1]))
    records = [inspect_runtime(runtime, distro, evidence) for runtime in runtimes]
    resolve_decoders(records)
    attach_exposure(records, inventory)
    return finish(records, issues, scope=(inventory or {}).get("scope"), diagnostics=diagnostics, metadata=metadata)


def audit_probe(path):
    report = finish([], ["Executed version is a hint, not loaded-image or decoder proof"], "probe")
    report["target"] = path
    require(absolute_path(path) and Path(path).is_absolute(), "Probe needs an absolute trusted binary path")
    require(sys.platform != "win32" or path.lower().endswith(".exe"), "Windows probe needs an .exe")
    before = hash_file(path)["sha256"]
    run = command([path, "--version"])
    require(run.returncode == 0, "Node version probe failed")
    require(hash_file(path)["sha256"] == before, "Binary changed during probe")
    version = run.stdout.strip().removeprefix("v")
    report.update(sha256=before, version_hints=[{"version": version, "upstream_comparison": upstream_status(version),
                                               "cve_comparisons": upstream_cves(version)}])
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    target = parser.add_mutually_exclusive_group()
    target.add_argument("--ssh", metavar="USER@HOST")
    target.add_argument("--container", metavar="NAME_OR_ID")
    target.add_argument("--probe-node", metavar="TRUSTED_BINARY", help="Opt-in execution of --version; hints only")
    parser.add_argument("--sudo", action="store_true", help="Noninteractive remote sudo")
    parser.add_argument("--engine", choices=("docker", "podman"), default="docker")
    parser.add_argument("--remote-os", choices=("linux", "macos", "windows"), default="linux")
    parser.add_argument("--remote-python", help="Absolute target Python path; required for Windows SSH")
    parser.add_argument("--inventory", help="Reviewed deployment inventory JSON")
    parser.add_argument("--evidence", help="Trusted build/vendor evidence JSON")
    parser.add_argument("--files", action="store_true", help="Assess only explicitly listed installed files")
    parser.add_argument("--draft-inventory", action="store_true", help="Print an unconfirmed draft, always exit 2")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        require(sys.version_info >= (3, 9), "Python 3.9+ is required")
        require(not args.sudo or args.ssh, "--sudo requires SSH")
        require(not args.remote_python or args.ssh or args.container, "--remote-python requires a remote target")
        require(args.remote_os == "linux" or args.ssh, "--remote-os requires SSH")
        require(not args.files or args.inventory, "--files requires inventory")
        require(not args.draft_inventory or not any((args.inventory, args.evidence, args.files, args.probe_node)),
                "--draft-inventory requires discovery only")
        require(not args.probe_node or not any((args.inventory, args.evidence, args.files)),
                "Probe mode cannot consume inventory/evidence")
        inventory = load_json(args.inventory) if args.inventory else None
        evidence = load_json(args.evidence) if args.evidence else {"schema": 1}
        validate_config(inventory, evidence)
        if args.ssh:
            report = audit_ssh(args.ssh, args.sudo, inventory, evidence, args.files,
                               args.remote_os, args.remote_python, args.draft_inventory)
        elif args.container:
            report = audit_container(args.container, args.engine, inventory, evidence,
                                     args.files, args.remote_python, args.draft_inventory)
        elif args.probe_node:
            report = audit_probe(args.probe_node)
        else:
            report = draft_inventory() if args.draft_inventory else audit_local(inventory, evidence, args.files)
    except (AuditError, OSError, ValueError, TypeError, EOFError, zlib.error) as exc:
        report = finish([], [str(exc)], diagnostics=[error_diagnostic(exc)])
    if args.draft_inventory and "draft_inventory" in report:
        print(json.dumps(report["draft_inventory"], indent=2))
    elif args.json:
        print(json.dumps({"schema": 1, "exit_status": report["exit_status"], "reports": [report]}, indent=2))
    else:
        print(f'[{report["verdict"]}] ' + json.dumps(report.get("target", report.get("scope") or "local namespace")))
        if report.get("assessment_scope"):
            print("  Scope: " + report["assessment_scope"])
        for row in report["runtimes"]:
            print(f'  {row["status"]}: PID {row["pid"]} {row["kind"]} ' + json.dumps(row["path"]))
            print("    " + json.dumps(row.get("detail", "")))
            if "file_status" in row:
                print("    Installed file: " + row["file_status"] + "; loaded image unverified")
            if row.get("exploitability") == "POTENTIALLY_EXPLOITABLE":
                print("    POTENTIALLY_EXPLOITABLE: affected CVE and operator-reviewed reachable conditions")
            for cve, result in row["cve_results"].items():
                print("    " + cve + ": " + result["status"] + "; " + json.dumps(result["detail"]))
            for cve, result in row.get("file_cve_results", {}).items():
                print("    Installed file " + cve + ": " + result["status"])
            for finding in row.get("diagnostics", []):
                print("    " + finding["code"] + ": " + json.dumps(finding["next_step"]))
        for issue in report["issues"]:
            print("  " + json.dumps(issue))
        for hint in report.get("version_hints", []):
            print("  Version hint: " + json.dumps(hint))
    return report["exit_status"]


if __name__ == "__main__":
    raise SystemExit(main())
