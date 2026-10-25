#!/usr/bin/env python3
"""Create build evidence from an official Node.js archive, without running or extracting it."""
import argparse
import gzip
import hashlib
import io
import json
import re
import stat
import tarfile
import tempfile
import urllib.request
import zipfile

LIMIT = 512 * 1024 * 1024
PLATFORMS = ("linux-x64", "linux-arm64", "darwin-x64", "darwin-arm64", "win-x64", "win-arm64", "win-x86")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("Unexpected redirect from official release URL")


def download(url, stream, limit):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    count = 0
    digest = hashlib.sha256()
    with opener.open(url, timeout=30) as response:
        while True:
            block = response.read(min(1024 * 1024, limit - count + 1))
            if not block:
                break
            count += len(block)
            if count > limit:
                raise ValueError("Release download exceeds size limit")
            digest.update(block)
            stream.write(block)
    stream.seek(0)
    return digest.hexdigest()


class BoundedReader:
    def __init__(self, stream):
        self.stream, self.total = stream, 0

    def read(self, size=-1):
        block = self.stream.read(min(size if size >= 0 else LIMIT + 1, LIMIT - self.total + 1))
        self.total += len(block)
        if self.total > LIMIT:
            raise ValueError("Expanded release archive exceeds size limit")
        return block


def digest_stream(stream):
    digest, size = hashlib.sha256(), 0
    for block in iter(lambda: stream.read(1024 * 1024), b""):
        size += len(block)
        if size > LIMIT:
            raise ValueError("Node artifact exceeds size limit")
        digest.update(block)
    if not size:
        raise ValueError("Node artifact is empty")
    return digest.hexdigest()


def artifact_digest(stream, prefix, windows=False):
    wanted = prefix + ("/node.exe" if windows else "/bin/node")
    matches = []
    if windows:
        with zipfile.ZipFile(stream) as archive:
            if sum(item.file_size for item in archive.infolist()) > LIMIT:
                raise ValueError("Expanded release archive exceeds size limit")
            for item in archive.infolist():
                if item.filename == wanted:
                    mode = item.external_attr >> 16
                    if item.is_dir() or stat.S_ISLNK(mode):
                        raise ValueError("Node artifact is not a regular file")
                    with archive.open(item) as member:
                        matches.append(digest_stream(member))
    else:
        with gzip.GzipFile(fileobj=stream) as expanded:
            with tarfile.open(fileobj=BoundedReader(expanded), mode="r|") as archive:
                for item in archive:
                    if item.name == wanted:
                        if not item.isfile() or not 0 < item.size <= LIMIT:
                            raise ValueError("Node artifact is not a regular bounded file")
                        with archive.extractfile(item) as member:
                            matches.append(digest_stream(member))
    if len(matches) != 1:
        raise ValueError("Archive must contain exactly one expected Node artifact")
    return matches[0]


def release_evidence(version, platform):
    if not re.fullmatch(r"(?:22|24|26)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", version) or platform not in PLATFORMS:
        raise ValueError("Choose a stable 22.x, 24.x or 26.x version and supported platform")
    prefix = f"node-v{version}-{platform}"
    name = prefix + (".zip" if platform.startswith("win-") else ".tar.gz")
    base = f"https://nodejs.org/dist/v{version}/"
    manifest = io.BytesIO()
    download(base + "SHASUMS256.txt", manifest, 1024 * 1024)
    digests = [line.split()[0] for line in manifest.getvalue().decode("ascii").splitlines()
               if len(line.split()) == 2 and line.split()[1] == name]
    if len(digests) != 1 or not re.fullmatch(r"[0-9a-f]{64}", digests[0]):
        raise ValueError("Official manifest has no unique archive checksum")
    with tempfile.TemporaryFile() as archive:
        if download(base + name, archive, LIMIT) != digests[0]:
            raise ValueError("Official archive checksum mismatch")
        sha256 = artifact_digest(archive, prefix, platform.startswith("win-"))
    return {"schema": 1, "builds": [{"sha256": sha256, "kind": "node", "decoder": "bundled",
                                    "node_version": version,
                                    "source": f"{base}{name}; HTTPS SHASUMS256.txt sha256={digests[0]}"}]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--platform", required=True, choices=PLATFORMS)
    args = parser.parse_args(argv)
    try:
        result = release_evidence(args.version, args.platform)
    except (OSError, ValueError, tarfile.TarError, zipfile.BadZipFile, EOFError) as exc:
        parser.exit(2, f"Release evidence failed: {exc}\n")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
