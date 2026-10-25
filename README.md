# Node2Shell patch audit

Read-only audit for **all ten named CVEs in Node's October 2026 security advisory**,
including the Brotli vulnerability known as Node2Shell. Identifies running Node
executables, embedded `libnode` and loaded Brotli decoder libraries; checks artifact
identity against trusted build or vendor evidence; and reports each CVE separately.
Unresolved evidence remains `UNKNOWN`.

Supports Linux, macOS and Windows discovery, installed-file checks, SSH, and
Docker/Podman container inspection. Python **3.9+**, standard library only.
Windows discovery uses Windows PowerShell. Nothing is installed on targets.

**An affected runtime is not proof of an exploitable application.** Each CVE has
its own prerequisites. The audit records application exposure per CVE and can flag
`POTENTIALLY_EXPLOITABLE` when that same CVE is affected and its prerequisites have
operator-reviewed reachability evidence. This does not imply code execution;
the advisory also covers validation bypasses, information disclosure and other impacts.

The auditor performs no patching, restarts, service changes, HTTP probes or malformed Brotli payloads.
The default audit reads files without executing Node. The explicit `--probe-node`
option runs a selected trusted binary with `--version`, producing hints only.

## Advisory and fixed versions

The [Node.js October 2026 advisory](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases)
defines the following scope. Branch applicability comes from its explicit affected
branch statements; omissions in shorter release changelogs do not establish safety.

| CVE | Issue and exposure conditions to review | Affected supported branches |
| --- | --- | --- |
| CVE-2026-105482 | NUL truncation in `dns.resolve*()`/`dns.reverse()`; validated hostnames subsequently resolved with those APIs. | 22, 24, 26 |
| CVE-2026-105483 | TLS IP verification bypass with fullwidth/non-ASCII host spellings. | 24, 26 |
| CVE-2026-106069 | TLS verification/resolver disagreement on leading-zero IPv4 literals; platform resolver behavior matters. | 22, 24, 26 |
| CVE-2026-111497 | Brotli decoder memory corruption; attacker-controlled compressed input reaches decompression. | 22, 24, 26 |
| CVE-2026-105481 | HTTP Agent reuse accepts an unsolicited response queued before a new request. | 22, 24, 26 |
| CVE-2026-106072 | TLS accepts DNS SANs for non-canonical IPv4 endpoints; trusted numeric DNS certificate and compatible resolver required. | 22, 24, 26 |
| CVE-2026-106074 | Crypto entropy caches repeat across startup snapshots/SEAs when populated during snapshot creation. | 22, 24, 26 |
| CVE-2026-106070 | `zlib.ZipFile` retains an invalid local header and can return attacker-selected prefix bytes. | 26 |
| CVE-2026-106071 | Permission Model wildcard radix lookup over-grants shorter filesystem paths. | 26 |
| CVE-2026-106073 | Permission Model omits checks in `fs.realpathSync()`. | 22, 24, 26 |

The fixed upstream release boundaries for the applicable CVEs are:

| Branch | First fixed release |
| --- | --- |
| 22.x | [22.23.4](https://nodejs.org/en/blog/release/v22.23.4/) |
| 24.x | [24.22.1](https://nodejs.org/en/blog/release/v24.22.1/) |
| 26.x | [26.12.1](https://nodejs.org/en/blog/release/v26.12.1/) |

These comparisons apply to SHA-256-identified, trusted upstream-equivalent builds.
They are not vendor package thresholds. EOL branches, other major versions,
prereleases and vendor suffixes remain `UNKNOWN` without explicit CVE evidence.
An unknown or EOL version is not safe. With trusted version evidence, a listed
supported branch outside a CVE's affected scope returns `NOT_AFFECTED` for that CVE.

The release also updates c-ares, CA certificates (including the eMudhra incident),
OpenSSL, SQLite and Undici, with branch-specific applicability. Installing the
complete official security release includes its bundled dependency changes. The
auditor's individual CVE results cover the ten identifiers above; it does not
independently inventory every externally linked dependency or system trust store.
Custom/vendor builds need their supplier's evidence for those additional updates.

Distribution builds can use a shared Brotli library.
[Debian's tracker](https://security-tracker.debian.org/tracker/CVE-2026-111497)
explicitly documents this arrangement. The built-in Debian rules cover:

| Exact OS | Verified decoder package | Fixed package revision |
| --- | --- | --- |
| Debian 12 | `libbrotli1` | `1.0.9-2+deb12u1` |
| Debian 13 | `libbrotli1` | `1.1.0-2+deb13u1` |

The corresponding Debian 12 Node 18 (`nodejs`, `libnode108`) and Debian 13 Node 20
(`nodejs`, `libnode115`) artifacts delegate **only their Brotli CVE assessment** to
verified libraries loaded by the same process. Other CVEs require independent Node
package/build evidence and remain unknown without it. A patched library installed
on disk does not clear a worker using an old mapping. Rules were checked on
**2026-10-24**; derivatives do not inherit Debian rules.

## Quick start

```sh
# Discover candidate paths; this outputs an UNCONFIRMED draft and exits 2.
python3 node2shell-audit.py --draft-inventory > inventory.draft.json

# Discovery on a remote Linux host. Existing SSH host trust and credentials required.
python3 node2shell-audit.py --ssh auditor@host --sudo --draft-inventory > inventory.draft.json

# After reviewing inventory and supplying trusted artifact evidence:
python3 node2shell-audit.py --inventory inventory.json --evidence evidence.json --json

# Audit the actual remote workers, with target-specific inventory paths.
python3 node2shell-audit.py --ssh auditor@host --sudo \
  --inventory inventory.json --evidence evidence.json --json > report.json

# Audit an already-running container with Python available inside it.
python3 node2shell-audit.py --container api-1 \
  --inventory inventory.json --evidence evidence.json --json

# Explicitly assess listed files, including inactive installations.
python3 node2shell-audit.py --files --inventory inventory.json --evidence evidence.json --json
```

Without a confirmed inventory, discovery still reports any identified affected
artifacts but cannot clear a host. To prepare an inventory, review the draft's
`discovery_issues`, add missing deployments and change `coverage_confirmed` to
`true` only when the scope is actually accounted for. Check renamed executables,
PM2/cluster workers, nvm/mise/Volta installations, bundled applications, containers,
chroots and inactive images. List every discovered `node`, `libnode` and `brotli`
artifact. Multiple workers using the same path need only one inventory entry.
Do not assume the default shell's Node is the service's Node.

The [POSIX example](inventory.example.json) and
[Windows example](inventory.windows.example.json) intentionally start unconfirmed.
An invalid configuration exits 2 with a diagnostic.

### Result meanings

| Exit | Verdict | Meaning |
| --- | --- | --- |
| 0 | `PATCHED` | All ten CVEs have fixed/not-affected evidence across the assessed Node artifacts, inventory coverage is confirmed, and no inspection/restart uncertainty remains. |
| 1 | `AFFECTED` | At least one assessed artifact matches affected evidence. Other unknowns and coverage gaps remain in the report. |
| 2 | `UNKNOWN` | Evidence, access, identity or coverage is incomplete; also used for discovery drafts and probe-only results. |

`--files` always labels the report `installed-files-only`. Its verdict covers only
the listed files, never running workers. A missing/inaccessible process, failed
transport, unknown build, changed file, unresolved decoder or missing expected
artifact cannot become a successful clearance.

Windows running records always retain `status: UNKNOWN`, with a separate
`file_status` and `file_cve_results` for the observed pathname. A loaded Windows image is not verified
by hashing the current disk file. Review affected `file_status` values as well as
the aggregate verdict; use `--files` for explicit installed-file assessments.

JSON includes the target platform, UTC timestamp, audit source SHA-256, input
fingerprints, runtime paths/PIDs, artifact digests, evidence sources, diagnostics,
restart flags and exposure assertions. It omits command-line arguments and process
environments. Treat reports and inventories as internal operational data.

Each artifact has `cve_results` containing status, explanation and evidence sources
per applicable CVE. Reports include `cve_summary` across the assessed artifacts.
`NOT_AFFECTED` requires verified upstream branch evidence; missing evidence remains
`UNKNOWN`. A standalone Brotli library covers only CVE-2026-111497. Its record can
be patched while the report remains unknown for the nine unassessed Node CVEs.

## Build evidence

### Official release archives

Generate evidence once on the controller for the **actual version and platform
being assessed**, then reuse it for identical binary bytes across the fleet:

```sh
python3 release_evidence.py --version 24.22.0 --platform linux-x64 > affected-build.json
python3 release_evidence.py --version 24.22.1 --platform linux-x64 > fixed-build.json
```

The helper fetches `SHASUMS256.txt` and the selected archive directly from
`https://nodejs.org/dist/`, verifies the archive checksum, and hashes its Node
executable without extracting or executing it. Downloads and archive expansion
are bounded to 512 MiB. Redirects and environment HTTP proxies are disabled.
Trust is HTTPS to Node's release service; **PGP signatures are not verified**.
For environments requiring signed provenance, verify release signatures through
your release process using [Node's binary-verification instructions](https://github.com/nodejs/node#verifying-binaries)
and supply the resulting trusted build record.

Supported archive targets: `linux-x64`, `linux-arm64`, `darwin-x64`, `darwin-arm64`,
`win-x64`, `win-arm64`, `win-x86`. Other architectures can supply build evidence
directly. The helper does not install Node and the auditor never fetches releases.
Combine records from multiple generated files into one `builds` array when a host
runs several versions. Duplicate SHA-256 records are rejected.

### Custom builds, Homebrew, MacPorts, embedded runtimes and backports

An evidence file has `schema: 1` and optional `builds` and `vendor_fixes` arrays.
Every build record needs `sha256` (64 lowercase hex characters), `kind` and a
nonempty `source` identifying trusted build/advisory provenance. The hash is of the
actual executable/library bytes, not a version string, archive or image tag.

For a bundled official-equivalent Node build:

```json
{
  "schema": 1,
  "builds": [{
    "sha256": "REPLACE_WITH_VERIFIED_BINARY_SHA256",
    "kind": "node",
    "decoder": "bundled",
    "node_version": "24.22.1",
    "source": "Trusted build record proving this exact binary uses the upstream bundled decoder"
  }]
}
```

For a backport or a standalone Brotli decoder, replace `node_version` with
`"status": "PATCHED"` (or `"AFFECTED"`) and `"cves": ["CVE-2026-111497"]`.
Use `kind: "brotli"` for a decoder library and omit `decoder`; `kind: "libnode"`
describes an embedded Node shared library. Never turn a locally computed hash
into a patch assertion without independent provenance for the corresponding bytes.
The `cves` list must name exactly the CVEs supported by that evidence. Unlisted
CVEs stay unknown; a Brotli library cannot assert fixes for Node's other CVEs.
To clear a complete backported Node build, provide evidence covering all ten.

For a Node/libnode build proven to delegate decoding externally, use
`"decoder": "external"`. Without version/status evidence this establishes linkage
only. A trusted `node_version` can establish the core CVE results, or `status` plus
`cves` can cover an explicit subset of core fixes. Neither can clear the external
Brotli decoder: its CVE still needs verified same-process library evidence.
A file-only audit cannot resolve external linkage.
If a platform uses renamed or unusually named libraries, inventory them explicitly.

### Vendor backports

Linux supports installed file checksums and native version comparison for
**dpkg, RPM, APK and pacman**. A checksum mismatch blocks package-based clearance.
APK currently supports installed-file `Q1` checksums; other encodings remain unknown.

Each `vendor_fixes` entry requires `os_id`, `os_version`, `manager`, `package`,
`kind`, `fixed_version`, a nonempty `cves` list, and nonempty HTTPS `sources`.
Rules with distinct CVE sets may use different fixed package revisions. Overlapping
rules for the same package/CVE scope are rejected. Node/libnode rules also need
`decoder: "bundled"` or `"external"`; external rules may cover core CVEs only.
RPM additionally requires exact `arch`, `vendor` and `module`
metadata; an empty module string means explicitly non-modular, not unavailable.
The comparator runs the system package manager, never a lexicographic or generic
SemVer comparison. Rules apply only to the exact OS release and binary package.

There are no built-in Ubuntu, RHEL, Alpine or Arch fix thresholds. Supply a verified
vendor rule or SHA-256 build record. For a custom dynamically linked build on those
systems, use linkage evidence for Node/libnode and CVE evidence for the decoder.
Homebrew/MacPorts receipts and Windows version resources alone cannot clear files;
use trusted build records. NixOS, Gentoo, Slackware and other unsupported package
databases can also use build records.

## Application exposure review

For each service, review the prerequisites in the CVE table above. For Brotli,
trace whether attacker-controlled input reaches
decompression. Cover request-body middleware (`Content-Encoding: br`), uploads,
archive/data processing, fetched remote responses, proxies, image processing and
background jobs. Follow dependencies as well as direct `node:zlib` calls.
Listening ports and response compression alone do not establish this path.

[Vercel's advisory](https://vercel.com/kb/bulletin/node-js-security-advisory)
also describes the outbound-response route: an inbound WAF rule does not cover
data a Node process fetches from another server.

Concrete paths to review include:

- Configured Express 5 request parsers. The [Express migration guide](https://expressjs.com/en/guide/migrating-5/)
  documents Brotli support, and [body-parser 2.0.0](https://github.com/expressjs/body-parser/releases/tag/2.0.0)
  introduced it. Parser placement, accepted content types, inflation settings and
  authentication order matter. Installing Express, listening on HTTP, or emitting
  Brotli-compressed responses does not by itself establish decoder exposure.
- Built-in `fetch()` and other clients that decode remote responses. Review how an
  attacker could influence the fetched URL, upstream server or returned content.
  Disabling inbound parser inflation does not cover this route.
- Bundled tools processing untrusted repositories or data. The
  [cdxgen advisory](https://github.com/cdxgen/cdxgen/security/advisories/GHSA-5266-jm88-3grm)
  describes both outbound podspec fetching and server-mode request decompression.
  Omitting Brotli from an outgoing request's accepted encodings is not proof that
  a client will reject a Brotli response. Inventory the bundled runtime separately.

Optional inventory evidence:

```json
"exposure": {
  "CVE-2026-111497": {
    "reachability": "reachable",
    "source": "APPSEC-123: deployed API parser accepts unauthenticated br bodies"
  },
  "CVE-2026-105482": {
    "reachability": "unknown",
    "source": "DNS validation and resolution path not reviewed yet"
  }
}
```

`reachability` values are `reachable`, `not_observed`, or `unknown`, with a required
review source per CVE. Each assertion applies to every matching worker in the inventory.
This is an operator assertion; the auditor does not inspect application source or
validate the assertion. `not_observed` does not clear an affected artifact.
`POTENTIALLY_EXPLOITABLE` requires affected bytes and reviewed reachability for the
same CVE. A Brotli exposure review cannot establish DNS/TLS/Permission Model exposure.
Review outbound clients, snapshot/SEA build pipelines, ZIP consumers and Permission
Model configurations as applicable. Keep evidence current as deployments change.

## Research and detection coverage

Reviewed on **2026-10-24**. These are evidence limits, not endorsements of other
scanners or claims that every exploit variant has been tested.

[Imperva's original exploit analysis](https://www.imperva.com/blog/node2shell-from-brotli-data-to-remote-code-execution/)
reports code execution through inbound parser and outbound fetch paths on the
official Node 24.22.0 Linux arm64 build; 24.22.1 rejected the same inputs. Their
success depended on the tested build/application setup and was not guaranteed on
every attempt. This auditor has not reproduced that exploit.

The [upstream Brotli patch](https://github.com/google/brotli/commit/0ed4268a4401abcb4472096340477cf4af7d1a2b)
distinguishes an invalid block transition from a request for more input and
propagates a permanent format error. **Do not rely on the Brotli version string
alone:** [Node 24.22.1's bundled version header](https://github.com/nodejs/node/blob/v24.22.1/deps/brotli/c/common/version.h)
still declares 1.2.0 despite containing the fix. Exported error names alone also
do not establish which decoder bytes a worker is using.

| Method or evidence reviewed | What it can establish | This auditor's treatment |
| --- | --- | --- |
| Official release provenance and fix commits | Whether an identified upstream artifact includes the fix. | SHA-256-bound evidence and branch-specific Node boundaries; `assess_file` never clears from a bare version hint. |
| [Public Unix/Windows version detector](https://github.com/shivrajem/node2shell-detect/tree/49ac68c57173fd3b6b9181b5de1aca4e6c7927f4) | Candidate installations and version-based triage. Its classification paths read embedded strings/Windows metadata, fall back to executing `--version`, and compare release thresholds; container checks execute a command inside the container. | Reviewed source at the linked revision, not executed or exhaustively audited. These signals alone do not prove running-image identity, vendor backports, loaded shared decoder status or application reachability. Our optional version probe remains `UNKNOWN`. |
| [Tenable local package check, plugin 370530](https://www.tenable.com/plugins/nessus/370530) | Vendor-reported package presence/status; its published description identifies that basis. | Useful corroboration. Installed package metadata alone cannot clear modified files or workers retaining old mappings. The plugin's unresolved-package solution text is not a claim that no upstream fix exists. |
| HTTP banners, headers, response compression and normal valid Brotli requests | Product hints or successful decompression on the specific tested route. | Neither fixed decoder behavior nor all application paths are established. No HTTP-based clearance. |
| Malformed-stream/crash/RCE probes | Behavior of a particular target/input; a successful exploit can demonstrate that tested path. | Not implemented. A negative result, crash, request rejection or WAF block is not general patch proof; malformed input can damage availability. |
| WAF rules and request-filter changes | Mitigation of traffic within the rule's coverage. | Not patch evidence; outbound decompression and bypass paths require separate review. |
| Renamed/embedded Node and external Brotli | Artifact-specific results when inventory and provenance identify the real executable and dependencies. | Explicit inventory plus same-process library assessment. Automatic discovery cannot enumerate every statically embedded or inactive runtime. |

The Intelsieve checker surfaced in search, but its page returned HTTP 403 during
review. Its implementation and accuracy were not vetted or used for verdicts.
No comprehensive census of public exploit repositories or commercial rules was
performed. The exploit/detector comparison above concerns Brotli. For the other
nine CVEs, scope and prerequisites were checked against Node's original advisory;
their exploits and third-party detectors were not reproduced or independently
audited. The code review covered per-CVE branch classification, byte provenance,
partial vendor/build evidence, external-decoder resolution, CVE-specific exposure
and remote report validation. A fix for one CVE cannot clear the others.
Application source/reachability analysis is still an operator task.

This is a Node deployment audit. The underlying Brotli flaw also affects other
consumers; it is not a complete inventory of Bun, Python extensions, proxies or
every application bundling Brotli. Those need their own product/vendor assessment.

## Remote and fleet use

SSH sends the audit source and configuration to the target Python process over
stdin. No audit files are installed there. The controller validates the result's
per-run token, source/input fingerprints, schema, exit status and aggregate verdict.
SSH uses strict existing host-key trust, batch authentication, a 10-second connect
timeout, and a 120-second overall command timeout. Timeouts produce `UNKNOWN`.
`--sudo` uses noninteractive `/usr/bin/sudo`; required permissions are your policy.

Default target Python: `/usr/bin/python3`. Use `--remote-python /absolute/path`
where different. For Windows OpenSSH:

```sh
python3 node2shell-audit.py --ssh auditor@windows-host --remote-os windows \
  --remote-python 'C:\Program Files\Python314\python.exe' \
  --inventory inventory.windows.json --evidence evidence.json --json
```

For macOS SSH use `--remote-os macos` and an installed Python 3.9+ path.
Containers must already have Python. `--engine podman` selects Podman; audit each
container separately. Linux/macOS controllers support the container transport;
Windows controllers support local and SSH modes. Container engine access is subject
to the caller's existing privileges. Images, other containers and the host are not
covered by a container's result. Kubernetes targets can run the local command inside
each relevant pod using existing fleet tooling; there is no Kubernetes connector.

Use one invocation per deployment with its own reviewed inventory. For example,
from an existing orchestration job:

```sh
python3 node2shell-audit.py --ssh auditor@api-01 --sudo \
  --inventory inventories/api-01.json --evidence evidence.json --json > reports/api-01.json
```

Retain exit codes **and** JSON. Prioritize affected artifacts with reviewed exposure,
then affected artifacts with unknown exposure, then unresolved inventory/access/build
evidence. The auditor does not enumerate a company's network or discover cloud accounts.

## Patching guidance

First establish **which artifacts and vendor releases fix each applicable CVE**, then follow
that provider's update procedure. A general package-management guide explains how
to apply an available update; it does not establish that the vendor has shipped a
fix. Guides below were checked for relevant content and release scope on 2026-10-24.

### Fix availability and product scope

- **Upstream Node:** use the [fixed releases listed above](#advisory-and-fixed-versions)
  or a later supported fixed release. The official release pages provide Linux,
  Windows and macOS artifacts. Verify provenance and update the runtime actually
  selected by the service. Updating npm, Express or body-parser alone does not
  replace a bundled vulnerable decoder.
- **Snapshots and single executable applications:** for CVE-2026-106074, rebuild
  user-land startup snapshots and SEAs with a fixed runtime, then redeploy the
  resulting artifacts. Updating a system Node executable does not rebuild an
  already distributed SEA or snapshot. Review the crypto-cache prerequisites in
  the [original advisory](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases).
- **Debian:** the [CVE tracker](https://security-tracker.debian.org/tracker/CVE-2026-111497)
  identifies the Debian 12/13 shared-Brotli fixes used by the built-in rules. This
  establishes only the Brotli fix; obtain Node package evidence for the other CVEs.
- **Ubuntu:** [Canonical's tracker](https://ubuntu.com/security/CVE-2026-111497)
  listed Node/Brotli releases as needing evaluation for Brotli when checked. No Ubuntu fix
  threshold is inferred from an update command or from Debian's advisory.
- **RHEL and other RPM vendors:** check the supplier's product, release,
  architecture and module-specific errata. [Red Hat's CVE portal](https://access.redhat.com/security/cve/cve-2026-111497)
  is the status entry point; its detailed product status was not retrievable by
  the web research tool in this review. No RHEL CVE fix threshold is built in.
- **Amazon Linux:** the [ALAS CVE page](https://explore.alas.aws.amazon.com/CVE-2026-111497.html)
  had package-specific pending-fix, no-fix-planned and not-affected entries when
  checked. Those labels cannot be generalized to every Node/Brotli package or
  used as a substitute for exact artifact evidence.
- **Standalone Brotli:** the [upstream 1.2.1 release](https://github.com/google/brotli/releases/tag/v1.2.1)
  explicitly fixes CVE-2026-111497. Existing vendor backports or other maintained Brotli
  branches require their own evidence; do not replace a distro library by hand
  solely to make its version number match this release.
- **cdxgen bundled binaries/images:** the [maintainer advisory](https://github.com/cdxgen/cdxgen/security/advisories/GHSA-5266-jm88-3grm)
  identifies fixed product releases 12.8.9 and 13.5.0. It specifically warns that
  12.8.8's standalone artifacts still carried the old runtime. npm installs use
  the host Node instead. Verify actual shipped bytes and deployed image identity.

The linked Debian, Ubuntu, Red Hat, Amazon Linux and cdxgen status pages above
concern **CVE-2026-111497**, not the complete ten-CVE advisory. Check each supplier's
status for every applicable CVE; these pages cannot establish the other nine fixes.

If the supplier has not released an applicable fix, keep the finding open and
follow its support/migration guidance. Partial mitigations do not become `PATCHED`.

### Applying the appropriate update

| Installation | Official update procedure | Scope to retain |
| --- | --- | --- |
| Debian | [Keeping a system up to date](https://www.debian.org/doc/manuals/debian-handbook/sect.regular-upgrades.en.html) | Match the CVE tracker to the deployed release and shared decoder package. |
| Ubuntu | [Install and manage packages](https://ubuntu.com/server/docs/how-to/software/package-management/) | An available package update is not itself evidence the applicable CVEs are fixed. |
| RHEL 9 | [Managing and monitoring security updates](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/managing_and_monitoring_security_updates/index) | Select applicable security advisories; use the matching guide for other RHEL releases. |
| Rocky Linux | [DNF package manager](https://docs.rockylinux.org/guides/package_management/dnf_package_manager/) | Use Rocky's repositories and advisory evidence. |
| AlmaLinux | [Security errata and updateinfo](https://wiki.almalinux.org/documentation/errata.html) | Match package revisions to the relevant advisory. |
| Fedora using DNF5 | [Upgrade command](https://dnf5.readthedocs.io/en/latest/commands/upgrade.8.html) | DNF5 supports advisory/security filters; verify release/package applicability. |
| Oracle Linux | [Updating software](https://docs.oracle.com/en/operating-systems/oracle-linux/software-management/sfw-mgmt-UpdateSoftwareonEnterpriseLinux.html) | Use the correct enabled Oracle repositories and vendor fix evidence. |
| Amazon Linux 2023 | [Applying security updates in place](https://docs.aws.amazon.com/linux/al2023/ug/security-inplace-update.html) | Match the advisory and target repository release; this guide is not for Amazon Linux 2. |
| SLES 15 SP7 | [YaST online update](https://documentation.suse.com/sles/15-SP7/html/SLES-all/cha-onlineupdate-you.html) | Use the guide and advisories for the actual SLES release. |
| Alpine | [APK package updates](https://docs.alpinelinux.org/user-handbook/0.1a/Working/apk.html#_upgrading_packages) | Verify the decoder used by the deployed Node build. |
| Arch | [System maintenance](https://wiki.archlinux.org/title/System_maintenance) | Full upgrades are required; partial upgrades are unsupported. Derivatives need their own guidance. |
| NixOS | [Updating NixOS](https://wiki.nixos.org/wiki/Updating_NixOS) and [NixOS manual](https://nixos.org/manual/nixos/stable/) | Update the selected channel or flake inputs/lockfile and rebuild the deployed configuration. Verify the resulting store artifact and service selection; retain rollback generations. |
| Gentoo | [Upgrading Gentoo](https://wiki.gentoo.org/wiki/Upgrading_Gentoo) and [Gentoo Linux Security Advisories](https://wiki.gentoo.org/wiki/GLSA) | Sync repository metadata, review news/USE/configuration changes and update dependencies. GLSA checks cover published advisories; verify the actual Node/Brotli build. |
| Slackware | [Slackpkg update procedures](https://docs.slackware.com/slackware:slackpkg) | Match release and architecture mirrors, verify signed package/advisory provenance, update package lists and applicable packages, and review configuration changes. Third-party packages need their own supplier's guidance. |
| macOS Homebrew | [Updating packages](https://docs.brew.sh/FAQ#how-do-i-update-my-local-packages) | Updating the formula index alone does not upgrade installed runtime bytes. |
| macOS MacPorts | [Upgrading ports](https://guide.macports.org/#using.port.upgrade) | Retain evidence for the selected Node port and any external decoder. |
| nvm | [Version installation and selection](https://github.com/nvm-sh/nvm#usage) | Install/select the fixed version for each service account and project. |
| mise | [Node runtime management](https://mise.jdx.dev/lang/node.html) | Project pins override defaults; verify the deployed selection. |
| Volta | [Managing toolchains and project pins](https://docs.volta.sh/guide/understanding/) | Update both the selected toolchain and relevant project pins. |
| Official Windows/macOS/Linux installers or archives | [Node fixed-release downloads](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases) and [signature verification](https://github.com/nodejs/node#verifying-binaries) | Match OS/architecture and replace the actual service runtime; Windows Update does not update every standalone Node installation. |
| Containers | [Rebuild images with fresh inputs](https://docs.docker.com/build/building/best-practices/#rebuild-your-images-often) | Replace running deployments after rebuilding; pulling an image or updating the host does not replace workers. |

The NixOS, Gentoo and Slackware guides were read for their update workflows and
scope, including channel/flake pins, Portage dependency updates and Slackware
mirror/configuration handling. This review did not establish an all-ten-CVE vendor
fixed-package matrix for those systems. Their package databases are not parsed by
the auditor; supply trusted SHA-256 build evidence. Other package managers and
embedded products likewise need their supplier's procedure and build provenance.

Restart or replace all consumers of an updated executable/shared decoder through
the deployment's normal procedure, check application health and rerun the audit.
Retain evidence for replaced artifacts until no old workers use them. A WAF rule,
disabled inbound Brotli, or a successful package-manager update is not patch proof.

## Validation and limits

```sh
python3 -m unittest discover -q
python3 verify_native.py
python3 verify_release.py --version 24.22.0 --expect AFFECTED
python3 verify_release.py --version 24.22.1 --expect PATCHED
python3 verify_service.py
```

`verify_native.py` compiles temporary executable/shared-library fixtures on Unix
(requires a C compiler) or uses a Python stand-in on Windows. They prove collector
and identity behavior, not Node vulnerability semantics. `verify_release.py`
downloads official native binaries, verifies their bytes, and runs temporary idle
Node workers without listeners or malformed data. It does not install Node.
`--expect` supplies the advisory-based expected verdict independently of the
classifier being tested. CI covers affected/fixed pairs 22.23.3/22.23.4,
24.22.0/24.22.1 and 26.12.0/26.12.1 on each supported operating system.

`verify_service.py` is a separate lab acceptance test. It downloads official Node
24.22.0 and 24.22.1 into temporary directories and runs four HTTP workers on
ephemeral **127.0.0.1-only** ports. Every worker accepts valid Brotli request bodies;
the test checks responses while invoking the auditor's actual CLI. It exercises
mixed affected/fixed workers, an explicitly inventoried renamed runtime, per-CVE
results and reviewed exposure assertions. On Linux/macOS it replaces the executable
on disk while affected workers keep serving, then restarts workers in stages. On
Windows it uses separate runtime paths and preserves loaded-image uncertainty.
A configured worker that is absent must prevent clearance. Processes and files
are cleaned up on completion or an assertion failure. This test sends no malformed
payloads and does not reproduce exploitation or measure production capacity.
The verifier supervises independent Node workers; it does not exercise PM2,
systemd, IIS or a particular application's routing/authentication configuration.

Exposure assertions apply to every matching process using an inventory path.
If services with different exposure share that executable, keep the assertion
unknown or audit them in separate deployment scopes; a shared pathname does not
distinguish application roles.

This service-level acceptance passed on **2026-10-24** on macOS arm64, Ubuntu
26.04 x86_64, Windows 11 x86_64, and OrbStack Debian 13 arm64/emulated x86_64.
All four workers served valid requests during each CLI audit. Linux retained
`AFFECTED` for old running bytes after their disk file was replaced; macOS retained
`UNKNOWN` with restart required. In isolated containers, the aggregate report
stayed `AFFECTED` through the first worker restart, became `PATCHED` after the
last old worker restarted, and became `UNKNOWN` when an expected worker was absent.
Windows preserved separate file results and `UNKNOWN` running-image results.
The non-isolated macOS/Ubuntu hosts retained unrelated coverage gaps; their whole
host reports were not cleared. This adds realistic runtime/service evidence without
claiming completeness for an unreviewed production fleet.

The expanded ten-CVE implementation was checked on **2026-10-24**. Each environment
below passed **74 offline regressions**, native identity fixtures, and per-CVE
installed-file/idle-worker checks for official Node 22.23.3/22.23.4,
24.22.0/24.22.1 and 26.12.0/26.12.1:

| Environment | Architecture | Real-release results |
| --- | --- | --- |
| macOS host | arm64 | Affected/fixed pairs returned `AFFECTED` / `PATCHED`. |
| Ubuntu 26.04 host | x86_64 | Affected/fixed pairs returned `AFFECTED` / `PATCHED`. |
| Windows 11 host | x86_64 | File results matched each pair; running-image status remained `UNKNOWN`, as designed. |
| Debian 13 containers on OrbStack | arm64 and emulated x86_64 | Affected/fixed pairs returned `AFFECTED` / `PATCHED`. |

Python 3.9 regressions also passed in containers on both Linux architectures;
the refreshed Windows x86_64 checks used Python 3.13. The earlier 64-test version
also passed on Windows arm64 in Parallels and Windows x86_64 with Python 3.14;
those two combinations were not rerun after the ten-CVE expansion.
Core Ruff checks passed. A negative regression proves the release verifier rejects
an incorrect classifier verdict and covers uppercase Windows architecture names.
The research comparison adds source review, not exploit reproduction.

Live SSH checks against Ubuntu and Windows verified affected/fixed synthetic
fixtures, including file-only and running-process modes and Ubuntu's noninteractive
`--sudo` path. Ubuntu and Docker checks used the CLI; Windows exercised the SSH
transport with a separate connection to bypass a stalled shared SSH session.
Docker checks passed in isolated arm64 and emulated x86_64 containers. These checks
also verified that Brotli-only patch evidence leaves the complete report `UNKNOWN`.
SSH fixture results did not clear unrelated host processes or access gaps.

Before the ten-CVE expansion, real package ownership, installed-file checksums and native version comparison
passed for Debian 13/dpkg, Rocky Linux 9/RPM, Alpine 3.24/APK and Arch Linux/pacman.
Those checks validate package handling; they do not add CVE fix thresholds for
vendors without verified advisories. Arch package checks ran on native x86_64
because its package-download sandbox failed under emulation.

The existing regressions cover the research-derived verdict boundaries:

| Failure case | Regression coverage |
| --- | --- |
| Release/version hints mistaken for patch proof | Branch boundaries, nonstandard/EOL versions, changed bytes and probe-only `UNKNOWN` results. |
| Vendor backport or shared decoder misclassified | Exact distro/package rules, checksum mismatch, RPM stream/vendor/architecture, external linkage and same-process decoder resolution. |
| One CVE fix clearing the whole advisory | Complete ten-CVE scope, branch exclusions, partial evidence, separate vendor thresholds, Brotli-only dependency resolution and per-CVE remote-envelope validation. |
| Updated disk files masking stale or unverified workers | Replaced artifacts, PID reuse, namespace changes, Windows file/loaded-image separation and native replacement checks. |
| Reachability evidence treated as patch status or proof of RCE | Exposure validation, affected-plus-reachable classification, and inactive-file exclusion. |
| Incomplete inventory or transport failure clearing a deployment | Missing/extra workers, inspection failures, unconfirmed inventory and authenticated transport-envelope checks. |

Podman transport, macOS SSH, Intel/older macOS and production fleet acceptance
remain untested. The available Windows Podman machine was stopped; Windows
controllers support local/SSH modes, not container transport. The validation results
above come from direct local, SSH and container runs. Hosted results are reported
separately in [GitHub Actions](https://github.com/beardedeagle/node2shell-patch-audit/actions/workflows/audit.yml).
Before fleet acceptance, reconcile a representative deployment's report with its
known runtime inventory and reviewed application paths. Validate any additional
transport/platform combination used by that fleet.

The host, package database and supplied evidence are trusted. This does not detect
root compromise, forged package metadata, live memory modification, injected code,
or prior exploitation. Process inspection is a point-in-time sample. Short-lived,
hidden, protected, statically embedded or renamed runtimes may need explicit
inventory. Linux namespaces must be audited from inside the deployment; macOS
protected processes can prevent complete inspection. Source-only review and a
complete production fleet assessment are separate activities.
