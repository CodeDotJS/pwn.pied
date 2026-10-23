<p align="center">
  <img src="media/brot.gif" width="128" alt="DETRO" />
</p>

<h1 align="center">pied</h1>

<p align="center">Read-only scanner for two October 2026 incidents.</p>

- The eMudhra / emSign intermediate CA incident. Eight intermediate keys were generated so weakly that they have to be treated as compromised. Clients that trust `emSign ECC Root CA - G3`, `emSign Root TLS CA - G3`, or `emSign Root CS CA - G3` can accept a forged certificate for any site. `pip` before 26.2.2 keeps doing that through its vendored certifi even after the operating system trust store is fixed.
- Node.js CVE-2026-111497, a high-severity out-of-bounds write in the bundled Brotli decoder. The same 21 October 2026 releases fix nine more CVEs and refresh Node's CA store to NSS 3.131.1.

pied checks versions and certificate fingerprints. Every finding names the CVE or GHSA that applies to that release line. It does not install packages, edit trust stores, send Brotli payloads, or contact the public demonstration hosts (those servers record clients that still connect).

## Set up the repository

Python 3.9 or newer is the only requirement. pied uses the standard library, so a checkout runs with no install. Nothing in these steps upgrades pip, certifi, Node, Go, or a trust store.

### Download without git

curl:

```bash
curl -fsSL https://github.com/CodeDotJS/pwn.pied/archive/refs/heads/main.tar.gz | tar -xz
cd pwn.pied-main
./bin/pied --version
```

wget:

```bash
wget -qO- https://github.com/CodeDotJS/pwn.pied/archive/refs/heads/main.tar.gz | tar -xz
cd pwn.pied-main
./bin/pied --version
```

### Clone and run locally

```bash
git clone https://github.com/CodeDotJS/pwn.pied.git
cd pwn.pied
./bin/pied --version
```

The same tree over SSH:

```bash
git clone git@github.com:CodeDotJS/pwn.pied.git
cd pwn.pied
./bin/pied --version
```

`bin/pied` adds this checkout's `src` directory to `PYTHONPATH` and runs `python3 -m pied`. The same command without the wrapper:

```bash
PYTHONPATH=src python3 -m pied --version
```

An install is optional. It only adds a `pied` command on your `PATH`:

```bash
python3 -m pip install -e .
pied --version
```

`setup.md` repeats this and then lists every scan you can run from that checkout.

### GitHub access

pied reads repository metadata and manifest files through the GitHub API. It does not clone the repository.

A token is resolved in this order: `GH_TOKEN`, `GITHUB_TOKEN`, then `gh auth token` after `gh auth login`. Public repositories can be scanned with no token until GitHub's unauthenticated rate limit. A private repository or an organization scan needs a token that can read repository contents. The `repo` scope covers private repositories.

Forks and archived repositories are skipped unless you pass `--include-forks` or `--include-archived`. `--max-repos 5` stops an organization scan early, which is the right first run on a large org.

### Confirm the checkout

```bash
PYTHONPATH=src python3 tests/test_pied.py
./bin/pied scan --path .
```

The tests use temporary directories. They do not read your trust store and they do not call GitHub. `scan --path .` on this repository itself should be clean: the only manifest is `pyproject.toml`.

## Commands

Scan one repository, several repositories, or every repository in an organization:

```bash
./bin/pied scan --path .
./bin/pied scan --repo owner/name
./bin/pied scan --repo owner/one --repo owner/two
./bin/pied scan --org my-org --max-repos 5
./bin/pied scan --org my-org --repo payments
./bin/pied scan --repo owner/name --format json --output report.json
```

`--path` and `--org` / `--repo` cannot be combined. `--repo` is either `owner/name`, or a repository name together with `--org`. `--verbose` includes pins that are already at a fixed release. `--fail-on` defaults to `high` and accepts `critical`, `high`, `medium`, `low`, `info`, or `ok`.

`pied host` is also read-only, and it is the check for a machine rather than a git tree. It versions interpreters on `PATH` and in the usual install locations, walks for virtualenvs, fingerprints CA bundles, reads the trust stores Python's `ssl` module and Node's `tls.rootCertificates` load, and reads the Go toolchain embedded in executables (`--max-binaries`, default 80). When a Node binary loads `libbrotlidec`, CVE-2026-111497 is compared with that library (fixed in Brotli 1.2.1). Docker probes, when the daemon is running, use `docker run --network none` and only images whose names look like Python, Node, Go, uv, Bun, or Deno unless you pass `--docker-all`.

```bash
./bin/pied host --no-docker
./bin/pied host --quiet
```

`--quiet` hides results that are already patched. A host report names local paths. `research/host-scan.txt`, `research/local/`, and a root `report.json` are gitignored. Write any other output outside the repo, or add it to `.gitignore`, before you commit.

Exit status is `0` when nothing at or above `--fail-on` was found, `1` when a finding meets that bar, and `2` when the scan could not run (no target, a bad token, or no matching repository).

## Examples

Run these from the pied checkout. They only read. A local scan does not write into the tree you point at. `--output` is optional; if you use it, write the file outside that tree (for example `/tmp`).

In a terminal the severity words are colored: critical and high are red, medium is yellow, low is cyan, info is blue, and a clean result is green. `--no-color`, or the `NO_COLOR` environment variable, prints plain text. Pipes and `--format json` are plain text already.

```bash
# This repo. Expect exit 0.
./bin/pied scan --path .

# Any other checkout on disk. Replace the path.
./bin/pied scan --path /path/to/project

# Public repositories.
./bin/pied scan --repo certifi/python-certifi
./bin/pied scan --repo expressjs/express
./bin/pied scan --org psf --repo requests

# Several repositories in one run.
./bin/pied scan --repo certifi/python-certifi --repo expressjs/express

# First look at an organization, then one repository inside it.
./bin/pied scan --org my-org --max-repos 5
./bin/pied scan --org my-org --repo payments

# This machine. Read-only. The report names local paths.
./bin/pied host --no-docker
```

`setup.md` is the full list: unit tests, JSON output, `--fail-on`, a throwaway tree that should exit 1, and where each command is safe to point.

## What a repository scan reads

Manifests and lockfiles, Dockerfiles and compose files, GitHub Actions workflows, `.nvmrc`, `.node-version`, `.python-version`, `.tool-versions`, `go.mod`, `Cargo.toml`, `Cargo.lock`, and PEM trust bundles. A local `--path` scan also notices direct `brotliDecompress` / `createBrotliDecompress` calls outside `node_modules`, and reads the Go buildinfo header in native binaries so an already-built tool is checked against CVE-2026-111943. A remote scan does not download every source file, so that binary check is local and host only. GitHub scans read at most 80 manifest files per repository, each up to 2.5 MB, and the report says when that cap was reached.

A clean manifest result means those files do not pin a vulnerable release. It does not prove a deployed image or a developer's laptop is patched. Run `pied host` on the machines and rebuild images.

## Fixed releases

| Component | Fixed at | Identifier |
| --- | --- | --- |
| certifi | 2026.10.19 | GHSA-6q48-6c7w-9gw2 |
| pip | 26.2.2 | GHSA-6q48-6c7w-9gw2 (vendored certifi; pip has no separate advisory) |
| uv | 0.13.4 | GHSA-hq85-5cpj-mr62 |
| sigstore / conda / pixi | 4.5.1 / 26.9.4 / 0.82.1 | bundled roots, no separate CVE |
| CPython ensurepip | 3.13.17, 3.14.9, 3.15.1 | GHSA-6q48-6c7w-9gw2 |
| Node.js | 22.23.4, 24.22.1, 26.12.1 | the ten CVEs below; CA store becomes NSS 3.131.1 |
| Bun / Deno | 1.4.4 / 2.9.8 | CVE-2026-111497 / bundled roots |
| Go | 1.26.10, 1.27.3 | CVE-2026-111943 |
| Java | 8u511, 11.0.33, 17.0.21, 21.0.13, 25.0.5, 27.0.1 | CVE-2026-91403 |
| Electron | 42.11.16, 43.8.1, 44.9.1 | Chromium trust store |
| rustls-webpki / webpki-root-certs | 0.103.16 / 1.0.10 | webpki bundle |
| system Brotli (`libbrotlidec`) | 1.2.1 | CVE-2026-111497, when Node loads this library |

Node.js 20, 23, 25, and anything older has no fix for CVE-2026-111497. Go 1.25 and older has no published eMudhra fix. pip 26.2.2 requires Python 3.10 or newer; older interpreters stay exposed until the environment moves. certifi 2026.10.18 is not the release to install: it drops every emSign root, including ones this incident did not affect.

## Identifiers

JSON findings carry these in `cves`. Text output prints them on the `ids` line. A Node finding lists only the CVEs Node says apply to that major. `lts/jod` is 22. An unpinned tag lists all ten.

| ID | Severity | Where it applies |
| --- | --- | --- |
| CVE-2026-111497 | high | Node 22, 24, 26, and end-of-life lines. Bun before 1.4.4. Brotli out-of-bounds write. |
| CVE-2026-105482 | high | Node 22, 24, 26. `dns.resolve` and NUL bytes. |
| CVE-2026-105483 | high | Node 24 and 26 only. TLS hostname, fullwidth digits. |
| CVE-2026-106069 | high | Node 22, 24, 26. TLS hostname that loosely resolves to an IP. |
| CVE-2026-105481 | medium | Node 22, 24, 26. Keep-alive response before the request. |
| CVE-2026-106072 | medium | Node 22, 24, 26. Non-canonical IPv4 hostname. |
| CVE-2026-106074 | medium | Node 22, 24, 26. Entropy cache reused from a snapshot or single-executable app. |
| CVE-2026-106070 | low | Node 26 only. ZIP local-header prefix. |
| CVE-2026-106071 | low | Node 26 only. Permission-model wildcard over-grant. |
| CVE-2026-106073 | low | Node 22, 24, 26. Permission-model `fs.realpathSync` bypass. |
| GHSA-6q48-6c7w-9gw2 | high, CVSS 7.4 | certifi below 2026.10.19, and pip that vendors it. |
| GHSA-hq85-5cpj-mr62 | high | uv below 0.13.4. |
| CVE-2026-111943 | high | Go below 1.26.10 or 1.27.3. Blocks the eight keys by SPKI hash. |
| CVE-2026-91403 | high, CVSS 9.1 | Java JSSE builds below the October 2026 CPU. |

Express 5 and body-parser 2.x decompress `Content-Encoding: br`. pied raises the Node finding when one of those is present, and that finding still carries CVE-2026-111497. The runtime is what to upgrade. Rejecting Brotli at a proxy does not cover `fetch()` responses.

The eMudhra incident has no single CVE. High trust-store findings are the three emSign roots and the sixteen intermediate certificates. `AAA Certificate Services` is medium: it is the Sectigo cross-sign anchor, and deleting it breaks unrelated sites. Fingerprints and the eight SPKI hashes are in `research/indicators.json`. pied matches certificate SHA-256. It does not parse SPKI.

Affected lines, the rationale for each floor, and what pied deliberately does not detect are in `docs/ADVISORIES.md`.

## Archive

`setup.md` has every scan variation, where to point it, and what exit code to expect. Research notes, fingerprints, and screenshots are in `research/`. A host report from the machine where this was built stays in `research/host-scan.txt` and is gitignored. The design note is `docs/plans/2026-10-23-pied-design.md`. The advisory catalog is `docs/ADVISORIES.md`.

---

<br>

<div align="center">

<p align="center">
  <img src="media/crab.svg" alt="pied" width="160" />
</p>



__License__

<br>

Copyright © 2026 [Rishi Giri](https://rishi.rest)

<br>

pwn.pied is released under the [MIT License](LICENSE)

</div>