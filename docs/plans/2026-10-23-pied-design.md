# pied design

23 October 2026

## What it decides

A target is exposed when a runtime, lockfile, image, or trust bundle is still on the vulnerable side of a published fix, or when a bundle still contains a certificate fingerprint from the disclosure site.

The two incidents share a version check on Node.js: 22.23.4, 24.22.1, and 26.12.1 fix CVE-2026-111497, the other nine CVEs in that release, and ship the NSS 3.131.1 CA store. Other ecosystems have their own floors, stored in `src/pied/advisories.py`. `docs/ADVISORIES.md` is the human copy of that catalog.

## Layout

`cli.py` parses `scan` and `host`. `local.py` walks a tree. `github.py` lists an org, then fetches one git tree and only the manifest blobs. `host.py` runs installed binaries and reads CA files. All three call `manifests.scan_text` and `certs.py`, then `finalize`, then `report.py`.

`finalize` raises a vulnerable Node finding from high to critical when the same target also has an Express 5, body-parser 2, or direct Brotli-decoder entry point. A floating Node pin becomes high in that case, because the entry point is real and the runtime is not pinned. It also attaches identifiers: a Node finding gets the CVEs for the major named in the pin (`lts/jod` is 22; an unpinned tag gets all ten), and certifi, pip, uv, Go, and Java findings get GHSA-6q48-6c7w-9gw2, GHSA-hq85-5cpj-mr62, CVE-2026-111943, or CVE-2026-91403. `.python-version` and a direct `Cargo.toml` pin are read the same way as the lockfiles. SPKI hashes are archived for the Go fix and are not parsed.

A local path and `pied host` read the Go buildinfo header (`\xff Go buildinf:`) inside native binaries. The string there is the toolchain that compiled the file. Host scans also fingerprint `ssl.create_default_context()` and `tls.rootCertificates`, and classify `curl -V`. Those are the stores a handshake in that process would use. pied still does not connect to the demonstration hosts. If `otool -L` or `ldd` shows `libbrotlidec`, CVE-2026-111497 is moved onto that library and compared with Brotli 1.2.1.

## Severity

- high: an exact release below the floor, a range that still allows one, or a high-severity root fingerprint (`emSign ECC Root CA - G3`, `emSign Root TLS CA - G3`, `emSign Root CS CA - G3`, or one of the sixteen intermediate certificates)
- medium: a floating tag, an unpinned upgrade, or `AAA Certificate Services` (the Sectigo cross-sign anchor; removing it breaks unrelated certificates)
- info: a `go` language line, an old ensurepip, a Docker daemon that is not running
- ok: checked and at or above the floor. Shown for `pied host`, hidden for repository scans unless `--verbose`

Exit status follows `--fail-on`, default high. A scan that cannot authenticate or cannot see any repository exits 2.

## What stays out

No trust-store edits, no package installs, no Brotli inputs, no connections to the demonstration hosts. Those hosts log successful clients. Fingerprinting the local bundle answers the same question without that call.

Remote scans do not download general source. `brotliDecompress` is detected on `--path` only. A clean repository scan does not claim the deployed image is patched.

## Tests

`tests/test_pied.py` covers the version floors, lockfiles, Docker tags, the Express escalation, per-line CVE identifiers, the indicator file, certificate fingerprints, and the CLI exit codes. The docs are checked for every catalog id so the write-up cannot drop one. `pied host` and a scan of `certifi/python-certifi` were run while building this.
