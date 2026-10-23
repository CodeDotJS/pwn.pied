# Research notes, 23 October 2026

pied's rules were taken from the primary advisories, not from the social posts. Private-key scalars are not recorded here. The public certificates are enough for anyone to recompute those scalars, so this archive keeps subjects and SHA-256 fingerprints only.

## eMudhra / emSign

On 17 October 2026 a researcher told Apple, Google, Microsoft, and Mozilla that eight eMudhra intermediate CA keys were weak. eMudhra revoked them on 18 October. Browsers blocked them through OneCRL, CRLSets, and the Apple/Microsoft distrust lists. Most non-browser TLS clients do not check revocation and do not enforce Certificate Transparency, so they stay exposed until their own trust bundle is updated.

The keys are P-384. A normal private scalar is 384 bits. These eight scalars fit in a single byte, so they are treated as compromised from the day the certificates were created in April 2025. Six issue TLS (DV, OV, EV, series G3B and G3C). Two issue code-signing certificates (`EM OV CS CA - G3B` and `G3C`). Each key also has a Sectigo cross-sign from `AAA Certificate Services`.

Chains:

- `emSign ECC Root CA - G3` cross-signs `emSign Root TLS CA - G3`, which issued the six TLS intermediates. This is the root in Mozilla-derived bundles, including certifi and `/etc/ssl/cert.pem` on macOS.
- `emSign Root CS CA - G3` issued the code-signing intermediates. Microsoft trusted it for code signing.
- `AAA Certificate Services` issued the cross-signs. Mozilla and Chrome had already stopped trusting it for websites in April 2025. Apple and many OS bundles still ship it. Removing it also breaks unrelated certificates, so pied reports it as medium rather than telling anyone to delete it.

No malicious use had been reported as of 22 October 2026. Certificate Transparency logs had no certificates from these TLS intermediates before the browser blocks, which is why CT-enforcing browsers were not a useful target. Package managers, CI, `curl`, Go binaries, and container images were.

Python is not itself compromised. Seth Larson's announcement on discuss.python.org (20 October 2026) says to upgrade:

- certifi 2026.10.19 (2026.10.18 removed every emSign root; 2026.10.19 is the release to install because it keeps the unaffected emSign roots)
- pip 26.2.2
- uv 0.13.4
- sigstore 4.5.1, conda 26.9.4, pixi 0.82.1

Christian Heimes's follow-up is the operational point: pip always loads its vendored certifi in addition to the system store, and there is no supported switch to turn that off. `REQUESTS_CA_BUNDLE` and `--cert` only add anchors. Updating macOS or `ca-certificates` does not fix pip. uv can use `UV_SYSTEM_CERTS=true` against an already patched OS store. pip cannot.

The checksum-pinned pip wheel in the announcement is the bootstrap that does not depend on the old verifier. CPython 3.15.1, 3.14.9, and 3.13.17 bundle pip 26.2.2. Existing virtualenvs do not pick that up, and `ensurepip` on older interpreters still creates vulnerable environments. pip 26.2.2 does not support Python older than 3.10.

Official Python Docker images were still shipping pip 26.2.1 on 21 October 2026 (`python:3.15-slim-trixie`). Images have to be rebuilt after the base image and the pip pin move.

Go's fix is CVE-2026-111943, in Go 1.26.10 and 1.27.3. It blocks the eight keys by SPKI hash. Those hashes, and the certificate fingerprints, are in `indicators.json`. A binary built with an older Go keeps the old behavior until it is rebuilt. pied reads the toolchain from the Go buildinfo header inside the binary, on a local path and on `pied host`, so a compiled tool is not invisible just because `go.mod` only names a language version. Java's fix is CVE-2026-91403 (CVSS 9.1 on the incident tracker): 8u511, 11.0.33, 17.0.21, 21.0.13, 25.0.5, 27.0.1.

Other published floors, with no separate CVE in this catalog: sigstore 4.5.1, conda 26.9.4, pixi 0.82.1, Deno 2.9.8, Electron 42.11.16 / 43.8.1 / 44.9.1, rustls-webpki 0.103.16, webpki-root-certs 1.0.10. uv's advisory is GHSA-hq85-5cpj-mr62. certifi's is GHSA-6q48-6c7w-9gw2 (CVSS 7.4). pip has no advisory of its own; 26.2.2 vendors the fixed certifi.

## Node.js, 21 October 2026

Fixed releases: 22.23.4, 24.22.1, 26.12.1. Lines 20, 23, 25, and older are end of life and were not patched.

The same releases update the bundled CA store to NSS 3.131.1, which is the eMudhra fix for Node. One version check covers both. The full set, with the lines Node named:

| ID | Severity | Lines |
| --- | --- | --- |
| CVE-2026-111497 | high | 22, 24, 26, and end-of-life lines (Brotli out-of-bounds write) |
| CVE-2026-105482 | high | 22, 24, 26 (`dns.resolve` and NUL bytes) |
| CVE-2026-105483 | high | 24, 26 only (TLS hostname, fullwidth digits) |
| CVE-2026-106069 | high | 22, 24, 26 (TLS hostname that loosely resolves to an IP) |
| CVE-2026-105481 | medium | 22, 24, 26 |
| CVE-2026-106072 | medium | 22, 24, 26 |
| CVE-2026-106074 | medium | 22, 24, 26 |
| CVE-2026-106070 | low | 26 only |
| CVE-2026-106071 | low | 26 only |
| CVE-2026-106073 | low | 22, 24, 26 |

`docs/ADVISORIES.md` is the catalog pied's findings are generated from. A Node 22 finding does not list CVE-2026-105483, CVE-2026-106070, or CVE-2026-106071. An end-of-life finding lists CVE-2026-111497 only.

Aikido's 22 October write-up (and Imperva's the same day) describes who actually decompresses attacker-controlled Brotli:

- Express 5 and body-parser 2.x decompress `Content-Encoding: br` on request bodies. A bare Node HTTP server does not.
- `fetch()` decompresses Brotli responses, including from a server the application chose to call.
- Direct `node:zlib` Brotli calls do the same.

Bun before 1.4.4 is affected. A distribution Node built against the system Brotli library is fixed when that library is fixed, not only when the Node version number moves. Upstream Brotli 1.2.1, dated 21 October 2026, is the release that fixes CVE-2026-111497. pied resolves `libbrotlidec` from `otool -L` or `ldd` and uses that version for this one CVE. Public research had demonstrated code execution against unmodified Node.js 24.22.0 in lab conditions. No in-the-wild exploitation had been reported as of 22 October. Node.js 24.22.1 rejects the same input when it vendors the decoder. There is no upstream workaround. Dropping inbound `Content-Encoding: br` does not protect `fetch()`.

## What pied checks, and what it will not do

Fingerprints come from `roots.json` and `impacted-intermediates.json` on the disclosure site, cross-checked with the CVE Brief table. pied applies them to PEM files, to certificates compiled into a Go binary, and to the sets Python `ssl.create_default_context()` and Node `tls.rootCertificates` load. That is the trust decision a handshake in that process would use, and it does not require a connection. `curl -V` distinguishes SecureTransport, which follows Apple's 22 October 2026 platform distrust, from a PEM-backed curl. pied does not call `*.emudhra.we-have-a-problem.com`, because that site logs user agents that still trust the chain.

pied also does not apply the disclosure site's temporary trust-store edits. Those remove `AAA Certificate Services` as well as the eMudhra root, which breaks unrelated sites. The vendor upgrades above are the fix.

## Sources

Retrieved 23 October 2026.

- https://discuss.python.org/t/information-for-python-users-regarding-emudhra-emsign-ca-certificate-security-incident/109576
- https://emudhra.we-have-a-problem.com/
- https://emudhra.we-have-a-problem.com/impacted-intermediates.json
- https://emudhra.we-have-a-problem.com/roots.json
- https://pwn.watch/i/emudhra-intermediate-ca-compromise
- https://github.com/advisories/GHSA-6q48-6c7w-9gw2
- https://nodejs.org/en/blog/vulnerability/october-2026-security-releases
- https://www.aikido.dev/blog/node2shell-nodejs-brotli-rce-cve-2026-111497
- https://www.imperva.com/blog/node2shell-from-brotli-data-to-remote-code-execution/
- https://scotthelme.co.uk/eight-bits-of-trust-emudhras-ca-keys-cracked-in-milliseconds/
- https://emudhra.com/en/post/certificate-security-incident
- https://www.openwall.com/lists/oss-security/2026/10/20/1
- https://x.com/L4UR3N7/status/2113291274664976774

Screenshots are in `research/screenshots/`. The social images are the posts supplied with the request. `research/host-scan.txt` is a `pied host` run on this machine and is gitignored, because it names local paths. `research/sources/certifi-repo-scan.txt` is a smoke scan of `certifi/python-certifi`, which was clean (7 files, the published tree no longer carries the compromised root).
