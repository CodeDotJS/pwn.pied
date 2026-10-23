# Advisories pied reports

As of 23 October 2026. The same records live in `src/pied/advisories.py`. A finding's `ids` line, and the `cves` field in JSON, are chosen from this catalog. Floors below are the first release each vendor said was fixed.

The eMudhra incident itself has no single CVE. Exposure is a trust-store problem: clients that still contain one of the fingerprints in `research/indicators.json` can accept a certificate issued from a key that has to be treated as compromised.

## Node.js, 21 October 2026

Fixed releases: **22.23.4**, **24.22.1**, **26.12.1**. The same builds update the bundled CA store to NSS 3.131.1, so one version check covers the Brotli decoder and the eMudhra roots.

20.x, 23.x, 25.x, and every older major are end of life. Node did not publish a fix for them. pied reports CVE-2026-111497 on those lines and does not claim the other nine CVEs, because the Node.js advisory lists those nine against 22, 24, and 26 only.

An exact version is matched to its line. `lts/jod` is Node 22. A tag with no version, or an unbounded `>=` range, can land on more than one line, so the finding lists all ten CVEs. `^` and `~` stay on one major and get that line's set.

| ID | Severity | Release lines | What it is |
| --- | --- | --- | --- |
| CVE-2026-111497 | high | 22, 24, 26, and end-of-life lines | Brotli decoder out-of-bounds write. Node.js describes this as permitting remote code execution. Bun before 1.4.4 is affected too. |
| CVE-2026-105482 | high | 22, 24, 26 | `dns.resolve` truncates names that contain a NUL byte. |
| CVE-2026-105483 | high | 24, 26 | TLS hostname check accepts an IP written with fullwidth digits. Not listed for 22.x. |
| CVE-2026-106069 | high | 22, 24, 26 | TLS hostname check accepts a host that loosely resolves to an IP address. |
| CVE-2026-105481 | medium | 22, 24, 26 | A keep-alive socket can process a response written before the request was sent. |
| CVE-2026-106072 | medium | 22, 24, 26 | A non-canonical IPv4 hostname lets a DNS SAN authenticate an IP endpoint. |
| CVE-2026-106074 | medium | 22, 24, 26 | `crypto.randomUUID` and `randomInt` entropy caches are reused from startup snapshots and single-executable applications. |
| CVE-2026-106070 | low | 26 | `ZipFile` returns attacker-controlled prefix bytes after a failed ZIP header check. |
| CVE-2026-106071 | low | 26 | Permission-model filesystem over-grant via wildcard radix lookup. |
| CVE-2026-106073 | low | 22, 24, 26 | Permission-model bypass with `fs.realpathSync`. |

Source: https://nodejs.org/en/blog/vulnerability/october-2026-security-releases

CVE-2026-111497 is the issue public write-ups called Node2Shell. Express 5 and body-parser 2.x decompress `Content-Encoding: br` on request bodies. `fetch()` decompresses Brotli responses. Direct `node:zlib` Brotli calls do the same. Those packages are entry points, not the bug. pied raises a vulnerable Node finding from high to critical when one of them is in the same tree. There is no upstream workaround. Dropping inbound `Content-Encoding: br` does not cover `fetch()`.

When `otool -L` or `ldd` shows that a Node binary loads `libbrotlidec`, pied resolves that library and compares it with upstream Brotli 1.2.1, the 21 October 2026 release that fixes CVE-2026-111497. The Node version finding then omits that one CVE and keeps the others. A Node that vendors its own decoder is still judged by the Node version.

## Trust store

| ID | Severity | What it covers | Fixed in |
| --- | --- | --- | --- |
| GHSA-6q48-6c7w-9gw2 | high, CVSS 7.4 | certifi from 2019.3.9 up to, but not including, 2026.10.19 still ships emSign roots. pip before 26.2.2 vendors that bundle and loads it in addition to the system store. There is no separate pip GHSA; pied puts this identifier on certifi, pip, and ensurepip findings for that reason. | certifi 2026.10.19. pip 26.2.2 (Python 3.10 or newer). |
| GHSA-hq85-5cpj-mr62 | high | uv before 0.13.4 bundled a Mozilla CA store that still trusted the compromised chain. | uv 0.13.4. `UV_SYSTEM_CERTS=true` is a bridge only after the OS store is already patched. |
| CVE-2026-111943 | high | Go's `crypto/x509` accepts chains that use the eight compromised keys. A binary keeps the toolchain it was built with. pied reads that version from the Go buildinfo header on `--path` and on `pied host`. | Go 1.26.10 and 1.27.3. The fix blocks the keys by SPKI hash. Go 1.25 and older have no published fix. Rebuild existing binaries. |
| CVE-2026-91403 | high, CVSS 9.1 as reported by the incident tracker | Java JSSE still trusts the eight intermediates. | 8u511, 11.0.33, 17.0.21, 21.0.13, 25.0.5, 27.0.1, or a newer vendor build. |

certifi 2026.10.18 removed every emSign root. 2026.10.19 is the release Python told users to install, because it keeps the emSign roots that were not part of this incident. pied treats anything below 2026.10.19 as unfixed.

CPython security releases that bundle pip 26.2.2: 3.13.17, 3.14.9, 3.15.1. An existing virtualenv does not pick that up. 3.12 and older were not part of that ensurepip update. pied reports those pins as info.

These floors have no separate CVE in the catalog. pied still flags a version below them:

| Component | Fixed at | Why |
| --- | --- | --- |
| sigstore | 4.5.1 | Bundled roots. |
| conda | 26.9.4 | Bundled roots. |
| pixi | 0.82.1 | Bundled roots. |
| Deno | 2.9.8 | Bundled roots. |
| Bun | 1.4.4 | Brotli decoder and bundled roots. The finding carries CVE-2026-111497. |
| Electron | 42.11.16, 43.8.1, 44.9.1 | Chromium trust store. |
| rustls-webpki | 0.103.16 | WebPKI verifier. |
| webpki-root-certs | 1.0.10 | Root bundle. The `webpki-roots` crate is reported as info so a human can confirm the release. |
| Node bundled CA | NSS 3.131.1 | Shipped inside the Node releases above. Not a separate version pied parses. |

## Fingerprints

pied matches SHA-256 of the certificate DER. It reads PEM bundles, Debian `ca-certificates.conf` names, certificates embedded in a Go binary, and the stores Python's `ssl` module and Node's `tls.rootCertificates` actually load. It does not parse SPKI and it does not connect to the demonstration hosts. `curl -V` says which verifier a handshake would use: SecureTransport follows Apple's platform distrust from 22 October 2026, and an OpenSSL or LibreSSL curl follows a PEM bundle, which is reported on its own.

High: `emSign ECC Root CA - G3`, `emSign Root TLS CA - G3`, `emSign Root CS CA - G3`, and the sixteen intermediate certificates (eight keys, each issued by eMudhra and cross-signed by Sectigo).

Medium: `AAA Certificate Services`. It is the Sectigo cross-sign anchor. Mozilla and Chrome already stopped trusting it for websites. Deleting it also breaks unrelated certificates, so pied does not recommend that.

The eight SPKI hashes Go blocks, and the certificate fingerprints, are in `research/indicators.json`. Private-key scalars and certificate PEMs are not in this repository.

## Sources

- https://discuss.python.org/t/information-for-python-users-regarding-emudhra-emsign-ca-certificate-security-incident/109576
- https://github.com/advisories/GHSA-6q48-6c7w-9gw2
- https://github.com/advisories/GHSA-hq85-5cpj-mr62
- https://github.com/golang/go/issues/82345
- https://nodejs.org/en/blog/vulnerability/october-2026-security-releases
- https://www.aikido.dev/blog/node2shell-nodejs-brotli-rce-cve-2026-111497
- https://pwn.watch/i/emudhra-intermediate-ca-compromise
- https://emudhra.we-have-a-problem.com/
