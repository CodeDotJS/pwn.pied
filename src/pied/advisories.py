from __future__ import annotations

import re
from dataclasses import dataclass

from pied.versions import parse_version, Version


# Floors are the first release each vendor says is fixed.
# certifi 2026.10.18 dropped every emSign root; 2026.10.19 is the release
# Python told users to install because it keeps the unaffected emSign roots.
CERTIFI_FLOOR = Version((2026, 10, 19))
PIP_FLOOR = Version((26, 2, 2))
UV_FLOOR = Version((0, 13, 4))
SIGSTORE_FLOOR = Version((4, 5, 1))
CONDA_FLOOR = Version((26, 9, 4))
PIXI_FLOOR = Version((0, 82, 1))
BUN_FLOOR = Version((1, 4, 4))
# Upstream Brotli 1.2.1, released 21 October 2026, is the fix for CVE-2026-111497
# when a Node binary loads libbrotlidec instead of the copy Node vendors.
BROTLI_FLOOR = Version((1, 2, 1))
DENO_FLOOR = Version((2, 9, 8))
RUSTLS_WEBPKI_FLOOR = Version((0, 103, 16))
WEBPKI_ROOT_CERTS_FLOOR = Version((1, 0, 10))
GO_126_FLOOR = Version((1, 26, 10))
GO_127_FLOOR = Version((1, 27, 3))

NODE_FLOORS = {
    22: Version((22, 23, 4)),
    24: Version((24, 22, 1)),
    26: Version((26, 12, 1)),
}
# These lines were already end of life on 21 Oct 2026 and did not get a patch.
NODE_EOL_MAJORS = set(range(0, 22)) | {23, 25}

ELECTRON_FLOORS = {
    42: Version((42, 11, 16)),
    43: Version((43, 8, 1)),
    44: Version((44, 9, 1)),
}

# Java builds named by the disclosure tracker. Comparison uses the
# major.minor.security tuple (the trailing vendor build is ignored).
JAVA_FLOORS = {
    8: Version((8, 0, 511)),
    11: Version((11, 0, 33)),
    17: Version((17, 0, 21)),
    21: Version((21, 0, 13)),
    25: Version((25, 0, 5)),
    27: Version((27, 0, 1)),
}

CPYTHON_ENSUREPIP = {
    13: Version((3, 13, 17)),
    14: Version((3, 14, 9)),
    15: Version((3, 15, 1)),
}

PYTHON_ANNOUNCEMENT = (
    "https://discuss.python.org/t/information-for-python-users-regarding-"
    "emudhra-emsign-ca-certificate-security-incident/109576"
)
NODE_ANNOUNCEMENT = "https://nodejs.org/en/blog/vulnerability/october-2026-security-releases"
DISCLOSURE = "https://emudhra.we-have-a-problem.com/"
GHSA_CERTIFI = "https://github.com/advisories/GHSA-6q48-6c7w-9gw2"
GHSA_UV = "https://github.com/advisories/GHSA-hq85-5cpj-mr62"
PWN_WATCH = "https://pwn.watch/i/emudhra-intermediate-ca-compromise"
AIKIDO = "https://www.aikido.dev/blog/node2shell-nodejs-brotli-rce-cve-2026-111497"

# Checksum-pinned wheel from the Python announcement. Used only as text
# the operator can run; pied never installs it.
PIP_BOOTSTRAP = (
    'python -m pip install "pip @ https://files.pythonhosted.org/packages/'
    "3f/06/3e4420302363fbb71be3c7f35ce042f54bfca330e3e66b3a2e3c4cca579f/"
    "pip-26.2.2-py3-none-any.whl"
    '#sha256=fd7f4dfa8190e014013b9f08f3e973f4e4c26ffd179a204895533a7254813a70"'
)

@dataclass(frozen=True)
class Advisory:
    """One published identifier. `lines` are Node majors the advisory names."""

    id: str
    severity: str
    title: str
    affected: str
    fixed: str
    url: str
    lines: tuple[int, ...] = ()
    eol: bool = False


# Node.js security release of 21 October 2026. `lines` is the set the
# Node.js blog says the issue affects. `eol` means unsupported lines are
# also treated as affected because Node does not patch them.
NODE_ADVISORIES: tuple[Advisory, ...] = (
    Advisory(
        "CVE-2026-111497",
        "high",
        "Brotli decoder out-of-bounds write permits remote code execution",
        "Node.js 22.x, 24.x, and 26.x before the 21 October 2026 release. 20.x, 23.x, 25.x, and older are end of life and get no fix. Bun before 1.4.4.",
        "Node.js 22.23.4, 24.22.1, 26.12.1. Bun 1.4.4.",
        NODE_ANNOUNCEMENT,
        (22, 24, 26),
        True,
    ),
    Advisory(
        "CVE-2026-105482",
        "high",
        "dns.resolve truncates names containing a NUL byte",
        "Node.js 22.x, 24.x, and 26.x before the 21 October 2026 release.",
        "Node.js 22.23.4, 24.22.1, 26.12.1.",
        NODE_ANNOUNCEMENT,
        (22, 24, 26),
    ),
    Advisory(
        "CVE-2026-105483",
        "high",
        "TLS certificate hostname bypass when the IP is written with fullwidth digits",
        "Node.js 24.x and 26.x before the 21 October 2026 release. Not listed for 22.x.",
        "Node.js 24.22.1, 26.12.1.",
        NODE_ANNOUNCEMENT,
        (24, 26),
    ),
    Advisory(
        "CVE-2026-106069",
        "high",
        "TLS certificate hostname bypass when the host loosely resolves to an IP address",
        "Node.js 22.x, 24.x, and 26.x before the 21 October 2026 release.",
        "Node.js 22.23.4, 24.22.1, 26.12.1.",
        NODE_ANNOUNCEMENT,
        (22, 24, 26),
    ),
    Advisory(
        "CVE-2026-105481",
        "medium",
        "Keep-alive socket processes a response written before the request was sent",
        "Node.js 22.x, 24.x, and 26.x before the 21 October 2026 release.",
        "Node.js 22.23.4, 24.22.1, 26.12.1.",
        NODE_ANNOUNCEMENT,
        (22, 24, 26),
    ),
    Advisory(
        "CVE-2026-106072",
        "medium",
        "Non-canonical IPv4 hostnames let a DNS SAN authenticate an IP endpoint",
        "Node.js 22.x, 24.x, and 26.x before the 21 October 2026 release.",
        "Node.js 22.23.4, 24.22.1, 26.12.1.",
        NODE_ANNOUNCEMENT,
        (22, 24, 26),
    ),
    Advisory(
        "CVE-2026-106074",
        "medium",
        "crypto.randomUUID and randomInt entropy caches are reused from startup snapshots and single-executable applications",
        "Node.js 22.x, 24.x, and 26.x before the 21 October 2026 release.",
        "Node.js 22.23.4, 24.22.1, 26.12.1.",
        NODE_ANNOUNCEMENT,
        (22, 24, 26),
    ),
    Advisory(
        "CVE-2026-106070",
        "low",
        "ZipFile returns attacker-controlled prefix bytes after a failed ZIP header check",
        "Node.js 26.x before 26.12.1.",
        "Node.js 26.12.1.",
        NODE_ANNOUNCEMENT,
        (26,),
    ),
    Advisory(
        "CVE-2026-106071",
        "low",
        "Permission model filesystem over-grant via wildcard radix lookup",
        "Node.js 26.x before 26.12.1.",
        "Node.js 26.12.1.",
        NODE_ANNOUNCEMENT,
        (26,),
    ),
    Advisory(
        "CVE-2026-106073",
        "low",
        "Permission model bypass with fs.realpathSync",
        "Node.js 22.x, 24.x, and 26.x before the 21 October 2026 release.",
        "Node.js 22.23.4, 24.22.1, 26.12.1.",
        NODE_ANNOUNCEMENT,
        (22, 24, 26),
    ),
)

OTHER_ADVISORIES: tuple[Advisory, ...] = (
    Advisory(
        "GHSA-6q48-6c7w-9gw2",
        "high",
        "certifi bundles emSign roots whose intermediate keys were compromised",
        "certifi 2019.3.9 up to, but not including, 2026.10.19. pip before 26.2.2 vendors that bundle and loads it in addition to the system trust store.",
        "certifi 2026.10.19. pip 26.2.2. CVSS 7.4 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N).",
        GHSA_CERTIFI,
    ),
    Advisory(
        "GHSA-hq85-5cpj-mr62",
        "high",
        "uv bundled a Mozilla CA store that still trusted the compromised eMudhra chain",
        "uv before 0.13.4.",
        "uv 0.13.4.",
        GHSA_UV,
    ),
    Advisory(
        "CVE-2026-111943",
        "high",
        "Go crypto/x509 accepts chains that use the compromised eMudhra intermediate keys",
        "Go 1.26 before 1.26.10 and Go 1.27 before 1.27.3. Go 1.25 and older have no published fix. Rebuilding is required.",
        "Go 1.26.10 and 1.27.3. The fix blocks the eight keys by SPKI hash.",
        "https://github.com/golang/go/issues/82345",
    ),
    Advisory(
        "CVE-2026-91403",
        "high",
        "Java JSSE still trusts the eight compromised eMudhra intermediates",
        "Oracle and OpenJDK builds before the October 2026 CPU. CVSS 9.1 as reported by the incident tracker.",
        "8u511, 11.0.33.0.2, 17.0.21.0.2, 21.0.13.0.2, 25.0.5.0.2, 27.0.1.0.2, or a newer vendor build.",
        DISCLOSURE,
    ),
)

ALL_ADVISORIES: tuple[Advisory, ...] = NODE_ADVISORIES + OTHER_ADVISORIES

# Identifiers that are not specific to one Node release line.
RULE_CVES: dict[str, tuple[str, ...]] = {
    "EM-CERTIFI": ("GHSA-6q48-6c7w-9gw2",),
    "EM-PIP": ("GHSA-6q48-6c7w-9gw2",),
    "EM-ENSUREPIP": ("GHSA-6q48-6c7w-9gw2",),
    "EM-UV": ("GHSA-hq85-5cpj-mr62",),
    "EM-GO": ("CVE-2026-111943",),
    "EM-JAVA": ("CVE-2026-91403",),
    "BUN-1.4.4": ("CVE-2026-111497",),
    "N2S-EXPOSURE": ("CVE-2026-111497",),
    "N2S-LIBBROTLI": ("CVE-2026-111497",),
}

# Node 22's release codename, from the 22.23.4 release notes.
_NODE_CODENAMES = {"jod": 22}


def node_cves(text: str, *, bundled_brotli: bool = True) -> tuple[str, ...]:
    """CVE ids that apply to the Node line named in `text`.

    An unpinned spec gets the full October release set. An end-of-life major
    gets only CVE-2026-111497, which is the issue vendors said those lines
    will not receive a fix for. When the binary loads libbrotlidec,
    CVE-2026-111497 is reported on that library instead.
    """
    major = _node_major(text)
    chosen: list[str] = []
    for item in NODE_ADVISORIES:
        if item.id == "CVE-2026-111497" and not bundled_brotli:
            continue
        if major is None:
            chosen.append(item.id)
        elif major in item.lines:
            chosen.append(item.id)
        elif item.eol and major in NODE_EOL_MAJORS:
            chosen.append(item.id)
    return tuple(chosen)


def _node_major(text: str) -> int | None:
    """Return the Node major when the text names one release line.

    `lts/jod` is Node 22. An unbounded `>=` range, or a tag with no version,
    can resolve onto more than one line, so the caller reports every CVE in
    the October release.
    """
    lowered = text.lower()
    for name, major in _NODE_CODENAMES.items():
        if re.search(rf"lts/{name}\b", lowered):
            return major
    if re.search(r">=?", text) and "<" not in text:
        return None
    version = parse_version(text)
    if version is None:
        return None
    return version.major


def attach_identifiers(finding) -> None:
    """Fill `finding.cves` from the catalog. Safe to call more than once."""
    if finding.cves:
        return
    if finding.rule == "NODE-2026-10-21":
        finding.cves = node_cves(f"{finding.title}\n{finding.evidence}")
        return
    finding.cves = RULE_CVES.get(finding.rule, ())

# Certificate SHA-256 values published by the disclosure site.
# These identify public certificates already in trust bundles.
# Private key material is intentionally not stored.
ROOTS = (
    {
        "name": "emSign ECC Root CA - G3",
        "sha256": "86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B",
        "severity": "high",
        "detail": (
            "Mozilla-trusted root that cross-signs emSign Root TLS CA - G3. "
            "A bundle that still contains it can build a chain to the compromised TLS intermediates."
        ),
    },
    {
        "name": "emSign Root TLS CA - G3",
        "sha256": "7DD78D5F4F13459A83DFF9ABBBA62EDBAF6F2D102BF257FD712F4D9F2746ED8D",
        "severity": "high",
        "detail": "Direct issuer of the six compromised TLS intermediates.",
    },
    {
        "name": "emSign Root CS CA - G3",
        "sha256": "F2EDAAFF3D9B701FB4D14C9F285F8C0BAD90FC3BCC1FA07D47F4718EDABA34A5",
        "severity": "high",
        "detail": "Direct issuer of the two compromised code-signing intermediates. Microsoft trusted this root for code signing.",
    },
    {
        "name": "AAA Certificate Services",
        "sha256": "D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4",
        "severity": "medium",
        "detail": (
            "Sectigo root that cross-signed all eight intermediates. "
            "Mozilla and Chrome stopped trusting it for websites in April 2025; "
            "Apple and many OS bundles still ship it. Removing it also breaks unrelated certificates."
        ),
    },
)

# Sixteen public certificates: eight keys, each issued once by eMudhra and once by Sectigo.
INTERMEDIATE_FINGERPRINTS = {
    "42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493": "EM DV TLS CA - G3B (eMudhra)",
    "45A883F349AEDFD5F3A649B5498FFB121712BA8B448F3F2A91DBC5A766FCDDBE": "EM DV TLS CA - G3B (Sectigo cross-sign)",
    "98B896625C0C230ADEEC3EB2CF6AAD5001ECF9156A68644E82374CE5833BC25B": "EM OV TLS CA - G3B (eMudhra)",
    "5F1DED4DD590AF74631290CF073B122A2AAC6A1FA479778A0BD43579BD832699": "EM OV TLS CA - G3B (Sectigo cross-sign)",
    "E7568FE6E12331F4FD7DE61DA4C7559D0F8EB192A218D4741A3BA75184333838": "EM EV TLS CA - G3B (eMudhra)",
    "579480AEA166290BD3C643589E795FC0D0E54E86505D180F1DFF99EFD3199512": "EM EV TLS CA - G3B (Sectigo cross-sign)",
    "0164D7CEAE5BB909C272AF151FF44B1177AE9B47D9424B94F1D9558C30934D19": "EM DV TLS CA - G3C (eMudhra)",
    "62B7F9868263F72F6911FC78CEAF72C1979158B7368BF648683BB2AA39B02E72": "EM DV TLS CA - G3C (Sectigo cross-sign)",
    "CB6E15165AC802E9B3F993F16C25D41F4E81C21EBDE71AE1B012AC00BF9C7C3F": "EM OV TLS CA - G3C (eMudhra)",
    "7485B51C0ED192878FA1D2F948FB529AE1842CC5086C4B67F7BE5B2039DE9489": "EM OV TLS CA - G3C (Sectigo cross-sign)",
    "432EC25F0D28DE9006D97BF752F17BBB2CD41F669933FCB072D9A1148D0261F3": "EM EV TLS CA - G3C (eMudhra)",
    "FD9D5C2DBBD4995AB69B8D50C439D9527B00529199C2FD01B2174EB58F07021F": "EM EV TLS CA - G3C (Sectigo cross-sign)",
    "9E39DE2881273ACC225A149C72BA3E0F51424963669AB633EE1DC7DF5DB067B4": "EM OV CS CA - G3B (eMudhra)",
    "A496E23AC0CAB8155FC9B117B97EAE368EFCBB9041AEC8804D5A308D2D01C2D8": "EM OV CS CA - G3B (Sectigo cross-sign)",
    "4B2460A466F95FD40113BCDCCA2CEB29B3B093921DE45474DA7DF48874C630B1": "EM OV CS CA - G3C (eMudhra)",
    "84112972B8E59D14560AE7E7119654474AAD119990CF3722BFC1E3B91615E1FD": "EM OV CS CA - G3C (Sectigo cross-sign)",
}

ROOT_BY_FINGERPRINT = {item["sha256"]: item for item in ROOTS}

DATA_AS_OF = "2026-10-23"
