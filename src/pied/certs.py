from __future__ import annotations

import base64
import hashlib
import re

from pied.advisories import INTERMEDIATE_FINGERPRINTS, ROOT_BY_FINGERPRINT
from pied.model import Finding


PEM_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----",
    re.DOTALL,
)

# Debian and Ubuntu list trust anchors by filename. A leading "!" disables one.
CONF_LINE = re.compile(
    r"(?m)^(!)?\s*(?:mozilla/)?([^\s#]*emSign_ECC_Root_CA_-_G3[^\s#]*|"
    r"[^\s#]*emSign_Root_TLS[^\s#]*|"
    r"[^\s#]*emSign_Root_CS[^\s#]*|"
    r"[^\s#]*Comodo_AAA_Services_root[^\s#]*|"
    r"[^\s#]*AAA_Certificate_Services[^\s#]*)"
)


def certificate_fingerprints(text: str) -> set[str]:
    found: set[str] = set()
    for body in PEM_RE.findall(text):
        try:
            der = base64.b64decode("".join(body.split()), validate=False)
        except (ValueError, TypeError):
            continue
        if not der:
            continue
        found.add(hashlib.sha256(der).hexdigest().upper())
    return found


def findings_for_fingerprints(location: str, fingerprints: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    for fingerprint in sorted(fingerprints):
        root = ROOT_BY_FINGERPRINT.get(fingerprint)
        if root:
            findings.append(
                Finding(
                    rule="EM-ROOT",
                    severity=root["severity"],
                    title=f"Trust bundle contains {root['name']}",
                    location=location,
                    evidence=f"SHA-256 {fingerprint}",
                    remediation=(
                        "Install the vendor CA update (certifi 2026.10.19, NSS 3.131.1, "
                        "a distro ca-certificates update, or the matching runtime release) "
                        "and restart every process that already loaded the bundle. "
                        "pied does not edit trust stores."
                    ),
                    advisory="https://emudhra.we-have-a-problem.com/",
                )
            )
            continue
        intermediate = INTERMEDIATE_FINGERPRINTS.get(fingerprint)
        if intermediate:
            findings.append(
                Finding(
                    rule="EM-INTERMEDIATE",
                    severity="high",
                    title=f"Trust bundle contains compromised intermediate {intermediate}",
                    location=location,
                    evidence=f"SHA-256 {fingerprint}",
                    remediation=(
                        "Remove this intermediate from the bundle or move it to the platform "
                        "distrust list, then install the vendor update. Revocation lists alone "
                        "do not protect clients that never check them."
                    ),
                    advisory="https://emudhra.we-have-a-problem.com/",
                )
            )
    return findings


def findings_for_pem(location: str, text: str) -> list[Finding]:
    return findings_for_fingerprints(location, certificate_fingerprints(text))


def findings_for_ca_conf(location: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for match in CONF_LINE.finditer(text):
        disabled = bool(match.group(1))
        name = match.group(2)
        if disabled:
            findings.append(
                Finding(
                    rule="EM-ROOT",
                    severity="ok",
                    title=f"CA config distrusts {name}",
                    location=location,
                    evidence=match.group(0).strip(),
                    remediation="No change required for this line.",
                    advisory="https://emudhra.we-have-a-problem.com/",
                )
            )
            continue
        findings.append(
            Finding(
                rule="EM-ROOT",
                severity="high",
                title=f"CA config still enables {name}",
                location=location,
                evidence=match.group(0).strip(),
                remediation=(
                    "Install the distribution ca-certificates update. "
                    "A leading '!' on this line is the temporary Debian/Ubuntu distrust mark; "
                    "pied will not rewrite the file."
                ),
                advisory="https://emudhra.we-have-a-problem.com/",
            )
        )
    return findings
