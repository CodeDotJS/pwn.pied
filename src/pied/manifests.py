from __future__ import annotations

import json
import re

from pied.advisories import (
    AIKIDO,
    attach_identifiers,
    BUN_FLOOR,
    CERTIFI_FLOOR,
    CONDA_FLOOR,
    CPYTHON_ENSUREPIP,
    DENO_FLOOR,
    DISCLOSURE,
    ELECTRON_FLOORS,
    GHSA_CERTIFI,
    NODE_ANNOUNCEMENT,
    PIP_BOOTSTRAP,
    PIP_FLOOR,
    PIXI_FLOOR,
    PYTHON_ANNOUNCEMENT,
    RUSTLS_WEBPKI_FLOOR,
    SIGSTORE_FLOOR,
    UV_FLOOR,
    WEBPKI_ROOT_CERTS_FLOOR,
)
from pied.certs import findings_for_ca_conf, findings_for_pem
from pied.model import Finding
from pied.versions import (
    Version,
    classify_electron,
    classify_go,
    classify_minimum,
    classify_node,
    parse_version,
)


STATUS_SEVERITY = {
    "vulnerable": "high",
    "floating": "medium",
    "unknown": "info",
    "patched": "ok",
}

MANIFEST_RE = re.compile(
    r"(?i)(?:^|/)(?:"
    r"[^/]*requirements[^/]*\.txt|"
    r"constraints[^/]*\.txt|"
    r"pyproject\.toml|poetry\.lock|uv\.lock|pdm\.lock|pipfile|pipfile\.lock|"
    r"setup\.cfg|setup\.py|pixi\.toml|pixi\.lock|"
    r"environment\.ya?ml|conda-lock\.ya?ml|"
    r"package\.json|package-lock\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lock|"
    r"\.nvmrc|\.node-version|\.python-version|\.tool-versions|"
    r"go\.mod|cargo\.lock|cargo\.toml|"
    r"dockerfile(?:\..*)?|[^/]*\.dockerfile|"
    r"docker-compose[^/]*\.ya?ml|compose\.ya?ml|"
    r"cacert\.pem|ca-certificates\.crt|cert\.pem|ca-certificates\.conf"
    r")$"
)
WORKFLOW_RE = re.compile(r"(?i)(?:^|/)\.github/workflows/[^/]+\.ya?ml$")
PRUNE_PARTS = {
    ".git",
    "node_modules",
    "site-packages",
    "__pycache__",
    ".tox",
    ".nox",
    "dist",
    "build",
    ".next",
    "vendor",
    ".venv",
    "venv",
}

REQ_LINE = re.compile(
    r"(?i)^(?P<name>certifi|pip|sigstore|uv|pixi|conda)\s*(?:\[[^\]]+\])?\s*(?P<spec>\S*)"
)
QUOTED_DEP = re.compile(
    r"(?i)[\"'](?P<name>certifi|pip|sigstore|uv|pixi|electron)(?P<spec>[^\"']*)[\"']"
)
ASSIGN_DEP = re.compile(
    r"(?im)^(?P<name>certifi|pip|sigstore|uv|pixi)\s*=\s*[\"'](?P<spec>[^\"']+)[\"']"
)
CONDA_FILE = re.compile(r"(?i)\b(?P<name>certifi|pip)-(?P<version>\d+\.\d+\.\d+)\b")
LOCK_SPLIT = re.compile(r"(?m)^\[\[package\]\]\s*$")
LOCK_NAME = re.compile(r'(?m)^name\s*=\s*"(?P<name>[^"]+)"')
LOCK_VERSION = re.compile(r'(?m)^version\s*=\s*"(?P<version>[^"]+)"')
FROM_RE = re.compile(r"(?im)^\s*FROM\s+(?P<ref>\S+)")
IMAGE_KEY = re.compile(r"(?im)^[^\S\n]*image:\s*[\"']?(?P<ref>[^\s\"'#]+)")
PIP_PIN = re.compile(r"(?i)\bpip3?\s*(?P<op>==|>=|~=|<=|<)\s*(?P<ver>[^\s\\'\"]+)")
PIP_UPGRADE = re.compile(r"(?i)(?:--upgrade|-U)\s+pip3?\b")
NODE_KEY = re.compile(r"(?im)^[^\S\n]*node-version:\s*[\"']?(?P<value>[^\"'#\n]+)")
GO_KEY = re.compile(r"(?im)^[^\S\n]*go-version:\s*[\"']?(?P<value>[^\"'#\n]+)")
TOOL_LINE = re.compile(
    r"(?im)^(?P<name>nodejs|node|golang|go|uv|bun|deno|python)\s+(?P<value>\S+)"
)
TOOLCHAIN = re.compile(r"(?m)^toolchain\s+go(?P<version>\S+)")
GO_DIRECTIVE = re.compile(r"(?m)^go\s+(?P<version>\d+\.\d+(?:\.\d+)?)")
LOCK_JS = re.compile(
    r'"(?:node_modules/)?(?P<name>express|body-parser)"\s*:\s*\{'
)
YARN_LOCK = re.compile(
    r"(?m)^(?P<name>express|body-parser)@[^:\n]*:\n(?:[ \t].*\n)*?[ \t]+version \"(?P<version>[^\"]+)\""
)
PNPM_LOCK = re.compile(r"(?m)^(?P<name>express|body-parser)@(?P<version>\d+\.\d+\.\d+)")


PYTHON_PACKAGES = {
    "certifi": (CERTIFI_FLOOR, "EM-CERTIFI", GHSA_CERTIFI),
    "pip": (PIP_FLOOR, "EM-PIP", PYTHON_ANNOUNCEMENT),
    "sigstore": (SIGSTORE_FLOOR, "EM-SIGSTORE", PYTHON_ANNOUNCEMENT),
    "uv": (UV_FLOOR, "EM-UV", PYTHON_ANNOUNCEMENT),
    "pixi": (PIXI_FLOOR, "EM-PIXI", PYTHON_ANNOUNCEMENT),
    "conda": (CONDA_FLOOR, "EM-CONDA", PYTHON_ANNOUNCEMENT),
}


def is_manifest(path: str) -> bool:
    normalized = path.replace("\\", "/")
    parts = set(normalized.split("/"))
    if parts & PRUNE_PARTS:
        return False
    return bool(MANIFEST_RE.search(normalized) or WORKFLOW_RE.search(normalized))


def finalize(findings: list[Finding]) -> list[Finding]:
    unique: list[Finding] = []
    seen: set[tuple[str, str, str, str]] = set()
    for finding in findings:
        attach_identifiers(finding)
        key = (finding.rule, finding.location, finding.evidence, finding.title)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    exposure = any(
        finding.rule == "N2S-EXPOSURE" and finding.severity in {"medium", "high", "critical"}
        for finding in unique
    )
    if not exposure:
        return unique
    for finding in unique:
        if finding.rule != "NODE-2026-10-21":
            continue
        if finding.severity == "high":
            finding.severity = "critical"
            if "Brotli entry point" not in finding.title:
                finding.title += ", and a Brotli entry point is in this tree"
        elif finding.severity == "medium":
            finding.severity = "high"
    return unique


def scan_text(path: str, text: str, *, include_ok: bool = False) -> list[Finding]:
    normalized = path.replace("\\", "/")
    base = normalized.rsplit("/", 1)[-1].lower()
    findings: list[Finding] = []
    if base.endswith(".pem") or base in {"ca-certificates.crt", "cert.pem"}:
        findings.extend(findings_for_pem(path, text))
    elif base == "ca-certificates.conf":
        findings.extend(findings_for_ca_conf(path, text))
    elif base == "package.json":
        findings.extend(_package_json(path, text, include_ok))
    elif base in {"package-lock.json"}:
        findings.extend(_js_lock_objects(path, text))
    elif base == "yarn.lock":
        findings.extend(_yarn(path, text))
    elif base == "pnpm-lock.yaml":
        findings.extend(_pnpm(path, text))
    elif base in {"poetry.lock", "uv.lock", "pdm.lock", "cargo.lock"}:
        findings.extend(_toml_lock(path, text, include_ok))
    elif base in {"go.mod"}:
        findings.extend(_go_mod(path, text))
    elif base in {".nvmrc", ".node-version"}:
        findings.extend(_node_spec(path, text.strip(), "runtime file", include_ok))
    elif base == ".python-version":
        findings.extend(_cpython_pin(path, text.strip()))
    elif base == "cargo.toml":
        findings.extend(_cargo_manifest(path, text, include_ok))
    elif base == ".tool-versions":
        findings.extend(_tool_versions(path, text, include_ok))
    elif "dockerfile" in base or base.endswith(".dockerfile"):
        findings.extend(_dockerfile(path, text, include_ok))
    elif WORKFLOW_RE.search(normalized) or "docker-compose" in base or base.startswith("compose."):
        findings.extend(_workflow(path, text, include_ok))
        findings.extend(_dockerfile(path, text, include_ok))
    if _is_python_manifest(base):
        findings.extend(_python_pins(path, text, include_ok))
    if base in {"environment.yml", "environment.yaml", "pixi.lock", "conda-lock.yml", "conda-lock.yaml"}:
        findings.extend(_conda_filenames(path, text, include_ok))
    if not include_ok:
        findings = [finding for finding in findings if finding.severity != "ok"]
    return findings


def _is_python_manifest(base: str) -> bool:
    return (
        base in {"pyproject.toml", "setup.cfg", "setup.py", "pipfile", "pixi.toml"}
        or base.endswith("requirements.txt")
        or base.startswith("requirements")
        or "constraints" in base
    )


def _emit_status(
    status: str,
    *,
    rule: str,
    title: str,
    location: str,
    evidence: str,
    remediation: str,
    advisory: str,
    include_ok: bool,
    vulnerable_title: str | None = None,
    floating_title: str | None = None,
) -> Finding | None:
    if status == "patched" and not include_ok:
        return None
    if status == "ok" and not include_ok:
        return None
    severity = STATUS_SEVERITY.get(status, "info")
    if status == "vulnerable" and vulnerable_title:
        title = vulnerable_title
    elif status == "floating" and floating_title:
        title = floating_title
    elif status == "patched":
        title = title + " is at or above the fixed release"
        severity = "ok"
    return Finding(rule, severity, title, location, evidence, remediation, advisory)


def _python_pins(path: str, text: str, include_ok: bool) -> list[Finding]:
    findings: list[Finding] = []
    base = path.rsplit("/", 1)[-1].lower()
    lines: list[tuple[str, str, str]] = []
    if base.endswith(".txt") or "constraints" in base or base == "pipfile":
        for raw in text.splitlines():
            stripped = raw.split("#", 1)[0].strip()
            if not stripped or stripped.startswith("-"):
                continue
            match = REQ_LINE.match(stripped)
            if match:
                lines.append((match.group("name").lower(), match.group("spec"), stripped))
    else:
        for match in QUOTED_DEP.finditer(text):
            lines.append((match.group("name").lower(), match.group("spec").strip(), match.group(0)))
        for match in ASSIGN_DEP.finditer(text):
            lines.append((match.group("name").lower(), match.group("spec").strip(), match.group(0)))
    for name, spec, evidence in lines:
        package = PYTHON_PACKAGES.get(name)
        if package is None:
            continue
        floor, rule, advisory = package
        status = classify_minimum(spec or "*", floor)
        finding = _emit_status(
            status,
            rule=rule,
            title=f"{name} {spec or '(unpinned)'}".strip(),
            vulnerable_title=f"{name} {spec or '(unpinned)'} is below {floor}",
            floating_title=f"{name} is not pinned to {floor} or newer",
            location=path,
            evidence=evidence.strip(),
            remediation=_python_remediation(name, floor),
            advisory=advisory,
            include_ok=include_ok,
        )
        if finding:
            findings.append(finding)
    return findings


def _python_remediation(name: str, floor: Version) -> str:
    if name == "pip":
        return (
            "Upgrade every virtualenv, not just the OS trust store. "
            f"pip before {floor} keeps trusting the compromised intermediates through its vendored certifi. "
            f"Bootstrap with the checksum from the Python announcement, then upgrade certifi: {PIP_BOOTSTRAP}"
        )
    if name == "uv":
        return (
            f"Upgrade uv to {floor} or newer. If the OS trust store is already patched, "
            "`UV_SYSTEM_CERTS=true uv self update` avoids the copy of the roots bundled in the old uv."
        )
    return (
        f"Upgrade {name} to {floor} or newer and rebuild container images with layer cache disabled. "
        "An OS ca-certificates update does not replace a copy vendored in the environment."
    )


def _conda_filenames(path: str, text: str, include_ok: bool) -> list[Finding]:
    findings: list[Finding] = []
    for match in CONDA_FILE.finditer(text):
        name = match.group("name").lower()
        package = PYTHON_PACKAGES.get(name)
        if package is None:
            continue
        floor, rule, advisory = package
        status = classify_minimum(match.group("version"), floor)
        finding = _emit_status(
            status,
            rule=rule,
            title=f"{name} {match.group('version')}",
            vulnerable_title=f"{name} {match.group('version')} is below {floor}",
            location=path,
            evidence=match.group(0),
            remediation=_python_remediation(name, floor),
            advisory=advisory,
            include_ok=include_ok,
        )
        if finding:
            findings.append(finding)
    return findings


def _package_json(path: str, text: str, include_ok: bool) -> list[Finding]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        return [
            Finding(
                "PARSE",
                "info",
                "package.json did not parse",
                path,
                str(exc),
                "Fix the JSON so the scanner can see engines and dependencies.",
                NODE_ANNOUNCEMENT,
            )
        ]
    if not isinstance(data, dict):
        return []
    findings: list[Finding] = []
    engines = data.get("engines") or {}
    node_spec = engines.get("node") if isinstance(engines, dict) else None
    node_status = None
    if isinstance(node_spec, str):
        node_status = classify_node(node_spec)
        finding = _node_finding(path, node_spec, node_status, "package.json engines.node", include_ok)
        if finding:
            findings.append(finding)
    deps: dict[str, str] = {}
    for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        value = data.get(key) or {}
        if isinstance(value, dict):
            deps.update({str(name): str(spec) for name, spec in value.items()})
    express = deps.get("express")
    body = deps.get("body-parser")
    if express is not None:
        findings.extend(_exposure(path, "express", express, 5, node_status))
    if body is not None:
        findings.extend(_exposure(path, "body-parser", body, 2, node_status))
    electron = deps.get("electron")
    if electron is not None:
        status = classify_electron(electron)
        floor_text = ", ".join(f"{major}.x >= {floor}" for major, floor in sorted(ELECTRON_FLOORS.items()))
        finding = _emit_status(
            status,
            rule="EM-ELECTRON",
            title=f"electron {electron}",
            vulnerable_title=f"electron {electron} is below the eMudhra fix ({floor_text})",
            floating_title="electron is not pinned to a release that dropped the eMudhra roots",
            location=path,
            evidence=f"electron: {electron}",
            remediation="Upgrade Electron to 44.9.1, 43.8.1, or 42.11.16, or a newer patch on that major.",
            advisory=DISCLOSURE,
            include_ok=include_ok,
        )
        if finding:
            findings.append(finding)
    return findings


def _exposure(path: str, name: str, spec: str, major: int, node_status: str | None) -> list[Finding]:
    state = _exposes_major(spec, major)
    if state == "no":
        return []
    if node_status == "patched":
        severity = "info"
        title = f"{name} {spec} decompresses Brotli, and engines.node is on a patched line"
    else:
        severity = "medium"
        title = f"{name} {spec} decompresses attacker-controlled Brotli when the runtime is unpatched"
    return [
        Finding(
            rule="N2S-EXPOSURE",
            severity=severity,
            title=title,
            location=path,
            evidence=f"{name}@{spec}",
            remediation=(
                "The bug is in the Node.js runtime, not this package. "
                "Upgrade Node.js to 22.23.4, 24.22.1, or 26.12.1 or newer on that line. "
                "Rejecting Content-Encoding: br at a proxy only covers inbound requests, not fetch() responses."
            ),
            advisory=AIKIDO,
        )
    ]


def _exposes_major(spec: str, major: int) -> str:
    text = spec.strip().strip("'\"")
    if text in {"*", "latest", "x"}:
        return "unknown"
    version = parse_version(text)
    if version is None:
        return "unknown"
    if text.startswith((">=", ">")) and version.major < major:
        return "unknown"
    return "yes" if version.major >= major else "no"


def _node_spec(path: str, spec: str, where: str, include_ok: bool) -> list[Finding]:
    status = classify_node(spec)
    finding = _node_finding(path, spec, status, where, include_ok)
    return [finding] if finding else []


def _node_finding(path: str, spec: str, status: str, where: str, include_ok: bool) -> Finding | None:
    return _emit_status(
        status,
        rule="NODE-2026-10-21",
        title=f"Node.js {spec}",
        vulnerable_title=f"Node.js {spec} is below the 21 Oct 2026 security release",
        floating_title=f"Node.js {spec} does not pin a patched patch release",
        location=path,
        evidence=f"{where}: {spec}",
        remediation=(
            "Install Node.js 22.23.4, 24.22.1, or 26.12.1, or a newer patch on that line. "
            "20.x, 23.x, 25.x and older have no fix for CVE-2026-111497. "
            "Rebuild images after the pin changes. The same releases update the bundled CA store to NSS 3.131.1. "
            "The ids on this finding are the CVEs Node says apply to this release line."
        ),
        advisory=NODE_ANNOUNCEMENT,
        include_ok=include_ok,
    )


def _js_lock_objects(path: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for match in LOCK_JS.finditer(text):
        window = text[match.end() : match.end() + 400]
        version = re.search(r'"version"\s*:\s*"([^"]+)"', window)
        if not version:
            continue
        name = match.group("name")
        major = 5 if name == "express" else 2
        findings.extend(_exposure(path, name, version.group(1), major, None))
    return findings


def _yarn(path: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for match in YARN_LOCK.finditer(text):
        major = 5 if match.group("name") == "express" else 2
        findings.extend(_exposure(path, match.group("name"), match.group("version"), major, None))
    return findings


def _pnpm(path: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for match in PNPM_LOCK.finditer(text):
        major = 5 if match.group("name") == "express" else 2
        findings.extend(_exposure(path, match.group("name"), match.group("version"), major, None))
    return findings


def _toml_lock(path: str, text: str, include_ok: bool) -> list[Finding]:
    findings: list[Finding] = []
    for block in LOCK_SPLIT.split(text)[1:]:
        name_match = LOCK_NAME.search(block)
        version_match = LOCK_VERSION.search(block)
        if not name_match or not version_match:
            continue
        name = name_match.group("name")
        version = version_match.group("version")
        lowered = name.lower()
        if lowered in PYTHON_PACKAGES:
            floor, rule, advisory = PYTHON_PACKAGES[lowered]
            status = classify_minimum(version, floor)
            finding = _emit_status(
                status,
                rule=rule,
                title=f"{lowered} {version}",
                vulnerable_title=f"lockfile {lowered} {version} is below {floor}",
                location=path,
                evidence=f'{lowered} = "{version}"',
                remediation=_python_remediation(lowered, floor),
                advisory=advisory,
                include_ok=include_ok,
            )
            if finding:
                findings.append(finding)
        elif name == "express":
            findings.extend(_exposure(path, name, version, 5, None))
        elif name == "body-parser":
            findings.extend(_exposure(path, name, version, 2, None))
        elif name == "electron":
            status = classify_electron(version)
            finding = _emit_status(
                status,
                rule="EM-ELECTRON",
                title=f"electron {version}",
                vulnerable_title=f"lockfile electron {version} is below the eMudhra fix",
                location=path,
                evidence=f'electron = "{version}"',
                remediation="Upgrade Electron to 44.9.1, 43.8.1, or 42.11.16 or newer on that major.",
                advisory=DISCLOSURE,
                include_ok=include_ok,
            )
            if finding:
                findings.append(finding)
        elif name == "rustls-webpki":
            findings.extend(
                _floor_package(
                    path, name, version, RUSTLS_WEBPKI_FLOOR, "EM-RUSTLS", include_ok,
                    "Upgrade rustls-webpki to 0.103.16 or newer and rebuild.",
                )
            )
        elif name == "webpki-root-certs":
            findings.extend(
                _floor_package(
                    path, name, version, WEBPKI_ROOT_CERTS_FLOOR, "EM-WEBPKI", include_ok,
                    "Upgrade webpki-root-certs to 1.0.10 or newer and rebuild.",
                )
            )
        elif name == "webpki-roots":
            findings.append(
                Finding(
                    "EM-WEBPKI",
                    "info",
                    f"webpki-roots {version} is present",
                    path,
                    f'webpki-roots = "{version}"',
                    "Confirm this crate release dropped the eMudhra roots. The published fix line is webpki-root-certs 1.0.10 and rustls-webpki 0.103.16.",
                    DISCLOSURE,
                )
            )
    return findings


def _floor_package(
    path: str,
    name: str,
    version: str,
    floor: Version,
    rule: str,
    include_ok: bool,
    remediation: str,
) -> list[Finding]:
    status = classify_minimum(version, floor)
    finding = _emit_status(
        status,
        rule=rule,
        title=f"{name} {version}",
        vulnerable_title=f"{name} {version} is below {floor}",
        location=path,
        evidence=f'{name} = "{version}"',
        remediation=remediation,
        advisory=DISCLOSURE,
        include_ok=include_ok,
    )
    return [finding] if finding else []


def _go_mod(path: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    toolchain = TOOLCHAIN.search(text)
    if toolchain:
        version = toolchain.group("version")
        status = classify_go(version)
        if status == "vulnerable":
            findings.append(_go_finding(path, version, "high", "toolchain directive"))
        elif status == "floating":
            findings.append(_go_finding(path, version, "medium", "toolchain directive"))
    directive = GO_DIRECTIVE.search(text)
    if directive:
        version = directive.group("version")
        status = classify_go(version)
        if status == "vulnerable":
            findings.append(
                Finding(
                    "EM-GO",
                    "info",
                    f"go.mod language version is go {version}",
                    path,
                    f"go {version}",
                    "The go line is the language version, not the toolchain that compiled the binary. "
                    "Rebuild with Go 1.26.10 or 1.27.3 or newer (CVE-2026-111943). "
                    "An already-built binary keeps the old roots until it is rebuilt.",
                    DISCLOSURE,
                )
            )
    return findings


_CARGO_DEP = re.compile(
    r'(?m)^(?P<name>rustls-webpki|webpki-root-certs|webpki-roots)\s*=\s*'
    r'(?:\{[^}\n]*\bversion\s*=\s*"(?P<inline>[^"]+)"|"(?P<plain>[^"]+)")'
)


def _cargo_manifest(path: str, text: str, include_ok: bool) -> list[Finding]:
    findings: list[Finding] = []
    for match in _CARGO_DEP.finditer(text):
        name = match.group("name")
        version = match.group("inline") or match.group("plain")
        if name == "rustls-webpki":
            findings.extend(
                _floor_package(
                    path, name, version, RUSTLS_WEBPKI_FLOOR, "EM-RUSTLS", include_ok,
                    "Upgrade rustls-webpki to 0.103.16 or newer and rebuild.",
                )
            )
        elif name == "webpki-root-certs":
            findings.extend(
                _floor_package(
                    path, name, version, WEBPKI_ROOT_CERTS_FLOOR, "EM-WEBPKI", include_ok,
                    "Upgrade webpki-root-certs to 1.0.10 or newer and rebuild.",
                )
            )
        else:
            findings.append(
                Finding(
                    "EM-WEBPKI",
                    "info",
                    f"webpki-roots {version} is present",
                    path,
                    f'{name} = "{version}"',
                    "Confirm this crate release dropped the eMudhra roots. The published fix line is webpki-root-certs 1.0.10 and rustls-webpki 0.103.16.",
                    DISCLOSURE,
                )
            )
    return findings


def _cpython_pin(path: str, text: str, *, where: str = ".python-version") -> list[Finding]:
    spec = ""
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            spec = line.split()[0]
            break
    version = parse_version(spec)
    if version is None or len(version.parts) < 2 or version.parts[0] != 3:
        return []
    minor = version.parts[1]
    floor = CPYTHON_ENSUREPIP.get(minor)
    if floor is None:
        if minor < 13:
            needs = "pip 26.2.2 requires Python 3.10 or newer." if minor < 10 else "Upgrade pip to 26.2.2 inside each environment."
            return [
                Finding(
                    "EM-ENSUREPIP",
                    "info",
                    f"CPython {spec} has no October 2026 ensurepip security release",
                    path,
                    f"{where}: {spec}",
                    "This line was not part of the 3.13.17 / 3.14.9 / 3.15.1 ensurepip updates. "
                    f"A new virtualenv can still install an old pip. {needs}",
                    PYTHON_ANNOUNCEMENT,
                )
            ]
        return []
    if len(version.parts) < 3 or version < floor:
        shown = spec if len(version.parts) >= 3 else f"{spec} (patch not pinned)"
        return [
            Finding(
                "EM-ENSUREPIP",
                "info",
                f"CPython {shown} is below the ensurepip security release {floor}",
                path,
                f"{where}: {spec}",
                f"CPython {floor} bundles pip 26.2.2. An environment that already exists does not pick that up until pip is upgraded.",
                PYTHON_ANNOUNCEMENT,
            )
        ]
    return []


def _go_finding(path: str, version: str, severity: str, where: str) -> Finding:
    return Finding(
        "EM-GO",
        severity,
        f"Go {version} is below the eMudhra fix" if severity == "high" else f"Go {version} is not pinned to a patched toolchain",
        path,
        f"{where}: {version}",
        "Rebuild with Go 1.26.10 or 1.27.3 or newer. Go 1.25 and older have no published fix. "
        "The release blocks the eight compromised keys (CVE-2026-111943). Updating the OS store does not rewrite an already-built binary.",
        DISCLOSURE,
    )


def _tool_versions(path: str, text: str, include_ok: bool) -> list[Finding]:
    findings: list[Finding] = []
    for match in TOOL_LINE.finditer(text):
        name = match.group("name").lower()
        value = match.group("value")
        if name in {"node", "nodejs"}:
            findings.extend(_node_spec(path, value, name, include_ok))
        elif name in {"go", "golang"}:
            status = classify_go(value)
            if status == "vulnerable":
                findings.append(_go_finding(path, value, "high", name))
            elif status == "floating":
                findings.append(_go_finding(path, value, "medium", name))
            elif status == "patched" and include_ok:
                findings.append(
                    Finding("EM-GO", "ok", f"Go {value} is at or above the fixed release", path, match.group(0), "No change required.", DISCLOSURE)
                )
        elif name == "uv":
            finding = _emit_status(
                classify_minimum(value, UV_FLOOR),
                rule="EM-UV",
                title=f"uv {value}",
                vulnerable_title=f"uv {value} is below {UV_FLOOR}",
                location=path,
                evidence=match.group(0),
                remediation=_python_remediation("uv", UV_FLOOR),
                advisory=PYTHON_ANNOUNCEMENT,
                include_ok=include_ok,
            )
            if finding:
                findings.append(finding)
        elif name == "bun":
            finding = _emit_status(
                classify_minimum(value, BUN_FLOOR),
                rule="BUN-1.4.4",
                title=f"Bun {value}",
                vulnerable_title=f"Bun {value} is below {BUN_FLOOR}",
                location=path,
                evidence=match.group(0),
                remediation="Upgrade Bun to 1.4.4 or newer. That release covers both the Brotli flaw and the eMudhra CA store.",
                advisory=AIKIDO,
                include_ok=include_ok,
            )
            if finding:
                findings.append(finding)
        elif name == "python":
            findings.extend(_cpython_pin(path, value, where="python"))
        elif name == "deno":
            finding = _emit_status(
                classify_minimum(value, DENO_FLOOR),
                rule="EM-DENO",
                title=f"Deno {value}",
                vulnerable_title=f"Deno {value} is below {DENO_FLOOR}",
                location=path,
                evidence=match.group(0),
                remediation="Upgrade Deno to 2.9.8 or newer so its bundled roots drop the compromised chain.",
                advisory=DISCLOSURE,
                include_ok=include_ok,
            )
            if finding:
                findings.append(finding)
    return findings


def _dockerfile(path: str, text: str, include_ok: bool) -> list[Finding]:
    findings: list[Finding] = []
    pip_bump = _pip_bump(text)
    refs = [(match.group("ref"), match.group(0).strip()) for match in FROM_RE.finditer(text)]
    refs.extend((match.group("ref"), match.group(0).strip()) for match in IMAGE_KEY.finditer(text))
    for ref, evidence in refs:
        name, tag = _split_image(ref)
        if name in {"python"}:
            findings.extend(_python_image(path, evidence, tag, pip_bump))
        elif name in {"node"}:
            findings.extend(_node_spec(path, tag, evidence, include_ok))
        elif name in {"golang", "go"}:
            status = classify_go(tag)
            if status == "vulnerable":
                findings.append(_go_finding(path, tag, "high", evidence))
            elif status == "floating":
                findings.append(_go_finding(path, tag, "medium", evidence))
        elif name == "uv":
            if tag == "digest":
                continue
            finding = _emit_status(
                classify_minimum(tag, UV_FLOOR),
                rule="EM-UV",
                title=f"uv image {tag}",
                vulnerable_title=f"uv image {tag} is below {UV_FLOOR}",
                floating_title=f"uv image tag {tag} is not a patched pin",
                location=path,
                evidence=evidence,
                remediation=_python_remediation("uv", UV_FLOOR),
                advisory=PYTHON_ANNOUNCEMENT,
                include_ok=include_ok,
            )
            if finding:
                findings.append(finding)
        elif name == "bun":
            finding = _emit_status(
                classify_minimum(tag, BUN_FLOOR),
                rule="BUN-1.4.4",
                title=f"Bun image {tag}",
                vulnerable_title=f"Bun image {tag} is below {BUN_FLOOR}",
                location=path,
                evidence=evidence,
                remediation="Upgrade the image to Bun 1.4.4 or newer and rebuild.",
                advisory=AIKIDO,
                include_ok=include_ok,
            )
            if finding:
                findings.append(finding)
        elif name == "deno":
            finding = _emit_status(
                classify_minimum(tag, DENO_FLOOR),
                rule="EM-DENO",
                title=f"Deno image {tag}",
                vulnerable_title=f"Deno image {tag} is below {DENO_FLOOR}",
                location=path,
                evidence=evidence,
                remediation="Upgrade the image to Deno 2.9.8 or newer and rebuild.",
                advisory=DISCLOSURE,
                include_ok=include_ok,
            )
            if finding:
                findings.append(finding)
    for match in PIP_PIN.finditer(text):
        spec = match.group("op") + match.group("ver")
        status = classify_minimum(spec, PIP_FLOOR)
        finding = _emit_status(
            status,
            rule="EM-PIP",
            title=f"pip {spec}",
            vulnerable_title=f"Dockerfile pins pip {spec}, below {PIP_FLOOR}",
            location=path,
            evidence=match.group(0),
            remediation=_python_remediation("pip", PIP_FLOOR),
            advisory=PYTHON_ANNOUNCEMENT,
            include_ok=include_ok,
        )
        if finding:
            findings.append(finding)
    findings.extend(_python_pins(path, text, include_ok))
    return findings


def _python_image(path: str, evidence: str, tag: str, pip_bump: str | None) -> list[Finding]:
    if pip_bump == "patched":
        return []
    if pip_bump == "vulnerable":
        return []
    if tag == "digest":
        severity = "medium"
        title = "Python image is pinned by digest, so the pip version is not visible"
    elif pip_bump == "floating":
        severity = "medium"
        title = "Python image upgrades pip without pinning 26.2.2"
    else:
        severity = "high"
        title = "Python image does not pin pip >= 26.2.2"
    return [
        Finding(
            "EM-PIP",
            severity,
            title,
            path,
            evidence,
            "Official Python images were still shipping pip 26.2.1 on 21 Oct 2026. "
            "Pin `python -m pip install --upgrade 'pip>=26.2.2'` (or the checksummed wheel) and rebuild with --no-cache. "
            + PIP_BOOTSTRAP,
            PYTHON_ANNOUNCEMENT,
        )
    ]


def _pip_bump(text: str) -> str | None:
    pins = PIP_PIN.findall(text)
    if pins:
        statuses = [classify_minimum(op + ver, PIP_FLOOR) for op, ver in pins]
        if "vulnerable" in statuses:
            return "vulnerable"
        if statuses and all(status == "patched" for status in statuses):
            return "patched"
        return "floating"
    if PIP_UPGRADE.search(text):
        return "floating"
    return None


def _split_image(ref: str) -> tuple[str, str]:
    if "@" in ref and ":" not in ref.rsplit("/", 1)[-1]:
        name = ref.split("@", 1)[0].rsplit("/", 1)[-1]
        return name.lower(), "digest"
    last = ref.rsplit("/", 1)[-1]
    if ":" not in last:
        return last.lower(), "latest"
    name, tag = last.rsplit(":", 1)
    return name.lower(), tag


def _workflow(path: str, text: str, include_ok: bool) -> list[Finding]:
    findings: list[Finding] = []
    for match in NODE_KEY.finditer(text):
        value = match.group("value").strip()
        pieces = re.findall(r"v?\d+(?:\.\d+){0,3}|lts/[\w.-]+|latest|\d+\.x", value, flags=re.I)
        targets = pieces or [value]
        for piece in targets:
            findings.extend(_node_spec(path, piece, "node-version", include_ok))
    for match in GO_KEY.finditer(text):
        value = match.group("value").strip()
        status = classify_go(value)
        if status == "vulnerable":
            findings.append(_go_finding(path, value, "high", "go-version"))
        elif status == "floating":
            findings.append(_go_finding(path, value, "medium", "go-version"))
        elif status == "patched" and include_ok:
            findings.append(
                Finding("EM-GO", "ok", f"Go {value} is at or above the fixed release", path, match.group(0).strip(), "No change required.", DISCLOSURE)
            )
    return findings
