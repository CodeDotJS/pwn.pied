from __future__ import annotations

import glob
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from pied.advisories import (
    AIKIDO,
    BROTLI_FLOOR,
    BUN_FLOOR,
    CERTIFI_FLOOR,
    CPYTHON_ENSUREPIP,
    DENO_FLOOR,
    DISCLOSURE,
    GO_126_FLOOR,
    GO_127_FLOOR,
    NODE_ANNOUNCEMENT,
    node_cves,
    PIP_BOOTSTRAP,
    PIP_FLOOR,
    PYTHON_ANNOUNCEMENT,
    UV_FLOOR,
)
from pied.bins import brotli_version, contains_buildinfo, go_binary_findings, is_native_binary, linked_brotli
from pied.certs import findings_for_ca_conf, findings_for_fingerprints, findings_for_pem
from pied.manifests import finalize
from pied.model import Finding, Target
from pied.versions import classify_go, classify_java, classify_minimum, classify_node, parse_version


PROBE = r"""
import json, sys
info = {"python": ".".join(map(str, sys.version_info[:3])), "executable": sys.executable}
try:
    import certifi
    info["certifi"] = certifi.__version__
    info["certifi_path"] = certifi.where()
except Exception as exc:
    info["certifi_error"] = type(exc).__name__
try:
    import hashlib, ssl
    ctx = ssl.create_default_context()
    info["ssl_fingerprints"] = [
        hashlib.sha256(der).hexdigest().upper() for der in ctx.get_ca_certs(binary_form=True)
    ]
except Exception as exc:
    info["ssl_error"] = type(exc).__name__
print(json.dumps(info))
"""

NODE_TRUST = r"""
const tls = require("tls");
const crypto = require("crypto");
const ids = tls.rootCertificates.map((pem) => {
  const body = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  return crypto.createHash("sha256").update(Buffer.from(body, "base64")).digest("hex").toUpperCase();
});
process.stdout.write(String(tls.rootCertificates.length) + "\n" + ids.join("\n"));
"""

WALK_SKIP = {
    "Library",
    "node_modules",
    ".git",
    "Caches",
    ".cache",
    ".npm",
    "Movies",
    "Music",
    "Pictures",
    ".Trash",
    "Applications",
    "site-packages",
    "__pycache__",
    "target",
    "dist",
    "build",
    ".next",
    "Pods",
    "vendor",
    ".cargo",
    ".rustup",
    "pkg",
    ".cursor",
    ".npm",
    "Cache",
}
WALK_KEEP_HIDDEN = {".pyenv", ".venv", ".local", ".asdf"}

BUNDLE_PATHS = (
    "/etc/ssl/cert.pem",
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    "/opt/homebrew/etc/ca-certificates/cert.pem",
    "/usr/local/etc/ca-certificates/cert.pem",
    "/opt/homebrew/etc/openssl@3/cert.pem",
    "/etc/ca-certificates.conf",
)
KEYCHAINS = (
    "/System/Library/Keychains/SystemRootCertificates.keychain",
    "/Library/Keychains/System.keychain",
)
KEYCHAIN_NAMES = (
    "emSign ECC Root CA - G3",
    "emSign Root TLS CA - G3",
    "emSign Root CS CA - G3",
    "AAA Certificate Services",
)
IMAGE_HINTS = ("python", "node", "golang", "uv", "bun", "deno")


def scan_host(
    *,
    venv_roots: list[Path] | None = None,
    max_depth: int = 6,
    max_venvs: int = 120,
    max_binaries: int = 80,
    docker: bool = True,
    docker_all: bool = False,
    docker_limit: int = 30,
    include_ok: bool = True,
) -> Target:
    target = Target(name="host")
    findings: list[Finding] = []
    roots = list(_default_roots())
    if venv_roots:
        roots.extend(venv_roots)
    pythons = _discover_pythons(roots, max_depth, max_venvs, target)
    seen_certifi: set[str] = set()
    for python in pythons:
        findings.extend(_scan_python(python, include_ok, seen_certifi))
        target.files_scanned += 1
    discovered = _discover_bins()
    toolchain = {str(path.resolve()) for path, kind in discovered if kind == "go"}
    for binary, kind in discovered:
        findings.extend(_scan_binary(binary, kind, include_ok))
        target.files_scanned += 1
    findings.extend(_scan_go_binaries(include_ok, toolchain, max_binaries, target))
    seen_bundles: set[str] = set()
    for path in list(BUNDLE_PATHS) + _openssl_bundles():
        resolved = _existing(path)
        if resolved is None or resolved in seen_bundles:
            continue
        seen_bundles.add(resolved)
        findings.extend(_scan_bundle(Path(resolved), include_ok))
    findings.extend(_scan_curl(include_ok))
    findings.extend(_scan_keychains())
    if docker:
        findings.extend(_scan_docker(docker_all, docker_limit, include_ok, target))
    if not pythons:
        findings.append(
            Finding(
                "EM-PIP",
                "info",
                "No Python interpreter was found",
                "host",
                "PATH and the standard install locations",
                "Install a patched pip in every environment you actually use, or pass --venv-root.",
                PYTHON_ANNOUNCEMENT,
            )
        )
    target.findings = finalize(findings)
    return target


def _default_roots() -> list[Path]:
    home = Path.home()
    return [
        home,
        Path("/opt"),
        Path("/usr/local"),
        Path("/Library/Frameworks"),
        Path("/opt/homebrew"),
    ]


def _discover_pythons(roots: list[Path], max_depth: int, max_venvs: int, target: Target) -> list[Path]:
    found: list[str] = []
    patterns = [
        "/usr/bin/python3*",
        "/usr/local/bin/python3*",
        "/opt/homebrew/bin/python3*",
        "/Library/Frameworks/Python.framework/Versions/*/bin/python3*",
        str(Path.home() / ".pyenv/versions/*/bin/python*"),
        str(Path.home() / ".local/share/mise/installs/python/*/bin/python*"),
        str(Path.home() / ".asdf/installs/python/*/bin/python*"),
    ]
    for pattern in patterns:
        found.extend(glob.glob(pattern))
    for name in ("python3", "python"):
        located = shutil.which(name)
        if located:
            found.append(located)
    venvs = _find_venvs(roots, max_depth, max_venvs)
    if len(venvs) >= max_venvs:
        target.error = f"venv cap reached at {max_venvs}; raise --max-venvs to continue the walk"
    for venv in venvs:
        python = Path(venv) / "bin" / "python"
        if python.exists():
            found.append(str(python))
    unique: list[Path] = []
    seen: set[str] = set()
    for item in found:
        path = Path(item)
        if not path.is_file() or not os.access(path, os.X_OK):
            continue
        if path.name.endswith(("-config", "-build")) or "pythonw" in path.name:
            continue
        if not path.name.startswith("python"):
            continue
        real = str(path.resolve())
        if real in seen:
            continue
        seen.add(real)
        unique.append(path)
    return unique


def _find_venvs(roots: list[Path], max_depth: int, max_venvs: int) -> list[Path]:
    found: list[Path] = []
    for root in roots:
        if not root.exists() or not root.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(root, onerror=lambda _exc: None):
            if len(found) >= max_venvs:
                return found
            relative = Path(dirpath).relative_to(root)
            if len(relative.parts) > max_depth:
                dirnames[:] = []
                continue
            dirnames[:] = [
                name
                for name in dirnames
                if name not in WALK_SKIP and (not name.startswith(".") or name in WALK_KEEP_HIDDEN)
            ]
            if "pyvenv.cfg" in filenames:
                found.append(Path(dirpath))
                dirnames[:] = []
    return found


def _scan_python(python: Path, include_ok: bool, seen_certifi: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    code, out = _run([str(python), "-c", PROBE], timeout=15)
    info: dict = {}
    if code == 0:
        try:
            info = json.loads(out.splitlines()[-1])
        except (json.JSONDecodeError, IndexError):
            info = {}
    pip_code, pip_out = _run([str(python), "-m", "pip", "--version"], timeout=15)
    pip_version = _pip_version(pip_out) if pip_code == 0 else None
    location = str(python)
    if pip_version:
        status = classify_minimum(pip_version, PIP_FLOOR)
        if status != "patched" or include_ok:
            severity = "ok" if status == "patched" else "high"
            findings.append(
                Finding(
                    "EM-PIP",
                    severity,
                    f"pip {pip_version} at {python}",
                    location,
                    pip_out.strip().splitlines()[0] if pip_out.strip() else pip_version,
                    "No change required." if status == "patched" else _pip_remediation(pip_out),
                    PYTHON_ANNOUNCEMENT,
                )
            )
    elif info:
        findings.append(
            Finding(
                "EM-PIP",
                "medium",
                f"pip could not be queried for {python}",
                location,
                info.get("python", ""),
                "Run `python -m pip --version` in this environment and upgrade to pip >= 26.2.2 if it is installed.",
                PYTHON_ANNOUNCEMENT,
            )
        )
    certifi_version = info.get("certifi")
    certifi_path = info.get("certifi_path")
    if certifi_version:
        status = classify_minimum(str(certifi_version), CERTIFI_FLOOR)
        if status != "patched" or include_ok:
            findings.append(
                Finding(
                    "EM-CERTIFI",
                    "ok" if status == "patched" else "high",
                    f"certifi {certifi_version}",
                    str(certifi_path or python),
                    f"{python} imports certifi {certifi_version}",
                    "No change required."
                    if status == "patched"
                    else f"Upgrade certifi to {CERTIFI_FLOOR} or newer after pip itself is upgraded.",
                    "https://github.com/advisories/GHSA-6q48-6c7w-9gw2",
                )
            )
    if certifi_path and certifi_path not in seen_certifi:
        seen_certifi.add(certifi_path)
        findings.extend(_scan_bundle(Path(certifi_path), include_ok))
    fingerprints = info.get("ssl_fingerprints")
    if isinstance(fingerprints, list) and fingerprints:
        loaded = findings_for_fingerprints(f"{python} (ssl default context)", {str(item) for item in fingerprints})
        if loaded:
            findings.extend(loaded)
        elif include_ok:
            findings.append(
                Finding(
                    "EM-TLS",
                    "ok",
                    "Python ssl default context does not include a compromised eMudhra certificate",
                    location,
                    f"{len(fingerprints)} certificates loaded by ssl.create_default_context()",
                    "No change required for this handshake store. pip still uses its own vendored bundle.",
                    PYTHON_ANNOUNCEMENT,
                )
            )
    py_version = parse_version(str(info.get("python") or ""))
    if py_version and py_version.major == 3 and py_version.minor in CPYTHON_ENSUREPIP:
        floor = CPYTHON_ENSUREPIP[py_version.minor]
        if len(py_version.parts) >= 3 and py_version < floor:
            findings.append(
                Finding(
                    "EM-ENSUREPIP",
                    "info",
                    f"CPython {py_version} still bundles an old ensurepip wheel",
                    location,
                    f"security release for 3.{py_version.minor} is {floor}",
                    "New virtualenvs created from this interpreter can reintroduce pip < 26.2.2. "
                    "Upgrade pip immediately after creating them, or move to the CPython security release.",
                    PYTHON_ANNOUNCEMENT,
                )
            )
    return findings


def _discover_bins() -> list[tuple[Path, str]]:
    found: list[tuple[Path, str]] = []
    patterns = {
        "node": [
            "node",
            str(Path.home() / ".nvm/versions/node/*/bin/node"),
            str(Path.home() / ".local/share/mise/installs/node/*/bin/node"),
            str(Path.home() / ".asdf/installs/nodejs/*/bin/node"),
            str(Path.home() / ".volta/tools/image/node/*/bin/node"),
            "/opt/homebrew/bin/node",
            "/usr/local/bin/node",
        ],
        "uv": ["uv", "/opt/homebrew/bin/uv", str(Path.home() / ".local/bin/uv"), str(Path.home() / ".cargo/bin/uv")],
        "go": ["go", "/opt/homebrew/bin/go", "/usr/local/go/bin/go"],
        "bun": ["bun", str(Path.home() / ".bun/bin/bun"), "/opt/homebrew/bin/bun"],
        "deno": ["deno", str(Path.home() / ".deno/bin/deno"), "/opt/homebrew/bin/deno"],
        "java": ["java", "/usr/bin/java", "/opt/homebrew/bin/java"],
    }
    seen: set[str] = set()
    for kind, items in patterns.items():
        for item in items:
            paths = [item] if "/" not in item and "*" not in item else glob.glob(item) or ([item] if "*" not in item else [])
            if item in {"node", "uv", "go", "bun", "deno", "java"}:
                located = shutil.which(item)
                paths = [located] if located else []
            for candidate in paths:
                if not candidate:
                    continue
                path = Path(candidate)
                if not path.is_file():
                    continue
                real = str(path.resolve())
                key = f"{kind}:{real}"
                if key in seen:
                    continue
                seen.add(key)
                found.append((path, kind))
    return found


def _scan_binary(path: Path, kind: str, include_ok: bool) -> list[Finding]:
    if kind == "node":
        code, out = _run([str(path), "--version"], timeout=10)
        version = out.strip().split()[-1] if out.strip() else ""
        status = classify_node(version) if code == 0 and version else "unknown"
        findings = _runtime_finding(
            "NODE-2026-10-21",
            f"Node.js {version or 'unknown'}",
            str(path),
            out.strip() or "node --version failed",
            status,
            (
                "Install 22.23.4, 24.22.1, or 26.12.1, or a newer patch on that line. "
                "20.x, 23.x, 25.x and older have no fix for CVE-2026-111497. "
                "The same releases update the bundled CA store to NSS 3.131.1."
            ),
            NODE_ANNOUNCEMENT,
            include_ok,
        )
        findings = _apply_brotli_linkage(path, findings, include_ok)
        findings.extend(_node_trust(path, include_ok))
        return findings
    if kind == "uv":
        code, out = _run([str(path), "--version"], timeout=10)
        version = _release(out)
        status = classify_minimum(version, UV_FLOOR) if version else "unknown"
        return _runtime_finding(
            "EM-UV",
            f"uv {version or 'unknown'}",
            str(path),
            out.strip(),
            status,
            f"Upgrade uv to {UV_FLOOR} or newer. A patched OS store plus UV_SYSTEM_CERTS=true is only a bridge.",
            PYTHON_ANNOUNCEMENT,
            include_ok,
        )
    if kind == "go":
        code, out = _run([str(path), "version"], timeout=10)
        version = _release(out)
        status = classify_go(version) if version else "unknown"
        floor = f"{GO_126_FLOOR} or {GO_127_FLOOR}"
        return _runtime_finding(
            "EM-GO",
            f"Go {version or 'unknown'}",
            str(path),
            out.strip(),
            status,
            f"Install Go {floor} or newer and rebuild binaries. CVE-2026-111943 blocks the compromised keys inside the toolchain.",
            DISCLOSURE,
            include_ok,
        )
    if kind == "bun":
        code, out = _run([str(path), "--version"], timeout=10)
        version = _release(out)
        status = classify_minimum(version, BUN_FLOOR) if version else "unknown"
        return _runtime_finding(
            "BUN-1.4.4",
            f"Bun {version or 'unknown'}",
            str(path),
            out.strip(),
            status,
            f"Upgrade Bun to {BUN_FLOOR} or newer.",
            AIKIDO,
            include_ok,
        )
    if kind == "deno":
        code, out = _run([str(path), "--version"], timeout=10)
        version = _release(out)
        status = classify_minimum(version, DENO_FLOOR) if version else "unknown"
        return _runtime_finding(
            "EM-DENO",
            f"Deno {version or 'unknown'}",
            str(path),
            out.strip(),
            status,
            f"Upgrade Deno to {DENO_FLOOR} or newer.",
            DISCLOSURE,
            include_ok,
        )
    if kind == "java":
        _, out = _run([str(path), "-version"], timeout=10)
        if not out.strip() or "unable to locate a java runtime" in out.lower():
            return []
        status = classify_java(out)
        version = _release(out) or "unknown"
        return _runtime_finding(
            "EM-JAVA",
            f"Java {version}",
            str(path),
            out.strip().splitlines()[0] if out.strip() else "java -version failed",
            status,
            "Install a Java build that distrusts the eight intermediates (CVE-2026-91403): "
            "8u511, 11.0.33, 17.0.21, 21.0.13, 25.0.5, or 27.0.1, or a newer vendor build.",
            DISCLOSURE,
            include_ok,
        )
    return []


def _runtime_finding(
    rule: str,
    title: str,
    location: str,
    evidence: str,
    status: str,
    remediation: str,
    advisory: str,
    include_ok: bool,
) -> list[Finding]:
    if status == "patched":
        if not include_ok:
            return []
        return [Finding(rule, "ok", title + " is at or above the fixed release", location, evidence, "No change required.", advisory)]
    severity = {"vulnerable": "high", "floating": "medium"}.get(status, "info")
    if status == "vulnerable":
        title = title + " is below the fixed release"
    elif status == "floating":
        title = title + " is not pinned to a patched release"
    return [Finding(rule, severity, title, location, evidence or title, remediation, advisory)]


def _scan_bundle(path: Path, include_ok: bool) -> list[Finding]:
    if not path.is_file():
        return []
    try:
        if path.stat().st_size > 8_000_000:
            return []
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    if path.name == "ca-certificates.conf":
        findings = findings_for_ca_conf(str(path), text)
    else:
        findings = findings_for_pem(str(path), text)
        if include_ok and not any(item.severity in {"high", "critical"} for item in findings):
            findings.append(
                Finding(
                    "EM-ROOT",
                    "ok",
                    "No compromised eMudhra root or intermediate fingerprint in this bundle",
                    str(path),
                    f"{text.count('BEGIN CERTIFICATE')} certificates",
                    "No change required for these fingerprints. AAA Certificate Services is reported separately when present.",
                    DISCLOSURE,
                )
            )
    if not include_ok:
        findings = [item for item in findings if item.severity != "ok"]
    return findings


def _scan_keychains() -> list[Finding]:
    findings: list[Finding] = []
    if not shutil.which("security"):
        return findings
    for keychain in KEYCHAINS:
        if not Path(keychain).exists():
            continue
        for name in KEYCHAIN_NAMES:
            code, out = _run(
                ["security", "find-certificate", "-a", "-c", name, "-p", keychain],
                timeout=20,
            )
            if code != 0 or "BEGIN CERTIFICATE" not in out:
                continue
            matched = findings_for_pem(f"{keychain} ({name})", out)
            for finding in matched:
                if finding.severity == "high":
                    finding.severity = "medium"
                    finding.title += " in the platform keychain"
                    finding.remediation = (
                        "Apple blocked the intermediates in the platform verifier on 22 Oct 2026. "
                        "This entry still matters for tools that export the keychain into a PEM and skip revocation, "
                        "notably /etc/ssl/cert.pem. Prefer the vendor update over deleting unrelated roots."
                    )
            findings.extend(matched)
    return findings


def _scan_docker(docker_all: bool, limit: int, include_ok: bool, target: Target) -> list[Finding]:
    if not shutil.which("docker"):
        return [
            Finding(
                "DOCKER",
                "info",
                "Docker is not installed",
                "host",
                "docker was not on PATH",
                "Image scans run when docker is available. Rebuild images after the base image and pip or Node pin is patched.",
                DISCLOSURE,
            )
        ]
    code, out = _run(["docker", "image", "ls", "--format", "{{.Repository}}:{{.Tag}}"], timeout=20)
    if code != 0:
        return [
            Finding(
                "DOCKER",
                "info",
                "Docker images were not listed",
                "host",
                out.strip()[:300] or "docker image ls failed",
                "Start Docker if local images should be part of the host check.",
                DISCLOSURE,
            )
        ]
    images = [line.strip() for line in out.splitlines() if line.strip() and "<none>" not in line]
    chosen = images if docker_all else [image for image in images if _hinted(image)]
    skipped = len(images) - len(chosen)
    chosen = chosen[:limit]
    findings: list[Finding] = []
    if skipped and not docker_all:
        findings.append(
            Finding(
                "DOCKER",
                "info",
                f"{skipped} local images were not probed",
                "host",
                "name did not look like python, node, golang, uv, bun, or deno",
                "Rerun with --docker-all to probe every local image (still offline: --network none).",
                DISCLOSURE,
            )
        )
    for image in chosen:
        findings.extend(_probe_image(image, include_ok))
        target.files_scanned += 1
    return findings


def _hinted(image: str) -> bool:
    leaf = image.rsplit("/", 1)[-1]
    return any(hint in leaf.split(":")[0] for hint in IMAGE_HINTS)


def _probe_image(image: str, include_ok: bool) -> list[Finding]:
    script = (
        "node --version 2>/dev/null; "
        "python3 -m pip --version 2>/dev/null; "
        "python -m pip --version 2>/dev/null; "
        "go version 2>/dev/null; "
        "uv --version 2>/dev/null"
    )
    code, out = _run(
        ["docker", "run", "--rm", "--network", "none", "--entrypoint", "sh", image, "-c", script],
        timeout=20,
    )
    if code != 0 and not out.strip():
        return [
            Finding(
                "DOCKER",
                "info",
                f"Could not execute a version probe in {image}",
                image,
                "the image has no sh entrypoint override, or it failed before printing a version",
                "Check this image's runtime manually, then rebuild it on a patched base.",
                DISCLOSURE,
            )
        ]
    findings: list[Finding] = []
    for line in out.splitlines():
        text = line.strip()
        if text.startswith("v") and text[1:2].isdigit():
            status = classify_node(text)
            findings.extend(
                _runtime_finding(
                    "NODE-2026-10-21",
                    f"image Node.js {text}",
                    image,
                    text,
                    status,
                    "Rebuild the image on Node.js 22.23.4, 24.22.1, or 26.12.1 or newer.",
                    NODE_ANNOUNCEMENT,
                    include_ok,
                )
            )
        elif text.lower().startswith("pip "):
            version = _pip_version(text)
            status = classify_minimum(version, PIP_FLOOR) if version else "unknown"
            findings.extend(
                _runtime_finding(
                    "EM-PIP",
                    f"image pip {version or text}",
                    image,
                    text,
                    status,
                    "Rebuild with pip >= 26.2.2. " + PIP_BOOTSTRAP,
                    PYTHON_ANNOUNCEMENT,
                    include_ok,
                )
            )
        elif text.lower().startswith("go version"):
            version = _release(text)
            status = classify_go(version) if version else "unknown"
            findings.extend(
                _runtime_finding(
                    "EM-GO",
                    f"image Go {version or text}",
                    image,
                    text,
                    status,
                    "Rebuild with Go 1.26.10 or 1.27.3 or newer.",
                    DISCLOSURE,
                    include_ok,
                )
            )
        elif text.lower().startswith("uv "):
            version = _release(text)
            status = classify_minimum(version, UV_FLOOR) if version else "unknown"
            findings.extend(
                _runtime_finding(
                    "EM-UV",
                    f"image uv {version or text}",
                    image,
                    text,
                    status,
                    f"Rebuild with uv >= {UV_FLOOR}.",
                    PYTHON_ANNOUNCEMENT,
                    include_ok,
                )
            )
    return findings


def _pip_remediation(pip_output: str) -> str:
    runtime = re.search(r"\(python (\d+)\.(\d+)", pip_output)
    if runtime and (int(runtime.group(1)), int(runtime.group(2))) < (3, 10):
        return (
            "pip 26.2.2 requires Python 3.10 or newer, so this interpreter cannot take the fixed wheel. "
            "Move the environment to Python 3.10+ before upgrading pip. Until then it still trusts the "
            "compromised intermediates through its vendored certifi, and an OS trust update does not fix pip."
        )
    return (
        "This pip still loads a vendored certifi that trusts the compromised intermediates. "
        "An OS trust-store update does not fix it. " + PIP_BOOTSTRAP
    )


def _pip_version(text: str) -> str | None:
    parts = text.split()
    if len(parts) >= 2 and parts[0].lower() == "pip":
        return parts[1]
    return None


def _existing(path: str) -> str | None:
    candidate = Path(path)
    if not candidate.is_file():
        return None
    try:
        return str(candidate.resolve())
    except OSError:
        return str(candidate)


def _openssl_bundles() -> list[str]:
    if not shutil.which("openssl"):
        return []
    code, out = _run(["openssl", "version", "-d"], timeout=10)
    if code != 0:
        return []
    match = re.search(r'OPENSSLDIR:\s*"([^"]+)"', out)
    if not match:
        return []
    root = Path(match.group(1))
    return [str(root / "cert.pem"), str(root / "certs" / "ca-certificates.crt")]


def _scan_curl(include_ok: bool) -> list[Finding]:
    curl = shutil.which("curl")
    if not curl:
        return []
    code, out = _run([curl, "-V"], timeout=10)
    if code != 0:
        return []
    backend = ""
    match = re.search(r"libcurl/\S+\s+\(([^)]+)\)", out)
    if match:
        backend = match.group(1)
    first = out.splitlines()[0] if out else curl
    if "SecureTransport" in backend:
        if not include_ok:
            return []
        return [
            Finding(
                "EM-TLS",
                "ok",
                "curl handshakes with SecureTransport",
                curl,
                first,
                "Apple blocked the compromised intermediates in the platform verifier on 22 Oct 2026. "
                "PEM bundles used by other clients are reported separately. pied does not open a connection.",
                DISCLOSURE,
            )
        ]
    if backend:
        return [
            Finding(
                "EM-TLS",
                "info",
                f"curl handshakes with {backend}",
                curl,
                first,
                "This backend uses a CA file rather than the platform verifier. "
                "The OpenSSL directory and the known system bundles are fingerprinted in this scan.",
                DISCLOSURE,
            )
        ]
    return []


def _scan_go_binaries(include_ok: bool, skip: set[str], limit: int, target: Target) -> list[Finding]:
    findings: list[Finding] = []
    found = 0
    truncated = False
    for path in _candidate_binaries():
        if found >= limit:
            truncated = True
            break
        try:
            resolved = str(path.resolve())
        except OSError:
            continue
        if resolved in skip:
            continue
        try:
            size = path.stat().st_size
            prefix = path.read_bytes()[:4]
        except OSError:
            continue
        if size < 64 or size > 40_000_000 or not is_native_binary(prefix):
            continue
        if not contains_buildinfo(path):
            continue
        try:
            data = path.read_bytes()
        except OSError:
            continue
        binary_findings = go_binary_findings(resolved, data, include_ok=include_ok)
        if not binary_findings:
            continue
        findings.extend(binary_findings)
        target.files_scanned += 1
        found += 1
    if truncated:
        note = f"stopped after {found} Go binaries (cap {limit})"
        target.error = f"{target.error}; {note}" if target.error else note
    return findings


def _candidate_binaries() -> list[Path]:
    directories: list[Path] = []
    for item in os.environ.get("PATH", "").split(os.pathsep):
        if item:
            directories.append(Path(item))
    directories.append(Path.home() / "go" / "bin")
    directories.append(Path.home() / "bin")
    gobin = os.environ.get("GOBIN")
    if gobin:
        directories.append(Path(gobin))
    seen: set[str] = set()
    found: list[Path] = []
    for directory in directories:
        if not directory.is_dir():
            continue
        try:
            entries = list(directory.iterdir())
        except OSError:
            continue
        for path in entries:
            try:
                if not path.is_file() or not os.access(path, os.X_OK):
                    continue
                key = str(path.resolve())
            except OSError:
                continue
            if key in seen:
                continue
            seen.add(key)
            found.append(path)
    return found


def _apply_brotli_linkage(path: Path, findings: list[Finding], include_ok: bool) -> list[Finding]:
    linked = _node_brotli(path)
    if linked is None:
        return findings
    library, version = linked
    for finding in findings:
        if finding.rule != "NODE-2026-10-21":
            continue
        finding.cves = node_cves(f"{finding.title}\n{finding.evidence}", bundled_brotli=False)
        finding.remediation += (
            " This binary loads libbrotlidec, so CVE-2026-111497 follows that library rather than the Node version."
        )
    status = classify_minimum(version, BROTLI_FLOOR) if version else "unknown"
    if status == "patched" and not include_ok:
        return findings
    severity = {"vulnerable": "high", "patched": "ok"}.get(status, "high")
    shown = version or "unknown"
    findings.append(
        Finding(
            "N2S-LIBBROTLI",
            severity,
            f"libbrotlidec {shown} is loaded by Node"
            if severity == "ok"
            else f"libbrotlidec {shown} decides CVE-2026-111497 for this Node",
            library,
            f"{path} loads {library}",
            "No change required."
            if severity == "ok"
            else "Upgrade the system Brotli package to 1.2.1 or newer. That is the 21 Oct 2026 upstream fix. "
            "A Node version bump does not replace a decoder this binary loads from the system.",
            "https://nodejs.org/en/blog/vulnerability/october-2026-security-releases",
            ("CVE-2026-111497",),
        )
    )
    return findings


def _node_brotli(path: Path) -> tuple[str, str] | None:
    if sys.platform == "darwin":
        if not shutil.which("otool"):
            return None
        code, out = _run(["otool", "-L", str(path)], timeout=10)
    else:
        if not shutil.which("ldd"):
            return None
        code, out = _run(["ldd", str(path)], timeout=10)
    if code != 0:
        return None
    library = linked_brotli(out)
    if not library:
        return None
    resolved = library
    candidate = Path(library)
    if candidate.is_symlink() or candidate.exists():
        try:
            resolved = str(candidate.resolve())
        except OSError:
            resolved = library
    version = brotli_version(resolved) or ""
    if not version and sys.platform == "darwin" and shutil.which("otool"):
        _, detail = _run(["otool", "-L", resolved], timeout=10)
        match = re.search(r"current version (\d+\.\d+\.\d+)", detail)
        if match:
            version = match.group(1)
    return resolved, version


def _node_trust(path: Path, include_ok: bool) -> list[Finding]:
    code, out = _run([str(path), "-e", NODE_TRUST], timeout=15)
    if code != 0 or not out.strip():
        return []
    lines = [line.strip() for line in out.splitlines() if line.strip()]
    if not lines:
        return []
    count = lines[0] if lines[0].isdigit() else "?"
    fingerprints = {line for line in lines[1:] if len(line) == 64}
    loaded = findings_for_fingerprints(f"{path} (tls.rootCertificates)", fingerprints)
    if loaded:
        return loaded
    if not include_ok:
        return []
    return [
        Finding(
            "EM-TLS",
            "ok",
            "Node tls.rootCertificates does not include a compromised eMudhra certificate",
            str(path),
            f"{count} certificates loaded by tls.rootCertificates",
            "No change required for this handshake store. The Node version check still covers the rest of the 21 Oct 2026 release.",
            NODE_ANNOUNCEMENT,
        )
    ]


def _release(text: str) -> str:
    """First dotted release in a command's output, ignoring dates and hashes."""
    match = re.search(r"(\d+\.\d+\.\d+)", text)
    return match.group(1) if match else ""


def _run(command: list[str], timeout: int) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, str(exc)
    return proc.returncode, ((proc.stdout or "") + (proc.stderr or "")).strip()
