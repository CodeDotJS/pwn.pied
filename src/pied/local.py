from __future__ import annotations

import os
from pathlib import Path

from pied.bins import go_binary_findings, is_native_binary
from pied.manifests import PRUNE_PARTS, finalize, is_manifest, scan_text
from pied.model import Finding, Target


BROTLI_RE_TEXT = ("brotliDecompress", "brotliDecompressSync", "createBrotliDecompress")
SOURCE_SUFFIXES = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}
MAX_BYTES = 3_000_000


def scan_path(root: Path, *, include_ok: bool = False, max_files: int = 400) -> Target:
    root = root.resolve()
    target = Target(name=str(root))
    if not root.exists():
        target.error = f"path does not exist: {root}"
        return target
    manifests = _manifests(root, max_files, target)
    findings: list[Finding] = []
    for path in manifests:
        text = _read(path)
        if text is None:
            continue
        location = _location(root, path)
        findings.extend(scan_text(location, text, include_ok=include_ok))
        target.files_scanned += 1
    hits = _brotli_sources(root)
    if hits:
        shown = ", ".join(hits[:8])
        extra = f" (+{len(hits) - 8} more)" if len(hits) > 8 else ""
        findings.append(
            Finding(
                rule="N2S-EXPOSURE",
                severity="medium",
                title="Source calls the Node.js Brotli decoder",
                location=str(root),
                evidence=shown + extra,
                remediation=(
                    "Upgrade the Node.js runtime to 22.23.4, 24.22.1, or 26.12.1 or newer. "
                    "These calls decompress with the bundled decoder fixed in CVE-2026-111497."
                ),
                advisory="https://nodejs.org/en/blog/vulnerability/october-2026-security-releases",
            )
        )
    binary_hits, examined, truncated = _go_binaries(root, include_ok)
    findings.extend(binary_hits)
    target.files_scanned += examined
    if truncated:
        note = "stopped after 40 Go binaries"
        target.error = f"{target.error}; {note}" if target.error else note
    target.findings = finalize(findings)
    return target


def _manifests(root: Path, max_files: int, target: Target) -> list[Path]:
    if root.is_file():
        return [root]
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [name for name in dirnames if name not in PRUNE_PARTS]
        for filename in filenames:
            path = Path(dirpath) / filename
            if is_manifest(_location(root, path)):
                found.append(path)
    found.sort(key=lambda path: (len(path.parts), path.as_posix()))
    if len(found) > max_files:
        target.error = f"manifest cap reached: scanned {max_files} of {len(found)} files"
        return found[:max_files]
    return found


def _brotli_sources(root: Path) -> list[str]:
    if root.is_file():
        return []
    hits: list[str] = []
    checked = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [name for name in dirnames if name not in PRUNE_PARTS]
        for filename in filenames:
            if checked >= 1500 or len(hits) >= 40:
                return hits
            path = Path(dirpath) / filename
            if path.suffix.lower() not in SOURCE_SUFFIXES:
                continue
            checked += 1
            try:
                if path.stat().st_size > 500_000:
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if any(token in text for token in BROTLI_RE_TEXT):
                hits.append(_location(root, path))
    return hits


def _go_binaries(root: Path, include_ok: bool) -> tuple[list[Finding], int, bool]:
    if root.is_file():
        found = _one_binary(root, include_ok)
        return found, 1 if found else 0, False
    findings: list[Finding] = []
    seen = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [name for name in dirnames if name not in PRUNE_PARTS]
        for filename in filenames:
            if seen >= 40:
                return findings, seen, True
            path = Path(dirpath) / filename
            try:
                if not path.is_file() or path.stat().st_size > 40_000_000 or path.stat().st_size < 64:
                    continue
                if not is_native_binary(path.read_bytes()[:4]):
                    continue
                data = path.read_bytes()
            except OSError:
                continue
            seen += 1
            findings.extend(go_binary_findings(_location(root, path), data, include_ok=include_ok))
    return findings, seen, False


def _one_binary(path: Path, include_ok: bool) -> list[Finding]:
    try:
        if path.stat().st_size > 40_000_000 or not is_native_binary(path.read_bytes()[:4]):
            return []
        return go_binary_findings(path.name, path.read_bytes(), include_ok=include_ok)
    except OSError:
        return []


def _read(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _location(root: Path, path: Path) -> str:
    if path == root:
        return path.name
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()
