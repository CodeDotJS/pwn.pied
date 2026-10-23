"""Read-only checks of binaries already on disk.

Go records its toolchain in the buildinfo header. Node packages from a
distribution sometimes load libbrotlidec instead of the decoder Node vendors.
Neither check executes the binary.
"""

from __future__ import annotations

import re

from pied.advisories import DISCLOSURE
from pied.certs import findings_for_pem
from pied.model import Finding
from pied.versions import classify_go

MAGIC = b"\xff Go buildinf:"
_NATIVE = (
    b"\x7fELF",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
    b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
)
_BROTLI_LIB = re.compile(r"(?P<path>\S*libbrotlidec\S*)")
_TRIPLE = re.compile(r"(\d+\.\d+\.\d+)")


def is_native_binary(prefix: bytes) -> bool:
    return any(prefix.startswith(magic) for magic in _NATIVE)


def contains_buildinfo(path) -> bool:
    """Stream a file just far enough to see a Go buildinfo header."""
    try:
        handle = path.open("rb")
    except OSError:
        return False
    overlap = b""
    try:
        while True:
            chunk = handle.read(1 << 20)
            if not chunk:
                return False
            window = overlap + chunk
            if MAGIC in window:
                return True
            overlap = window[1 - len(MAGIC) :]
    finally:
        handle.close()


def go_toolchain(data: bytes) -> str | None:
    """Return `go1.x.y` from a Go buildinfo header, or None."""
    start = 0
    while True:
        idx = data.find(MAGIC, start)
        if idx < 0:
            return None
        start = idx + 1
        if idx + 34 > len(data):
            continue
        ptr = data[idx + 14]
        flags = data[idx + 15]
        if ptr not in (4, 8) or not flags & 2:
            continue
        version = _go_string(data[idx + 32 :])
        if version and version.startswith("go1."):
            return version
    return None


def go_binary_findings(location: str, data: bytes, *, include_ok: bool) -> list[Finding]:
    findings: list[Finding] = []
    version = go_toolchain(data)
    if version:
        status = classify_go(version)
        if status == "patched":
            if include_ok:
                findings.append(
                    Finding(
                        "EM-GO",
                        "ok",
                        f"{location} was built with {version}",
                        location,
                        version,
                        "No change required.",
                        DISCLOSURE,
                    )
                )
        elif status == "vulnerable":
            findings.append(
                Finding(
                    "EM-GO",
                    "high",
                    f"{location} was built with {version}, which is below the eMudhra fix",
                    location,
                    version,
                    "Rebuild this binary with Go 1.26.10 or 1.27.3 or newer. "
                    "CVE-2026-111943 blocks the eight compromised keys inside the toolchain. "
                    "Replacing the OS trust store does not rewrite a binary that is already built.",
                    DISCLOSURE,
                )
            )
        else:
            findings.append(
                Finding(
                    "EM-GO",
                    "info",
                    f"{location} was built with {version}",
                    location,
                    version,
                    "Confirm the toolchain is Go 1.26.10 or 1.27.3 or newer and rebuild.",
                    DISCLOSURE,
                )
            )
    if b"BEGIN CERTIFICATE" in data:
        findings.extend(findings_for_pem(location, data.decode("latin-1", errors="replace")))
    return findings


def linked_brotli(text: str) -> str | None:
    """Path of libbrotlidec from `otool -L` or `ldd` output."""
    for line in text.splitlines():
        if "libbrotlidec" not in line:
            continue
        arrow = re.search(r"=>\s+(\S+)", line)
        if arrow and not arrow.group(1).startswith("("):
            return arrow.group(1)
        match = _BROTLI_LIB.search(line)
        if match:
            return match.group("path")
    return None


def brotli_version(path: str) -> str | None:
    """Release triple embedded in a resolved library filename, such as 1.2.1."""
    name = path.rsplit("/", 1)[-1]
    match = _TRIPLE.search(name)
    return match.group(1) if match else None


def _go_string(data: bytes) -> str | None:
    decoded = _uvarint(data)
    if decoded is None:
        return None
    length, size = decoded
    if length <= 0 or length > 64 or size + length > len(data):
        return None
    try:
        return data[size : size + length].decode("ascii")
    except UnicodeDecodeError:
        return None


def _uvarint(data: bytes) -> tuple[int, int] | None:
    value = 0
    shift = 0
    for index, byte in enumerate(data[:10]):
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, index + 1
        shift += 7
    return None
