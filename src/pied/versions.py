from __future__ import annotations

import re
from functools import total_ordering


@total_ordering
class Version:
    def __init__(self, parts: tuple[int, ...] | list[int]):
        self.parts = tuple(int(part) for part in parts)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Version):
            return NotImplemented
        return self._padded(other) == other._padded(self)

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Version):
            return NotImplemented
        return self._padded(other) < other._padded(self)

    def _padded(self, other: Version) -> tuple[int, ...]:
        width = max(len(self.parts), len(other.parts))
        return self.parts + (0,) * (width - len(self.parts))

    def __repr__(self) -> str:
        return ".".join(str(part) for part in self.parts)

    @property
    def major(self) -> int:
        return self.parts[0] if self.parts else 0

    @property
    def minor(self) -> int | None:
        return self.parts[1] if len(self.parts) > 1 else None


_VERSION_RE = re.compile(r"\d+(?:\.\d+){0,5}")


def parse_version(text: str | None) -> Version | None:
    if text is None:
        return None
    raw = str(text).strip().strip("'\"")
    raw = re.sub(r"^[vV]", "", raw)
    raw = raw.replace("_", ".")
    match = _VERSION_RE.search(raw)
    if not match:
        return None
    return Version(tuple(int(part) for part in match.group(0).split(".")))


def parse_java_version(text: str) -> Version | None:
    legacy = re.search(r"1\.(\d+)\.(\d+)_(\d+)", text)
    if legacy:
        return Version((int(legacy.group(1)), int(legacy.group(2)), int(legacy.group(3))))
    compact = re.search(r"\b(\d+)u(\d+)\b", text)
    if compact:
        return Version((int(compact.group(1)), 0, int(compact.group(2))))
    return parse_version(text)


def _incomplete(version: Version, floor: Version) -> bool:
    return len(version.parts) < len(floor.parts) and version.parts == floor.parts[: len(version.parts)]


def _classify_comma(text: str, floor: Version) -> str:
    lower: Version | None = None
    lower_inclusive = False
    upper: Version | None = None
    upper_inclusive = False
    saw_bound = False
    for part in text.split(","):
        if not part or part.startswith("!="):
            continue
        if part.startswith(">="):
            version = parse_version(part[2:])
            inclusive = True
            bound = "lower"
        elif part.startswith("<="):
            version = parse_version(part[2:])
            inclusive = True
            bound = "upper"
        elif part.startswith(">"):
            version = parse_version(part[1:])
            inclusive = False
            bound = "lower"
        elif part.startswith("<"):
            version = parse_version(part[1:])
            inclusive = False
            bound = "upper"
        elif part.startswith("=="):
            version = parse_version(part[2:])
            if version is None:
                return "unknown"
            return "patched" if version >= floor else "vulnerable"
        elif part.startswith("~="):
            version = parse_version(part[2:])
            if version is None:
                return "unknown"
            return "patched" if version >= floor else "vulnerable"
        else:
            return "floating"
        if version is None:
            return "unknown"
        saw_bound = True
        if bound == "lower":
            lower, lower_inclusive = version, inclusive
        else:
            upper, upper_inclusive = version, inclusive
    if not saw_bound:
        return "floating"
    if lower is not None and lower >= floor and (lower_inclusive or lower > floor):
        if upper is not None and (
            (upper_inclusive and upper < floor) or (not upper_inclusive and upper <= floor)
        ):
            return "vulnerable"
        return "patched"
    if lower is None:
        return "vulnerable"
    if lower < floor:
        return "vulnerable"
    return "floating"


def classify_minimum(spec: str, floor: Version) -> str:
    """Classify a pin against a single minimum fixed version.

    patched: every version the spec allows is at or above the floor
    vulnerable: the spec allows a release below the floor
    floating: the spec does not name a complete version
    unknown: the spec could not be parsed
    """
    text = spec.strip().strip("'\"")
    text = re.sub(r"^[vV]", "", text)
    text = re.sub(r"\s+", "", text)
    if text in {"", "*", "latest"} or text.endswith(".x") or text.endswith(".*"):
        return "floating"
    if "," in text:
        return _classify_comma(text, floor)
    caret = re.fullmatch(r"\^(\d+(?:\.\d+){0,5})", text)
    tilde = re.fullmatch(r"~(\d+(?:\.\d+){0,5})", text)
    if caret or tilde:
        version = parse_version((caret or tilde).group(1))
        if version is None:
            return "unknown"
        if _incomplete(version, floor):
            return "floating"
        return "patched" if version >= floor else "vulnerable"
    if text.startswith(">="):
        version = parse_version(text[2:])
        if version is None:
            return "unknown"
        return "patched" if version >= floor else "vulnerable"
    if text.startswith(">"):
        version = parse_version(text[1:])
        if version is None:
            return "unknown"
        return "patched" if version >= floor else "vulnerable"
    if text.startswith("<=") or text.startswith("<") or text.startswith("!="):
        return "vulnerable" if text.startswith("<") else "floating"
    if text.startswith("=="):
        text = text[2:]
    if text.startswith("~="):
        version = parse_version(text[2:])
        if version is None:
            return "unknown"
        return "patched" if version >= floor else "vulnerable"
    cleaned = re.split(r"[-@+/]", text, maxsplit=1)[0]
    version = parse_version(cleaned)
    if version is None:
        return "unknown"
    if _incomplete(version, floor):
        return "floating"
    return "patched" if version >= floor else "vulnerable"


def classify_node(spec: str) -> str:
    from pied.advisories import NODE_EOL_MAJORS, NODE_FLOORS

    text = spec.strip().strip("'\"")
    lowered = text.lower()
    if not text or lowered in {"latest", "node", "current", "lts", "stable", "hydrogen"}:
        return "floating"
    if "lts/" in lowered or "*" in text or re.search(r"(?i)\.x\b", text):
        major_match = re.search(r"\d+", text)
        if major_match and int(major_match.group(0)) in NODE_EOL_MAJORS:
            return "vulnerable"
        return "floating"
    compact = re.sub(r"\s+", "", text)
    bounded = re.fullmatch(r">=v?(\d+(?:\.\d+){2})<v?(\d+)(?:\.0){0,2}", compact)
    if bounded:
        lower = parse_version(bounded.group(1))
        upper_major = int(bounded.group(2))
        if lower is None:
            return "unknown"
        if lower.major in NODE_EOL_MAJORS:
            return "vulnerable"
        floor = NODE_FLOORS.get(lower.major)
        if floor and upper_major == lower.major + 1 and lower >= floor:
            return "patched"
        if floor:
            return "vulnerable"
        return "floating"
    ranged = re.fullmatch(r"[\^~]v?(\d+(?:\.\d+){0,3})", compact)
    if ranged:
        version = parse_version(ranged.group(1))
        if version is None:
            return "unknown"
        if version.major in NODE_EOL_MAJORS:
            return "vulnerable"
        floor = NODE_FLOORS.get(version.major)
        if floor is None:
            return "patched" if version.major > 26 else "unknown"
        if len(version.parts) < 3:
            return "floating"
        return "patched" if version >= floor else "vulnerable"
    if any(operator in compact for operator in (">=", "<=", ">", "<", "||")):
        major_match = re.search(r"\d+", compact)
        if major_match and int(major_match.group(0)) in NODE_EOL_MAJORS and compact.startswith("<"):
            return "vulnerable"
        return "floating"
    cleaned = re.split(r"[-@]", re.sub(r"^[vV]", "", text), maxsplit=1)[0]
    if re.fullmatch(r"\d+", cleaned):
        major = int(cleaned)
        if major in NODE_EOL_MAJORS:
            return "vulnerable"
        if major in NODE_FLOORS:
            return "floating"
        return "patched" if major > 26 else "unknown"
    version = parse_version(cleaned)
    if version is None:
        return "unknown"
    if version.major in NODE_EOL_MAJORS:
        return "vulnerable"
    floor = NODE_FLOORS.get(version.major)
    if floor is None:
        return "patched" if version.major > 26 else "unknown"
    if len(version.parts) < 3:
        return "floating"
    return "patched" if version >= floor else "vulnerable"


def classify_go(spec: str) -> str:
    from pied.advisories import GO_126_FLOOR, GO_127_FLOOR

    text = spec.strip().strip("'\"")
    text = re.sub(r"(?i)^go", "", text)
    cleaned = re.split(r"[-@]", text, maxsplit=1)[0]
    version = parse_version(cleaned)
    if version is None or version.major != 1 or version.minor is None:
        return "unknown"
    minor = version.minor
    if len(version.parts) < 3:
        if minor >= 28:
            return "floating"
        if minor in {26, 27}:
            return "floating"
        return "vulnerable"
    if minor >= 28:
        return "patched"
    if minor == 27:
        return "patched" if version >= GO_127_FLOOR else "vulnerable"
    if minor == 26:
        return "patched" if version >= GO_126_FLOOR else "vulnerable"
    return "vulnerable"


def classify_electron(spec: str) -> str:
    from pied.advisories import ELECTRON_FLOORS

    status = classify_minimum(spec, Version((0,)))
    if status == "floating":
        return "floating"
    version = parse_version(re.sub(r"^[vV^~>=<]+", "", spec.strip()))
    if version is None:
        return "unknown"
    if version.major in ELECTRON_FLOORS:
        floor = ELECTRON_FLOORS[version.major]
        if len(version.parts) < 3 and version.parts == floor.parts[: len(version.parts)]:
            return "floating"
        return "patched" if version >= floor else "vulnerable"
    if version.major > 44:
        return "patched"
    return "vulnerable"


def classify_java(spec: str) -> str:
    from pied.advisories import JAVA_FLOORS

    version = parse_java_version(spec)
    if version is None:
        return "unknown"
    major = version.major
    if major == 1 and version.minor == 8:
        major = 8
        version = Version((8,) + version.parts[2:])
    floor = JAVA_FLOORS.get(major)
    if floor is None:
        return "floating"
    if len(version.parts) < 3:
        return "floating"
    return "patched" if version >= floor else "vulnerable"
