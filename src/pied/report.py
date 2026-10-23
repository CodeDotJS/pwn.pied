from __future__ import annotations

import sys

from pied import __version__
from pied.advisories import DATA_AS_OF
from pied.model import SEVERITY_RANK, Finding, Target

# critical is bold red. The others are the usual terminal palette.
_PAINT = {
    "critical": "\033[1;31m",
    "high": "\033[31m",
    "medium": "\033[33m",
    "low": "\033[36m",
    "info": "\033[34m",
    "ok": "\033[32m",
}
_RESET = "\033[0m"


def render_text(targets: list[Target], *, verbose: bool, color: bool) -> str:
    lines: list[str] = [f"pied {__version__}   advisories as of {DATA_AS_OF}"]
    counts = {name: 0 for name in SEVERITY_RANK}
    files = 0
    for target in targets:
        files += target.files_scanned
        visible = [finding for finding in target.findings if verbose or finding.severity != "ok"]
        lines.append(f"\n{target.name}")
        if target.error:
            lines.append(f"  note     {target.error}")
        if not visible:
            lines.append("  " + _paint("clean", "ok", color) + "    no vulnerable pins or trust anchors in the files that were read")
        for finding in sorted(visible, key=lambda item: (SEVERITY_RANK.get(item.severity, 9), item.rule)):
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
            lines.append(_format_finding(finding, color))
    lines.append("")
    summary = "  ".join(
        _paint(f"{name} {counts.get(name, 0)}", name, color)
        for name in ("critical", "high", "medium", "low", "info", "ok")
    )
    lines.append(f"summary  {summary}  files {files}  targets {len(targets)}")
    lines.append(
        "pied reads versions and certificate fingerprints. It does not change trust stores, "
        "install packages, or contact the public demonstration hosts."
    )
    return "\n".join(lines).rstrip() + "\n"


def render_json(targets: list[Target]) -> str:
    import json

    payload = {
        "tool": "pied",
        "advisory_date": DATA_AS_OF,
        "targets": [target.to_dict() for target in targets],
        "counts": _counts(targets),
    }
    return json.dumps(payload, indent=2) + "\n"


def _counts(targets: list[Target]) -> dict[str, int]:
    counts = {name: 0 for name in SEVERITY_RANK}
    for target in targets:
        for finding in target.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts


def _format_finding(finding: Finding, color: bool) -> str:
    # Pad before painting. The escape codes are wider than the word and would shift the rule column.
    label = _paint(f"{finding.severity.upper():<8}", finding.severity, color)
    block = [
        f"  {label}  {finding.rule:<16}  {finding.title}",
        f"           location     {finding.location}",
        f"           evidence     {finding.evidence}",
    ]
    if finding.cves and finding.severity != "ok":
        block.append("           ids          " + ", ".join(finding.cves))
    if finding.severity != "ok":
        block.append(f"           fix          {finding.remediation}")
        if finding.advisory:
            block.append(f"           advisory     {finding.advisory}")
    return "\n".join(block)


def _paint(text: str, severity: str, color: bool) -> str:
    if not color:
        return text
    code = _PAINT.get(severity, "")
    if not code:
        return text
    return f"{code}{text}{_RESET}"


def use_color(enabled: bool) -> bool:
    if not enabled:
        return False
    return sys.stdout.isatty() and not _no_color()


def _no_color() -> bool:
    import os

    return bool(os.environ.get("NO_COLOR"))
