from __future__ import annotations

import argparse
import sys
from pathlib import Path

from pied import __version__
from pied.github import GitHub, GitHubError, list_repos, load_token, scan_named
from pied.host import scan_host
from pied.local import scan_path
from pied.model import SEVERITY_RANK, Target
from pied.report import render_json, render_text, use_color


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pied",
        description=(
            "Read-only scanner for the October 2026 eMudhra intermediate CA incident "
            "and the Node.js 21 Oct 2026 security release (CVE-2026-111497 and the nine CVEs shipped with it)."
        ),
    )
    parser.add_argument("--version", action="version", version=f"pied {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser("scan", help="scan a git tree, one repository, or every repository in an org")
    scan.add_argument("--path", help="local file or directory")
    scan.add_argument("--org", help="GitHub organization or user")
    scan.add_argument("--repo", action="append", default=[], help="owner/name, or a name inside --org. Repeatable.")
    scan.add_argument("--include-forks", action="store_true")
    scan.add_argument("--include-archived", action="store_true")
    scan.add_argument("--jobs", type=int, default=6)
    scan.add_argument("--max-repos", type=int, default=0, help="stop after this many repositories (0 means all)")
    scan.add_argument("--format", choices=("text", "json"), default="text")
    scan.add_argument("--output", help="write the report to this file as well as stdout")
    scan.add_argument("--verbose", action="store_true", help="include patched pins")
    scan.add_argument("--fail-on", choices=tuple(SEVERITY_RANK), default="high")
    scan.add_argument("--no-color", action="store_true", help="plain text. Color is on when stdout is a terminal.")

    host = commands.add_parser("host", help="scan this machine: runtimes, CA bundles, virtualenvs, and local images")
    host.add_argument("--venv-root", action="append", default=[], help="extra directory to walk for virtualenvs")
    host.add_argument("--max-depth", type=int, default=6)
    host.add_argument("--max-venvs", type=int, default=120)
    host.add_argument("--max-binaries", type=int, default=80, help="cap on compiled Go binaries read from PATH")
    host.add_argument("--no-docker", action="store_true")
    host.add_argument("--docker-all", action="store_true", help="probe every local image, not only language-runtime names")
    host.add_argument("--docker-limit", type=int, default=30)
    host.add_argument("--quiet", action="store_true", help="hide results that are already patched")
    host.add_argument("--format", choices=("text", "json"), default="text")
    host.add_argument("--output")
    host.add_argument("--fail-on", choices=tuple(SEVERITY_RANK), default="high")
    host.add_argument("--no-color", action="store_true", help="plain text. Color is on when stdout is a terminal.")

    args = parser.parse_args(argv)
    try:
        if args.command == "scan":
            targets = _scan(args)
            verbose = args.verbose
        else:
            roots = [Path(item) for item in args.venv_root] or None
            targets = [
                scan_host(
                    venv_roots=roots,
                    max_depth=args.max_depth,
                    max_venvs=args.max_venvs,
                    max_binaries=args.max_binaries,
                    docker=not args.no_docker,
                    docker_all=args.docker_all,
                    docker_limit=args.docker_limit,
                    include_ok=not args.quiet,
                )
            ]
            verbose = not args.quiet
    except GitHubError as exc:
        print(f"pied: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        text = render_json(targets)
        saved = text
    else:
        text = render_text(targets, verbose=verbose, color=use_color(not args.no_color))
        saved = text if args.no_color or not use_color(True) else render_text(targets, verbose=verbose, color=False)
    sys.stdout.write(text)
    if args.output:
        Path(args.output).write_text(saved, encoding="utf-8")
    return _exit_code(targets, args.fail_on)


def _scan(args: argparse.Namespace) -> list[Target]:
    if args.path and (args.org or args.repo):
        raise GitHubError("Use either --path or --org/--repo, not both.")
    if args.path:
        return [scan_path(Path(args.path), include_ok=args.verbose)]
    if not args.org and not args.repo:
        raise GitHubError("Tell pied what to scan: --path, --org, --repo owner/name, or --org plus --repo.")
    client = GitHub(load_token())
    names = _repo_names(client, args)
    if not names:
        raise GitHubError("No repositories matched. Forks and archived repos are skipped unless you opt in.")

    def progress(message: str) -> None:
        print(message, file=sys.stderr)

    return scan_named(client, names, jobs=args.jobs, include_ok=args.verbose, progress=progress)


def _repo_names(client: GitHub, args: argparse.Namespace) -> list[tuple[str, str]]:
    if args.org and not args.repo:
        repos = list_repos(
            client,
            args.org,
            include_forks=args.include_forks,
            include_archived=args.include_archived,
        )
        names = [(args.org, repo["name"]) for repo in repos]
    else:
        names = []
        for repo in args.repo:
            if "/" in repo:
                owner, name = repo.split("/", 1)
                names.append((owner, name))
            elif args.org:
                names.append((args.org, repo))
            else:
                raise GitHubError(f"{repo} needs to be owner/name, or pass --org.")
    if args.max_repos:
        return names[: args.max_repos]
    return names


def _exit_code(targets: list[Target], fail_on: str) -> int:
    if targets and all(target.error and not target.findings and target.files_scanned == 0 for target in targets):
        return 2
    threshold = SEVERITY_RANK[fail_on]
    for target in targets:
        for finding in target.findings:
            if SEVERITY_RANK.get(finding.severity, 9) <= threshold:
                return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
