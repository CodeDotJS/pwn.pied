from __future__ import annotations

import json
import os
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

from pied.manifests import finalize, is_manifest, scan_text
from pied.model import Finding, Target


API = "https://api.github.com"
MAX_BLOB = 2_500_000
USER_AGENT = "pied-scanner"


class GitHubError(RuntimeError):
    pass


class GitHub:
    def __init__(self, token: str = ""):
        self.token = token

    def request(self, url: str, accept: str = "application/vnd.github+json") -> tuple[int, dict, bytes]:
        headers = {
            "Accept": accept,
            "User-Agent": USER_AGENT,
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        request = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=45) as response:
                return response.status, dict(response.headers), response.read()
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers), exc.read()

    def json(self, url: str) -> tuple[dict | list, dict]:
        status, headers, body = self.request(url)
        if status == 404:
            raise GitHubError(f"GitHub returned 404 for {url}")
        if status == 401:
            raise GitHubError("GitHub rejected the token (401). Check GH_TOKEN or `gh auth status`.")
        if status == 403:
            message = body.decode("utf-8", "replace")
            if "rate limit" in message.lower() or headers.get("X-RateLimit-Remaining") == "0":
                raise GitHubError("GitHub rate limit reached. Set GH_TOKEN or wait and rerun.")
            raise GitHubError(f"GitHub refused the request (403): {message[:300]}")
        if status >= 400:
            raise GitHubError(f"GitHub returned {status} for {url}")
        return json.loads(body.decode("utf-8")), headers

    def text_blob(self, owner: str, repo: str, sha: str) -> str:
        url = f"{API}/repos/{owner}/{repo}/git/blobs/{sha}"
        status, _, body = self.request(url, accept="application/vnd.github.raw")
        if status >= 400:
            payload = json.loads(body.decode("utf-8"))
            import base64

            return base64.b64decode(payload["content"]).decode("utf-8", "replace")
        return body.decode("utf-8", "replace")


def load_token() -> str:
    for key in ("GH_TOKEN", "GITHUB_TOKEN"):
        value = os.environ.get(key, "").strip()
        if value:
            return value
    try:
        proc = subprocess.run(
            ["gh", "auth", "token"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    if proc.returncode == 0:
        return proc.stdout.strip()
    return ""


def list_repos(client: GitHub, org: str, *, include_forks: bool, include_archived: bool) -> list[dict]:
    url = f"{API}/orgs/{urllib.parse.quote(org)}/repos?per_page=100&type=all"
    try:
        page, headers = client.json(url)
    except GitHubError as exc:
        if "404" not in str(exc):
            raise
        url = f"{API}/users/{urllib.parse.quote(org)}/repos?per_page=100&type=owner"
        page, headers = client.json(url)
    repos: list[dict] = []
    while True:
        if not isinstance(page, list):
            break
        for repo in page:
            if repo.get("fork") and not include_forks:
                continue
            if repo.get("archived") and not include_archived:
                continue
            if repo.get("disabled"):
                continue
            repos.append(repo)
        link = headers.get("Link") or headers.get("link")
        nxt = _next_link(link)
        if not nxt:
            break
        page, headers = client.json(nxt)
    repos.sort(key=lambda item: item.get("name", "").lower())
    return repos


def scan_repository(
    client: GitHub,
    owner: str,
    repo: str,
    *,
    include_ok: bool = False,
    max_files: int = 80,
    default_branch: str = "",
) -> Target:
    target = Target(name=f"{owner}/{repo}")
    try:
        if not default_branch:
            meta, _ = client.json(f"{API}/repos/{owner}/{repo}")
            if not isinstance(meta, dict):
                target.error = "unexpected repository payload"
                return target
            default_branch = str(meta.get("default_branch") or "HEAD")
        branch = urllib.parse.quote(default_branch, safe="")
        tree, _ = client.json(f"{API}/repos/{owner}/{repo}/git/trees/{branch}?recursive=1")
    except GitHubError as exc:
        target.error = str(exc)
        return target
    if not isinstance(tree, dict):
        target.error = "unexpected tree payload"
        return target
    blobs = []
    for entry in tree.get("tree", []):
        if entry.get("type") != "blob":
            continue
        path = entry.get("path") or ""
        if not is_manifest(path):
            continue
        size = int(entry.get("size") or 0)
        if size > MAX_BLOB:
            continue
        blobs.append(entry)
    blobs.sort(key=lambda item: (_priority(item["path"]), item["path"]))
    if len(blobs) > max_files:
        target.error = f"manifest cap reached: scanned {max_files} of {len(blobs)} files"
        blobs = blobs[:max_files]
    if tree.get("truncated"):
        target.error = (target.error + "; " if target.error else "") + "GitHub truncated the file tree"
    findings: list[Finding] = []
    for entry in blobs:
        try:
            text = client.text_blob(owner, repo, entry["sha"])
        except (GitHubError, KeyError, ValueError) as exc:
            findings.append(
                Finding(
                    "FETCH",
                    "info",
                    f"Could not read {entry['path']}",
                    f"{owner}/{repo}:{entry['path']}",
                    str(exc),
                    "Rerun with a token that can read this repository.",
                    "",
                )
            )
            continue
        findings.extend(scan_text(f"{owner}/{repo}:{entry['path']}", text, include_ok=include_ok))
        target.files_scanned += 1
    target.findings = finalize(findings)
    return target


def scan_named(
    client: GitHub,
    names: list[tuple[str, str]],
    *,
    jobs: int,
    include_ok: bool,
    progress,
) -> list[Target]:
    results: list[Target | None] = [None] * len(names)

    def _one(index: int, owner: str, repo: str) -> tuple[int, Target]:
        progress(f"scanning {owner}/{repo} ({index + 1}/{len(names)})")
        return index, scan_repository(client, owner, repo, include_ok=include_ok)

    workers = max(1, min(jobs, len(names) or 1))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_one, index, owner, repo) for index, (owner, repo) in enumerate(names)]
        for future in as_completed(futures):
            index, target = future.result()
            results[index] = target
    return [target for target in results if target is not None]


def _priority(path: str) -> int:
    name = path.rsplit("/", 1)[-1].lower()
    if name in {"package.json", "pyproject.toml", "uv.lock", "poetry.lock", "go.mod", "dockerfile"}:
        return 0
    if "requirement" in name or "dockerfile" in name:
        return 1
    return 2


def _next_link(header: str | None) -> str | None:
    if not header:
        return None
    for part in header.split(","):
        if 'rel="next"' in part:
            return part.split(";")[0].strip().strip("<>")
    return None
