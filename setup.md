# Setup and ways to test pied

Python 3.9 or newer is enough. Nothing here installs packages, edits a trust store, or contacts the demonstration hosts.

## Set up the repository

### Download without git

curl:

```bash
curl -fsSL https://github.com/CodeDotJS/pwn.pied/archive/refs/heads/main.tar.gz | tar -xz
cd pwn.pied-main
./bin/pied --version
```

wget:

```bash
wget -qO- https://github.com/CodeDotJS/pwn.pied/archive/refs/heads/main.tar.gz | tar -xz
cd pwn.pied-main
./bin/pied --version
```

### Clone and run locally

```bash
git clone https://github.com/CodeDotJS/pwn.pied.git
cd pwn.pied
./bin/pied --version
```

Over SSH:

```bash
git clone git@github.com:CodeDotJS/pwn.pied.git
cd pwn.pied
./bin/pied --version
```

`./bin/pied` is `python3 -m pied` with `src` on `PYTHONPATH`. The same commands work as `PYTHONPATH=src python3 -m pied ...`.

A `pied` command on your `PATH` is optional, and it does not upgrade anything:

```bash
python3 -m pip install -e .
pied --version
```

Confirm the checkout before you point pied at anything else:

```bash
PYTHONPATH=src python3 tests/test_pied.py
./bin/pied scan --path .
```

The tests use temporary directories. `scan --path .` on this repository should be clean.

Every command below assumes you are inside that checkout (`pwn.pied` after a clone, `pwn.pied-main` after curl or wget).

A scan reads files and the GitHub API. It does not write into the project you point `--path` at. If you want a copy of the report, send `--output` somewhere else, such as `/tmp`.

Exit status:

| Code | Meaning |
| --- | --- |
| 0 | Nothing at or above `--fail-on` (default `high`) |
| 1 | At least one finding meets `--fail-on` |
| 2 | The scan could not run: no target, a rejected token, or no matching repository |

In a terminal, severity labels and the summary counts are colored. Critical and high are red, medium is yellow, low is cyan, info is blue, and clean or ok is green. Pass `--no-color`, or set `NO_COLOR`, for plain text. A pipe is plain text too. `--output` saves a plain copy even when the terminal is colored. `--format json` is never colored.

## 1. Unit tests

Where: this checkout. No GitHub calls, no trust-store reads.

```bash
PYTHONPATH=src python3 tests/test_pied.py
```

Expect `OK` and exit 0. The tests build temporary directories and delete them.

## 2. This repository

Where: the pied checkout.

```bash
./bin/pied scan --path .
```

Expect `clean` and exit 0. The only manifest is `pyproject.toml`.

## 3. Another local checkout

Where: any project directory you already have. pied does not clone it and does not modify it.

```bash
./bin/pied scan --path /path/to/project
```

A single file works too:

```bash
./bin/pied scan --path /path/to/project/Dockerfile
```

Exit 0 means the manifests that were read do not pin a vulnerable release. It does not prove the laptop or a deployed image is patched. Use `pied host` for the machine.

## 4. One public repository

Where: GitHub, read through the API. No clone. A token is optional until the unauthenticated rate limit. `GH_TOKEN`, `GITHUB_TOKEN`, or `gh auth token` are used when set.

```bash
./bin/pied scan --repo certifi/python-certifi
./bin/pied scan --repo expressjs/express
./bin/pied scan --org psf --repo requests
```

`--repo` is `owner/name`, or a bare name together with `--org`.

## 5. Several repositories

```bash
./bin/pied scan \
  --repo certifi/python-certifi \
  --repo expressjs/express \
  --repo psf/requests \
```

`--jobs` defaults to 6. Lower it if you are near a rate limit:

```bash
./bin/pied scan --repo certifi/python-certifi --repo expressjs/express --jobs 1
```

## 6. An organization

Replace `my-org` with an org your token can read. Start with a cap.

```bash
./bin/pied scan --org my-org --max-repos 5
```

One repository inside that org, without writing `owner/` again:

```bash
./bin/pied scan --org my-org --repo payments
```

Forks and archived repositories are skipped unless you opt in:

```bash
./bin/pied scan --org my-org --max-repos 5 --include-forks --include-archived
```

`--path` cannot be combined with `--org` or `--repo`. That exits 2.

## 7. A finding, without using a real project

This builds a temporary tree, scans it, and deletes it. Expect exit 1: critical on Node.js 22.23.3 (Express 5 raises it), high on certifi. The Node ids are the 22.x set. CVE-2026-105483 is not in that list; it applies to 24 and 26 only.

```bash
dir=$(mktemp -d)
printf 'certifi==2024.8.30\n' > "$dir/requirements.txt"
printf '%s\n' '{"engines":{"node":"22.23.3"},"dependencies":{"express":"^5.0.0"}}' > "$dir/package.json"
./bin/pied scan --path "$dir"
echo "exit:$?"
rm -rf "$dir"
```

## 8. JSON, and a copy of the report

JSON goes to stdout. `--output` also writes that same text. Keep the file out of the project you scanned.

```bash
./bin/pied scan --repo certifi/python-certifi --format json --output /tmp/pied-certifi.json
```

`research/host-scan.txt`, `research/local/`, and a `report.json` at the root of this repo are gitignored. Other filenames are not. Do not commit a report that names a home directory or a private repository.

## 9. Severity and already-patched pins

`--fail-on` defaults to `high`. Use `medium` when an unpinned `pip install --upgrade pip` should fail the command too:

```bash
./bin/pied scan --path /path/to/project --fail-on medium
```

`--verbose` prints pins that are already at a fixed release. Those lines are `ok` and do not change the exit status unless `--fail-on ok`.

```bash
./bin/pied scan --repo certifi/python-certifi --verbose
```

## 10. This machine

`pied host` is read-only. It runs version commands (`python --version`, `node --version`, `go version`, and the same for uv, Bun, Deno, and Java), reads CA files, and reads Go buildinfo headers inside executables. It does not install, delete certificates, or open a connection to the demonstration hosts.

Skip Docker if the daemon is not something you want queried:

```bash
./bin/pied host --no-docker
```

Hide results that are already patched:

```bash
./bin/pied host --no-docker --quiet
```

Limit how much of the disk is walked:

```bash
./bin/pied host --no-docker --max-venvs 20 --max-binaries 20 --max-depth 3
```

Extra virtualenv roots:

```bash
./bin/pied host --no-docker --venv-root /path/to/work
```

Docker probes, when you leave them on, use `docker run --network none`. By default only images whose names look like Python, Node, Go, uv, Bun, or Deno are started. `--docker-all` is every local image, still offline, capped by `--docker-limit` (default 30).

```bash
./bin/pied host --docker-limit 5
```

Write the report outside any project:

```bash
./bin/pied host --no-docker --output /tmp/pied-host.txt
```

Expect exit 1 on a machine that still has an old pip, an old Node, or an emSign root in a PEM bundle. Exit 0 means nothing at or above high was found.

## What a clean result does not mean

A repository scan reads manifests, lockfiles, Dockerfiles, compose files, workflows, `.python-version`, `.nvmrc`, `go.mod`, `Cargo.toml`, `Cargo.lock`, and PEM bundles. Remote scans stop at 80 manifest files per repository, 2.5 MB each, and say so in the report. They do not download built binaries. `pied host` and a local `--path` scan are what see a compiled Go tool and the trust store a process actually loads.
