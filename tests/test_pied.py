from __future__ import annotations

import json
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from contextlib import redirect_stdout
from unittest.mock import patch

from pied.advisories import ALL_ADVISORIES, INTERMEDIATE_FINGERPRINTS, ROOTS, node_cves
from pied.bins import brotli_version, contains_buildinfo, go_toolchain, linked_brotli
from pied.certs import certificate_fingerprints, findings_for_ca_conf, findings_for_fingerprints
from pied.cli import main
from pied.model import Finding, Target
from pied.report import render_text
from pied.host import _pip_remediation, _release
from pied.manifests import finalize, scan_text
from pied.versions import Version, classify_go, classify_java, classify_minimum, classify_node

REPO = Path(__file__).resolve().parents[1]


ROOT = "86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B"
AAA = "D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4"
INTERMEDIATE = "42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493"


class VersionTests(unittest.TestCase):
    def test_node_release_lines(self):
        cases = {
            "24.22.1": "patched",
            "v24.22.1": "patched",
            "24.22.0": "vulnerable",
            "24.22.1-alpine": "patched",
            "22.23.4": "patched",
            "22.23.3": "vulnerable",
            "26.12.1": "patched",
            "26.12.0": "vulnerable",
            "26.13.0": "patched",
            "27.0.0": "patched",
            "20.19.5": "vulnerable",
            "20": "vulnerable",
            "23.5.0": "vulnerable",
            "25.1.0": "vulnerable",
            "22": "floating",
            "22.23": "floating",
            "22.x": "floating",
            "lts/jod": "floating",
            "latest": "floating",
            "^24.22.1": "patched",
            "^24.22.0": "vulnerable",
            "^22.0.0": "vulnerable",
            "~24.22.1": "patched",
            ">=22.23.4 <23": "patched",
            ">=22.0.0 <23": "vulnerable",
            ">=24.22.1": "floating",
        }
        for spec, expected in cases.items():
            with self.subTest(spec=spec):
                self.assertEqual(classify_node(spec), expected)

    def test_minimum_pins(self):
        floor = Version((2026, 10, 19))
        cases = {
            "2026.10.19": "patched",
            "2026.10.18": "vulnerable",
            "==2026.10.19": "patched",
            "==2024.8.30": "vulnerable",
            ">=2026.10.19": "patched",
            ">=2024.8.30": "vulnerable",
            ">=2024.8.30,<2025": "vulnerable",
            ">=2026.10.19,<2027": "patched",
            "~=2026.10.19": "patched",
            "2026.10": "floating",
            "*": "floating",
        }
        uv = Version((0, 13, 4))
        self.assertEqual(classify_minimum("^0.13.3", uv), "vulnerable")
        self.assertEqual(classify_minimum("26.2.2", Version((26, 2, 2))), "patched")
        self.assertEqual(classify_minimum("26.2.1", Version((26, 2, 2))), "vulnerable")
        self.assertEqual(classify_minimum("26.3", Version((26, 2, 2))), "patched")
        self.assertEqual(classify_minimum("26.2", Version((26, 2, 2))), "floating")
        for spec, expected in cases.items():
            with self.subTest(spec=spec):
                self.assertEqual(classify_minimum(spec, floor), expected)

    def test_go_and_java(self):
        self.assertEqual(classify_go("1.27.3"), "patched")
        self.assertEqual(classify_go("1.27.2"), "vulnerable")
        self.assertEqual(classify_go("1.26.10"), "patched")
        self.assertEqual(classify_go("1.26.9"), "vulnerable")
        self.assertEqual(classify_go("1.25.0"), "vulnerable")
        self.assertEqual(classify_go("1.27"), "floating")
        self.assertEqual(classify_go("go1.27.3"), "patched")
        self.assertEqual(classify_java('openjdk version "17.0.21" 2026-10-20'), "patched")
        self.assertEqual(classify_java('openjdk version "17.0.13" 2024-10-15'), "vulnerable")
        self.assertEqual(classify_java('java version "1.8.0_412"'), "vulnerable")
        self.assertEqual(classify_java("8u511"), "patched")
        self.assertEqual(_release("uv 0.9.21 (0dc9556ad 2025-12-30)"), "0.9.21")
        self.assertEqual(_release("go version go1.25.6 darwin/arm64"), "1.25.6")
        self.assertEqual(classify_minimum("0.9.21", Version((0, 13, 4))), "vulnerable")
        old_python = _pip_remediation("pip 21.2.4 from /usr (python 3.9)")
        self.assertIn("Python 3.10", old_python)
        current = _pip_remediation("pip 26.2.1 from /usr (python 3.12)")
        self.assertIn("sha256=fd7f4dfa8190e014013b9f08f3e973f4e4c26ffd179a204895533a7254813a70", current)


class ManifestTests(unittest.TestCase):
    def rules(self, path: str, text: str) -> list[tuple[str, str]]:
        return [(item.rule, item.severity) for item in scan_text(path, text)]

    def test_requirements_and_lock(self):
        self.assertIn(("EM-CERTIFI", "high"), self.rules("requirements.txt", "certifi==2024.8.30\n"))
        self.assertEqual(self.rules("requirements-dev.txt", "certifi==2026.10.19\n"), [])
        self.assertIn(("EM-PIP", "high"), self.rules("requirements.txt", "pip==26.2.1\n"))
        lock = '[[package]]\nname = "certifi"\nversion = "2024.8.30"\n'
        self.assertIn(("EM-CERTIFI", "high"), self.rules("uv.lock", lock))
        safe = '[[package]]\nname = "certifi"\nversion = "2026.10.19"\n'
        self.assertEqual(self.rules("poetry.lock", safe), [])

    def test_node_exposure_escalates(self):
        package = {
            "engines": {"node": "24.22.0"},
            "dependencies": {"express": "^5.0.0", "body-parser": "^2.1.0"},
        }
        findings = finalize(scan_text("package.json", json.dumps(package)))
        by_rule = {item.rule: item.severity for item in findings}
        self.assertEqual(by_rule["NODE-2026-10-21"], "critical")
        self.assertEqual(by_rule["N2S-EXPOSURE"], "medium")

    def test_patched_node_keeps_exposure_informational(self):
        package = {"engines": {"node": "24.22.1"}, "dependencies": {"express": "^5.1.0"}}
        findings = scan_text("package.json", json.dumps(package))
        self.assertEqual([(item.rule, item.severity) for item in findings], [("N2S-EXPOSURE", "info")])

    def test_express_4_is_not_an_entry_point(self):
        package = {"dependencies": {"express": "^4.21.2", "body-parser": "^1.20.3"}}
        self.assertEqual(scan_text("package.json", json.dumps(package)), [])

    def test_docker_images(self):
        vulnerable = "FROM node:24.22.0-alpine\n"
        self.assertIn(("NODE-2026-10-21", "high"), self.rules("Dockerfile", vulnerable))
        patched = "FROM node:24.22.1-bookworm-slim\n"
        self.assertEqual(self.rules("Dockerfile", patched), [])
        python_image = "FROM python:3.13-slim\nRUN pip install flask\n"
        self.assertIn(("EM-PIP", "high"), self.rules("Dockerfile", python_image))
        pinned = "FROM python:3.13-slim\nRUN python -m pip install 'pip>=26.2.2'\n"
        self.assertEqual(self.rules("Dockerfile", pinned), [])
        floating = "FROM python:3.13-slim\nRUN python -m pip install --upgrade pip\n"
        self.assertIn(("EM-PIP", "medium"), self.rules("Dockerfile", floating))
        compose = "services:\n  api:\n    image: golang:1.27.2\n"
        self.assertIn(("EM-GO", "high"), self.rules("docker-compose.yml", compose))

    def test_go_mod_distinguishes_toolchain_from_language(self):
        text = "module example.com/app\n\ngo 1.22.0\n\ntoolchain go1.27.2\n"
        found = self.rules("go.mod", text)
        self.assertIn(("EM-GO", "info"), found)
        self.assertIn(("EM-GO", "high"), found)

    def test_workflow_node(self):
        text = "jobs:\n  test:\n    steps:\n      - uses: actions/setup-node@v4\n        with:\n          node-version: 20\n"
        self.assertIn(("NODE-2026-10-21", "high"), self.rules(".github/workflows/ci.yml", text))

    def test_identifiers_follow_the_release_line(self):
        def ids(spec: str) -> tuple[str, ...]:
            findings = finalize(scan_text("package.json", json.dumps({"engines": {"node": spec}})))
            return next(item.cves for item in findings if item.rule == "NODE-2026-10-21")

        node_24 = ids("24.22.0")
        self.assertIn("CVE-2026-111497", node_24)
        self.assertIn("CVE-2026-105483", node_24)
        self.assertNotIn("CVE-2026-106070", node_24)
        node_22 = ids("22.23.3")
        self.assertIn("CVE-2026-111497", node_22)
        self.assertIn("CVE-2026-106069", node_22)
        self.assertNotIn("CVE-2026-105483", node_22)
        self.assertIn("CVE-2026-106070", ids("26.12.0"))
        self.assertIn("CVE-2026-106071", ids("26.12.0"))
        self.assertEqual(ids("20.19.5"), ("CVE-2026-111497",))
        self.assertEqual(len(ids("latest")), 10)
        jod = ids("lts/jod")
        self.assertIn("CVE-2026-111497", jod)
        self.assertNotIn("CVE-2026-105483", jod)
        bounded = node_cves(">=22.23.4 <23")
        self.assertIn("CVE-2026-111497", bounded)
        self.assertNotIn("CVE-2026-105483", bounded)

        certifi = finalize(scan_text("requirements.txt", "certifi==2024.8.30\n"))
        self.assertEqual(certifi[0].cves, ("GHSA-6q48-6c7w-9gw2",))
        go_mod = finalize(scan_text("go.mod", "module example.com/app\n\ngo 1.22.0\n\ntoolchain go1.27.2\n"))
        toolchain = next(item for item in go_mod if item.severity == "high")
        self.assertEqual(toolchain.cves, ("CVE-2026-111943",))

    def test_more_manifests(self):
        electron = json.dumps({"dependencies": {"electron": "42.11.15"}})
        self.assertIn(("EM-ELECTRON", "high"), self.rules("package.json", electron))
        cargo = 'rustls-webpki = "0.103.15"\nwebpki-roots = "0.26.8"\n'
        cargo_rules = self.rules("Cargo.toml", cargo)
        self.assertIn(("EM-RUSTLS", "high"), cargo_rules)
        self.assertIn(("EM-WEBPKI", "info"), cargo_rules)
        lock = '[[package]]\nname = "webpki-root-certs"\nversion = "1.0.9"\n'
        self.assertIn(("EM-WEBPKI", "high"), self.rules("Cargo.lock", lock))
        tools = "nodejs 22.23.3\npython 3.13.0\ngo 1.26.10\n"
        tool_rules = self.rules(".tool-versions", tools)
        self.assertIn(("NODE-2026-10-21", "high"), tool_rules)
        self.assertIn(("EM-ENSUREPIP", "info"), tool_rules)
        self.assertNotIn(("EM-GO", "high"), tool_rules)
        self.assertIn(("EM-ENSUREPIP", "info"), self.rules(".python-version", "3.12.8\n"))
        self.assertEqual(self.rules(".python-version", "3.15.1\n"), [])
        yarn = 'express@^5.0.0:\n  version "5.1.0"\n'
        self.assertIn(("N2S-EXPOSURE", "medium"), self.rules("yarn.lock", yarn))
        self.assertIn(("N2S-EXPOSURE", "medium"), self.rules("pnpm-lock.yaml", "express@5.0.1:\n"))


def _go_binary(version: str = "go1.25.6") -> bytes:
    payload = bytes([len(version)]) + version.encode("ascii")
    body = b"\x7fELF" + b"\x00" * 12 + b"\xff Go buildinf:" + bytes([8, 2]) + b"\x00" * 16 + payload
    return body + b"\x00" * (128 - len(body))


class BinaryTests(unittest.TestCase):
    def test_go_buildinfo_and_brotli_linkage(self):
        blob = _go_binary()
        self.assertEqual(go_toolchain(blob), "go1.25.6")
        self.assertIsNone(go_toolchain(b"\xff Go buildinf:" + b"\x00" * 40))
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "tool"
            binary.write_bytes(blob)
            self.assertTrue(contains_buildinfo(binary))
            binary.write_bytes(b"\x7fELF" + b"\x00" * 200)
            self.assertFalse(contains_buildinfo(binary))
        sample = "\t/opt/brotli/lib/libbrotlidec.1.dylib (compatibility version 1.0.0, current version 1.2.0)\n"
        self.assertEqual(linked_brotli(sample), "/opt/brotli/lib/libbrotlidec.1.dylib")
        linux = "libbrotlidec.so.1 => /usr/lib/libbrotlidec.so.1 (0x1000)\n"
        self.assertEqual(linked_brotli(linux), "/usr/lib/libbrotlidec.so.1")
        self.assertEqual(brotli_version("/usr/lib/libbrotlidec.1.2.1.dylib"), "1.2.1")
        self.assertIsNone(brotli_version("/usr/lib/libbrotlidec.1.dylib"))
        bundled = node_cves("Node.js 24.22.0")
        system = node_cves("Node.js 24.22.0", bundled_brotli=False)
        self.assertIn("CVE-2026-111497", bundled)
        self.assertNotIn("CVE-2026-111497", system)
        self.assertIn("CVE-2026-105483", system)

    def test_path_scan_reads_a_built_go_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "tool"
            binary.write_bytes(_go_binary())
            findings = finalize(scan_text("go.mod", "module example.com/app\n\ngo 1.22.0\n"))
            from pied.local import scan_path

            target = scan_path(Path(directory))
        self.assertTrue(any(item.rule == "EM-GO" and item.severity == "info" for item in findings))
        built = [item for item in target.findings if item.rule == "EM-GO" and item.severity == "high"]
        self.assertEqual(len(built), 1)
        self.assertIn("go1.25.6", built[0].evidence)
        self.assertEqual(built[0].cves, ("CVE-2026-111943",))


class CertificateTests(unittest.TestCase):
    def test_known_fingerprints(self):
        roots = findings_for_fingerprints("bundle.pem", {ROOT, AAA, INTERMEDIATE, "AA"})
        severities = {item.evidence.split()[-1]: item.severity for item in roots}
        self.assertEqual(severities[ROOT], "high")
        self.assertEqual(severities[AAA], "medium")
        self.assertEqual(severities[INTERMEDIATE], "high")
        self.assertNotIn("AA", severities)

    def test_pem_round_trip(self):
        import base64
        import hashlib

        der = b"not-a-real-certificate"
        body = base64.encodebytes(der).decode()
        pem = f"-----BEGIN CERTIFICATE-----\n{body}-----END CERTIFICATE-----\n"
        self.assertEqual(certificate_fingerprints(pem), {hashlib.sha256(der).hexdigest().upper()})

    def test_debian_conf(self):
        enabled = findings_for_ca_conf("ca-certificates.conf", "mozilla/emSign_ECC_Root_CA_-_G3.crt\n")
        disabled = findings_for_ca_conf("ca-certificates.conf", "!mozilla/emSign_ECC_Root_CA_-_G3.crt\n")
        self.assertEqual(enabled[0].severity, "high")
        self.assertEqual(disabled[0].severity, "ok")

    def test_indicator_file_matches_the_scanner(self):
        data = json.loads((REPO / "research" / "indicators.json").read_text(encoding="utf-8"))
        text = (REPO / "research" / "indicators.json").read_text(encoding="utf-8")
        self.assertNotIn("BEGIN CERTIFICATE", text)
        self.assertEqual({item["sha256"] for item in data["roots"]}, {item["sha256"] for item in ROOTS})
        self.assertEqual({item["sha256"] for item in data["intermediates"]}, set(INTERMEDIATE_FINGERPRINTS))
        self.assertEqual(len({item["spki_sha256"] for item in data["intermediates"]}), 8)


class CatalogTests(unittest.TestCase):
    def test_docs_name_every_advisory(self):
        for relative in ("docs/ADVISORIES.md", "research/NOTES.md", "README.md"):
            text = (REPO / relative).read_text(encoding="utf-8")
            for item in ALL_ADVISORIES:
                with self.subTest(doc=relative, advisory=item.id):
                    self.assertIn(item.id, text)


class ReportTests(unittest.TestCase):
    def test_color_stays_on_the_severity_word(self):
        target = Target(
            name="demo",
            files_scanned=1,
            findings=[
                Finding("EM-CERTIFI", "high", "certifi old", "requirements.txt", "certifi==1", "upgrade", "https://example.test")
            ],
        )
        text = render_text([target], verbose=False, color=True)
        self.assertIn("\033[31mHIGH", text)
        self.assertIn("\033[0m  EM-CERTIFI", text)
        plain = render_text([target], verbose=False, color=False)
        self.assertNotIn("\033", plain)
        self.assertIn("HIGH      EM-CERTIFI", plain)


class CommandTests(unittest.TestCase):
    def test_path_scan_exits_for_a_vulnerable_tree(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "requirements.txt").write_text("certifi==2024.8.30\n", encoding="utf-8")
            (root / "package.json").write_text(
                json.dumps({"engines": {"node": "22.23.3"}, "dependencies": {"express": "^5.0.0"}}),
                encoding="utf-8",
            )
            stdout = StringIO()
            with redirect_stdout(stdout):
                code = main(["scan", "--path", directory, "--format", "json", "--no-color"])
            payload = json.loads(stdout.getvalue())
        self.assertEqual(code, 1)
        rules = {item["rule"] for item in payload["targets"][0]["findings"]}
        self.assertIn("EM-CERTIFI", rules)
        self.assertIn("NODE-2026-10-21", rules)
        certifi = next(item for item in payload["targets"][0]["findings"] if item["rule"] == "EM-CERTIFI")
        self.assertEqual(certifi["cves"], ["GHSA-6q48-6c7w-9gw2"])
        node = next(item for item in payload["targets"][0]["findings"] if item["rule"] == "NODE-2026-10-21")
        self.assertIn("CVE-2026-111497", node["cves"])
        self.assertNotIn("CVE-2026-105483", node["cves"])
        self.assertEqual(
            next(item["severity"] for item in payload["targets"][0]["findings"] if item["rule"] == "NODE-2026-10-21"),
            "critical",
        )

    def test_clean_tree_exits_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "requirements.txt").write_text("certifi==2026.10.19\n", encoding="utf-8")
            stdout = StringIO()
            with redirect_stdout(stdout):
                code = main(["scan", "--path", directory, "--no-color"])
        self.assertEqual(code, 0)
        self.assertIn("clean", stdout.getvalue())

    def test_missing_arguments(self):
        with patch("sys.stderr", new_callable=StringIO):
            code = main(["scan"])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
