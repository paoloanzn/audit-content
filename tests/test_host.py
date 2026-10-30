"""Host-side checks that need no VM, no Claude token, and no internet.

Run with: python3 -m unittest discover -s tests -v

The install tests put stand-ins for `container` and `security` first on PATH, so `uninstall`
never reaches the real sandbox image or the Keychain token.
"""

from __future__ import annotations

import http.client
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("audit_content", ROOT / "audit-content.py")
assert _spec is not None and _spec.loader is not None
ac: Any = importlib.util.module_from_spec(_spec)
sys.modules["audit_content"] = ac  # dataclasses look their module up here
_spec.loader.exec_module(ac)

FAKE_CONTAINER = """#!/bin/sh
echo "container $*" >> "$(dirname "$0")/calls.log"
case "$*" in
  --version) echo "container CLI version 1.6.0" ;;
  "system status") echo "apiserver is running" ;;
  *--format*) echo "[]" ;;
esac
"""
FAKE_SECURITY = """#!/bin/sh
echo "security $*" >> "$(dirname "$0")/calls.log"
"""


def passwordless_sudo() -> bool:
    return shutil.which("sudo") is not None and subprocess.run(
        ["sudo", "-n", "true"], capture_output=True).returncode == 0


class ProxyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.proxy = ac.EgressProxy("127.0.0.1", "127.0.0.0/8", "real-token", None)
        self.ports: Dict[str, int] = self.proxy.start()

    def tearDown(self) -> None:
        self.proxy.stop()

    def status(self, role: str, method: str, path: str) -> int:
        conn = http.client.HTTPConnection("127.0.0.1", self.ports[role], timeout=10)
        try:
            conn.request(method, path, body=b"{}" if method == "POST" else None)
            return conn.getresponse().status
        finally:
            conn.close()

    def test_llm_port_accepts_only_exact_messages_paths(self) -> None:
        n = self.proxy.nonce
        for path in (f"/{n}/v1/messages/../../v1/organizations", f"/{n}/v1/messagesX",
                     f"/{n}/v1/messages/batches", "/v1/messages", "/wrong/v1/messages"):
            self.assertEqual(self.status("llm", "POST", path), 403, path)
        self.assertEqual(self.status("llm", "GET", f"/{n}/v1/messages"), 403)
        self.assertEqual(self.status("llm", "CONNECT", "api.anthropic.com:443"), 405)

    def test_private_and_local_addresses_are_refused(self) -> None:
        for target in ("localhost:80", "127.0.0.1:22", "10.0.0.1:443", "192.168.1.1:80",
                       "169.254.169.254:80", "100.64.0.1:443", "[::1]:443"):
            self.assertEqual(self.status("browse", "CONNECT", target), 403, target)
        self.assertEqual(self.status("tools", "GET", "http://127.0.0.1:8080/"), 403)
        self.assertTrue(all(f.private and f.status.startswith("blocked") for f in self.proxy.flows))

    def test_mail_ports_are_refused(self) -> None:
        self.assertEqual(self.status("tools", "CONNECT", "smtp.example.com:25"), 403)
        self.assertEqual(self.proxy.flows[-1].status, "blocked: port 25 not allowed")

    def test_clients_outside_the_vm_network_are_ignored(self) -> None:
        other = ac.EgressProxy("127.0.0.1", "10.0.0.0/8", "real-token", None)
        port = other.start()["browse"]
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            with self.assertRaises(ConnectionError):
                conn.request("CONNECT", "example.com:443")
                conn.getresponse()
            self.assertEqual(other.flows, [])
        finally:
            other.stop()


class VerdictTest(unittest.TestCase):
    def specialists(self, verdict: str) -> Dict[str, Any]:
        return {name: {"status": "ok", "result": {"verdict": verdict, "findings": []}} for name in ac.SPECIALISTS}

    def test_worst_verdict_wins(self) -> None:
        specs = self.specialists("SAFE")
        specs["infra"]["result"]["verdict"] = "MALICIOUS"
        v = ac.merge({"specialists": specs}, [], 1.0)
        self.assertEqual((v.level, v.incomplete), ("MALICIOUS", False))

    def test_hard_evidence_cannot_be_talked_away(self) -> None:
        guest = {"specialists": self.specialists("SAFE"),
                 "indicators": [{"severity": "MALICIOUS", "title": "clipboard command"}]}
        self.assertEqual(ac.merge(guest, [], 1.0).level, "MALICIOUS")

    def test_missing_specialist_is_never_safe(self) -> None:
        specs = self.specialists("SAFE")
        del specs["web"]
        v = ac.merge({"specialists": specs}, [], 1.0)
        self.assertEqual((v.level, v.incomplete), ("SUSPICIOUS", True))


class TargetTest(unittest.TestCase):
    def test_non_web_schemes_are_refused_without_a_vm(self) -> None:
        for url in ("javascript:alert(1)", "file:///etc/passwd", "ms-msdt:/id", "vscode://x"):
            target, refusal = ac.parse_target(url, None)
            self.assertIsNone(target, url)
            self.assertIn("not a web page", refusal)

    def test_web_links_are_normalised(self) -> None:
        for url, want in (("example.com/a", "https://example.com/a"), ("http://[2001:db8::1]/", "http://[2001:db8::1]/"),
                          ("example.com:8080/x", "https://example.com:8080/x")):
            target, refusal = ac.parse_target(url, None)
            self.assertIsNone(refusal)
            self.assertEqual(target.url, want)


class InstallerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="audit-content-test-"))
        self.fake = self.tmp / "fakebin"
        self.src = self.tmp / "src"
        for d in (self.fake, self.src):
            d.mkdir()
        for name, body in (("container", FAKE_CONTAINER), ("security", FAKE_SECURITY)):
            (self.fake / name).write_text(body)
            (self.fake / name).chmod(0o755)
        for f in ("audit-content.py", "sandbox.py", "Containerfile"):
            shutil.copy2(ROOT / f, self.src / f)
        self.env = {**os.environ, "PATH": f"{self.fake}:/usr/bin:/bin", "SOURCE_DIR": str(self.src)}

    def tearDown(self) -> None:
        if passwordless_sudo():
            subprocess.run(["sudo", "-n", "rm", "-rf", str(self.tmp)], check=True)
        else:
            shutil.rmtree(self.tmp)

    def install(self, prefix: Path) -> str:
        p = subprocess.run(["sh", str(ROOT / "install.sh")], env={**self.env, "PREFIX": str(prefix)},
                           capture_output=True, text=True, timeout=120)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        return p.stdout

    def install_update_uninstall(self, prefix: Path) -> str:
        first = self.install(prefix)
        self.assertIn("Installed audit-content", first)
        app, link = prefix / "share" / "audit-content", prefix / "bin" / "audit-content"
        self.assertEqual(link.resolve(), (app / "audit-content.py").resolve())
        self.assertEqual((app / ".install-link").read_text().strip(), str(link))
        p = subprocess.run([str(link), "--help"], env=self.env, capture_output=True, text=True, timeout=60)
        self.assertIn("usage: audit-content", p.stdout)

        self.assertNotIn("sandbox changed", self.install(prefix))
        with (self.src / "sandbox.py").open("a") as f:
            f.write("\n# changed\n")
        self.assertIn("The sandbox changed", self.install(prefix))
        self.assertEqual(sorted(os.listdir(prefix / "share")), ["audit-content"])  # no staging leftovers

        p = subprocess.run([str(link), "uninstall"], env=self.env, capture_output=True, text=True, timeout=120)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertFalse(os.path.lexists(link))
        self.assertFalse(app.exists())
        calls = (self.fake / "calls.log").read_text()
        self.assertIn(f"container image delete {ac.IMAGE}", calls)
        self.assertIn(f"security delete-generic-password -a {ac.KEYCHAIN_ACCOUNT}", calls)
        return first

    def test_user_writable_prefix(self) -> None:
        self.assertNotIn("administrator", self.install_update_uninstall(self.tmp / "prefix"))

    @unittest.skipUnless(passwordless_sudo(), "needs passwordless sudo")
    def test_root_owned_prefix_uses_sudo(self) -> None:
        prefix = self.tmp / "root"
        subprocess.run(["sudo", "-n", "install", "-d", "-o", "root", "-g", "wheel", "-m", "755",
                        str(prefix / "bin"), str(prefix / "share")], check=True)
        self.assertIn("needs administrator rights", self.install_update_uninstall(prefix))

    def test_refuses_to_replace_a_regular_file(self) -> None:
        prefix = self.tmp / "taken"
        (prefix / "bin").mkdir(parents=True)
        (prefix / "bin" / "audit-content").write_text("someone else's tool\n")
        p = subprocess.run(["sh", str(ROOT / "install.sh")], env={**self.env, "PREFIX": str(prefix)},
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 1)
        self.assertIn("is not a link", p.stderr)
        self.assertFalse((prefix / "share").exists())


if __name__ == "__main__":
    unittest.main()
