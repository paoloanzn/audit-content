"""Host-side checks that need no VM, no Claude token, and no internet.

Run with: python3 -m unittest discover -s tests -v

The install tests put stand-ins for `container` and `security` first on PATH, so `uninstall`
never reaches the real sandbox image or the Keychain token.
"""

from __future__ import annotations

import http.client
import importlib.util
import os
import plistlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from unittest import mock

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


class ScheduleTest(unittest.TestCase):
    """Scheduled checks against the real domain list, state file, helper app and memory readings. Mail,
    Telegram, Claude and the VM are replaced, and HOME is a temp folder, so the real schedule is never touched."""

    def setUp(self) -> None:
        self.home = Path(tempfile.mkdtemp(prefix="audit-content-test-"))
        patcher = mock.patch.dict(os.environ, {"HOME": str(self.home)})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(shutil.rmtree, self.home)

    def test_what_is_worth_a_check(self) -> None:
        for url in ("https://docs.github.com/en/actions", "https://twitter.com/x/status/1", "https://www.wikipedia.org/",
                    "https://maps.app.goo.gl/abc", "https://www.irs.gov/forms"):  # known sites
            self.assertIsNone(ac.link_flags(url), url)
        self.assertIsNone(ac.link_flags("https://www.google.com/url?q=https://en.wikipedia.org/wiki/Mail"))
        for url in ("https://sites.google.com/view/payroll", "https://someone.github.io/claim", "https://goo.gl/abc",
                    "https://www.google.com/url?q=https://evil.example/"):  # anyone can publish there, or unknown
            self.assertEqual(ac.link_flags(url), (), url)
        for url, sign in (("http://192.0.2.7/login", "bare IP address"), ("https://xn--pple-43d.com/", "look-alike"),
                          ("https://аpple.com/", "look-alike"), ("https://github.com@evil.example/", "'@'"),
                          ("https://github.com/a/b/releases/download/v1/Setup.dmg", ".dmg file")):
            self.assertIn(sign, " ".join(ac.link_flags(url) or ("none",)), url)
        files = [("photo.jpg", "k1", None, None), ("invoice.pdf", "k2", None, None), ("invoice.pdf.html", "k3", None, None)]
        leads = ac.message_leads(["https://evil.example/a", "https://evil.example/b", "mailto:x@y.example",
                                  "en.wikipedia.org/wiki/Mail", "www.unknown-shop.example/x"], files,
                                 "Mail, me@x.example", "s", datetime(2026, 1, 1), True, "subject")
        self.assertEqual([(x.kind, x.target, bool(x.flags)) for x in leads], [  # one link per site
            ("link", "https://evil.example/a", False), ("link", "https://www.unknown-shop.example/x", False),
            ("file", "invoice.pdf", False), ("file", "invoice.pdf.html", True)])

    def test_memory_readings_match_macos(self) -> None:
        for name in ("hw.memsize", "kern.memorystatus_vm_pressure_level"):
            out = subprocess.run(["sysctl", "-n", name], capture_output=True, text=True).stdout
            self.assertEqual(ac.sysctl(name), int(out), name)
        self.assertIn(ac.memory_problem() is None or "memory" in ac.memory_problem(), (True,))

    def test_a_run_waiting_for_memory_stops_before_the_next_slot(self) -> None:
        with mock.patch.object(ac, "memory_problem", return_value="busy"), \
                mock.patch.object(ac, "RETRY_SECONDS", 0.2), mock.patch.object(ac.time, "sleep", wraps=ac.time.sleep) as sleep:
            self.assertFalse(ac.wait_for_memory(datetime.now().astimezone() + timedelta(seconds=0.5)))
        self.assertEqual(sleep.call_count, 2)  # a third look would pass the deadline: the run ends instead

    def lead(self, target: str, unread: bool = True, minutes: int = 0) -> Any:
        return ac.Lead("link", target, ac.lead_key(target), "Telegram, group “g”", "sender",
                       datetime(2026, 10, 30, 12, 0) - timedelta(minutes=minutes), unread, "text",
                       ac.link_flags(target) or ())

    def run_once(self, leads: List[Any], skip: Tuple[str, ...] = (), verdict: str = "SAFE"
                 ) -> Tuple[List[str], List[str], int]:
        """A background run over `leads`: what Claude was asked about, what was checked, and how many alerts."""
        asked: List[str] = []
        checked: List[str] = []

        def triage(ask: List[Any], token: str) -> Optional[Dict[int, Tuple[bool, str]]]:
            asked.extend(x.target for x in ask)
            return {i: (x.target not in skip, "") for i, x in enumerate(ask)}

        def check(lead: Any) -> Any:
            checked.append(lead.target)
            report = self.home / f"report-{len(checked)}.html"
            report.write_text("report")
            return ac.context_menu.Outcome(verdict, lead.label, ("reason",), report, 0)

        with mock.patch.object(ac, "gather", return_value=(leads, [], None)), \
                mock.patch.object(ac, "triage", side_effect=triage), \
                mock.patch.object(ac, "check_lead", side_effect=check), \
                mock.patch.object(ac, "keychain_get", return_value="token"), \
                mock.patch.object(ac, "memory_problem", return_value=None), \
                mock.patch.object(ac.context_menu, "alert", return_value=False) as alert:
            self.assertEqual(ac.scheduled_run(True, False), 0)
        return asked, checked, alert.call_count

    def test_each_link_is_triaged_and_checked_once(self) -> None:
        leads = [self.lead("https://a.example/", unread=False), self.lead("https://b.example/", minutes=5),
                 self.lead("http://192.0.2.7/")]
        self.assertEqual(self.run_once(leads, skip=("https://b.example/",)), (
            ["https://b.example/", "https://a.example/"],  # unread first
            ["http://192.0.2.7/", "https://a.example/"], 0))  # warning signs skip triage and go first
        self.assertEqual(list(self.home.glob("report-*")), [])  # reports of clean checks are deleted
        self.assertEqual(self.run_once(leads), ([], [], 0))
        self.assertEqual(self.run_once(leads), ([], [], 0))
        files = ac.ScheduleFiles.for_user()
        state = ac.load_state(files)
        self.assertEqual(sorted(x["outcome"] for x in state["seen"].values()), ["SAFE", "SAFE", "skipped"])
        self.assertEqual(len(state["runs"]), 2)  # the same news twice is kept once
        self.assertEqual(oct(files.state.stat().st_mode & 0o777), "0o600")

    def test_checks_per_run_are_capped_and_the_rest_waits_without_a_second_triage(self) -> None:
        leads = [self.lead(f"https://site{i}.example/", minutes=i) for i in range(ac.MAX_CHECKS + 3)]
        self.assertEqual(len(self.run_once(leads)[1]), ac.MAX_CHECKS)
        asked, checked, _ = self.run_once(leads)
        self.assertEqual((asked, len(checked)), ([], 3))

    def test_only_a_malicious_verdict_alerts(self) -> None:
        self.assertEqual(self.run_once([self.lead("https://grey.example/")], verdict="SUSPICIOUS")[2], 0)
        self.assertEqual(self.run_once([self.lead("https://evil.example/")], verdict="MALICIOUS")[2], 1)
        findings = ac.load_state(ac.ScheduleFiles.for_user())["findings"]
        self.assertEqual([f["verdict"] for f in findings], ["SUSPICIOUS", "MALICIOUS"])

    def test_helper_app_is_kept_when_unchanged_and_off_removes_everything(self) -> None:
        files = ac.ScheduleFiles.for_user()
        self.assertTrue(ac.build_helper(files.helper, "exit 3"))
        self.assertFalse(ac.build_helper(files.helper, "exit 3"))  # its Full Disk Access grant survives
        info = plistlib.loads((files.helper / "Contents" / "Info.plist").read_bytes())
        self.assertEqual((info["CFBundleIdentifier"], info["LSUIElement"]), (ac.SCHEDULE_LABEL, True))
        self.assertIn("runtime", subprocess.run(["codesign", "-dv", str(files.helper)], capture_output=True,
                                                text=True).stderr)  # no library injection into the helper
        job = ac.agent_definition(files.helper)
        # A failed run ends the app, instead of leaving an error dialog open that makes launchd skip later times.
        self.assertEqual(subprocess.run(job["ProgramArguments"], timeout=30).returncode, 0)
        # Launching it registered it with Launch Services, by its real path (/var is a link to /private/var).
        self.addCleanup(subprocess.run, [ac.LSREGISTER, "-u", str(files.helper.resolve())])
        ac.save_state(files, {"seen": {}})
        files.agent.parent.mkdir(parents=True)
        files.agent.write_bytes(plistlib.dumps(job))
        with mock.patch.object(ac, "run", return_value=(0, "")) as run:  # launchctl, tccutil, lsregister: not for real
            self.assertTrue(ac.schedule_off())
            self.assertFalse(ac.schedule_off())
        self.assertFalse(files.folder.exists() or files.agent.exists())
        self.assertEqual([c.args[0][:2] for c in run.call_args_list],
                         [["launchctl", "bootout"], ["tccutil", "reset"], [ac.LSREGISTER, "-u"]])


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
        for f in ("audit-content.py", "context_menu.py", "telegram.py", "mail.py", "known-domains.txt", "sandbox.py",
                  "Containerfile"):
            shutil.copy2(ROOT / f, self.src / f)
        self.home = self.tmp / "home"  # uninstall removes right-click entries: never the real ones
        self.env = {**os.environ, "PATH": f"{self.fake}:/usr/bin:/bin", "SOURCE_DIR": str(self.src),
                    "HOME": str(self.home)}

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

        p = subprocess.run([sys.executable, str(app / "context_menu.py"), "install"], env=self.env,
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        services = self.home / "Library" / "Services"
        self.assertEqual(len(list(services.glob("*.workflow"))), 2)
        p = subprocess.run([str(link), "uninstall"], env=self.env, capture_output=True, text=True, timeout=120)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertFalse(os.path.lexists(link))
        self.assertFalse(app.exists())
        self.assertEqual(list(services.iterdir()), [])
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
