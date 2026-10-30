"""Right-click entry checks: the service bundles, picking links out of a selection, and what a click does.

Each test uses its own home folder, so the real ~/Library/Services is never touched. macOS's
services registry and the alert are replaced by recorders, and audit-content by a small stand-in
that records its arguments and answers like the real one. On a Mac, the generated workflow is also
compared with Apple's own "Show Map" service.

Run with: python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import json
import os
import plistlib
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import context_menu as cm  # noqa: E402

APPLE_SERVICE = Path("/System/Library/Services/Show Map.workflow/Contents/Resources/document.wflow")

# Stands in for audit-content.py: records its arguments, then answers as FAKE_MODE says.
FAKE_PROGRAM = """import json, os, sys
args = sys.argv[1:]
with open(os.environ["FAKE_LOG"], "a") as f:
    f.write(json.dumps(args) + "\\n")
mode = os.environ["FAKE_MODE"]
if mode == "fail":
    sys.stderr.write("[  0.1s] checking\\naudit-content: the sandbox image is missing; run `audit-content setup`\\n")
    sys.exit(3)
if mode == "garbage":
    print("not json")
    sys.exit(0)
report = os.environ["FAKE_REPORT"]
open(report, "w").write("<html>report</html>")
target = args[-1].replace("--file=", "")
print(json.dumps({"verdict": "SUSPICIOUS", "target": target, "report": report, "reasons": [
    {"severity": "SUSPICIOUS", "title": "Asks for a password\\u202e on a lookalike domain", "source": "web"}]}))
sys.exit(1)
"""


class Recorder:
    """Takes the place of alert(): remembers each alert and answers with the next scripted button."""

    def __init__(self, answers: Tuple[bool, ...] = ()) -> None:
        self.calls: List[Tuple[str, str, int, str, Optional[str]]] = []
        self.answers = list(answers)

    def __call__(self, header: str, message: str, level: int, default: str = "OK",
                 alternate: Optional[str] = None) -> bool:
        self.calls.append((header, message, level, default, alternate))
        return self.answers.pop(0) if self.answers else False


class ContextMenuTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="audit-content-menu-test-"))
        self.home = self.tmp / "home"
        self.home.mkdir()
        self.services = self.home / "Library" / "Services"
        self.refreshes = 0
        program = self.tmp / "fake-audit-content.py"
        program.write_text(FAKE_PROGRAM)
        self.log, self.report = self.tmp / "calls.log", self.tmp / "report.html"
        self.patch(mock.patch.dict(os.environ, {"HOME": str(self.home), "FAKE_LOG": str(self.log),
                                                "FAKE_REPORT": str(self.report), "FAKE_MODE": "verdict"}))
        self.patch(mock.patch.object(cm, "refresh", self.count_refresh))
        self.patch(mock.patch.object(cm, "PROGRAM", program))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def patch(self, patcher: Any) -> None:
        patcher.start()
        self.addCleanup(patcher.stop)

    def count_refresh(self) -> None:
        self.refreshes += 1

    def calls(self) -> List[List[str]]:
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    @staticmethod
    def read(bundle: Path, name: str) -> Dict[str, Any]:
        value = plistlib.loads((bundle / "Contents" / name).read_bytes())
        assert isinstance(value, dict)
        return value

    # -- the entries

    def test_install_writes_one_service_per_entry(self) -> None:
        bundles = cm.install()
        self.assertEqual([b.name for b in bundles], ["Check Link with audit-content.workflow",
                                                     "Check File with audit-content.workflow"])
        self.assertEqual(self.refreshes, 1)
        link, file = (self.read(b, "Info.plist")["NSServices"][0] for b in bundles)
        self.assertEqual((link["NSMessage"], link["NSSendTypes"], link["NSRequiredContext"]),
                         ("runWorkflowAsService", ["public.utf8-plain-text"], {"NSTextContent": "URL"}))
        self.assertEqual((file["NSSendFileTypes"], file["NSRequiredContext"]),
                         (["public.data"], {"NSApplicationIdentifier": "com.apple.finder"}))
        for bundle, kind, method in zip(bundles, ("link", "file"), (0, 1)):
            doc = self.read(bundle, "document.wflow")
            parameters = doc["actions"][0]["action"]["ActionParameters"]
            self.assertEqual(parameters["inputMethod"], method)
            command = shlex.split(parameters["COMMAND_STRING"])
            self.assertEqual(command[0], "exec")
            self.assertEqual(command[2:], ["-I", "-B", str(ROOT / "context_menu.py"), "check", kind]
                             + (["$@"] if kind == "file" else []))
            self.assertEqual(doc["workflowMetaData"]["workflowTypeIdentifier"], "com.apple.Automator.servicesMenu")

    @unittest.skipUnless(APPLE_SERVICE.is_file(), "needs macOS's own service workflows")
    def test_workflow_matches_apples_layout(self) -> None:
        apple = plistlib.loads(APPLE_SERVICE.read_bytes())
        ours = cm.workflow(cm.ENTRIES[0], "/usr/bin/python3")
        self.assertEqual(set(ours) - {"state"}, set(apple) - {"state"})
        apple_action, our_action = apple["actions"][0]["action"], ours["actions"][0]["action"]  # type: ignore[index]
        self.assertEqual(set(our_action), set(apple_action))
        for key in ("ActionBundlePath", "BundleIdentifier", "Class Name"):
            self.assertEqual(our_action[key], apple_action[key])
        self.assertTrue(Path(our_action["ActionBundlePath"]).is_dir())

    def test_install_replaces_its_own_and_remove_takes_only_its_own(self) -> None:
        first = self.read(cm.install()[0], "document.wflow")
        second = self.read(cm.install()[0], "document.wflow")
        self.assertNotEqual(first["actions"][0]["action"]["UUID"], second["actions"][0]["action"]["UUID"])
        mine = self.services / "My Own.workflow"
        (mine / "Contents").mkdir(parents=True)
        (mine / "Contents" / "Info.plist").write_bytes(plistlib.dumps({"CFBundleIdentifier": "com.example.mine"}))
        self.assertEqual(len(cm.remove()), 2)
        self.assertEqual([p.name for p in self.services.iterdir()], ["My Own.workflow"])
        self.assertEqual(cm.remove(), [])  # nothing left of ours: no refresh either
        self.assertEqual(self.refreshes, 3)

    def test_a_bundle_of_the_same_name_that_is_not_ours_is_left_alone(self) -> None:
        taken = self.services / "Check Link with audit-content.workflow"
        (taken / "Contents").mkdir(parents=True)
        (taken / "Contents" / "Info.plist").write_bytes(plistlib.dumps({"CFBundleIdentifier": "com.example.other"}))
        with self.assertRaises(cm.MenuError):
            cm.install()
        self.assertEqual(self.read(taken, "Info.plist")["CFBundleIdentifier"], "com.example.other")
        self.assertEqual(cm.remove(), [])
        self.assertTrue(taken.exists())
        self.assertEqual(sorted(p.name for p in self.services.iterdir()), [taken.name])  # no staging left

    # -- picking what to check

    def test_links_in_a_selection(self) -> None:
        self.assertEqual(cm.links_in("  evil.example/login  "), ["evil.example/login"])
        self.assertEqual(cm.links_in("Log in at https://evil.example/a?x=1. Thanks!"), ["https://evil.example/a?x=1"])
        self.assertEqual(cm.links_in("(see https://en.wikipedia.org/wiki/X_(y)) and <www.b.example>"),
                         ["https://en.wikipedia.org/wiki/X_(y)", "www.b.example"])
        self.assertEqual(cm.links_in("visit evil.example today, mail me@ok.example"), ["evil.example"])
        self.assertEqual(cm.links_in("no links here at all"), [])
        many = " ".join(f"https://{i}.example" for i in range(9)) + " https://0.example"
        self.assertEqual(cm.links_in(many), [f"https://{i}.example" for i in range(cm.MAX_TARGETS)])

    # -- what a click does

    def test_a_link_is_checked_as_one_argument_and_the_report_kept_only_if_opened(self) -> None:
        hostile = "https://evil.example/a;$(touch${IFS}pwned)`id`|x&y'z"
        closed = Recorder((False,))
        with mock.patch.object(cm, "alert", closed):
            self.assertEqual(cm.check("link", [f"look: {hostile}"]), 1)
        self.assertEqual(self.calls(), [["--json", "--report", "--", hostile]])
        header, message, level, default, alternate = closed.calls[0]
        self.assertEqual((header, level, default, alternate),
                         (f"SUSPICIOUS: {hostile}", cm.CAUTION, "Open Report", "Close"))
        self.assertEqual(message, "• Asks for a password  on a lookalike domain")  # the direction override is gone
        self.assertFalse(self.report.exists())  # closed without opening: deleted

        opened = Recorder((True,))
        with mock.patch.object(cm, "alert", opened), mock.patch("subprocess.run") as run:
            cm.check("link", ["https://good.example"])
        run.assert_called_once_with(["/usr/bin/open", str(self.report)], timeout=30)
        self.assertTrue(self.report.exists())

    def test_files_are_passed_so_that_no_name_reads_as_an_option(self) -> None:
        with mock.patch.object(cm, "alert", Recorder()):
            cm.check("file", ["/tmp/-rf", "/tmp/offer letter.pdf"])
        self.assertEqual(self.calls(), [["--json", "--report", "--file=/tmp/-rf"],
                                        ["--json", "--report", "--file=/tmp/offer letter.pdf"]])

    def test_failures_are_shown_never_swallowed(self) -> None:
        shown = Recorder()
        with mock.patch.object(cm, "alert", shown):
            os.environ["FAKE_MODE"] = "fail"
            self.assertEqual(cm.check("link", ["https://x.example"]), 3)
            os.environ["FAKE_MODE"] = "garbage"
            self.assertEqual(cm.check("link", ["https://x.example"]), 3)
            self.assertEqual(cm.check("link", ["nothing to see"]), 1)
            with mock.patch.object(cm, "check", side_effect=RuntimeError("boom")), \
                    mock.patch.object(sys, "stdin", mock.Mock(buffer=mock.Mock(read=lambda n: b"x"))):
                self.assertEqual(cm.main(["check", "link"]), 3)
        self.assertEqual([(h, m, lvl) for h, m, lvl, _, _ in shown.calls], [
            ("audit-content could not check https://x.example",
             "the sandbox image is missing; run `audit-content setup`", cm.STOP),
            ("audit-content could not check https://x.example", "audit-content stopped (exit code 0).", cm.STOP),
            ("audit-content found nothing to check", "The selection does not contain a link.", cm.CAUTION),
            ("audit-content could not run the check", "RuntimeError: boom", cm.STOP)])

    def test_stopping_from_the_menu_bar_stops_the_check(self) -> None:
        cm._child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        child = cm._child
        try:
            with self.assertRaises(SystemExit):
                cm._stop(signal.SIGTERM, None)
            self.assertEqual(child.wait(timeout=10), -signal.SIGTERM)
        finally:
            child.kill()
            child.wait()
            cm._child = None


if __name__ == "__main__":
    unittest.main()
