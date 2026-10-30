#!/usr/bin/env python3
"""Right-click entries for audit-content: check a link or a file from the menu where you found it.

What it adds
  Two macOS services for the current user, in ~/Library/Services, which the right-click menu
  lists directly or, when an app offers many services, under Services:
    "Check Link with audit-content"  when selected text contains a link, in any app (Chrome, Safari,
                                     Mail, Notes...)
    "Check File with audit-content"  for files in Finder
  Choosing one runs the check in the background. macOS shows its spinning gear in the menu bar
  meanwhile (click it to stop the check), and the verdict appears in a native alert whose button
  opens the safe-view report.

How
  * Each entry is an Automator service: a .workflow bundle in the format of Apple's own in
    /System/Library/Services, whose single "Run Shell Script" action hands the selection to this
    file. Everything else happens here.
  * The check is audit-content itself, run with --json --report, so nothing about checking is
    repeated here; this file only picks the links out of a selection.
  * macOS is told about new entries through AppKit's NSUpdateDynamicServices, and alerts come from
    CoreFoundation's CFUserNotificationDisplayAlert, both called through ctypes. Like every system
    library they live in the dyld shared cache rather than as files, which dlopen handles.

Guarantees
  The selection is untrusted: each link goes to audit-content as one argument, never through a
  shell, and audit-content decides whether it is one. Nothing is left behind: remove() deletes
  exactly the bundles install() wrote (recognised by their bundle identifier), and a report that
  was not opened is deleted. Failures are shown in an alert, never swallowed.

Diagnostics: python3 context_menu.py [install | remove | check link|file] --help
"""

from __future__ import annotations

import argparse
import ctypes
import json
import plistlib
import re
import shlex
import shutil
import signal
import subprocess
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from types import FrameType
from typing import Dict, List, Optional, Sequence, Tuple

HERE = Path(__file__).resolve().parent
PROGRAM = HERE / "audit-content.py"
BUNDLE_ID = "audit-content.menu."  # bundle identifiers start with this: how remove() knows its own
MAX_SELECTION = 64 * 1024
MAX_TARGETS = 5  # links in one selection, or files selected at once


class MenuError(Exception):
    """Every failure of this module, with a message meant for people."""


@dataclass(frozen=True)
class Entry:
    kind: str  # what `check` receives: "link" or "file"
    title: str  # the menu item, and the bundle's name
    input_type: str  # Automator's name for the input, as Apple's own service workflows spell it
    service: Dict[str, object]  # NSServices keys: what may be sent, and where the entry appears
    input_method: int  # how Run Shell Script passes the selection: 0 on standard input, 1 as arguments


ENTRIES = (
    Entry("link", "Check Link with audit-content", "com.apple.Automator.text",
          {"NSSendTypes": ["public.utf8-plain-text"], "NSRequiredContext": {"NSTextContent": "URL"}}, 0),
    # Files only (public.data): audit-content checks files, not folders.
    Entry("file", "Check File with audit-content", "com.apple.Automator.fileSystemObject",
          {"NSSendFileTypes": ["public.data"],
           "NSRequiredContext": {"NSApplicationIdentifier": "com.apple.finder"}}, 1),
)


# --------------------------------------------------------------------------------------------
# Adding and removing the entries
# --------------------------------------------------------------------------------------------


def services_folder() -> Path:
    return Path.home() / "Library" / "Services"


def install() -> List[Path]:
    """Add the entries for the current user, replacing earlier versions of them. Returns their bundles."""
    folder = services_folder()
    python = interpreter()
    written: List[Path] = []
    for entry in ENTRIES:
        bundle = folder / f"{entry.title}.workflow"
        if bundle.exists() and not ours(bundle):
            raise MenuError(f"{bundle} is not audit-content's. Rename or remove it, then run setup again.")
        staging = folder / f".{entry.title}.workflow.new"  # not a .workflow: macOS ignores it until renamed
        try:
            shutil.rmtree(staging, ignore_errors=True)
            (staging / "Contents").mkdir(parents=True)
            (staging / "Contents" / "Info.plist").write_bytes(plistlib.dumps(bundle_info(entry)))
            (staging / "Contents" / "document.wflow").write_bytes(plistlib.dumps(workflow(entry, python)))
            if bundle.exists():
                shutil.rmtree(bundle)
            staging.rename(bundle)
        except OSError as e:
            raise MenuError(f"cannot write {bundle}: {e}") from e
        finally:
            shutil.rmtree(staging, ignore_errors=True)
        written.append(bundle)
    refresh()
    return written


def remove() -> List[Path]:
    """Delete the entries install() added, and nothing else. Returns the bundles removed."""
    removed: List[Path] = []
    for entry in ENTRIES:
        bundle = services_folder() / f"{entry.title}.workflow"
        if bundle.is_dir() and ours(bundle):
            try:
                shutil.rmtree(bundle)
            except OSError as e:
                raise MenuError(f"cannot remove {bundle}: {e}") from e
            removed.append(bundle)
    if removed:
        refresh()
    return removed


def ours(bundle: Path) -> bool:
    try:
        meta = plistlib.loads((bundle / "Contents" / "Info.plist").read_bytes())
    except Exception:  # missing, unreadable, or not a property list: plistlib raises several types
        return False
    ident = meta.get("CFBundleIdentifier") if isinstance(meta, dict) else None
    return isinstance(ident, str) and ident.startswith(BUNDLE_ID)


def interpreter() -> str:
    """The Python the entries run: macOS's own when its developer tools are installed, because it
    never moves; otherwise the one running now."""
    try:
        tools = subprocess.run(["/usr/bin/xcode-select", "-p"], capture_output=True, timeout=10).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        tools = False
    return "/usr/bin/python3" if tools else sys.executable


def refresh() -> None:
    """Tell macOS the services changed, so the entries appear (or go) right away."""
    try:
        appkit = ctypes.CDLL("/System/Library/Frameworks/AppKit.framework/AppKit")
        appkit.NSUpdateDynamicServices.argtypes = []
        appkit.NSUpdateDynamicServices.restype = None
        appkit.NSUpdateDynamicServices()
    except (OSError, AttributeError) as e:
        raise MenuError(f"cannot reach macOS's services registry: {e}") from e


def bundle_info(entry: Entry) -> Dict[str, object]:
    service: Dict[str, object] = {"NSMenuItem": {"default": entry.title}, "NSMessage": "runWorkflowAsService"}
    service.update(entry.service)
    return {"CFBundleDevelopmentRegion": "en_US", "CFBundleIdentifier": BUNDLE_ID + entry.kind,
            "CFBundleName": entry.title, "CFBundleShortVersionString": "1.0", "NSServices": [service]}


def workflow(entry: Entry, python: str) -> Dict[str, object]:
    """Automator's document: one Run Shell Script action, laid out like Apple's "Show Map" service."""
    arguments = ' "$@"' if entry.input_method == 1 else ""
    command = (f"exec {shlex.quote(python)} -I -B {shlex.quote(str(Path(__file__).resolve()))} "
               f"check {entry.kind}{arguments}")
    action_path = "/System/Library/Automator/Run Shell Script.action"
    parameters: Dict[str, object] = {"COMMAND_STRING": command, "CheckedForUserDefaultShell": True,
                                     "inputMethod": entry.input_method, "shell": "/bin/sh", "source": ""}
    action: Dict[str, object] = {
        "AMAccepts": {"Container": "List", "Optional": True, "Types": ["com.apple.cocoa.string"]},
        "AMActionVersion": "2.0.3", "AMApplication": ["Automator"],
        "AMParameterProperties": {name: {} for name in parameters},
        "AMProvides": {"Container": "List", "Types": ["com.apple.cocoa.string"]},
        "ActionBundlePath": action_path, "ActionName": "Run Shell Script", "ActionParameters": parameters,
        "BundleIdentifier": "com.apple.RunShellScript", "CFBundleVersion": "2.0.3",
        "CanShowSelectedItemsWhenRun": False, "CanShowWhenRun": True, "Category": ["AMCategoryUtilities"],
        "Class Name": "RunShellScriptAction", "InputUUID": _uuid(), "Keywords": ["Shell", "Script", "Command"],
        "OutputUUID": _uuid(), "UUID": _uuid(), "UnlocalizedApplications": ["Automator"], "arguments": {},
        "isViewVisible": True, "location": "309.500000:631.000000",
        "nibPath": f"{action_path}/Contents/Resources/en.lproj/main.nib"}
    return {"AMApplicationBuild": "346", "AMApplicationVersion": "2.3", "AMDocumentVersion": "2",
            "actions": [{"action": action, "isViewVisible": True}], "connectors": {},
            "workflowMetaData": {"serviceInputTypeIdentifier": entry.input_type,
                                 "serviceOutputTypeIdentifier": "com.apple.Automator.nothing",
                                 "serviceProcessesInput": 0,
                                 "workflowTypeIdentifier": "com.apple.Automator.servicesMenu"}}


def _uuid() -> str:
    return str(uuid.uuid4()).upper()


# --------------------------------------------------------------------------------------------
# What an entry does when chosen
# --------------------------------------------------------------------------------------------

TRAILING = ".,;:!?"
DOMAIN = re.compile(r"[^\s@/]+\.[A-Za-z]{2,}(?:[/?#]\S*)?")


@dataclass(frozen=True)
class Outcome:
    verdict: str  # SAFE, SUSPICIOUS or MALICIOUS; "" when the check could not run
    target: str
    reasons: Tuple[str, ...]
    report: Optional[Path]
    code: int  # audit-content's exit code
    error: str = ""


def links_in(text: str) -> List[str]:
    """What to check in a selection: all of it when it is one word, else the words that are links.

    macOS offers the entry only when it detects a link in the selection, but the selection may hold
    a sentence around it. Domains without a scheme count when no full link is there.
    """
    words: List[str] = []
    for word in text.split():
        word = word.strip("<>\"'`“”‘’«»").rstrip(TRAILING).lstrip("(")
        while word.endswith(")") and word.count(")") > word.count("("):  # the sentence's bracket, not the link's
            word = word[:-1].rstrip(TRAILING)
        if word:
            words.append(word)
    if len(words) == 1:
        return words
    found = [w for w in words if "://" in w or w.lower().startswith("www.")]
    found = found or [w for w in words if DOMAIN.fullmatch(w)]
    return list(dict.fromkeys(found))[:MAX_TARGETS]


_child: Optional["subprocess.Popen[bytes]"] = None  # the running check, for _stop


def run_check(args: List[str], label: str) -> Outcome:
    """audit-content on one target. Its JSON gives the verdict and report; on failure, its last words."""
    global _child
    try:
        _child = subprocess.Popen([sys.executable, str(PROGRAM), "--json", "--report", *args],
                                  stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as e:
        return Outcome("", label, (), None, 3, f"audit-content could not start: {e}")
    out, err = _child.communicate()
    code, _child = _child.returncode, None
    try:
        data = json.loads(out) if code in (0, 1, 2) else None
    except ValueError:
        data = None
    if not isinstance(data, dict) or data.get("verdict") not in ("SAFE", "SUSPICIOUS", "MALICIOUS"):
        lines = [line.strip() for line in err.decode("utf-8", "replace").splitlines() if line.strip()]
        last = lines[-1].replace("audit-content: ", "", 1) if lines else f"audit-content stopped (exit code {code})."
        return Outcome("", label, (), None, 3, last)
    reasons = tuple(str(r.get("title", "")) for r in data.get("reasons") or [] if isinstance(r, dict))
    report = data.get("report")
    return Outcome(str(data["verdict"]), label, reasons,  # what was right-clicked, not a long path
                   Path(report) if isinstance(report, str) and report else None, code)


def _stop(signum: int, frame: Optional[FrameType]) -> None:
    """The gear in the menu bar was clicked: let audit-content clean up its VM, and show nothing."""
    if _child is not None and _child.poll() is None:
        _child.terminate()
    raise SystemExit(130)


def show(outcome: Outcome) -> None:
    if not outcome.verdict:
        alert(f"audit-content could not check {printable(outcome.target, 200)}", printable(outcome.error, 1000), STOP)
        return
    reasons = "\n".join(f"• {printable(r, 300)}" for r in outcome.reasons[:5])
    message = reasons or "Nothing harmful was found."
    level = {"MALICIOUS": STOP, "SUSPICIOUS": CAUTION}.get(outcome.verdict, NOTE)
    header = f"{outcome.verdict}: {printable(outcome.target, 200)}"
    if outcome.report is None:
        alert(header, message, level)
        return
    if alert(header, message, level, "Open Report", "Close"):
        subprocess.run(["/usr/bin/open", str(outcome.report)], timeout=30)
    else:
        outcome.report.unlink(missing_ok=True)


def check(kind: str, items: Sequence[str]) -> int:
    """Check what was selected, one target after another, and show each verdict. Returns the
    highest of audit-content's exit codes."""
    targets: List[Tuple[List[str], str]]
    if kind == "link":
        targets = [(["--", link], link) for text in items for link in links_in(text)]
    else:  # --file=PATH, so that a name starting with "-" stays a file name
        targets = [([f"--file={path}"], Path(path).name) for path in items[:MAX_TARGETS]]
    if not targets:
        alert("audit-content found nothing to check", "The selection does not contain a link.", CAUTION)
        return 1
    signal.signal(signal.SIGTERM, _stop)
    worst = 0
    for args, label in targets:
        outcome = run_check(args, label)
        show(outcome)
        worst = max(worst, outcome.code)
    return worst


def printable(text: str, limit: int) -> str:
    """Text for an alert: no control or formatting characters, which could disguise what it says."""
    clean = "".join(c if c.isprintable() or c == "\n" else " " for c in text)
    return clean if len(clean) <= limit else clean[:limit - 1] + "…"


# --------------------------------------------------------------------------------------------
# Native alert: CoreFoundation's CFUserNotificationDisplayAlert
# --------------------------------------------------------------------------------------------

STOP, NOTE, CAUTION = 0, 1, 2  # kCFUserNotification...AlertLevel: the icon shown
UTF8 = 0x08000100  # kCFStringEncodingUTF8


def alert(header: str, message: str, level: int, default: str = "OK", alternate: Optional[str] = None) -> bool:
    """Show an alert and wait for a button. True when the default button was chosen."""
    try:
        cf = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
        cf.CFStringCreateWithCString.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint32]
        cf.CFStringCreateWithCString.restype = ctypes.c_void_p
        cf.CFRelease.argtypes = [ctypes.c_void_p]
        cf.CFRelease.restype = None
        obj = ctypes.c_void_p  # CFURLRef and CFStringRef: icon, sound and strings files, header, message, buttons
        cf.CFUserNotificationDisplayAlert.argtypes = [ctypes.c_double, ctypes.c_ulong, obj, obj, obj, obj, obj, obj,
                                                      obj, obj, ctypes.POINTER(ctypes.c_ulong)]
        cf.CFUserNotificationDisplayAlert.restype = ctypes.c_int32
    except (OSError, AttributeError):
        print(f"{header}\n{message}", file=sys.stderr)  # no window server: the log is all there is
        return False
    texts = [header, message, default] + ([alternate] if alternate else [])
    refs = [cf.CFStringCreateWithCString(None, t.replace("\0", " ").encode("utf-8"), UTF8) for t in texts]
    response = ctypes.c_ulong(0)
    try:
        status = cf.CFUserNotificationDisplayAlert(0.0, level, None, None, None, refs[0], refs[1], refs[2],
                                                   refs[3] if alternate else None, None, ctypes.byref(response))
    finally:
        for ref in refs:
            if ref:
                cf.CFRelease(ref)
    return bool(status == 0 and response.value & 0x3 == 0)  # kCFUserNotificationDefaultResponse


# --------------------------------------------------------------------------------------------
# Command line: what setup and the entries call
# --------------------------------------------------------------------------------------------


def main(argv: Sequence[str]) -> int:
    p = argparse.ArgumentParser(prog="context_menu.py", description="Right-click entries for audit-content.")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("install", help="add the entries for this user")
    sub.add_parser("remove", help="remove them")
    c = sub.add_parser("check", help="what the entries run: check the selection and show the verdict")
    c.add_argument("kind", choices=[e.kind for e in ENTRIES])
    c.add_argument("paths", nargs="*", help="the files, for `file`; a `link` selection is read from standard input")
    a = p.parse_args(argv)
    if a.cmd == "check":
        # The alerts report every outcome. The exit status stays 0, because Automator shows its own
        # "Run Shell Script encountered an error" dialog for any other, even after a clean verdict.
        try:
            selection = sys.stdin.buffer.read(MAX_SELECTION).decode("utf-8", "replace") if a.kind == "link" else ""
            check(a.kind, [selection] if a.kind == "link" else list(a.paths))
        except Exception as e:  # the entries have no other way to report: never fail silently
            alert("audit-content could not run the check", printable(f"{type(e).__name__}: {e}", 1000), STOP)
        return 0
    try:
        for bundle in install() if a.cmd == "install" else remove():
            print(f"{a.cmd}: {bundle}")
    except MenuError as e:
        print(f"context_menu.py: {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
