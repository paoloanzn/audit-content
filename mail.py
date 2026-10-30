#!/usr/bin/env python3
"""Read Apple Mail's accounts, mailboxes and messages on this Mac: read-only, standard library only.

What it reads
  Apple Mail keeps its data in ~/Library/Mail/V<n>. MailData/Envelope Index is a SQLite database
  with one row per message (sender, recipients, subject, dates, read and flag state, mailbox,
  Gmail labels, attachment names); each downloaded message is an .emlx file in its mailbox's
  folder, and Mail keeps the attachments of large messages as separate files next to it. This
  module finds that data without fixed paths, lists messages from the database, and parses a
  message's file on request: its headers, text, every link (in the text, behind HTML links and
  form buttons, in calendar invites and text attachments), and its attachments with the path of
  Mail's copy. Account names and addresses come from macOS's account store, and the files opened
  from Mail are listed from its Mail Downloads folder.

How
  * The version folder comes from Mail's PersistenceInfo.plist, else the newest V<n> that holds
    an Envelope Index. Mailbox folders follow from the mailbox URLs in the database, and message
    files from Mail's layout; when a file is not where the layout says, the account's folder is
    indexed once to find it.
  * The database is opened read-only through SQLite's own locking, so messages that arrived
    seconds ago (still in Mail's write-ahead log) are included while Mail keeps running.
  * A mailbox's role (inbox, sent, junk, trash...) comes from the IMAP special-use attributes Mail
    caches in each account's .mboxCache.plist, so it does not depend on folder names or language.
  * Message files are parsed with the standard library's lenient email parser and HTML parser.
    Their content is hostile data: it is only decoded, never rendered or followed.

Guarantees
  Nothing is written anywhere and nothing is left behind: files are opened read-only, the
  database through SQLite's read-only mode only while its shared-memory file exists (else
  immutable mode, so SQLite never creates one), and Mail keeps working undisturbed. If Mail
  crashed and left changes SQLite cannot read that way, `Session.stale` says the newest messages
  may be missing. A missing table or column raises FormatError instead of returning wrong data;
  a message file that cannot be parsed raises for that message only.

Permissions
  macOS lets only apps with Full Disk Access read ~/Library/Mail. There is no prompt: without it,
  every read fails, and this module raises AccessDenied explaining what to turn on.

Diagnostics: python3 mail.py [accounts | mailboxes | messages] --help
"""

from __future__ import annotations

import argparse
import email
import email.errors
import email.header
import email.message
import email.policy
import json
import os
import plistlib
import re
import sqlite3
import sys
import urllib.parse
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Sequence, Set, Tuple

Row = Tuple[Any, ...]  # a database row: SQLite decides the types

# --------------------------------------------------------------------------------------------
# Errors and guarded file access
# --------------------------------------------------------------------------------------------


class MailError(Exception):
    """Base class: every failure of this module is one of these, with a message meant for people."""


class AccessDenied(MailError):
    """macOS privacy protection refused to let this process read Mail's data."""


class NotSetUp(MailError):
    """Apple Mail has never been used on this Mac, so there is nothing to read."""


class FormatError(MailError):
    """The files are not in the layout this module understands, or are damaged."""


# Opens the Full Disk Access list in System Settings, for setup to show the user.
FULL_DISK_ACCESS_SETTINGS = "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"
MAX_MESSAGE_BYTES = 256 * 1024 * 1024  # larger than any mail server accepts
MAX_SCANNED_TEXT = 8 * 1024 * 1024  # text and HTML beyond this are kept but not searched for links


def denied_message(path: Path) -> str:
    return (f"macOS did not allow reading {path}. Apple Mail's data can only be read by an app with Full "
            "Disk Access: turn on the app that runs audit-content (for example Terminal) under System "
            "Settings > Privacy & Security > Full Disk Access, then try again.")


def _listdir(folder: Path) -> List[str]:
    try:
        return sorted(os.listdir(folder))
    except PermissionError as e:
        raise AccessDenied(denied_message(folder)) from e
    except (FileNotFoundError, NotADirectoryError):
        return []
    except OSError as e:  # never mistake a read error for an empty folder
        raise MailError(f"cannot read {folder}: {e}") from e


def _is_file(path: Path) -> bool:
    try:
        return path.is_file()
    except PermissionError as e:
        raise AccessDenied(denied_message(path)) from e


def _is_dir(path: Path) -> bool:
    try:
        return path.is_dir()
    except PermissionError as e:
        raise AccessDenied(denied_message(path)) from e


def read_bytes(path: Path, limit: int = MAX_MESSAGE_BYTES) -> bytes:
    try:
        with open(path, "rb") as f:
            data = f.read(limit + 1)
    except PermissionError as e:
        raise AccessDenied(denied_message(path)) from e
    except FileNotFoundError as e:
        raise FormatError(f"{path} no longer exists; Mail may have moved the message") from e
    except OSError as e:
        raise MailError(f"cannot read {path}: {e}") from e
    if len(data) > limit:
        raise FormatError(f"{path} is larger than {limit} bytes")
    return data


def _plist(path: Path) -> Dict[str, object]:
    """A property list Mail wrote, or {} when it is missing or unreadable as one."""
    try:
        data = read_bytes(path, 16 * 1024 * 1024)
    except FormatError:
        return {}
    try:
        value = plistlib.loads(data)
    except Exception:  # plistlib raises several unrelated types for damaged files
        return {}
    return value if isinstance(value, dict) else {}


# --------------------------------------------------------------------------------------------
# Finding Mail's data on this Mac
# --------------------------------------------------------------------------------------------

VERSION_DIR = re.compile(r"V(\d+)")


@dataclass(frozen=True)
class Installation:
    root: Path  # ~/Library/Mail/V<n>
    database: Path  # MailData/Envelope Index
    store_id: Optional[str]  # the folder inside each mailbox that holds its messages, when Mail names it
    accounts_database: Optional[Path]  # macOS's account store, for account names and addresses
    downloads: Path  # where Mail saves attachments that were opened


def discover() -> Installation:
    """Find Apple Mail's data for the current user without assuming a version folder."""
    library = Path.home() / "Library"
    mail = library / "Mail"
    try:
        names = os.listdir(mail)
    except FileNotFoundError as e:
        raise NotSetUp("Apple Mail has not been set up on this Mac (there is no ~/Library/Mail).") from e
    except PermissionError as e:
        raise AccessDenied(denied_message(mail)) from e
    except OSError as e:
        raise MailError(f"cannot read {mail}: {e}") from e
    persistence = _plist(mail / "PersistenceInfo.plist")
    versions = sorted((n for n in names if VERSION_DIR.fullmatch(n)), key=lambda n: int(n[1:]), reverse=True)
    last = persistence.get("LastUsedVersionDirectoryName")
    if isinstance(last, str) and last in versions:
        versions.remove(last)
        versions.insert(0, last)
    ids = persistence.get("VersionDirectoryIdentifiers")
    for name in versions:
        database = mail / name / "MailData" / "Envelope Index"
        if _is_file(database):
            store_id = ids.get(name) if isinstance(ids, dict) else None
            return Installation(
                root=mail / name, database=database, store_id=store_id if isinstance(store_id, str) else None,
                accounts_database=_accounts_database(library / "Accounts"),
                downloads=library / "Containers" / "com.apple.mail" / "Data" / "Library" / "Mail Downloads")
    raise NotSetUp("Apple Mail has no mailboxes on this Mac yet (no Envelope Index in ~/Library/Mail).")


def _accounts_database(folder: Path) -> Optional[Path]:
    """The newest AccountsN.sqlite: the number grows with the format, like Mail's V<n>."""
    try:
        found = [n for n in _listdir(folder) if re.fullmatch(r"Accounts\d+\.sqlite", n)]
    except MailError:
        return None  # names and addresses are a convenience; reading mail does not need them
    found.sort(key=lambda n: int(n[len("Accounts"):-len(".sqlite")]))
    return folder / found[-1] if found else None


def check_access() -> Optional[str]:
    """None when this process can read Mail's data, or Mail is not set up; otherwise what to do."""
    try:
        discover()
    except AccessDenied as e:
        return str(e)
    except MailError:
        return None
    return None


# --------------------------------------------------------------------------------------------
# Read-only SQLite
# --------------------------------------------------------------------------------------------


def open_database(path: Path) -> Tuple[sqlite3.Connection, bool]:
    """Open a database another app is writing; also says whether its newest changes may be missing.

    Read-only mode creates a missing shared-memory file, so it is used only when that file exists:
    the app may be running, and read-only mode takes part in its locking, so committed changes
    still in the write-ahead log are seen. Otherwise, or when that fails, immutable mode reads the
    main file alone and creates nothing; a log left next to it (the app crashed) cannot be read
    without creating the shared memory, so its changes are reported missing.
    """
    base = "file:" + urllib.parse.quote(str(path)) + "?mode=ro"
    try:
        wal_size = Path(f"{path}-wal").stat().st_size
    except OSError:
        wal_size = 0
    attempts = [(base, False)] if Path(f"{path}-shm").exists() else []
    attempts.append((base + "&immutable=1", wal_size > 0))
    error: Optional[sqlite3.DatabaseError] = None
    for uri, stale in attempts:
        try:
            return _connect(uri), stale
        except sqlite3.DatabaseError as e:
            error = e
    raise FormatError(f"cannot open {path} read-only: {error}") from error


def _connect(uri: str) -> sqlite3.Connection:
    con = sqlite3.connect(uri, uri=True, isolation_level=None)  # transactions are begun explicitly
    try:
        con.execute("SELECT count(*) FROM sqlite_master").fetchone()
        con.execute("PRAGMA query_only = ON")
    except BaseException:
        con.close()
        raise
    return con


def _columns(con: sqlite3.Connection) -> Dict[str, Set[str]]:
    tables = [str(r[0]) for r in con.execute("SELECT name FROM sqlite_master WHERE type = 'table'")]
    return {t: {str(c[1]) for c in con.execute('PRAGMA table_info("%s")' % t.replace('"', '""'))} for t in tables}


# --------------------------------------------------------------------------------------------
# What comes out
# --------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Account:
    id: str  # Mail's folder name for it, and the host part of its mailbox URLs
    kind: str  # the account type in macOS, such as Google, IMAP, Exchange, OnMyDevice; "" if unknown
    name: Optional[str]
    address: Optional[str]
    folder: Path


@dataclass(frozen=True)
class Mailbox:
    id: int
    url: str
    account_id: str
    name: str  # path inside the account, such as "INBOX" or "[Gmail]/Spam"
    role: str  # inbox, sent, drafts, trash, junk, archive, all, flagged, important; "" for others
    folder: Path
    unread_count: int


@dataclass(frozen=True)
class Address:
    address: str
    name: Optional[str] = None


@dataclass(frozen=True)
class Message:
    id: int  # row in the Envelope Index, which also names the message's .emlx file
    account_id: str
    mailbox_id: int  # where Mail stores it; for Gmail, All Mail
    mailbox_ids: Tuple[int, ...]  # every mailbox showing it, Gmail labels included
    subject: str
    sender: Optional[Address]
    to: Tuple[Address, ...]
    cc: Tuple[Address, ...]
    bcc: Tuple[Address, ...]
    date_sent: Optional[datetime]
    date_received: datetime
    read: bool
    flagged: bool
    deleted: bool  # marked for deletion, not yet removed from the server
    junk: bool  # shown in a Junk or Spam mailbox
    message_id: Optional[str]  # the Message-ID header
    attachment_names: Tuple[str, ...]
    path: Optional[Path]  # the .emlx file; None when Mail has not downloaded the message
    partial: bool  # its attachments are stored as separate files, not inside the .emlx


@dataclass(frozen=True)
class Attachment:
    part: str  # MIME part number, counted the way IMAP and Mail's Attachments folder count them
    name: Optional[str]
    mime_type: str
    size: Optional[int]  # None when Mail stored the data separately and has not downloaded it
    inline: bool  # shown inside the message, like a pasted image or a calendar invite
    local_path: Optional[Path]  # Mail's separate copy, when it keeps one
    in_message: bool  # the data is inside the .emlx itself


@dataclass(frozen=True)
class Content:
    headers: Tuple[Tuple[str, str], ...]  # every top-level header, encoded words decoded
    text: str  # the plain-text body, or the HTML body as text when there is none
    html: str
    links: Tuple[str, ...]
    attachments: Tuple[Attachment, ...]


@dataclass(frozen=True)
class Download:
    path: Path
    size: int
    modified: datetime


# --------------------------------------------------------------------------------------------
# Mail's folders: mailbox URLs, roles, and where message files live
# --------------------------------------------------------------------------------------------

# IMAP special-use attributes as Mail caches them in .mboxCache.plist (IMAPMailboxAttributes): one
# bit per RFC 6154 attribute, in that RFC's order, then RFC 8457's \Important. \Archive is inferred
# from the order; the others were checked against a Gmail account.
ROLE_BITS = (("all", 1 << 10), ("archive", 1 << 11), ("drafts", 1 << 12), ("flagged", 1 << 13),
             ("junk", 1 << 14), ("sent", 1 << 15), ("trash", 1 << 16), ("important", 1 << 17))
RECIPIENT_KINDS = {0: "to", 1: "cc", 2: "bcc"}  # recipients.type; bcc only appears in sent mail


def mailbox_path(url: str) -> Tuple[str, List[str]]:
    """Account id and folder names of a mailbox URL such as imap://<account>/%5BGmail%5D/Spam."""
    parts = urllib.parse.urlsplit(url)
    names = [urllib.parse.unquote(p) for p in parts.path.split("/") if p]
    if not parts.netloc or not names or any(n in (".", "..") or "/" in n or "\0" in n for n in names):
        raise FormatError(f"unexpected mailbox URL {url!r}")
    return parts.netloc, names


def partition(rowid: int) -> List[str]:
    """Mail's folders for a message: the digits of rowid // 1000, last digit first (17830 -> 7/1)."""
    thousands = rowid // 1000
    return list(reversed(str(thousands))) if thousands else []


def mailbox_roles(cache: Dict[str, object]) -> Dict[Tuple[str, ...], str]:
    """Role of each mailbox path in an account's .mboxCache.plist."""
    roles: Dict[Tuple[str, ...], str] = {}

    def walk(children: object, prefix: Tuple[str, ...]) -> None:
        if not isinstance(children, dict):
            return
        for key, entry in children.items():
            if not isinstance(entry, dict):
                continue
            component = entry.get("MailboxPathComponent")
            path = prefix + (component if isinstance(component, str) else str(key),)
            attributes = entry.get("IMAPMailboxAttributes")
            if isinstance(attributes, int):
                role = next((name for name, bit in ROLE_BITS if attributes & bit), "")
                if role:
                    roles[path] = role
            walk(entry.get("IMAPMailboxChildren"), path)

    walk(cache.get("mboxes"), ())
    return roles


# --------------------------------------------------------------------------------------------
# Message files: .emlx, MIME parts, text and links
# --------------------------------------------------------------------------------------------

URL_RE = re.compile(r"(?i)\b(?:(?:https?|ftps?|smb|file)://|www\.)[^\s<>\"'`]+")
# Not places a click takes you: mail and phone actions, references to parts of this message,
# and the links Apple adds for dates and addresses it detects.
IGNORED_SCHEMES = {"mailto", "tel", "sms", "cid", "mid", "about", "x-apple-data-detectors"}
# Mail stored this part's data in Attachments/<id>/<part>; the value is the encoded length, not the file's.
STRIPPED_PART = "X-Apple-Content-Length"
CLOSING = {")": "(", "]": "[", "}": "{"}


def emlx_message(data: bytes) -> bytes:
    """The RFC 822 message inside an .emlx: a byte count line, the message, then Mail's own plist."""
    head, newline, rest = data.partition(b"\n")
    if not newline or not head.strip().isdigit():
        raise FormatError("not an .emlx file: it does not start with the message length")
    length = int(head.strip())
    if length > len(rest):
        raise FormatError("the .emlx file is shorter than the length it states")
    return rest[:length]


def decode_header(value: object) -> str:
    """A header value with RFC 2047 encoded words decoded; the raw value when they are malformed."""
    raw = str(value)
    try:
        return str(email.header.make_header(email.header.decode_header(raw)))
    except (email.errors.HeaderParseError, LookupError, UnicodeError, ValueError):
        return raw


def mime_parts(msg: email.message.Message) -> Iterator[Tuple[str, email.message.Message]]:
    """Leaf parts with IMAP part numbers. An attached email is one part: its insides are its own."""
    if msg.get_content_maintype() != "multipart":
        yield "1", msg
        return

    def walk(container: email.message.Message, prefix: str) -> Iterator[Tuple[str, email.message.Message]]:
        payload = container.get_payload()
        for i, sub in enumerate(payload if isinstance(payload, list) else [], 1):
            if not isinstance(sub, email.message.Message):
                continue
            number = f"{prefix}.{i}" if prefix else str(i)
            if sub.get_content_maintype() == "multipart":
                yield from walk(sub, number)
            else:
                yield number, sub

    yield from walk(msg, "")


def part_text(part: email.message.Message) -> str:
    payload = part.get_payload(decode=True)
    return _decode(payload if isinstance(payload, bytes) else None, part.get_content_charset())


def _decode(data: Optional[bytes], charset: Optional[str]) -> str:
    if not data:
        return ""
    try:
        return data.decode(charset or "utf-8", "replace")
    except LookupError:  # a charset Python does not know
        return data.decode("utf-8", "replace")


class _HTMLScan(HTMLParser):
    """Visible text and link targets of an HTML document, which is never rendered."""

    BLOCKS = {"p", "div", "br", "tr", "li", "h1", "h2", "h3", "h4", "h5", "h6", "table", "blockquote"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.text: List[str] = []
        self.targets: List[str] = []
        self.base: Optional[str] = None
        self._hidden = 0

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        if tag in ("script", "style", "title"):
            self._hidden += 1
        if tag in self.BLOCKS:
            self.text.append("\n")
        values = {name: value for name, value in attrs if value}
        if tag == "base" and "href" in values:
            self.base = self.base or values["href"]
            return
        for name in ("href", "action", "formaction"):
            if name in values:
                self.targets.append(values[name] or "")
        if tag == "meta" and (values.get("http-equiv") or "").lower() == "refresh":
            m = re.search(r"(?i)url\s*=\s*['\"]?([^'\"]+)", values.get("content") or "")
            if m:
                self.targets.append(m.group(1))

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style", "title") and self._hidden:
            self._hidden -= 1
        if tag in self.BLOCKS:
            self.text.append("\n")

    def handle_data(self, data: str) -> None:
        if not self._hidden:
            self.text.append(data)


def html_scan(html: str) -> Tuple[str, List[str]]:
    """Text and absolute link targets of an HTML part."""
    scan = _HTMLScan()
    try:
        scan.feed(html[:MAX_SCANNED_TEXT])
        scan.close()
    except AssertionError:  # html.parser's reaction to some malformed markup: keep what was read
        pass
    links = [link for link in (absolute_link(t, scan.base) for t in scan.targets) if link]
    return re.sub(r"\n\s*\n+", "\n\n", "".join(scan.text)).strip(), links


def absolute_link(target: str, base: Optional[str]) -> Optional[str]:
    """Where a link goes, as a browser would read it; None for anchors and mail or phone actions."""
    target = re.sub(r"[\t\n\r]", "", target).strip()  # browsers drop these, so "java\nscript:" still runs
    if not target or target.startswith("#"):
        return None
    if target.startswith("//"):
        target = "https:" + target
    scheme = urllib.parse.urlsplit(target).scheme.lower() if re.match(r"[A-Za-z][A-Za-z0-9+.-]*:", target) else ""
    if not scheme:
        if base and re.match(r"(?i)https?://", base):
            return urllib.parse.urljoin(base, target)
        return target if target.lower().startswith("www.") else None
    return None if scheme in IGNORED_SCHEMES else target


def text_links(text: str) -> List[str]:
    """Links written out in text, without the punctuation of the sentence around them."""
    out: List[str] = []
    for m in URL_RE.finditer(text[:MAX_SCANNED_TEXT]):
        url = m.group(0).rstrip(".,;:!?'\">")
        while url and url[-1] in CLOSING and url.count(url[-1]) > url.count(CLOSING[url[-1]]):
            url = url[:-1].rstrip(".,;:!?'\">")  # "(see https://x.example/a)": the bracket is the sentence's
        out.append(url)
    return out


def unique_links(found: Sequence[str]) -> Tuple[str, ...]:
    return tuple(dict.fromkeys(u for u in found if u))


def parse_content(raw: bytes, attachments_dir: Optional[Path], names: Optional[Dict[str, str]] = None) -> Content:
    """Headers, text, links and attachments of one message. `attachments_dir` is Attachments/<id>,
    and `names` are Mail's names by part, which it also gives to parts that have none."""
    msg = email.message_from_bytes(raw, policy=email.policy.compat32)  # lenient, no structured headers
    headers = tuple((str(k), decode_header(v)) for k, v in msg.items())
    plain: List[str] = []
    html: List[str] = []
    html_text: List[str] = []
    links: List[str] = []
    attachments: List[Attachment] = []
    for number, part in mime_parts(msg):
        ctype = part.get_content_type()
        name = part.get_filename()
        disposition = part.get_content_disposition()
        stripped = part.get(STRIPPED_PART)
        if ctype in ("text/plain", "text/html") and name is None and disposition != "attachment" and stripped is None:
            body = part_text(part)
            if ctype == "text/plain":
                plain.append(body)
                links += text_links(body)
            else:
                html.append(body)
                shown, targets = html_scan(body)
                html_text.append(shown)
                links += targets + text_links(shown)
            continue
        local: Optional[Path] = None
        if stripped is not None and attachments_dir is not None:
            local = _single_file(attachments_dir / number)
        if part.get_content_maintype() == "text":  # invites, HTML and text files carry links too
            attached = part_text(part) if stripped is None else _decode(_small_file(local), part.get_content_charset())
            if ctype == "text/html":
                links += html_scan(attached)[1]
            links += text_links(attached)
        size: Optional[int] = None
        if local is not None:
            try:
                size = local.stat().st_size
            except OSError:
                size = None
        elif stripped is None:
            payload = part.get_payload(decode=True)
            size = len(payload) if isinstance(payload, bytes) else None
        attachments.append(Attachment(
            part=number, name=decode_header(name) if name is not None else (names or {}).get(number),
            mime_type=ctype, size=size,
            inline=disposition == "inline" or (disposition is None and part.get("Content-ID") is not None),
            local_path=local, in_message=stripped is None))
    text = "\n\n".join(p.strip() for p in plain if p.strip()) or "\n\n".join(t for t in html_text if t)
    return Content(headers, text, "\n".join(html), unique_links(links), tuple(attachments))


def _single_file(folder: Path) -> Optional[Path]:
    """Mail's copy of one stripped part: the only file in Attachments/<id>/<part>.

    Its name comes from the folder, never from the message, so a hostile file name cannot point
    anywhere else.
    """
    names = [n for n in _listdir(folder) if not n.startswith(".")]
    if len(names) != 1:
        return None
    path = folder / names[0]
    return path if _is_file(path) and not path.is_symlink() else None


def _small_file(path: Optional[Path]) -> Optional[bytes]:
    if path is None:
        return None
    try:
        return read_bytes(path, MAX_SCANNED_TEXT)
    except FormatError:
        return None


# --------------------------------------------------------------------------------------------
# Reading Mail
# --------------------------------------------------------------------------------------------


REQUIRED = {"messages": {"mailbox", "date_received", "sender", "subject"}, "mailboxes": {"url"},
            "subjects": {"subject"}, "addresses": {"address", "comment"},
            "recipients": {"message", "address", "type", "position"}}
BATCH = 500


class Session:
    """Mail's database opened read-only. Use as a context manager, or call close()."""

    def __init__(self, installation: Installation) -> None:
        self.installation = installation
        _listdir(installation.root)  # fails with AccessDenied before SQLite turns it into a vague error
        self.db, self.stale = open_database(installation.database)
        try:
            self.columns = _columns(self.db)
            missing = [f"{t}.{c}" for t, cols in REQUIRED.items() for c in sorted(cols - self.columns.get(t, set()))]
            if missing:
                raise FormatError(f"Mail's database lacks {', '.join(missing)}; this Mail version is not supported")
        except BaseException:
            self.db.close()
            raise
        self._accounts: Optional[Dict[str, Account]] = None
        self._mailboxes: Optional[Dict[int, Mailbox]] = None
        self._stores: Dict[Path, Optional[Path]] = {}
        self._file_index: Dict[str, Dict[int, Path]] = {}

    def __enter__(self) -> Session:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        self.db.close()

    # -- accounts and mailboxes

    def mailboxes(self) -> Dict[int, Mailbox]:
        """Every mailbox in the database, by id, with its role and folder."""
        if self._mailboxes is None:
            cols = self.columns["mailboxes"]
            unread = "unread_count" if "unread_count" in cols else "0"
            caches: Dict[str, Dict[Tuple[str, ...], str]] = {}
            out: Dict[int, Mailbox] = {}
            for rowid, url, unread_count in self.db.execute(f"SELECT ROWID, url, {unread} FROM mailboxes"):
                try:
                    account, names = mailbox_path(str(url))
                except FormatError:
                    continue
                if account not in caches:
                    caches[account] = mailbox_roles(_plist(self.installation.root / account / ".mboxCache.plist"))
                inbox = len(names) == 1 and names[0].upper() == "INBOX"  # IMAP's one fixed name
                role = "inbox" if inbox else caches[account].get(tuple(names), "")
                folder = self.installation.root.joinpath(account, *(n + ".mbox" for n in names))
                out[int(rowid)] = Mailbox(int(rowid), str(url), account, "/".join(names), role, folder,
                                          int(unread_count or 0))
            self._mailboxes = out
        return self._mailboxes

    def accounts(self) -> Dict[str, Account]:
        """Accounts that have mailboxes, with the name and address macOS keeps for them when readable."""
        if self._accounts is None:
            known = self._system_accounts()
            out: Dict[str, Account] = {}
            for box in self.mailboxes().values():
                if box.account_id not in out:
                    kind, name, address = known.get(box.account_id, ("", None, None))
                    out[box.account_id] = Account(box.account_id, kind, name, address,
                                                  self.installation.root / box.account_id)
            self._accounts = out
        return self._accounts

    def _system_accounts(self) -> Dict[str, Tuple[str, Optional[str], Optional[str]]]:
        """Type, name and address of each macOS account, filled in from parent accounts: Mail's
        IMAP account for Gmail is a child of the Google account that holds the name and address."""
        path = self.installation.accounts_database
        if path is None:
            return {}
        try:
            con, _ = open_database(path)
        except MailError:
            return {}
        try:
            rows = con.execute("SELECT a.Z_PK, a.ZIDENTIFIER, a.ZPARENTACCOUNT, a.ZACCOUNTDESCRIPTION, a.ZUSERNAME, "
                               "t.ZIDENTIFIER FROM ZACCOUNT a LEFT JOIN ZACCOUNTTYPE t ON t.Z_PK = a.ZACCOUNTTYPE"
                               ).fetchall()
        except sqlite3.DatabaseError:
            return {}
        finally:
            con.close()
        by_pk = {row[0]: row for row in rows}
        out: Dict[str, Tuple[str, Optional[str], Optional[str]]] = {}
        for row in rows:
            kind, name, address = "", None, None
            current, hops = row, 0
            while current is not None and hops < 6:
                kind = str(current[5] or kind).replace("com.apple.account.", "")
                name = name or (str(current[3]) if current[3] else None)
                address = address or (str(current[4]) if current[4] else None)
                current, hops = by_pk.get(current[2]), hops + 1
            if row[1]:
                out[str(row[1])] = (kind, name, address)
        return out

    # -- messages

    def messages(self, mailbox: Optional[int] = None, since: Optional[datetime] = None,
                 until: Optional[datetime] = None, newest_first: bool = False, limit: Optional[int] = None,
                 include_deleted: bool = False) -> Iterator[Message]:
        """Messages by date received, optionally in one mailbox (Gmail labels count) and in [since, until)."""
        m = self.columns["messages"]
        where: List[str] = []
        args: List[object] = []
        if since is not None:
            where.append("m.date_received >= ?")
            args.append(int(since.timestamp()))
        if until is not None:
            where.append("m.date_received < ?")
            args.append(int(until.timestamp()))
        if mailbox is not None:
            if self._has("labels", "message_id", "mailbox_id"):
                where.append("(m.mailbox = ? OR m.ROWID IN (SELECT message_id FROM labels WHERE mailbox_id = ?))")
                args += [mailbox, mailbox]
            else:
                where.append("m.mailbox = ?")
                args.append(mailbox)
        if not include_deleted and "deleted" in m:
            where.append("m.deleted = 0")
        order = "DESC" if newest_first else "ASC"
        sql = (self._select() + (" WHERE " + " AND ".join(where) if where else "")
               + f" ORDER BY m.date_received {order}, m.ROWID {order}")
        if limit is not None:
            sql += " LIMIT ?"
            args.append(max(limit, 0))
        with self._snapshot():
            rows: List[Row] = self.db.execute(sql, args).fetchall()
        for start in range(0, len(rows), BATCH):
            yield from self._build(rows[start:start + BATCH])

    def _has(self, table: str, *columns: str) -> bool:
        return set(columns) <= self.columns.get(table, set())

    def _select(self) -> str:
        m = self.columns["messages"]

        def col(name: str) -> str:
            return f"m.{name}" if name in m else "NULL"

        prefix = "COALESCE(m.subject_prefix, '') || " if "subject_prefix" in m else ""
        global_data = "global_message_id" in m and self._has("message_global_data", "message_id_header")
        return (f"SELECT m.ROWID, m.mailbox, {col('date_sent')}, m.date_received, {col('read')}, {col('flagged')}, "
                f"{col('deleted')}, {prefix}COALESCE(s.subject, ''), a.address, a.comment, "
                f"{'g.message_id_header' if global_data else 'NULL'} FROM messages m "
                "LEFT JOIN subjects s ON s.ROWID = m.subject LEFT JOIN addresses a ON a.ROWID = m.sender"
                + (" LEFT JOIN message_global_data g ON g.ROWID = m.global_message_id" if global_data else ""))

    @contextmanager
    def _snapshot(self) -> Iterator[None]:
        """Reads inside see one consistent state of the database, and Mail is held up no longer."""
        self.db.execute("BEGIN")
        try:
            yield
        finally:
            self.db.execute("COMMIT")

    def _build(self, rows: List[Row]) -> Iterator[Message]:
        ids = [int(r[0]) for r in rows]
        marks = ",".join("?" * len(ids))
        recipients: Dict[int, Dict[str, List[Address]]] = {}
        labels: Dict[int, List[int]] = {}
        names: Dict[int, List[str]] = {}
        with self._snapshot():
            for message, kind, address, comment in self.db.execute(
                    "SELECT r.message, r.type, a.address, a.comment FROM recipients r JOIN addresses a ON "
                    f"a.ROWID = r.address WHERE r.message IN ({marks}) ORDER BY r.message, r.type, r.position", ids):
                key = RECIPIENT_KINDS.get(int(kind)) if kind is not None else None
                if key and address:
                    recipients.setdefault(int(message), {}).setdefault(key, []).append(
                        Address(str(address), str(comment) if comment else None))
            if self._has("labels", "message_id", "mailbox_id"):
                for message, box in self.db.execute(
                        f"SELECT message_id, mailbox_id FROM labels WHERE message_id IN ({marks})", ids):
                    labels.setdefault(int(message), []).append(int(box))
            if self._has("attachments", "message", "name"):
                for message, name in self.db.execute(
                        f"SELECT message, name FROM attachments WHERE message IN ({marks}) ORDER BY ROWID", ids):
                    names.setdefault(int(message), []).append(str(name or ""))
        boxes = self.mailboxes()
        for row in rows:
            rowid, box_id = int(row[0]), int(row[1])
            box = boxes.get(box_id)
            shown = tuple(dict.fromkeys([box_id] + sorted(labels.get(rowid, []))))
            path, partial = self._message_file(rowid, box)
            people = recipients.get(rowid, {})
            yield Message(
                id=rowid, account_id=box.account_id if box else "", mailbox_id=box_id, mailbox_ids=shown,
                subject=str(row[7] or ""),
                sender=Address(str(row[8]), str(row[9]) if row[9] else None) if row[8] else None,
                to=tuple(people.get("to", [])), cc=tuple(people.get("cc", [])), bcc=tuple(people.get("bcc", [])),
                date_sent=_date(row[2]), date_received=_date(row[3]) or datetime.fromtimestamp(0, timezone.utc),
                read=bool(row[4]), flagged=bool(row[5]), deleted=bool(row[6]),
                junk=any(boxes[b].role == "junk" for b in shown if b in boxes),
                message_id=str(row[10]) if row[10] else None, attachment_names=tuple(names.get(rowid, [])),
                path=path, partial=partial)

    # -- message files

    def _message_file(self, rowid: int, box: Optional[Mailbox]) -> Tuple[Optional[Path], bool]:
        store = self._store(box.folder) if box else None
        if store is not None:
            folder = store.joinpath("Data", *partition(rowid), "Messages")
            for name, partial in ((f"{rowid}.emlx", False), (f"{rowid}.partial.emlx", True)):
                if _is_file(folder / name):
                    return folder / name, partial
        if box is None:
            return None, False
        found = self._indexed(box.account_id).get(rowid)
        return (found, found.name.endswith(".partial.emlx")) if found else (None, False)

    def _store(self, mailbox_folder: Path) -> Optional[Path]:
        """The folder inside a mailbox that holds Data/: named by Mail's store id, else the one there is."""
        if mailbox_folder not in self._stores:
            store_id = self.installation.store_id
            found: Optional[Path] = None
            if store_id and _is_dir(mailbox_folder / store_id / "Data"):
                found = mailbox_folder / store_id
            else:
                found = next((mailbox_folder / n for n in _listdir(mailbox_folder)
                              if not n.endswith(".mbox") and _is_dir(mailbox_folder / n / "Data")), None)
            self._stores[mailbox_folder] = found
        return self._stores[mailbox_folder]

    def _indexed(self, account_id: str) -> Dict[int, Path]:
        """Every message file of an account, found by walking its folder once: for files Mail keeps
        somewhere its usual layout does not predict."""
        if account_id not in self._file_index:
            index: Dict[int, Path] = {}
            root = self.installation.root / account_id
            try:
                for folder, dirs, files in os.walk(root, onerror=_raise, followlinks=False):
                    dirs[:] = [d for d in dirs if d != "Attachments"]
                    if Path(folder).name != "Messages":
                        continue
                    for name in files:
                        m = re.fullmatch(r"(\d+)(\.partial)?\.emlx", name)
                        if m:
                            index.setdefault(int(m.group(1)), Path(folder) / name)
            except PermissionError as e:
                raise AccessDenied(denied_message(root)) from e
            except FileNotFoundError:
                pass  # the account's folder is gone: none of its messages are downloaded
            except OSError as e:
                raise MailError(f"cannot read {root}: {e}") from e
            self._file_index[account_id] = index
        return self._file_index[account_id]

    def raw(self, message: Message) -> Optional[bytes]:
        """The message as received (RFC 822), or None when it is not downloaded. In a partial
        message, the parts stored as separate files are empty here; see content()."""
        return emlx_message(read_bytes(message.path)) if message.path else None

    def content(self, message: Message) -> Optional[Content]:
        """Headers, text, links and attachments from the message's file; None when not downloaded."""
        raw = self.raw(message)
        if raw is None or message.path is None:
            return None
        names: Dict[str, str] = {}
        if self._has("attachments", "message", "attachment_id", "name"):
            for part, name in self.db.execute("SELECT attachment_id, name FROM attachments WHERE message = ?",
                                              (message.id,)):
                if part is not None and name:
                    names[str(part)] = str(name)
        return parse_content(raw, message.path.parent.parent / "Attachments" / str(message.id), names)

    def attachment_data(self, message: Message, attachment: Attachment) -> Optional[bytes]:
        """An attachment's bytes, from Mail's separate copy or from inside the message file."""
        if attachment.local_path is not None:
            return read_bytes(attachment.local_path)
        raw = self.raw(message) if attachment.in_message else None
        if raw is None:
            return None
        msg = email.message_from_bytes(raw, policy=email.policy.compat32)
        for number, part in mime_parts(msg):
            if number == attachment.part:
                if part.get_content_type() == "message/rfc822":
                    inner = part.get_payload()
                    first = inner[0] if isinstance(inner, list) and inner else None
                    return first.as_bytes() if isinstance(first, email.message.Message) else None
                data = part.get_payload(decode=True)
                return data if isinstance(data, bytes) else None
        return None


def _raise(error: OSError) -> None:
    raise error


def _date(value: object) -> Optional[datetime]:
    if value is None:
        return None
    try:
        return datetime.fromtimestamp(int(str(value)), timezone.utc)
    except (ValueError, OverflowError, OSError):
        return None


def downloads(installation: Installation) -> List[Download]:
    """Attachments opened from Mail: it saves each into Mail Downloads/<random folder>/<name>."""
    out: List[Download] = []
    for folder in _listdir(installation.downloads):
        path = installation.downloads / folder
        entries = [path / n for n in _listdir(path)] if _is_dir(path) and not path.is_symlink() else [path]
        for entry in entries:
            if entry.name.startswith(".") or entry.is_symlink():
                continue
            try:
                st = entry.stat()
            except OSError:
                continue
            if entry.is_file():
                out.append(Download(entry, st.st_size, datetime.fromtimestamp(st.st_mtime, timezone.utc)))
    return sorted(out, key=lambda d: d.modified)


# --------------------------------------------------------------------------------------------
# Diagnostics: look at what this module sees, without the rest of audit-content
# --------------------------------------------------------------------------------------------


def _address(a: Optional[Address]) -> Optional[str]:
    return None if a is None else (f"{a.name} <{a.address}>" if a.name else a.address)


def _message_json(m: Message, boxes: Dict[int, Mailbox], content: Optional[Content]) -> Dict[str, object]:
    out: Dict[str, object] = {
        "id": m.id, "date": m.date_received.isoformat(),
        "mailboxes": [boxes[b].name for b in m.mailbox_ids if b in boxes],
        "from": _address(m.sender), "to": [_address(a) for a in m.to], "subject": m.subject, "read": m.read,
        "junk": m.junk, "attachments": list(m.attachment_names), "file": str(m.path) if m.path else None}
    if content is not None:
        out["links"] = list(content.links)
        out["attachment_files"] = [{"part": a.part, "name": a.name, "type": a.mime_type, "size": a.size,
                                    "path": str(a.local_path) if a.local_path else None} for a in content.attachments]
    return out


def main(argv: Sequence[str]) -> int:
    p = argparse.ArgumentParser(prog="mail.py", description="Show what audit-content can read from Apple Mail.")
    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("accounts", help="where Mail's data is, and its accounts (default)")
    sub.add_parser("mailboxes")
    sp = sub.add_parser("messages")
    sp.add_argument("--mailbox", type=int, help="mailbox id, from `mailboxes`")
    sp.add_argument("--since", help="ISO date or time, for example 2026-10-01")
    sp.add_argument("--limit", type=int, default=20)
    sp.add_argument("--content", action="store_true", help="also parse each message file for links and attachments")
    a = p.parse_args(argv)
    try:
        inst = discover()
        with Session(inst) as s:
            boxes = s.mailboxes()
            if a.cmd in (None, "accounts"):
                print(f"mail     {inst.root}")
                for acc in s.accounts().values():
                    count = sum(1 for b in boxes.values() if b.account_id == acc.id)
                    print(f"account  {acc.id}  {acc.kind or '?'}  {acc.name or '-'}  {acc.address or '-'}"
                          f"  {count} mailboxes")
                print(f"files    {len(downloads(inst))} opened from Mail, in {inst.downloads}")
                if s.stale:
                    print("note     Mail left changes this module cannot read; the newest messages may be missing")
                return 0
            if a.cmd == "mailboxes":
                for b in boxes.values():
                    print(f"{b.id:>6}  {b.role or '-':9} {b.unread_count:>5} unread  {b.account_id[:8]}  {b.name}")
                return 0
            since = datetime.fromisoformat(a.since).astimezone(timezone.utc) if a.since else None
            for m in s.messages(a.mailbox, since=since, newest_first=True, limit=a.limit):
                print(json.dumps(_message_json(m, boxes, s.content(m) if a.content else None), ensure_ascii=False))
            return 0
    except MailError as e:
        print(f"mail.py: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
