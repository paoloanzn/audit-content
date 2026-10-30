"""Mail reader checks against a synthetic Apple Mail setup.

The fixture builds what Apple Mail keeps on disk, from scratch, in a temporary home folder: the
version folder named by PersistenceInfo.plist, an Envelope Index whose newest rows are only in the
write-ahead log of a connection that stays open the way Mail's does, a Gmail account (messages in
All Mail, mailboxes as labels, roles in .mboxCache.plist) and an On My Mac account, full and
partial .emlx files with attachments stored next to them, macOS's account store, and Mail
Downloads. No real mail is read.

Run with: python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import base64
import contextlib
import os
import plistlib
import shutil
import sqlite3
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, List, Optional
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import mail  # noqa: E402

STORE = "17E52C42-C547-4779-A49A-A7F79AAAC254"
GMAIL = "ABB32D77-54EE-436F-9365-6C8B500214AC"
LOCAL = "F00C112A-3E20-44E7-9EC6-BB875D636403"
ALL_MAIL, INBOX, SPAM, DRAFTS, WORK = 1, 2, 3, 4, 5
FULL, PARTIAL, JUNK, MOVED, DELETED, NOTE, FRESH = 1001, 17830, 1002, 1003, 1004, 7, 1005
T0 = 1_790_000_000

FULL_MESSAGE = b"""From: =?utf-8?q?Alice_=C3=96?= <alice@example.com>
To: me@example.com
Subject: Quarterly report
Message-ID: <full@example.com>
Authentication-Results: mx.example; spf=fail
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="outer"

--outer
Content-Type: multipart/alternative; boundary="alt"

--alt
Content-Type: text/plain; charset=utf-8

See https://plain.example/a. and www.bare.example/x
--alt
Content-Type: text/html; charset=utf-8
Content-Transfer-Encoding: quoted-printable

<html><head><title>Hidden title</title><style>a {}</style><base href=3D"https://base.examp=
le/dir/"></head><body><p>Hi there</p>
<a href=3D"https://hidden.example/login?a=3D1&amp;b=3D2">Open</a>
<a href=3D"java&#10;script:alert(1)">x</a> <a href=3D"mailto:x@example.com">m</a> <a href=3D"#top">t</a>
<a href=3D"next/page">relative</a>
<form action=3D"//form.example/post"><button formaction=3D"https://button.example/go">b</button></form>
<script>var u =3D "https://script.example/";</script>
</body></html>
--alt
Content-Type: text/calendar; charset=utf-8

BEGIN:VCALENDAR
URL:https://meet.example/j/1
END:VCALENDAR
--alt--
--outer
Content-Type: application/zip; name="tools.zip"
Content-Disposition: attachment; filename="tools.zip"
Content-Transfer-Encoding: base64

""" + base64.encodebytes(b"PK\x03\x04zip data") + b"""
--outer--
"""

# Mail keeps the attachments of this one in Attachments/17830/<part>, and leaves their parts empty.
PARTIAL_MESSAGE = b"""From: billing@example.net
To: me@example.com
Subject: Invoice
Message-ID: <partial@example.net>
Content-Type: multipart/mixed; boundary="b"

--b
Content-Type: text/plain; charset=us-ascii

Invoice attached.
--b
Content-Type: application/pdf; name="../../escape.pdf"
Content-Disposition: attachment; filename="../../escape.pdf"
Content-Transfer-Encoding: base64
X-Apple-Content-Length: 1234

--b
Content-Type: text/html
Content-Transfer-Encoding: base64
X-Apple-Content-Length: 99

--b--
"""


def plain_message(text: str) -> bytes:
    return f"From: me@example.com\nSubject: note\n\n{text}\n".encode()


def emlx(message: bytes) -> bytes:
    return str(len(message)).encode() + b"\n" + message + plistlib.dumps({"flags": 1, "date-received": T0})


SCHEMA = """
CREATE TABLE messages (ROWID INTEGER PRIMARY KEY, message_id INTEGER, global_message_id INTEGER, remote_id INTEGER,
    sender INTEGER, subject_prefix TEXT, subject INTEGER, summary INTEGER, date_sent INTEGER, date_received INTEGER,
    mailbox INTEGER, flags INTEGER, read INTEGER, flagged INTEGER, deleted INTEGER, size INTEGER);
CREATE INDEX messages_date_received_index ON messages(date_received);
CREATE TABLE subjects (ROWID INTEGER PRIMARY KEY, subject TEXT);
CREATE TABLE addresses (ROWID INTEGER PRIMARY KEY, address TEXT, comment TEXT);
CREATE TABLE recipients (ROWID INTEGER PRIMARY KEY, message INTEGER, address INTEGER, type INTEGER, position INTEGER);
CREATE TABLE mailboxes (ROWID INTEGER PRIMARY KEY, url TEXT UNIQUE, total_count INTEGER, unread_count INTEGER);
CREATE TABLE labels (message_id INTEGER, mailbox_id INTEGER, PRIMARY KEY (message_id, mailbox_id)) WITHOUT ROWID;
CREATE TABLE attachments (ROWID INTEGER PRIMARY KEY, message INTEGER, attachment_id TEXT, name TEXT);
CREATE TABLE message_global_data (ROWID INTEGER PRIMARY KEY, message_id INTEGER, message_id_header TEXT);
"""


class Fixture:
    """A home folder with Apple Mail's data. `writer` plays Mail: it stays open and never checkpoints."""

    def __init__(self, base: Path) -> None:
        self.home = base / "home"
        self.mail = self.home / "Library" / "Mail"
        self.root = self.mail / "V10"
        (self.root / "MailData").mkdir(parents=True)
        (self.mail / "V11").mkdir()  # a newer version folder Mail never used: no database
        (self.mail / "V9" / "MailData").mkdir(parents=True)
        (self.mail / "V9" / "MailData" / "Envelope Index").write_bytes(b"")
        self.persistence = self.mail / "PersistenceInfo.plist"
        self.persistence.write_bytes(plistlib.dumps({"LastUsedVersionDirectoryName": "V10",
                                                     "VersionDirectoryIdentifiers": {"V10": STORE}}))
        cache = {"mboxes": {
            "INBOX": {"IMAPMailboxAttributes": 64, "MailboxPathComponent": "INBOX", "IMAPMailboxChildren": {}},
            "Work": {"IMAPMailboxAttributes": 64, "MailboxPathComponent": "Work", "IMAPMailboxChildren": {}},
            "[Gmail]": {"IMAPMailboxAttributes": 34, "MailboxPathComponent": "[Gmail]", "IMAPMailboxChildren": {
                "All Mail": {"IMAPMailboxAttributes": 1088, "MailboxPathComponent": "All Mail"},
                "Spam": {"IMAPMailboxAttributes": 16448, "MailboxPathComponent": "Spam"}}}}}
        (self.root / GMAIL).mkdir()
        (self.root / GMAIL / ".mboxCache.plist").write_bytes(plistlib.dumps(cache))

        all_mail = self.root / GMAIL / "[Gmail].mbox" / "All Mail.mbox" / STORE / "Data"
        self.write(all_mail / "1" / "Messages" / f"{FULL}.emlx", emlx(FULL_MESSAGE))
        self.write(all_mail / "7" / "1" / "Messages" / f"{PARTIAL}.partial.emlx", emlx(PARTIAL_MESSAGE))
        attachments = all_mail / "7" / "1" / "Attachments" / str(PARTIAL)
        self.write(attachments / "2" / "invoice.pdf", b"%PDF-1.7 fake invoice")
        self.write(attachments / "2" / ".DS_Store", b"\0")
        self.write(attachments / "3" / "Mail Attachment.html", b'<a href="https://attached.example/x">pay</a>')
        self.write(all_mail / "1" / "Messages" / f"{DELETED}.emlx", b"999\nshort")  # damaged
        # Not where Mail's layout puts message 1003 (Data/1/Messages): found by walking the account.
        self.write(self.root / GMAIL / "Work.mbox" / STORE / "Data" / "9" / "Messages" / f"{MOVED}.emlx",
                   emlx(plain_message("moved https://moved.example/")))
        self.write(self.root / LOCAL / "Drafts.mbox" / STORE / "Data" / "Messages" / f"{NOTE}.emlx",
                   emlx(plain_message("draft")))
        downloads = self.home / "Library" / "Containers" / "com.apple.mail" / "Data" / "Library" / "Mail Downloads"
        self.write(downloads / "65EB1B4B" / "report.pdf", b"%PDF opened")
        self.write(downloads / "FE8890D8" / ".DS_Store", b"\0")
        self.accounts_database(self.home / "Library" / "Accounts" / "Accounts4.sqlite")

        self.database = self.root / "MailData" / "Envelope Index"
        self.writer = sqlite3.connect(self.database, isolation_level=None)
        self.writer.execute("PRAGMA journal_mode=WAL")
        self.writer.executescript(SCHEMA)
        w = self.writer
        w.executemany("INSERT INTO mailboxes VALUES (?, ?, 0, ?)", [
            (ALL_MAIL, f"imap://{GMAIL}/%5BGmail%5D/All%20Mail", 1), (INBOX, f"imap://{GMAIL}/INBOX", 0),
            (SPAM, f"imap://{GMAIL}/%5BGmail%5D/Spam", 1), (DRAFTS, f"local://{LOCAL}/Drafts", 0),
            (WORK, f"imap://{GMAIL}/Work", 0)])
        w.executemany("INSERT INTO addresses VALUES (?, ?, ?)", [
            (1, "alice@example.com", "Alice Ö"), (2, "me@example.com", None), (3, "billing@example.net", None),
            (4, "boss@example.com", "Boss"), (5, "audit@example.com", None)])
        w.executemany("INSERT INTO subjects VALUES (?, ?)", [(1, "Quarterly report"), (2, "Invoice"), (3, "note")])
        w.executemany("INSERT INTO message_global_data VALUES (?, 0, ?)", [(1, "<full@example.com>")])
        w.executemany("INSERT INTO messages (ROWID, global_message_id, sender, subject_prefix, subject, date_sent,"
                      " date_received, mailbox, read, flagged, deleted) VALUES (?,?,?,?,?,?,?,?,?,?,?)", [
                          (FULL, 1, 1, "Re: ", 1, T0 - 60, T0 + 1, ALL_MAIL, 1, 1, 0),
                          (PARTIAL, None, 3, None, 2, None, T0 + 2, ALL_MAIL, 1, 0, 0),
                          (JUNK, None, 3, None, 2, T0, T0 + 3, ALL_MAIL, 0, 0, 0),
                          (MOVED, None, 2, None, 3, T0, T0 + 4, WORK, 1, 0, 0),
                          (DELETED, None, 2, None, 3, T0, T0 + 5, ALL_MAIL, 1, 0, 1),
                          (NOTE, None, 2, None, 3, T0, T0 + 6, DRAFTS, 1, 0, 0)])
        w.executemany("INSERT INTO recipients (message, address, type, position) VALUES (?, ?, ?, ?)", [
            (FULL, 2, 0, 0), (FULL, 4, 1, 0), (FULL, 5, 2, 0), (FULL, 1, 7, 0),  # 7: a kind this module does not know
            (PARTIAL, 2, 0, 0), (3, 2, 0, 0)])  # row 3 is gone: its recipient row is left over, as in real data
        w.executemany("INSERT INTO labels VALUES (?, ?)", [(FULL, INBOX), (PARTIAL, INBOX), (JUNK, SPAM)])
        w.executemany("INSERT INTO attachments (message, attachment_id, name) VALUES (?, ?, ?)", [
            (FULL, "1.3", "invite.ics"), (FULL, "2", "tools.zip"),
            (PARTIAL, "2", "../../escape.pdf"), (PARTIAL, "3", "Mail Attachment.html")])
        w.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        w.execute("PRAGMA wal_autocheckpoint=0")
        # Arrived after Mail's last checkpoint: only in the write-ahead log.
        w.execute("INSERT INTO messages (ROWID, sender, subject, date_sent, date_received, mailbox, read, flagged,"
                  " deleted) VALUES (?, 1, 1, ?, ?, ?, 0, 0, 0)", (FRESH, T0, T0 + 7, ALL_MAIL))

    @staticmethod
    def write(path: Path, data: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    @staticmethod
    def accounts_database(path: Path) -> None:
        path.parent.mkdir(parents=True)
        c = sqlite3.connect(path)
        c.executescript("""
            CREATE TABLE ZACCOUNTTYPE (Z_PK INTEGER PRIMARY KEY, ZIDENTIFIER TEXT);
            CREATE TABLE ZACCOUNT (Z_PK INTEGER PRIMARY KEY, ZIDENTIFIER TEXT, ZPARENTACCOUNT INTEGER,
                ZACCOUNTDESCRIPTION TEXT, ZUSERNAME TEXT, ZACCOUNTTYPE INTEGER);""")
        c.executemany("INSERT INTO ZACCOUNTTYPE VALUES (?, ?)", [
            (1, "com.apple.account.Google"), (2, "com.apple.account.IMAP"), (3, "com.apple.account.OnMyDevice")])
        # Mail's IMAP account for Gmail is a child of the Google account, which has the name and address.
        c.executemany("INSERT INTO ZACCOUNT VALUES (?, ?, ?, ?, ?, ?)", [
            (1, "GOOGLE-PARENT", None, "Work Gmail", "me@example.com", 1), (2, GMAIL, 1, None, None, 2),
            (3, LOCAL, None, "On My Mac", None, 3)])
        c.commit()
        c.close()

    def files(self) -> List[str]:
        """Every file and folder under the home folder, for checking that nothing was added."""
        return sorted(str(p.relative_to(self.home)) for p in self.home.rglob("*"))


class MailTest(unittest.TestCase):
    fx: Fixture
    tmp: Path

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = Path(tempfile.mkdtemp(prefix="audit-content-mail-test-"))
        cls.fx = Fixture(cls.tmp)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.fx.writer.close()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    @contextlib.contextmanager
    def home(self, path: Optional[Path] = None) -> Iterator[None]:
        with mock.patch.dict(os.environ, {"HOME": str(path or self.fx.home)}):
            yield

    def session(self) -> mail.Session:
        with self.home():
            return mail.Session(mail.discover())

    def listed(self, mailbox: Optional[int] = None, since: Optional[datetime] = None,
               until: Optional[datetime] = None, newest_first: bool = False, limit: Optional[int] = None,
               include_deleted: bool = False) -> List[int]:
        with self.session() as s:
            return [m.id for m in s.messages(mailbox, since, until, newest_first, limit, include_deleted)]

    def test_discovery_without_fixed_paths(self) -> None:
        with self.home():
            inst = mail.discover()
            self.assertEqual((inst.root, inst.store_id), (self.fx.root, STORE))
            self.assertEqual(inst.accounts_database, self.fx.home / "Library" / "Accounts" / "Accounts4.sqlite")
            saved = self.fx.persistence.read_bytes()
            try:
                self.fx.persistence.write_bytes(plistlib.dumps({"LastUsedVersionDirectoryName": "V9"}))
                self.assertEqual(mail.discover().root, self.fx.mail / "V9")  # Mail's own record comes first
                self.fx.persistence.unlink()  # then the newest version folder with a database: not V11
                self.assertEqual((mail.discover().root, mail.discover().store_id), (self.fx.root, None))
            finally:
                self.fx.persistence.write_bytes(saved)
            self.assertEqual([d.path.name for d in mail.downloads(inst)], ["report.pdf"])
        with self.home(self.tmp / "nobody"):
            self.assertRaises(mail.NotSetUp, mail.discover)
            self.assertIsNone(mail.check_access())

    @unittest.skipIf(os.geteuid() == 0, "root reads everything")
    def test_access_denied_is_explained_not_empty(self) -> None:
        os.chmod(self.fx.mail, 0)
        try:
            with self.home():
                with self.assertRaises(mail.AccessDenied) as caught:
                    mail.discover()
                self.assertIn("Full Disk Access", str(caught.exception))
                self.assertIn("Full Disk Access", mail.check_access() or "")
        finally:
            os.chmod(self.fx.mail, 0o755)

    def test_accounts_and_mailboxes(self) -> None:
        with self.session() as s:
            boxes = s.mailboxes()
            self.assertEqual({b.id: (b.role, b.name) for b in boxes.values()}, {
                ALL_MAIL: ("all", "[Gmail]/All Mail"), INBOX: ("inbox", "INBOX"), SPAM: ("junk", "[Gmail]/Spam"),
                DRAFTS: ("", "Drafts"), WORK: ("", "Work")})
            self.assertEqual(boxes[ALL_MAIL].folder, self.fx.root / GMAIL / "[Gmail].mbox" / "All Mail.mbox")
            accounts = s.accounts()
            self.assertEqual((accounts[GMAIL].kind, accounts[GMAIL].name, accounts[GMAIL].address),
                             ("Google", "Work Gmail", "me@example.com"))
            self.assertEqual((accounts[LOCAL].kind, accounts[LOCAL].name), ("OnMyDevice", "On My Mac"))

    def test_messages_from_the_index(self) -> None:
        with self.session() as s:
            msgs = {m.id: m for m in s.messages()}
        self.assertEqual(list(msgs), [FULL, PARTIAL, JUNK, MOVED, NOTE, FRESH])  # by date; deleted left out
        m = msgs[FULL]
        self.assertEqual((m.subject, m.sender, m.message_id), (
            "Re: Quarterly report", mail.Address("alice@example.com", "Alice Ö"), "<full@example.com>"))
        self.assertEqual((m.to, m.cc, m.bcc), ((mail.Address("me@example.com"),),
                                              (mail.Address("boss@example.com", "Boss"),),
                                              (mail.Address("audit@example.com"),)))
        self.assertEqual((m.date_sent, m.date_received), (datetime.fromtimestamp(T0 - 60, timezone.utc),
                                                          datetime.fromtimestamp(T0 + 1, timezone.utc)))
        self.assertEqual((m.read, m.flagged, m.junk, m.mailbox_ids, m.account_id),
                         (True, True, False, (ALL_MAIL, INBOX), GMAIL))
        self.assertEqual(m.attachment_names, ("invite.ics", "tools.zip"))
        self.assertEqual((msgs[JUNK].junk, msgs[JUNK].read, msgs[JUNK].path), (True, False, None))
        self.assertTrue(msgs[PARTIAL].partial)
        self.assertTrue(str(msgs[PARTIAL].path).endswith(f"Data/7/1/Messages/{PARTIAL}.partial.emlx"))
        self.assertTrue(str(msgs[NOTE].path).endswith(f"{STORE}/Data/Messages/{NOTE}.emlx"))
        self.assertTrue(str(msgs[MOVED].path).endswith(f"Data/9/Messages/{MOVED}.emlx"))  # found by walking
        self.assertEqual(self.listed(mailbox=INBOX), [FULL, PARTIAL])  # Gmail labels count
        self.assertIn(DELETED, self.listed(include_deleted=True))
        since, until = datetime.fromtimestamp(T0 + 2, timezone.utc), datetime.fromtimestamp(T0 + 4, timezone.utc)
        self.assertEqual(self.listed(since=since, until=until), [PARTIAL, JUNK])
        self.assertEqual(self.listed(newest_first=True, limit=2), [FRESH, NOTE])

    def test_content_links_and_attachments(self) -> None:
        with self.session() as s:
            msgs = {m.id: m for m in s.messages()}
            c = s.content(msgs[FULL])
            assert c is not None
            self.assertEqual(c.links, (
                "https://plain.example/a", "www.bare.example/x", "https://hidden.example/login?a=1&b=2",
                "javascript:alert(1)", "https://base.example/dir/next/page", "https://form.example/post",
                "https://button.example/go", "https://meet.example/j/1"))
            self.assertEqual(c.text, "See https://plain.example/a. and www.bare.example/x")
            self.assertIn("Hi there", c.html)
            self.assertIn(("From", "Alice Ö <alice@example.com>"), c.headers)
            self.assertIn(("Authentication-Results", "mx.example; spf=fail"), c.headers)
            self.assertEqual([(a.part, a.name, a.mime_type, a.in_message) for a in c.attachments], [
                ("1.3", "invite.ics", "text/calendar", True), ("2", "tools.zip", "application/zip", True)])
            self.assertEqual(s.attachment_data(msgs[FULL], c.attachments[1]), b"PK\x03\x04zip data")
            self.assertEqual(c.attachments[1].size, len(b"PK\x03\x04zip data"))

            p, path = s.content(msgs[PARTIAL]), msgs[PARTIAL].path
            assert p is not None and path is not None
            folder = path.parent.parent / "Attachments" / str(PARTIAL)
            pdf, page = p.attachments
            # The message's file name is only a label: the path comes from Mail's folder.
            self.assertEqual((pdf.name, pdf.local_path, pdf.size, pdf.in_message),
                             ("../../escape.pdf", folder / "2" / "invoice.pdf", len(b"%PDF-1.7 fake invoice"), False))
            self.assertEqual(s.attachment_data(msgs[PARTIAL], pdf), b"%PDF-1.7 fake invoice")
            self.assertEqual((page.name, page.local_path),
                             ("Mail Attachment.html", folder / "3" / "Mail Attachment.html"))
            self.assertEqual(p.links, ("https://attached.example/x",))  # read from Mail's copy of the HTML file

            note = s.content(msgs[NOTE])
            assert note is not None
            self.assertEqual((note.text, note.attachments), ("draft", ()))
            self.assertIsNone(s.content(msgs[JUNK]))  # not downloaded
            broken = next(m for m in s.messages(include_deleted=True) if m.id == DELETED)
            self.assertRaises(mail.FormatError, s.content, broken)

    def test_reads_the_log_while_mail_writes_and_leaves_nothing(self) -> None:
        before = self.fx.files()
        with self.session() as s:
            self.assertFalse(s.stale)
            self.assertIn(FRESH, {m.id for m in s.messages()})  # committed, but only in the log
            self.fx.writer.execute("INSERT INTO messages (ROWID, sender, subject, date_received, mailbox, read,"
                                   " flagged, deleted) VALUES (2000, 1, 1, ?, ?, 0, 0, 0)", (T0 + 8, ALL_MAIL))
            try:
                self.assertIn(2000, {m.id for m in s.messages()})  # each listing sees the newest state
            finally:
                self.fx.writer.execute("DELETE FROM messages WHERE ROWID = 2000")
            for m in s.messages():
                s.content(m)
        self.assertEqual(self.fx.files(), before)

    def test_closed_mail_is_read_without_creating_files(self) -> None:
        copy = self.tmp / "closed"
        copy.mkdir()
        shutil.copy(self.fx.database, copy / "db")
        con, stale = mail.open_database(copy / "db")  # no log, no shared memory: Mail quit cleanly
        con.close()
        self.assertFalse(stale)
        shutil.copy(f"{self.fx.database}-wal", copy / "db-wal")  # Mail crashed: a log without shared memory
        con, stale = mail.open_database(copy / "db")
        ids = {r[0] for r in con.execute("SELECT ROWID FROM messages")}
        con.close()
        self.assertEqual((stale, FRESH in ids, FULL in ids), (True, False, True))
        self.assertEqual(sorted(os.listdir(copy)), ["db", "db-wal"])

    def test_unknown_database_layout_fails_loudly(self) -> None:
        odd = self.tmp / "odd"
        odd.mkdir()
        con = sqlite3.connect(odd / "Envelope Index")
        con.executescript("CREATE TABLE messages (ROWID INTEGER PRIMARY KEY);")
        con.close()
        inst = mail.Installation(odd, odd / "Envelope Index", None, None, odd / "downloads")
        with self.assertRaises(mail.FormatError) as caught:
            mail.Session(inst)
        self.assertIn("messages.date_received", str(caught.exception))

    def test_parts_layout_helpers(self) -> None:
        self.assertEqual(mail.partition(17830), ["7", "1"])
        self.assertEqual(mail.partition(999), [])
        self.assertEqual(mail.partition(123456), ["3", "2", "1"])
        self.assertEqual(mail.mailbox_path(f"imap://{GMAIL}/%5BGmail%5D/Sent%20Mail"),
                         (GMAIL, ["[Gmail]", "Sent Mail"]))
        self.assertRaises(mail.FormatError, mail.mailbox_path, f"imap://{GMAIL}/..%2F..%2Fescape")
        self.assertRaises(mail.FormatError, mail.emlx_message, b"12\nshort")
        self.assertEqual(mail.absolute_link(" //cdn.example/x ", None), "https://cdn.example/x")
        self.assertIsNone(mail.absolute_link("x-apple-data-detectors://3", None))
        self.assertEqual(mail.text_links("(see https://a.example/wiki/X_(y)), and https://b.example."),
                         ["https://a.example/wiki/X_(y)", "https://b.example"])


if __name__ == "__main__":
    unittest.main()
