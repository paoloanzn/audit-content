"""Telegram reader checks against a synthetic, fully encrypted Telegram account.

The fixture builds what Telegram for macOS keeps on disk, from scratch: a key file encrypted with
the default passcode, a SQLCipher 4 database (80 reserved bytes per page, plaintext header, HMAC)
whose newest rows are only in the write-ahead log, Postbox tables, binary message records, and a
downloaded attachment. No real Telegram data is read.

Run with: python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import hashlib
import os
import shutil
import sqlite3
import struct
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import telegram as tg  # noqa: E402

PAGE, RESERVE = 4096, 80
GROUP = "6N38VWS5BX.ru.keepcoder.Telegram"
ME, ALICE, NEWS, BOT = 1001, 777000, (2 << 32) | 1234, 4242
BIG_ID = 6_000_000_000  # user ids above 2^32 are split around the namespace bits
BIG = ((BIG_ID >> 32) << 35) | (BIG_ID & 0xFFFFFFFF)
T0 = 1_760_000_000


# -- Postbox encoding, the mirror image of what telegram.py decodes

def fld(key: str, kind: int, payload: bytes) -> bytes:
    return bytes([len(key)]) + key.encode() + bytes([kind]) + payload


def s(key: str, text: str) -> bytes:
    data = text.encode()
    return fld(key, 4, struct.pack("<i", len(data)) + data)


def i32(key: str, v: int) -> bytes:
    return fld(key, 0, struct.pack("<i", v))


def i64(key: str, v: int) -> bytes:
    return fld(key, 1, struct.pack("<q", v))


def obj(type_name: str, *fields: bytes) -> bytes:
    data = b"".join(fields)
    return struct.pack("<Ii", tg.murmur3_32(type_name.encode()), len(data)) + data


def child(key: str, o: bytes) -> bytes:
    return fld(key, 5, o)


def children(key: str, objs: Sequence[bytes]) -> bytes:
    return fld(key, 8, struct.pack("<i", len(objs)) + b"".join(objs))


def root(o: bytes) -> bytes:
    return b"\x01_\x05" + o


def message(text: str, *, incoming: bool = True, author: Optional[int] = None, attributes: Sequence[bytes] = (),
            embedded: Sequence[bytes] = (), media: Sequence[Tuple[int, int]] = (), thread: Optional[int] = None,
            forward: Optional[int] = None, unique: Optional[int] = None) -> bytes:
    flags = (1 if unique is not None else 0) | (32 if thread is not None else 0)
    v = b"\x00" + struct.pack("<II", 1, 1) + bytes([flags])
    v += struct.pack("<q", unique) if unique is not None else b""
    v += struct.pack("<q", thread) if thread is not None else b""
    v += struct.pack("<II", (tg.INCOMING if incoming else 0) | 64, 0)
    v += bytes([1 | 2]) + struct.pack("<qiq", forward, T0, forward) if forward is not None else b"\x00"
    v += b"\x01" + struct.pack("<q", author) if author is not None else b"\x00"
    data = text.encode()
    v += struct.pack("<i", len(data)) + data
    for group in (attributes, embedded):
        v += struct.pack("<i", len(group)) + b"".join(struct.pack("<i", len(a)) + a for a in group)
    return v + struct.pack("<i", len(media)) + b"".join(struct.pack("<iq", ns, mid) for ns, mid in media)


def mkey(peer: int, ns: int, ts: int, mid: int) -> bytes:
    return struct.pack(">qiii", peer, ns, ts, mid)


# -- SQLCipher: encrypt a plain database and its WAL the way Telegram's SQLCipher stores them

def encrypt_page(page: bytes, pgno: int, key: bytes, mac_key: bytes) -> bytes:
    start = tg.PLAIN_HEADER if pgno == 1 else 0
    iv = os.urandom(16)
    cipher = tg.aes_cbc(key, iv, page[start:PAGE - RESERVE], encrypt=True)
    return page[:start] + cipher + iv + tg.page_mac(mac_key, cipher, iv, pgno)


def encrypt_db(plain: bytes, key: bytes, salt: bytes) -> bytes:
    mac_key = tg.hmac_key(key, salt)
    return b"".join(encrypt_page(plain[i:i + PAGE], i // PAGE + 1, key, mac_key) for i in range(0, len(plain), PAGE))


def encrypt_wal(plain: bytes, key: bytes, salt: bytes) -> bytes:
    mac_key = tg.hmac_key(key, salt)
    big = struct.unpack_from(">I", plain, 0)[0] == tg.WAL_MAGIC[1]
    out = bytearray(plain[:32])
    s0, s1 = struct.unpack_from(">II", plain, 24)
    for pos in range(32, len(plain) - (len(plain) - 32) % (24 + PAGE), 24 + PAGE):
        head = plain[pos:pos + 24]
        page = encrypt_page(plain[pos + 24:pos + 24 + PAGE], struct.unpack_from(">I", head, 0)[0], key, mac_key)
        s0, s1 = tg.wal_checksum(head[:8], s0, s1, big)
        s0, s1 = tg.wal_checksum(page, s0, s1, big)
        out += head[:16] + struct.pack(">II", s0, s1) + page
    return bytes(out)


def key_file(key: bytes, salt: bytes, passcode: bytes = tg.DEFAULT_PASSCODE) -> bytes:
    digest = hashlib.sha512(passcode).digest()
    plain = key + salt + struct.pack("<I", tg.murmur3_32(key + salt)) + bytes(12)
    return tg.aes_cbc(digest[:32], digest[-16:], plain, encrypt=True)


def new_database(path: Path) -> sqlite3.Connection:
    """A SQLite file with SQLCipher's 80 reserved bytes per page, made with the standard library."""
    c = sqlite3.connect(str(path))
    c.execute(f"PRAGMA page_size={PAGE}")
    c.execute("VACUUM")
    c.close()
    head = bytearray(path.read_bytes())
    head[20] = RESERVE
    struct.pack_into(">H", head, 105, PAGE - RESERVE)  # page 1 is empty: content starts at the usable end
    path.write_bytes(bytes(head))
    return sqlite3.connect(str(path), isolation_level=None)


class Fixture:
    """One Telegram for macOS install with one account under a fake home folder."""

    def __init__(self, base: Path) -> None:
        self.home = base / "home"
        self.data = self.home / "Library" / "Group Containers" / GROUP / "appstore"
        self.account = self.data / "account-12345"
        db_dir = self.account / "postbox" / "db"
        db_dir.mkdir(parents=True)
        (self.account / "postbox" / "media").mkdir()
        self.key, self.salt = os.urandom(32), os.urandom(16)
        (self.data / ".tempkeyEncrypted").write_bytes(key_file(self.key, self.salt))
        self.messages: Dict[bytes, bytes] = {}

        plain = base / "plain.db"
        c = new_database(plain)
        for name in ("t0", "t2", "t14"):
            c.execute(f"CREATE TABLE {name} (key INTEGER PRIMARY KEY, value BLOB)")
        for name in ("t6", "t7"):
            c.execute(f"CREATE TABLE {name} (key BLOB PRIMARY KEY, value BLOB)")
        c.execute("CREATE TABLE t4 (key BLOB PRIMARY KEY, value BLOB) WITHOUT ROWID")
        c.execute("INSERT INTO t0 VALUES (?, ?)", (tg.STATE_KEY, root(obj("AuthorizedAccountState", i64("peerId", ME)))))
        peers = [
            (ME, obj("TelegramUser", i64("i", ME), s("fn", "Me"))),
            (ALICE, obj("TelegramUser", i64("i", ALICE), s("fn", "Alice"), s("ln", "Smith"), s("un", "alice"),
                        s("p", "+100"))),
            (BIG, obj("TelegramUser", i64("i", BIG), s("fn", "Big"))),
            (BOT, obj("TelegramUser", i64("i", BOT), s("fn", "Helper"), child("bi", obj("BotUserInfo", i32("f", 0))))),
            (NEWS, obj("TelegramChannel", i64("i", NEWS), s("t", "News"), s("un", "news"))),
        ]
        c.executemany("INSERT INTO t2 VALUES (?, ?)", [(p, root(o)) for p, o in peers])
        # Alice has read nothing after message 5 in the cloud namespace.
        c.execute("INSERT INTO t14 VALUES (?, ?)", (ALICE, struct.pack("<iiBiiiiB", 1, 0, 0, 5, 3, 9, 4, 0)))
        doc = obj("TelegramMediaFile", s("mt", "application/pdf"), i32("s", 2048),
                  child("r", obj("CloudDocumentMediaResource", i32("d", 4), i64("f", 99))),
                  children("at", [obj("TelegramMediaFileAttribute", i32("t", 0), s("fn", "invoice.pdf"))]))
        c.execute("INSERT INTO t6 VALUES (?, ?)", (struct.pack(">iq", 0, 7), b"\x00" + struct.pack("<i", len(root(doc)))
                                                  + root(doc) + struct.pack("<i", 1)))
        (self.account / "postbox" / "media" / "telegram-cloud-document-4-99").write_bytes(b"%PDF-1.7 test")
        c.executemany("INSERT INTO t4 VALUES (?, ?)", [(struct.pack(">i", i), b"v" * i) for i in range(400)])

        # Entity ranges count UTF-16 units: the emoji before the link takes two.
        start = len("Here 😀 go ".encode("utf-16-le")) // 2
        hidden = root(obj("TextEntitiesMessageAttribute", children("entities", [
            obj("MessageTextEntity", i32("start", 0), i32("end", 4), i32("_rawValue", tg.ENTITY_TEXT_URL),
                s("url", "https://hidden.example/login")),
            obj("MessageTextEntity", i32("start", start), i32("end", start + len("evil.example/login?a=1")),
                i32("_rawValue", tg.ENTITY_URL)),
        ])))
        webpage = root(obj("TelegramMediaWebpage", child("c", obj("TelegramMediaWebpageLoadedContent",
                                                                     s("u", "https://preview.example/a")))))
        rows = [
            (mkey(ALICE, 0, T0 + 1, 1), message("hello", author=ALICE, unique=42)),
            (mkey(ALICE, 0, T0 + 2, 2), message("Here 😀 go evil.example/login?a=1 now", author=ALICE,
                                                attributes=[hidden])),
            (mkey(ALICE, 0, T0 + 3, 3), message("the invoice", author=ALICE, media=[(0, 7)])),
            (mkey(ALICE, 0, T0 + 4, 4), message("sure", incoming=False, author=ME)),
            (mkey(ALICE, 0, T0 + 5, 5), message("see https://plain.example/x.", author=ALICE, embedded=[webpage])),
            (mkey(ALICE, 0, T0 + 6, 6), message("x" * 20000, author=ALICE, forward=NEWS, thread=77)),
            (mkey(ALICE, 0, T0 + 7, 7), b"\x00garbage"),  # cannot be decoded: skipped and counted
            (mkey(ALICE, 1, T0 + 8, 1), message("local note", author=ALICE)),
            (mkey(BOT, 0, T0 + 9, 1), message("click", author=BOT, attributes=[root(obj(
                "ReplyMarkupMessageAttribute", children("r", [obj("ReplyMarkupRow", children("b", [obj(
                    "ReplyMarkupButton", s("t", "Open"), child("a", obj("#url", s("u", "https://button.example"))))]))])))])),
        ]
        rows += [(mkey(NEWS, 0, T0 + 100 + i, 100 + i), message(f"post {i} " + "y" * (i % 700), author=NEWS))
                 for i in range(2500)]
        c.executemany("INSERT INTO t7 VALUES (?, ?)", rows)
        self.messages.update(rows)

        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA wal_autocheckpoint=0")
        newest = [(mkey(ALICE, 0, T0 + 10_000, 8), message("fresh from the log", author=ALICE)),
                  (mkey(BIG, 0, T0 + 10_001, 1), message("hi", author=BIG))]
        c.executemany("INSERT INTO t7 VALUES (?, ?)", newest)
        self.messages.update(newest)
        db_bytes, wal_bytes = plain.read_bytes(), Path(f"{plain}-wal").read_bytes()
        c.close()
        if len(db_bytes) % PAGE or not wal_bytes:
            raise AssertionError("fixture database was not built as expected")
        self.db = db_dir / "db_sqlite"
        self.db.write_bytes(encrypt_db(db_bytes, self.key, self.salt))
        # A torn frame after the last commit must be ignored, as SQLite would.
        torn = bytes(24 + PAGE)
        Path(f"{self.db}-wal").write_bytes(encrypt_wal(wal_bytes, self.key, self.salt) + torn)


class TelegramTest(unittest.TestCase):
    tmp: Path
    fx: Fixture

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = Path(tempfile.mkdtemp(prefix="audit-content-telegram-test-"))
        cls.fx = Fixture(cls.tmp)

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.tmp)

    def session(self) -> tg.Session:
        return tg.Session(tg.Account(self.fx.account, self.fx.data / ".tempkeyEncrypted"))

    def test_key_file_and_passcode(self) -> None:
        self.assertEqual(tg.database_key(self.fx.data / ".tempkeyEncrypted"), (self.fx.key, self.fx.salt))
        locked = self.tmp / "locked.key"
        locked.write_bytes(key_file(self.fx.key, self.fx.salt, b"1234"))
        with self.assertRaises(tg.PasscodeRequired):
            tg.database_key(locked)
        with self.assertRaises(tg.PasscodeRequired):
            tg.database_key(locked, "0000")
        self.assertEqual(tg.database_key(locked, "1234"), (self.fx.key, self.fx.salt))

    def test_reader_sees_main_file_and_committed_log(self) -> None:
        db = tg.CipherDatabase(self.fx.db, self.fx.key, self.fx.salt)
        try:
            tree = tg.BTree(db)
            self.assertEqual({k: tree.table(k).layout for k in ("t2", "t4", "t7")},
                             {"t2": "rowid", "t4": "index", "t7": "autoindex"})
            t7 = tree.table("t7")
            stored = dict(tree.items(t7))
            self.assertEqual(stored, self.fx.messages)
            keys = sorted(self.fx.messages)
            lower, upper = mkey(NEWS, 0, T0 + 300, 0), mkey(NEWS, 0, T0 + 900, 0)
            want = [k for k in keys if lower <= k < upper]
            self.assertEqual([k for k, _ in tree.items(t7, lower, upper)], want)
            self.assertEqual([k for k, _ in tree.items(t7, lower, upper, reverse=True)], want[::-1])
            t4 = tree.table("t4")
            self.assertEqual(tree.get(t4, struct.pack(">i", 399)), b"v" * 399)
            self.assertEqual(len(list(tree.items(t4, struct.pack(">i", 10), struct.pack(">i", 20)))), 10)
            self.assertIsNone(tree.get(t7, b"\x00" * 20))
        finally:
            db.close()

    def test_tampered_page_or_wrong_key_fails_loudly(self) -> None:
        db = tg.CipherDatabase(self.fx.db, self.fx.key, self.fx.salt)
        pgno = min(set(range(2, db.pages)) - set(db.wal))  # a page only the main file holds
        db.close()
        broken = self.tmp / "broken.db"
        data = bytearray(self.fx.db.read_bytes())
        data[(pgno - 1) * PAGE + 100] ^= 1
        broken.write_bytes(bytes(data))
        for db in (tg.CipherDatabase(broken, self.fx.key, self.fx.salt),
                   tg.CipherDatabase(self.fx.db, os.urandom(32), self.fx.salt)):
            try:
                with self.assertRaises(tg.FormatError):
                    db.page(pgno)
            finally:
                db.close()

    def test_chats_and_identity(self) -> None:
        with self.session() as s:
            self.assertEqual(s.me(), ME)
            chats = s.chats()
            self.assertEqual((chats[ALICE].kind, chats[ALICE].title, chats[ALICE].username, chats[ALICE].phone),
                             ("user", "Alice Smith", "alice", "+100"))
            self.assertEqual((chats[BOT].kind, chats[NEWS].kind, chats[NEWS].title), ("bot", "channel", "News"))
            self.assertEqual(chats[BIG].telegram_id, BIG_ID)
            self.assertEqual(chats[NEWS].telegram_id, 1234)
            self.assertEqual(s.chat_ids_with_messages(), sorted([ALICE, BIG, BOT, NEWS]))

    def test_messages_links_attachments_and_read_state(self) -> None:
        with self.session() as s:
            msgs = {(m.namespace, m.id): m for m in s.messages(ALICE)}
            self.assertEqual(s.skipped, 1)
            self.assertEqual(sorted(msgs), [(0, 1), (0, 2), (0, 3), (0, 4), (0, 5), (0, 6), (0, 8), (1, 1)])
            self.assertEqual(msgs[(0, 2)].links, ("https://hidden.example/login", "evil.example/login?a=1"))
            self.assertEqual(msgs[(0, 5)].links, ("https://plain.example/x", "https://preview.example/a"))
            doc = msgs[(0, 3)].attachments[0]
            self.assertEqual((doc.kind, doc.file_name, doc.mime_type, doc.size), ("file", "invoice.pdf", "application/pdf", 2048))
            self.assertEqual(doc.local_path, self.fx.account / "postbox" / "media" / "telegram-cloud-document-4-99")
            self.assertEqual(len(msgs[(0, 6)].text), 20000)
            self.assertEqual((msgs[(0, 6)].forwarded_from, msgs[(0, 6)].thread_id), (NEWS, 77))
            self.assertEqual(msgs[(0, 8)].text, "fresh from the log")
            self.assertEqual([msgs[(0, i)].unread for i in (1, 4, 5, 6, 8)], [False, False, False, True, True])
            self.assertIsNone(msgs[(1, 1)].unread)
            self.assertFalse(msgs[(0, 4)].incoming)
            self.assertEqual(msgs[(0, 1)].date, datetime.fromtimestamp(T0 + 1, timezone.utc))
            bot = next(s.messages(BOT))
            self.assertEqual(bot.links, ("https://button.example",))

    def test_messages_across_chats_by_date(self) -> None:
        with self.session() as s:
            newest = list(s.messages(newest_first=True, limit=3))
            self.assertEqual([(m.chat_id, m.id) for m in newest], [(BIG, 1), (ALICE, 8), (NEWS, 2599)])
            since = datetime.fromtimestamp(T0 + 2595, timezone.utc)
            recent = [(m.chat_id, m.id) for m in s.messages(since=since)]
            self.assertEqual(recent, [(NEWS, 2595), (NEWS, 2596), (NEWS, 2597), (NEWS, 2598), (NEWS, 2599),
                                      (ALICE, 8), (BIG, 1)])
            until = datetime.fromtimestamp(T0 + 3, timezone.utc)
            self.assertEqual([m.id for m in s.messages(ALICE, until=until)], [1, 2])

    def test_discovery_without_fixed_paths(self) -> None:
        (self.fx.home / "Library" / "Group Containers" / "ABCDE.com.example.other").mkdir()
        (self.fx.home / "Library" / "Application Support" / "Telegram Desktop").mkdir(parents=True)
        with mock.patch.dict(os.environ, {"HOME": str(self.fx.home)}), \
                mock.patch.object(tg, "find_apps", return_value=[]):
            inst = tg.discover()
        self.assertEqual([a.path for a in inst.accounts], [self.fx.account])
        self.assertEqual(inst.accounts[0].record_id, "12345")
        self.assertTrue(any("Telegram Desktop" in n for n in inst.notes))

    def test_permission_prompt_never_hangs(self) -> None:
        release = threading.Event()

        def blocked(_path: object) -> List[str]:
            release.wait(5)
            return []

        folder = self.tmp / "prompted"
        folder.mkdir()
        try:
            with mock.patch("os.listdir", side_effect=blocked):
                started = time.monotonic()
                with self.assertRaises(tg.AccessPending):
                    tg.ensure_access(folder, timeout=0.3)
                self.assertLess(time.monotonic() - started, 2)
        finally:
            release.set()


if __name__ == "__main__":
    unittest.main()
