#!/usr/bin/env python3
"""Read Telegram for macOS chats and messages on this Mac: read-only, in memory, standard library only.

What it reads
  Telegram for macOS (the native app, bundle ru.keepcoder.Telegram, from the App Store or the
  website) keeps every logged-in account in a "Postbox": a SQLCipher 4 database holding Telegram's
  own binary records. This module finds that data without fixed paths (the app's signed
  entitlements name its group container, and a structural scan of Telegram-named containers is the
  fallback), decrypts the database key, and decodes chats and messages: text, every link (visible,
  hidden behind text, in link previews, in bot buttons), attachments with the path of the copy
  Telegram already downloaded, and whether an incoming message is still unread.
  Telegram Desktop (the separate Qt app) is detected but not read: it keeps no message history on disk.

How
  * `.tempkeyEncrypted` holds the database key, AES-encrypted with the local passcode, or with a
    fixed default when none is set. A MurmurHash3 checksum inside confirms the decryption.
  * Database pages are decrypted one at a time with macOS CommonCrypto (via ctypes), each checked
    against its HMAC. Committed frames of the write-ahead log are applied on top, so messages that
    arrived seconds ago are included while Telegram keeps running.
  * A small SQLite b-tree reader seeks and scans the tables. Messages use a fixed binary layout,
    everything else Telegram's key-value object encoding, whose type tags are MurmurHash3 hashes of
    the Swift class names, so types are recognised by name rather than by magic numbers.

Guarantees
  Nothing is written anywhere: files are opened read-only, decrypted data lives only in this
  process's memory, and Telegram keeps working undisturbed. A structural surprise raises
  FormatError instead of returning wrong data. A single message that cannot be decoded is skipped
  and counted in `Session.skipped`, so one odd record never hides the rest.

Permissions
  Since macOS 15, reading another app's data asks "... would like to access data from other apps"
  for the app running this code. Terminal asks again for every new process, so unattended runs need
  Full Disk Access for the app that starts them. While the prompt is open, file reads block: the
  first access runs on a worker thread and gives up with AccessPending after a timeout.

Diagnostics: python3 telegram.py [accounts | chats | messages] --help
"""

from __future__ import annotations

import argparse
import ctypes
import getpass
import hashlib
import heapq
import hmac
import json
import os
import plistlib
import re
import struct
import subprocess
import sys
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Sequence, Set, Tuple, Union

# --------------------------------------------------------------------------------------------
# Errors and guarded file access
# --------------------------------------------------------------------------------------------


class TelegramError(Exception):
    """Base class: every failure of this module is one of these, with a message meant for people."""


class AccessDenied(TelegramError):
    """macOS privacy protection refused to let this process read Telegram's data."""


class AccessPending(AccessDenied):
    """macOS is showing its privacy prompt and nobody answered it in time."""


class PasscodeRequired(TelegramError):
    """Telegram is locked with a local passcode, which is needed to decrypt the database key."""


class FormatError(TelegramError):
    """The files are not in the layout this module understands, or are damaged."""


ACCESS_TIMEOUT = 15.0
_granted: Set[str] = set()


def denied_message(path: Path) -> str:
    return (f"macOS did not allow reading {path}. Allow your terminal under System Settings > "
            "Privacy & Security > App Data, or give it Full Disk Access, then try again.")


def ensure_access(folder: Path, timeout: float = ACCESS_TIMEOUT) -> None:
    """Touch a protected folder from a worker thread before reading it.

    While macOS shows its privacy prompt, the first read blocks until someone answers. A
    scheduled run must never hang on that, so we wait at most `timeout` seconds. Once allowed,
    the whole process may read, so each folder is checked only once.
    """
    if str(folder) in _granted:
        return
    errors: List[BaseException] = []
    done = threading.Event()

    def probe() -> None:
        try:
            os.listdir(folder)
        except BaseException as e:  # reported to the caller below
            errors.append(e)
        finally:
            done.set()

    threading.Thread(target=probe, name="telegram-access", daemon=True).start()
    if not done.wait(timeout):
        raise AccessPending(f"macOS is asking whether this app may read {folder} (\"... would like to access "
                            "data from other apps\"). Allow it, or give the app Full Disk Access so it stops "
                            "asking, then try again.")
    if errors:
        if isinstance(errors[0], PermissionError):
            raise AccessDenied(denied_message(folder)) from errors[0]
        raise TelegramError(f"cannot read {folder}: {errors[0]}") from errors[0]
    _granted.add(str(folder))


def read_bytes(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except PermissionError as e:
        raise AccessDenied(denied_message(path)) from e
    except FileNotFoundError as e:
        raise FormatError(f"{path} does not exist") from e


# --------------------------------------------------------------------------------------------
# Crypto: AES from macOS CommonCrypto (the standard library has none), Telegram's key file
# --------------------------------------------------------------------------------------------

DEFAULT_PASSCODE = b"no-matter-key"  # Telegram's key-file password when no local passcode is set
HASH_SEED = -137723950  # Telegram's MurmurHash3 seed: key-file checksum and object type tags

_commoncrypto: Optional[ctypes.CDLL] = None


def aes_cbc(key: bytes, iv: bytes, data: bytes, encrypt: bool = False) -> bytes:
    """AES-CBC without padding through CommonCrypto's CCCrypt, which every macOS ships."""
    global _commoncrypto
    if _commoncrypto is None:
        _commoncrypto = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
        _commoncrypto.CCCrypt.restype = ctypes.c_int32
    if len(data) % 16 or len(key) not in (16, 24, 32) or len(iv) != 16:
        raise FormatError("bad AES input sizes")
    out = ctypes.create_string_buffer(len(data))
    moved = ctypes.c_size_t(0)
    rc = _commoncrypto.CCCrypt(ctypes.c_uint32(0 if encrypt else 1), ctypes.c_uint32(0), ctypes.c_uint32(0),
                               key, ctypes.c_size_t(len(key)), iv, data, ctypes.c_size_t(len(data)),
                               out, ctypes.c_size_t(len(data)), ctypes.byref(moved))
    if rc != 0 or moved.value != len(data):
        raise TelegramError(f"CommonCrypto failed with status {rc}")
    return out.raw


def murmur3_32(data: bytes, seed: int = HASH_SEED) -> int:
    c1, c2, h = 0xCC9E2D51, 0x1B873593, seed & 0xFFFFFFFF

    def mix(k: int) -> int:
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        return (k * c2) & 0xFFFFFFFF

    blocks = len(data) // 4
    for (k,) in struct.iter_unpack("<I", data[:blocks * 4]):
        h ^= mix(k)
        h = ((h << 13) | (h >> 19)) & 0xFFFFFFFF
        h = (h * 5 + 0xE6546B64) & 0xFFFFFFFF
    tail = data[blocks * 4:]
    if tail:
        h ^= mix(int.from_bytes(tail, "little"))
    h ^= len(data)
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & 0xFFFFFFFF
    return h ^ (h >> 16)


def database_key(key_file: Path, passcode: Optional[str] = None) -> Tuple[bytes, bytes]:
    """Decrypt `.tempkeyEncrypted` into the SQLCipher key and salt that all accounts share."""
    data = read_bytes(key_file)
    if len(data) < 64 or len(data) % 16:
        raise FormatError(f"{key_file} is not a Telegram key file")
    digest = hashlib.sha512(DEFAULT_PASSCODE if passcode is None else passcode.encode()).digest()
    plain = aes_cbc(digest[:32], digest[-16:], data)
    key, salt = plain[:32], plain[32:48]
    if murmur3_32(key + salt) == struct.unpack_from("<I", plain, 48)[0]:
        return key, salt
    if passcode is None:
        raise PasscodeRequired("Telegram is locked with a local passcode; it is needed to read the data")
    raise PasscodeRequired("the Telegram passcode is wrong")


# --------------------------------------------------------------------------------------------
# Encrypted SQLite: SQLCipher 4 pages plus the WAL, decrypted on demand, never written anywhere
# --------------------------------------------------------------------------------------------

SQLITE_MAGIC = b"SQLite format 3\x00"
WAL_MAGIC = (0x377F0682, 0x377F0683)  # checksums over little- or big-endian words
PLAIN_HEADER = 32  # Telegram leaves the first 32 bytes of page 1 unencrypted
PAGE_CACHE = 8192


def hmac_key(key: bytes, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha512", key, bytes(b ^ 0x3A for b in salt), 2, 32)


def page_mac(mac_key: bytes, cipher: bytes, iv: bytes, pgno: int) -> bytes:
    return hmac.new(mac_key, cipher + iv + struct.pack("<I", pgno), hashlib.sha512).digest()


def wal_checksum(data: bytes, s0: int, s1: int, big: bool) -> Tuple[int, int]:
    words = struct.unpack(f"{'>' if big else '<'}{len(data) // 4}I", data)
    for i in range(0, len(words), 2):
        s0 = (s0 + words[i] + s1) & 0xFFFFFFFF
        s1 = (s1 + words[i + 1] + s0) & 0xFFFFFFFF
    return s0, s1


class CipherDatabase:
    """A SQLCipher 4 database that Telegram may be writing while we read it.

    The committed part of the write-ahead log is read into memory first and takes precedence over
    the main file, the same view SQLite itself would give. Every page must pass its HMAC, so a
    wrong key, a page torn by a concurrent write (retried), or a damaged file fails loudly.
    """

    def __init__(self, path: Path, key: bytes, salt: bytes) -> None:
        self.path, self.key, self.mac_key = path, key, hmac_key(key, salt)
        try:
            self.file = path.open("rb")
        except PermissionError as e:
            raise AccessDenied(denied_message(path)) from e
        except FileNotFoundError as e:
            raise FormatError(f"{path} does not exist") from e
        head = self.file.read(PLAIN_HEADER)
        if len(head) < PLAIN_HEADER or not head.startswith(SQLITE_MAGIC):
            self.file.close()
            raise FormatError(f"{path} has no plaintext SQLite header; this Telegram version is not supported")
        size = struct.unpack_from(">H", head, 16)[0]
        self.page_size = 65536 if size == 1 else size
        self.reserve = head[20]
        if self.reserve < 80 or self.page_size < 1024:
            self.file.close()
            raise FormatError(f"{path} is not a SQLCipher 4 database")
        self.usable = self.page_size - self.reserve
        # The header's page count can lag behind in old files; the file size cannot.
        self.pages = max(struct.unpack_from(">I", head, 28)[0], os.fstat(self.file.fileno()).st_size // self.page_size)
        self.wal: Dict[int, bytes] = {}
        self.cache: Dict[int, bytes] = {}
        self._load_wal(Path(f"{path}-wal"))

    def close(self) -> None:
        self.file.close()
        self.cache.clear()
        self.wal.clear()

    def _load_wal(self, path: Path) -> None:
        try:
            data = path.read_bytes()
        except FileNotFoundError:
            return
        except PermissionError as e:
            raise AccessDenied(denied_message(path)) from e
        if len(data) < 32:
            return
        magic, _version, page_size, _seq, salt1, salt2, c1, c2 = struct.unpack_from(">8I", data, 0)
        big = magic == WAL_MAGIC[1]
        if magic not in WAL_MAGIC or page_size != self.page_size or wal_checksum(data[:24], 0, 0, big) != (c1, c2):
            return  # no valid log: the main file alone is the current state
        s = (c1, c2)
        frame = 24 + self.page_size
        pending: Dict[int, bytes] = {}
        pos = 32
        while pos + frame <= len(data):
            pgno, commit, f1, f2, k1, k2 = struct.unpack_from(">6I", data, pos)
            if (f1, f2) != (salt1, salt2):
                break  # left over from an earlier generation of the log
            s = wal_checksum(data[pos + 24:pos + frame], *wal_checksum(data[pos:pos + 8], *s, big), big)
            if s != (k1, k2):
                break  # torn or never-finished write
            pending[pgno] = data[pos + 24:pos + frame]
            if commit:
                self.wal.update(pending)
                pending.clear()
                self.pages = commit
            pos += frame

    def page(self, pgno: int) -> bytes:
        """Decrypted usable part of a page, verified with its HMAC."""
        cached = self.cache.get(pgno)
        if cached is not None:
            return cached
        if not 0 < pgno <= self.pages:
            raise FormatError(f"page {pgno} is outside {self.path.name}")
        for _ in range(3):
            raw = self.wal.get(pgno)
            if raw is None:
                self.file.seek((pgno - 1) * self.page_size)
                raw = self.file.read(self.page_size)
            plain = self._decrypt(pgno, raw)
            if plain is not None:
                if len(self.cache) >= PAGE_CACHE:
                    self.cache.clear()
                self.cache[pgno] = plain
                return plain
            if pgno in self.wal:
                break  # in-memory copy: retrying cannot help
        raise FormatError(f"page {pgno} of {self.path.name} failed its integrity check (wrong key or damaged file)")

    def _decrypt(self, pgno: int, raw: bytes) -> Optional[bytes]:
        if len(raw) != self.page_size:
            return None
        start = PLAIN_HEADER if pgno == 1 else 0
        cipher, iv = raw[start:self.usable], raw[self.usable:self.usable + 16]
        if not hmac.compare_digest(page_mac(self.mac_key, cipher, iv, pgno), raw[self.usable + 16:self.usable + 80]):
            return None
        return raw[:start] + aes_cbc(self.key, iv, cipher)


# --------------------------------------------------------------------------------------------
# SQLite b-trees: just enough of the file format to seek and scan Telegram's key-value tables
# --------------------------------------------------------------------------------------------

Value = Union[None, int, float, bytes, str]


def varint(buf: bytes, pos: int) -> Tuple[int, int]:
    result = 0
    for i in range(8):
        b = buf[pos + i]
        result = (result << 7) | (b & 0x7F)
        if b < 0x80:
            return result, pos + i + 1
    return (result << 8) | buf[pos + 8], pos + 9


def decode_record(payload: bytes) -> List[Value]:
    header_size, pos = varint(payload, 0)
    types: List[int] = []
    while pos < header_size:
        t, pos = varint(payload, pos)
        types.append(t)
    out: List[Value] = []
    pos = header_size
    for t in types:
        if t == 0:
            out.append(None)
        elif 1 <= t <= 6:
            n = (1, 2, 3, 4, 6, 8)[t - 1]
            out.append(int.from_bytes(payload[pos:pos + n], "big", signed=True))
            pos += n
        elif t == 7:
            out.append(struct.unpack_from(">d", payload, pos)[0])
            pos += 8
        elif t in (8, 9):
            out.append(t - 8)
        elif t >= 12:
            n = (t - 12) // 2
            chunk = payload[pos:pos + n]
            out.append(chunk if t % 2 == 0 else chunk.decode("utf-8", "replace"))
            pos += n
        else:
            raise FormatError(f"reserved SQLite serial type {t}")
    if pos != len(payload):
        raise FormatError("SQLite record has trailing bytes")
    return out


@dataclass(frozen=True)
class Table:
    name: str
    root: int
    layout: str  # "rowid" (INTEGER key), "index" (WITHOUT ROWID), or "autoindex" (BLOB key + rowid)
    index_root: int = 0


class BTree:
    """Read-only access to the three table layouts Telegram's Postbox creates."""

    def __init__(self, db: CipherDatabase) -> None:
        self.db = db
        u = db.usable
        self.max_local_table = u - 35
        self.max_local_index = (u - 12) * 64 // 255 - 23
        self.min_local = (u - 12) * 32 // 255 - 23
        self.tables: Dict[str, Table] = {}
        roots: Dict[str, Tuple[str, int, str]] = {}
        for _rowid, row in self.rows(1):
            if len(row) >= 5 and isinstance(row[1], str) and isinstance(row[3], int):
                roots[row[1]] = (str(row[0]), row[3], str(row[4] or ""))
        for name, (kind, root, sql) in roots.items():
            if kind != "table":
                continue
            if "WITHOUT ROWID" in sql.upper():
                self.tables[name] = Table(name, root, "index")
            elif re.search(r"\bkey\s+INTEGER\s+PRIMARY\s+KEY", sql, re.I):
                self.tables[name] = Table(name, root, "rowid")
            elif f"sqlite_autoindex_{name}_1" in roots:
                self.tables[name] = Table(name, root, "autoindex", roots[f"sqlite_autoindex_{name}_1"][1])

    def table(self, name: str) -> Table:
        t = self.tables.get(name)
        if t is None:
            raise FormatError(f"table {name} is missing from {self.db.path.name}")
        return t

    # -- raw pages and payloads

    def _page(self, pgno: int) -> Tuple[int, bytes, int, List[int]]:
        page = self.db.page(pgno)
        h = 100 if pgno == 1 else 0
        kind = page[h]
        if kind not in (2, 5, 10, 13):
            raise FormatError(f"page {pgno} is not a b-tree page")
        count = struct.unpack_from(">H", page, h + 3)[0]
        interior = kind in (2, 5)
        right = struct.unpack_from(">I", page, h + 8)[0] if interior else 0
        start = h + (12 if interior else 8)
        return kind, page, right, list(struct.unpack_from(f">{count}H", page, start))

    def _payload(self, page: bytes, pos: int, size: int, max_local: int) -> bytes:
        if size <= max_local:
            return page[pos:pos + size]
        u = self.db.usable
        local = self.min_local + (size - self.min_local) % (u - 4)
        if local > max_local:
            local = self.min_local
        parts = [page[pos:pos + local]]
        left = size - local
        nxt = struct.unpack_from(">I", page, pos + local)[0]
        hops = 0
        while left > 0 and nxt:
            hops += 1
            if hops > self.db.pages:
                raise FormatError("overflow chain loops")
            data = self.db.page(nxt)
            parts.append(data[4:4 + min(left, u - 4)])
            left -= u - 4
            nxt = struct.unpack_from(">I", data, 0)[0]
        if left > 0:
            raise FormatError("overflow chain ends early")
        return b"".join(parts)

    def _index_entries(self, page: bytes, ptrs: List[int], interior: bool) -> List[Tuple[int, List[Value]]]:
        out = []
        for p in ptrs:
            child = struct.unpack_from(">I", page, p)[0] if interior else 0
            size, pos = varint(page, p + 4 if interior else p)
            out.append((child, decode_record(self._payload(page, pos, size, self.max_local_index))))
        return out

    # -- rowid tables

    def rows(self, root: int) -> Iterator[Tuple[int, List[Value]]]:
        """Every row of a rowid table, in rowid order."""
        stack, depth = [root], 0
        while stack:
            depth += 1
            if depth > self.db.pages + 1:
                raise FormatError("b-tree loops")
            kind, page, right, ptrs = self._page(stack.pop())
            if kind == 5:
                stack.extend(reversed([struct.unpack_from(">I", page, p)[0] for p in ptrs] + [right]))
            elif kind == 13:
                for p in ptrs:
                    size, pos = varint(page, p)
                    rowid, pos = varint(page, pos)
                    yield rowid, decode_record(self._payload(page, pos, size, self.max_local_table))
            else:
                raise FormatError(f"index page inside table rooted at {root}")

    def row(self, root: int, rowid: int) -> Optional[List[Value]]:
        pgno = root
        for _ in range(64):
            kind, page, right, ptrs = self._page(pgno)
            if kind == 13:
                for p in ptrs:
                    size, pos = varint(page, p)
                    rid, pos = varint(page, pos)
                    if rid == rowid:
                        return decode_record(self._payload(page, pos, size, self.max_local_table))
                return None
            if kind != 5:
                raise FormatError(f"index page inside table rooted at {root}")
            pgno = right
            for p in ptrs:
                if rowid <= varint(page, p + 4)[0]:
                    pgno = struct.unpack_from(">I", page, p)[0]
                    break
        raise FormatError("b-tree too deep")

    # -- index b-trees (WITHOUT ROWID tables and automatic indexes), ordered by a BLOB key

    def entries(self, root: int, lower: Optional[bytes] = None, upper: Optional[bytes] = None,
                reverse: bool = False) -> Iterator[List[Value]]:
        """Records whose first column (a BLOB) is in [lower, upper), in key order, seeking past the rest."""
        yield from self._walk(root, lower, upper, reverse, 0)

    def _walk(self, pgno: int, lower: Optional[bytes], upper: Optional[bytes], reverse: bool,
              depth: int) -> Iterator[List[Value]]:
        if depth > 64:
            raise FormatError("b-tree too deep")
        kind, page, right, ptrs = self._page(pgno)
        if kind not in (2, 10):
            raise FormatError(f"table page inside index rooted near page {pgno}")
        entries = self._index_entries(page, ptrs, kind == 2)
        if kind == 10:
            for _child, rec in (reversed(entries) if reverse else entries):
                if _in_range(rec, lower, upper):
                    yield rec
            return
        # Interior page: child i holds keys below separator i; the separator is a record itself.
        parts: List[Tuple[int, Optional[List[Value]]]] = [(c, r) for c, r in entries] + [(right, None)]
        visit: List[Tuple[int, Optional[List[Value]]]] = []
        prev: Optional[bytes] = None
        for child, sep in parts:
            key = sep[0] if sep else None
            sep_key = key if isinstance(key, bytes) else None
            below = lower is not None and sep_key is not None and sep_key < lower
            above = upper is not None and prev is not None and prev >= upper
            if not below and not above:
                visit.append((child, sep))
            if sep_key is not None:
                prev = sep_key
        for child, sep in (reversed(visit) if reverse else visit):
            if reverse and sep is not None and _in_range(sep, lower, upper):
                yield sep
            yield from self._walk(child, lower, upper, reverse, depth + 1)
            if not reverse and sep is not None and _in_range(sep, lower, upper):
                yield sep

    # -- one interface for all three layouts: (key, value) pairs

    def items(self, t: Table, lower: Optional[bytes] = None, upper: Optional[bytes] = None,
              reverse: bool = False) -> Iterator[Tuple[Union[int, bytes], bytes]]:
        if t.layout == "rowid":
            if lower is not None or upper is not None or reverse:
                raise TelegramError("range reads need a BLOB-keyed table")
            for rowid, rec in self.rows(t.root):
                if len(rec) >= 2 and isinstance(rec[1], bytes):
                    yield rowid, rec[1]
        elif t.layout == "index":
            for rec in self.entries(t.root, lower, upper, reverse):
                if len(rec) >= 2 and isinstance(rec[0], bytes) and isinstance(rec[1], bytes):
                    yield rec[0], rec[1]
        else:
            for rec in self.entries(t.index_root, lower, upper, reverse):
                if len(rec) >= 2 and isinstance(rec[0], bytes) and isinstance(rec[-1], int):
                    row = self.row(t.root, rec[-1])
                    if row is not None and len(row) >= 2 and isinstance(row[1], bytes):
                        yield rec[0], row[1]

    def get(self, t: Table, key: Union[int, bytes]) -> Optional[bytes]:
        if t.layout == "rowid":
            if not isinstance(key, int):
                raise TelegramError(f"{t.name} has integer keys")
            rec = self.row(t.root, key)
            return rec[1] if rec is not None and len(rec) >= 2 and isinstance(rec[1], bytes) else None
        if not isinstance(key, bytes):
            raise TelegramError(f"{t.name} has binary keys")
        for k, value in self.items(t, key, key + b"\x00"):
            if k == key:
                return value
        return None


def _in_range(rec: List[Value], lower: Optional[bytes], upper: Optional[bytes]) -> bool:
    key = rec[0] if rec else None
    return isinstance(key, bytes) and (lower is None or key >= lower) and (upper is None or key < upper)


# --------------------------------------------------------------------------------------------
# Postbox objects: Telegram's key-value encoding, with type tags named after Swift classes
# --------------------------------------------------------------------------------------------

# Only used to name type tags in results and errors; unknown tags still decode. The message
# attributes and media come from Telegram's declareEncodable lists (AccountManager.swift).
KNOWN_TYPES = (
    "TelegramUser", "TelegramGroup", "TelegramChannel", "TelegramSecretChat",
    "TelegramMediaFile", "TelegramMediaImage", "TelegramMediaWebpage", "TelegramMediaAction",
    "TelegramMediaContact", "TelegramMediaMap", "TelegramMediaPoll", "TelegramMediaGame",
    "TelegramMediaInvoice", "TelegramMediaDice", "TelegramMediaStory", "TelegramMediaUnsupported",
    "TelegramMediaExpiredContent", "TelegramMediaGiveaway", "TelegramMediaPaidContent",
    "TelegramMediaImageRepresentation", "TelegramMediaFileAttribute", "TelegramMediaWebpageLoadedContent",
    "CloudDocumentMediaResource", "CloudPhotoSizeMediaResource", "CloudFileMediaResource",
    "LocalFileMediaResource", "CloudDocumentSizeMediaResource",
    "TextEntitiesMessageAttribute", "MessageTextEntity", "ReplyMessageAttribute",
    "ReplyMarkupMessageAttribute", "ReplyMarkupRow", "ReplyMarkupButton", "ForwardSourceInfoAttribute",
    "SourceReferenceMessageAttribute", "ViewCountMessageAttribute", "EditedMessageAttribute",
    "AuthorSignatureMessageAttribute", "InlineBotMessageAttribute", "AutoremoveTimeoutMessageAttribute",
    "AutoclearTimeoutMessageAttribute", "ConsumableContentMessageAttribute", "ReactionsMessageAttribute",
    "OutgoingMessageInfoAttribute", "WebpagePreviewMessageAttribute", "AuthorizedAccountState",
    "TelegramMediaGiveawayResults", "TelegramMediaLiveStream", "TelegramMediaTodo", "TelegramMediaWebFile",
    "AudioTranscriptionMessageAttribute", "AuthSessionInfoAttribute", "BoostCountMessageAttribute",
    "ChannelMessageStateVersionAttribute", "ConsumablePersonalMentionMessageAttribute",
    "ContentRequiresValidationMessageAttribute", "DerivedDataMessageAttribute", "EffectMessageAttribute",
    "EmbeddedMediaStickersMessageAttribute", "EmojiSearchQueryMessageAttribute",
    "EphemeralMessageAttribute", "EphemeralOutgoingMessageAttribute",
    "EphemeralReplacementMessageAttribute", "FactCheckMessageAttribute", "ForwardCountMessageAttribute",
    "ForwardOptionsMessageAttribute", "ForwardVideoTimestampAttribute", "GuestChatMessageAttribute",
    "InlineBusinessBotMessageAttribute", "InvertMediaMessageAttribute", "MediaSpoilerMessageAttribute",
    "NonPremiumMessageAttribute", "NotificationInfoMessageAttribute",
    "OutgoingChatContextResultMessageAttribute", "OutgoingContentInfoMessageAttribute",
    "OutgoingQuickReplyMessageAttribute", "OutgoingScheduleInfoMessageAttribute",
    "PaidStarsMessageAttribute", "ParticipantRankMessageAttribute", "PeerGroupMessageStateVersionAttribute",
    "PendingProcessingMessageAttribute", "PendingReactionsMessageAttribute",
    "PendingStarsReactionsMessageAttribute", "PendingWalletTransferMessageAttribute",
    "PublishedSuggestedPostMessageAttribute", "QuotedReplyMessageAttribute", "ReplyStoryAttribute",
    "ReplyThreadMessageAttribute", "ReportDeliveryMessageAttribute", "RestrictedContentMessageAttribute",
    "RichTextMessageAttribute", "ScheduledRepeatAttribute", "SendAsMessageAttribute",
    "SourceAuthorInfoMessageAttribute", "SuggestedPostMessageAttribute", "SummarizationMessageAttribute",
    "TelegramMediaWebpageAttribute", "TranslationMessageAttribute", "ValidationMessageAttribute",
)
TYPE_NAMES = {murmur3_32(name.encode()): name for name in KNOWN_TYPES}


@dataclass
class Obj:
    """One decoded Postbox object: its class name (or #hash) and its fields by key."""

    type: str
    fields: Dict[str, Field] = field(default_factory=dict)

    def string(self, key: str) -> Optional[str]:
        v = self.fields.get(key)
        return v if isinstance(v, str) else None

    def integer(self, key: str) -> Optional[int]:
        v = self.fields.get(key)
        return v if isinstance(v, int) and not isinstance(v, bool) else None

    def blob(self, key: str) -> Optional[bytes]:
        v = self.fields.get(key)
        return v if isinstance(v, bytes) else None

    def child(self, key: str) -> Optional[Obj]:
        v = self.fields.get(key)
        return v if isinstance(v, Obj) else None

    def children(self, key: str) -> List[Obj]:
        v = self.fields.get(key)
        return [x for x in v if isinstance(x, Obj)] if isinstance(v, list) else []

    def walk(self) -> Iterator[Union[str, Obj]]:
        """This object, nested objects, and every string anywhere inside."""
        yield self
        for v in self.fields.values():
            yield from _walk_field(v)


Field = Union[None, bool, int, float, str, bytes, Obj, List[int], List[str], List[bytes], List[Obj],
              List[Tuple[Obj, Obj]]]


def _walk_field(v: Field) -> Iterator[Union[str, Obj]]:
    if isinstance(v, str):
        yield v
    elif isinstance(v, Obj):
        yield from v.walk()
    elif isinstance(v, list):
        for item in v:
            if isinstance(item, tuple):
                for o in item:
                    yield from o.walk()
            elif isinstance(item, (str, Obj)):
                yield from _walk_field(item)


class Reader:
    """Bounds-checked little-endian reader over one record."""

    def __init__(self, buf: bytes, pos: int = 0, end: Optional[int] = None) -> None:
        self.buf, self.pos = buf, pos
        self.end = len(buf) if end is None else end

    def take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > self.end:
            raise FormatError(f"record ends early (wanted {n} bytes at {self.pos} of {self.end})")
        out = self.buf[self.pos:self.pos + n]
        self.pos += n
        return out

    def u8(self) -> int:
        return self.take(1)[0]

    def i32(self) -> int:
        v: int = struct.unpack("<i", self.take(4))[0]
        return v

    def u32(self) -> int:
        v: int = struct.unpack("<I", self.take(4))[0]
        return v

    def i64(self) -> int:
        v: int = struct.unpack("<q", self.take(8))[0]
        return v

    def blob(self) -> bytes:
        return self.take(self.i32())

    def text(self) -> str:
        return self.blob().decode("utf-8", "replace")

    def count(self) -> int:
        n = self.i32()
        if not 0 <= n <= self.end - self.pos:
            raise FormatError(f"implausible element count {n}")
        return n

    def done(self) -> bool:
        return self.pos >= self.end


def decode_object(buf: bytes, type_hash: int) -> Obj:
    o = Obj(TYPE_NAMES.get(type_hash, f"#{type_hash:08x}"))
    r = Reader(buf)
    while not r.done():
        key = r.take(r.u8()).decode("utf-8", "replace")
        value = _decode_value(r, r.u8())
        o.fields.setdefault(key, value)  # a few classes repeat a key; the first is the documented one
    return o


def _nested(r: Reader) -> Obj:
    type_hash = r.u32()
    return decode_object(r.blob(), type_hash)


def _decode_value(r: Reader, kind: int) -> Field:
    if kind == 0:
        return r.i32()
    if kind == 1:
        return r.i64()
    if kind == 2:
        return r.u8() != 0
    if kind == 3:
        v: float = struct.unpack("<d", r.take(8))[0]
        return v
    if kind == 4:
        return r.text()
    if kind == 5:
        return _nested(r)
    if kind == 6:
        n = r.count()
        return list(struct.unpack(f"<{n}i", r.take(4 * n)))
    if kind == 7:
        n = r.count()
        return list(struct.unpack(f"<{n}q", r.take(8 * n)))
    if kind == 8:
        return [_nested(r) for _ in range(r.count())]
    if kind == 9:
        return [(_nested(r), _nested(r)) for _ in range(r.count())]
    if kind == 10:
        return r.blob()
    if kind == 11:
        return None
    if kind == 12:
        return [r.text() for _ in range(r.count())]
    if kind == 13:
        return [r.blob() for _ in range(r.count())]
    raise FormatError(f"unknown Postbox value type {kind}")


def decode_root(buf: bytes) -> Obj:
    """A stored object: a single field "_" holding the object, as PostboxEncoder writes it."""
    r = Reader(buf)
    if r.take(r.u8()) != b"_" or r.u8() != 5:
        raise FormatError("not a Postbox root object")
    o = _nested(r)
    if not r.done():
        raise FormatError("Postbox root object has trailing bytes")
    return o


# --------------------------------------------------------------------------------------------
# Telegram records: peers, messages, media, read state
# --------------------------------------------------------------------------------------------

# Postbox table numbers (Postbox.swift); checked against the schema when a session opens.
T_METADATA, T_PEERS, T_MEDIA, T_MESSAGES, T_READ_STATE = "t0", "t2", "t6", "t7", "t14"
T_TOPICS = "t73"  # forum topics with their own read state (MessageHistoryThreadIndexTable)
STATE_KEY = 2  # metadata entry with the logged-in account (AuthorizedAccountState)

INCOMING = 4  # MessageFlags
CHANNEL_FORUM = 1 << 11  # TelegramChannelFlags
UNSENT, FAILED = 1, 2
CLOUD_NAMESPACE = 0
URL_RE = re.compile(r"(?i)\b(?:https?|tg|ton)://[^\s<>\"'`​]+")
ENTITY_URL, ENTITY_TEXT_URL = 4, 10  # MessageTextEntity raw types


def peer_namespace(peer_id: int) -> int:
    return (peer_id >> 32) & 0x7


def telegram_id(peer_id: int) -> int:
    """The id Telegram's servers and apps use, unpacked from Postbox's 64-bit peer id."""
    return ((peer_id >> 35) << 32) | (peer_id & 0xFFFFFFFF)


@dataclass(frozen=True)
class Chat:
    id: int  # Postbox peer id: what messages refer to
    kind: str  # user, bot, group, channel, secret, or unknown
    title: str
    username: Optional[str] = None
    phone: Optional[str] = None
    forum: bool = False  # a group split into topics, each with its own read state

    @property
    def telegram_id(self) -> int:
        return telegram_id(self.id)


@dataclass(frozen=True)
class Attachment:
    kind: str  # file, photo, or the media class name for anything else
    file_name: Optional[str] = None
    mime_type: Optional[str] = None
    size: Optional[int] = None
    local_path: Optional[Path] = None  # Telegram's downloaded copy, when it is complete


@dataclass(frozen=True)
class Message:
    chat_id: int
    namespace: int
    id: int
    date: datetime
    incoming: bool
    author_id: Optional[int]
    text: str
    links: Tuple[str, ...]
    attachments: Tuple[Attachment, ...]
    unread: Optional[bool]  # None when the read state is unknown
    forwarded_from: Optional[int] = None
    thread_id: Optional[int] = None
    failed: bool = False


@dataclass
class RawMessage:
    """A message record as stored: what MessageHistoryTable writes, before any lookups."""

    chat_id: int
    namespace: int
    timestamp: int
    id: int
    flags: int = 0
    tags: int = 0
    thread_id: Optional[int] = None
    forward_author: Optional[int] = None
    author_id: Optional[int] = None
    text: str = ""
    attributes: List[Obj] = field(default_factory=list)
    embedded_media: List[Obj] = field(default_factory=list)
    media_ids: List[Tuple[int, int]] = field(default_factory=list)


MESSAGE_KEY = struct.Struct(">qiii")  # peer id, namespace, timestamp, id: big-endian so keys sort


def parse_message(key: bytes, value: bytes) -> Optional[RawMessage]:
    """Decode one MessageHistoryTable record; None for a history hole (not a message)."""
    if len(key) != MESSAGE_KEY.size:
        raise FormatError(f"message key has {len(key)} bytes")
    peer, namespace, timestamp, mid = MESSAGE_KEY.unpack(key)
    r = Reader(value)
    if r.u8() != 0:
        return None
    m = RawMessage(peer, namespace, timestamp, mid)
    r.take(8)  # stable id and version
    data_flags = r.u8()
    for bit, size in ((0, 8), (1, 4), (2, 8), (3, 4), (4, 4)):  # unique id, global tags, grouping, group, local tags
        if data_flags & (1 << bit):
            r.take(size)
    if data_flags & (1 << 5):
        m.thread_id = r.i64()
    if data_flags & ~0x3F:
        raise FormatError(f"unknown message data flags {data_flags:#x}")
    m.flags, m.tags = r.u32(), r.u32()
    forward = r.u8()
    if forward:
        m.forward_author = r.i64()
        r.take(4)  # date
        if forward & (1 << 1):
            r.take(8)  # source peer
        if forward & (1 << 2):
            r.take(16)  # source message id
        if forward & (1 << 3):
            r.blob()  # author signature
        if forward & (1 << 4):
            r.blob()  # public service announcement type
        if forward & (1 << 5):
            r.take(4)  # flags
        if forward & ~0x3F:
            raise FormatError(f"unknown forward flags {forward:#x}")
    if r.u8() == 1:
        m.author_id = r.i64()
    m.text = r.text()
    m.attributes = [decode_root(r.blob()) for _ in range(r.count())]
    m.embedded_media = [decode_root(r.blob()) for _ in range(r.count())]
    for _ in range(r.count()):
        m.media_ids.append((r.i32(), r.i64()))
    if not r.done():  # saved-message tags, absent from records written by older versions
        for _ in range(r.count()):
            r.blob()
    if not r.done():
        raise FormatError("message record has trailing bytes")
    return m


def chat_from_peer(peer_id: int, o: Obj) -> Chat:
    if o.type == "TelegramUser":
        name = " ".join(x for x in (o.string("fn"), o.string("ln")) if x) or "Deleted account"
        kind = "bot" if o.fields.get("bi") is not None else "user"
        return Chat(peer_id, kind, name, o.string("un"), o.string("p"))
    if o.type == "TelegramChannel":
        return Chat(peer_id, "channel", o.string("t") or "", o.string("un"),
                    forum=bool((o.integer("fl") or 0) & CHANNEL_FORUM))
    if o.type == "TelegramGroup":
        return Chat(peer_id, "group", o.string("t") or "")
    if o.type == "TelegramSecretChat":
        return Chat(peer_id, "secret", "")
    return Chat(peer_id, "unknown", "")


def links_in(text: str, attributes: Sequence[Obj], media: Sequence[Obj]) -> Tuple[str, ...]:
    """Every link a message carries: in the text, behind formatted text, in previews and buttons."""
    found: List[str] = [m.group(0) for m in URL_RE.finditer(text)]
    utf16 = text.encode("utf-16-le")
    for attr in attributes:
        for entity in attr.children("entities"):
            kind, start, end = entity.integer("_rawValue"), entity.integer("start"), entity.integer("end")
            if kind == ENTITY_TEXT_URL and entity.string("url"):
                found.append(entity.string("url") or "")
            elif kind == ENTITY_URL and start is not None and end is not None and 0 <= start < end:
                found.append(utf16[2 * start:2 * end].decode("utf-16-le", "replace"))
    for o in list(attributes) + list(media):
        found += [m.group(0) for s in o.walk() if isinstance(s, str) for m in URL_RE.finditer(s)]
    clean = [u.rstrip(".,;:!?)]}>'\"") for u in found]
    return tuple(dict.fromkeys(u for u in clean if u))


def resource_id(o: Obj) -> Optional[str]:
    """The name MediaBox gives a downloaded file in postbox/media."""
    if o.type == "CloudDocumentMediaResource":
        parts = (o.integer("d"), o.integer("f"))
        return None if None in parts else "telegram-cloud-document-%s-%s" % parts
    if o.type == "CloudPhotoSizeMediaResource":
        parts2 = (o.integer("d"), o.integer("i"), o.string("s"))
        return None if None in parts2 else "telegram-cloud-photo-size-%s-%s-%s" % parts2
    if o.type == "LocalFileMediaResource":
        return None if o.integer("f") is None else f"local-file-{o.integer('f')}"
    return None


def resource_path(media_dir: Path, resource: Optional[Obj]) -> Optional[Path]:
    name = resource_id(resource) if resource is not None else None
    if not name or "/" in name:
        return None
    path = media_dir / name
    return path if path.is_file() else None


def attachment_from_media(media_dir: Path, o: Obj) -> Optional[Attachment]:
    if o.type == "TelegramMediaFile":
        name = next((a.string("fn") for a in o.children("at") if a.string("fn")), None)
        size = o.integer("s64") if o.integer("s64") is not None else o.integer("s")
        return Attachment("file", name, o.string("mt"), size, resource_path(media_dir, o.child("r")))
    if o.type == "TelegramMediaImage":
        reps = o.children("r") or o.children("rs")
        best = max(reps, key=lambda rep: (rep.integer("dx") or 0) * (rep.integer("dy") or 0), default=None)
        return Attachment("photo", local_path=resource_path(media_dir, best.child("r") if best else None))
    if o.type in ("TelegramMediaWebpage", "TelegramMediaAction"):
        return None  # links are collected separately; service messages carry no content
    return Attachment(o.type.replace("TelegramMedia", "").lower() or "media")


@dataclass(frozen=True)
class ReadState:
    max_incoming_read_id: int
    max_incoming_read_date: Optional[int]  # set when reading is tracked by date, as in secret chats
    unread_count: int  # what Telegram shows; the read mark can lag behind it, as in channels only previewed

    def passed(self, timestamp: int, mid: int) -> bool:
        """Whether a message lies past the read mark."""
        if self.max_incoming_read_date is not None:
            return (timestamp, mid) > (self.max_incoming_read_date, self.max_incoming_read_id)
        return mid > self.max_incoming_read_id


def parse_read_states(value: bytes) -> Dict[int, ReadState]:
    """MessageHistoryReadStateTable: per namespace, how far incoming messages have been read."""
    r = Reader(value)
    out: Dict[int, ReadState] = {}
    for _ in range(r.count()):
        namespace, kind = r.i32(), r.u8()
        if kind == 0:  # by message id
            max_incoming = r.i32()
            r.take(8)  # max outgoing read id, max known id
            out[namespace] = ReadState(max_incoming, None, r.i32())
        else:  # by message index: date, peer, namespace, id
            date = r.i32()
            r.take(12)
            max_incoming = r.i32()
            r.take(20)  # max outgoing read index
            out[namespace] = ReadState(max_incoming, date, r.i32())
        r.take(4)  # flags
    if not r.done():
        raise FormatError("read state has trailing bytes")
    return out


def parse_topic(value: bytes) -> Optional[ReadState]:
    """MessageHistoryThreadIndexTable: a forum topic's read state, kept in its encoded thread data."""
    data = decode_object(value, 0).fields.get("d")
    if not isinstance(data, bytes) or not data:
        return None
    topic = decode_root(data)
    mark, count = topic.integer("maxIncomingReadId"), topic.integer("incomingUnreadCount")
    return None if mark is None or count is None else ReadState(mark, None, count)


# --------------------------------------------------------------------------------------------
# Finding Telegram on this Mac
# --------------------------------------------------------------------------------------------

MAC_BUNDLE = "ru.keepcoder.Telegram"  # Telegram for macOS; beta and alpha builds extend this id
DESKTOP_BUNDLES = ("org.telegram.desktop", "com.tdesktop.Telegram")  # Telegram Desktop (Qt)
NAME_HINT = re.compile(r"telegram|keepcoder", re.I)
ACCOUNT_DIR = re.compile(r"account-\d+")
SKIP_DIRS = {"postbox", "media", "Wallpapers", "logs", "temp", "trlottie-animations", "Caches", "cached"}


@dataclass(frozen=True)
class App:
    path: Path
    bundle_id: str
    version: str
    groups: Tuple[str, ...]  # application groups from its signed entitlements

    @property
    def readable(self) -> bool:
        return self.bundle_id.startswith(MAC_BUNDLE)


@dataclass(frozen=True)
class Account:
    path: Path  # the account-<record id> folder
    key_file: Path  # .tempkeyEncrypted shared by the accounts next to each other

    @property
    def database(self) -> Path:
        return self.path / "postbox" / "db" / "db_sqlite"

    @property
    def media(self) -> Path:
        return self.path / "postbox" / "media"

    @property
    def record_id(self) -> str:
        return self.path.name.split("-", 1)[1]

    def stat(self) -> Tuple[int, float]:
        """Bytes used by the database (with its log) and when it last changed."""
        size, modified = 0, 0.0
        for p in (self.database, Path(f"{self.database}-wal")):
            try:
                st = p.stat()
            except OSError:
                continue
            size += st.st_size
            modified = max(modified, st.st_mtime)
        return size, modified


@dataclass(frozen=True)
class Installation:
    apps: Tuple[App, ...]
    accounts: Tuple[Account, ...]
    notes: Tuple[str, ...]  # things found that cannot be read, in plain words


def _plist(data: bytes) -> Dict[str, object]:
    try:
        value = plistlib.loads(data)
    except Exception:
        return {}
    return value if isinstance(value, dict) else {}


def find_apps() -> List[App]:
    """Telegram app bundles: Spotlight first, then the usual Applications folders."""
    candidates: List[Path] = []
    query = " || ".join(f"kMDItemCFBundleIdentifier == '{b}*'" for b in (MAC_BUNDLE,) + DESKTOP_BUNDLES)
    try:
        out = subprocess.run(["mdfind", query], capture_output=True, text=True, timeout=10).stdout
        candidates += [Path(line) for line in out.splitlines() if line.endswith(".app")]
    except (OSError, subprocess.SubprocessError):
        pass  # Spotlight off or missing: the folder scan below still works
    for folder in (Path("/Applications"), Path.home() / "Applications"):
        try:
            candidates += [p for p in folder.iterdir() if p.suffix == ".app" and "telegram" in p.name.lower()]
        except OSError:
            pass
    apps: Dict[Path, App] = {}
    for path in candidates:
        try:
            info = _plist((path / "Contents" / "Info.plist").read_bytes())
        except OSError:
            continue
        bundle = info.get("CFBundleIdentifier")
        if not isinstance(bundle, str) or not bundle.startswith((MAC_BUNDLE,) + DESKTOP_BUNDLES):
            continue
        version = info.get("CFBundleShortVersionString")
        apps[path.resolve()] = App(path, bundle, version if isinstance(version, str) else "", _app_groups(path))
    return sorted(apps.values(), key=lambda a: str(a.path))


def _app_groups(app: Path) -> Tuple[str, ...]:
    """Application groups the app is signed for: its data lives in ~/Library/Group Containers/<group>."""
    for args in (["--entitlements", "-", "--xml"], ["--entitlements", ":-"]):
        try:
            p = subprocess.run(["codesign", "-d", *args, str(app)], capture_output=True, timeout=15)
        except (OSError, subprocess.SubprocessError):
            return ()
        groups = _plist(p.stdout).get("com.apple.security.application-groups")
        if isinstance(groups, list):
            return tuple(g for g in groups if isinstance(g, str))
    return ()


def find_accounts(folder: Path, depth: int = 3) -> List[Account]:
    """Account folders below `folder`: account-<id>/postbox/db/db_sqlite next to a .tempkeyEncrypted."""
    found: List[Account] = []
    try:
        children = sorted(p for p in folder.iterdir() if p.is_dir() and not p.is_symlink())
    except PermissionError as e:
        raise AccessDenied(denied_message(folder)) from e
    except (FileNotFoundError, NotADirectoryError):
        return found
    except OSError as e:  # never mistake a read error for "no account here"
        raise TelegramError(f"cannot read {folder}: {e}") from e
    key_file = folder / ".tempkeyEncrypted"
    for child in children:
        if ACCOUNT_DIR.fullmatch(child.name):
            if key_file.is_file() and (child / "postbox" / "db" / "db_sqlite").is_file():
                found.append(Account(child, key_file))
        elif depth > 0 and child.name not in SKIP_DIRS:
            found += find_accounts(child, depth - 1)
    return found


def discover(timeout: float = ACCESS_TIMEOUT) -> Installation:
    """Find every Telegram for macOS account on this Mac without assuming fixed paths."""
    apps = find_apps()
    library = Path.home() / "Library"
    # macOS may ask once per container, so look where the data must be first: each app's main group.
    primary = [app.groups[0] for app in apps if app.readable and app.groups]
    others = [g for app in apps if app.readable for g in app.groups[1:]]
    try:  # Telegram-named containers of builds that Spotlight missed, or whose app was deleted
        others += sorted(p.name for p in (library / "Group Containers").iterdir() if NAME_HINT.search(p.name))
    except OSError:
        pass
    accounts: List[Account] = []
    scanned: Set[str] = set()
    for group in list(dict.fromkeys(primary)) + [None] + list(dict.fromkeys(others)):
        if group is None:
            if accounts:
                break  # found where expected: leave extension containers alone
            continue
        container = library / "Group Containers" / group
        if group not in scanned and container.is_dir():
            scanned.add(group)
            ensure_access(container, timeout)
            accounts += find_accounts(container)
    notes: List[str] = []
    desktop = [a for a in apps if not a.readable]
    desktop_data = (library / "Application Support" / "Telegram Desktop").is_dir()
    try:
        desktop_data = desktop_data or any(p.name.startswith(DESKTOP_BUNDLES) for p in (library / "Containers").iterdir())
    except OSError:
        pass
    if desktop or desktop_data:
        notes.append("Telegram Desktop is installed or left data here. It keeps message history on Telegram's "
                     "servers, not on this Mac, so it cannot be read; Telegram for macOS can.")
    if not accounts and not any(a.readable for a in apps):
        notes.append("Telegram for macOS is not installed.")
    elif not accounts:
        notes.append("Telegram for macOS is installed but no logged-in account was found.")
    return Installation(tuple(apps), tuple(dict.fromkeys(accounts)), tuple(notes))


# --------------------------------------------------------------------------------------------
# Reading an account
# --------------------------------------------------------------------------------------------


class Session:
    """One account opened read-only. Use as a context manager, or call close()."""

    def __init__(self, account: Account, passcode: Optional[str] = None) -> None:
        self.account = account
        ensure_access(account.path.parent)
        key, salt = database_key(account.key_file, passcode)
        self.db = CipherDatabase(account.database, key, salt)
        try:
            self.tree = BTree(self.db)
            self.peers = self.tree.table(T_PEERS)
            self.messages_table = self.tree.table(T_MESSAGES)
            self.media_table = self.tree.tables.get(T_MEDIA)
            self.read_table = self.tree.tables.get(T_READ_STATE)
            self.topics_table = self.tree.tables.get(T_TOPICS)
            if self.messages_table.layout == "rowid" or self.peers.layout != "rowid":
                raise FormatError("Telegram's tables have an unexpected layout; this Telegram version is not supported")
        except BaseException:
            self.db.close()
            raise
        self.skipped = 0
        self._chats: Optional[Dict[int, Chat]] = None
        self._media: Dict[Tuple[int, int], Optional[Obj]] = {}
        self._read: Dict[int, Dict[int, ReadState]] = {}
        self._topics: Dict[int, Dict[int, ReadState]] = {}
        self._oldest_unread: Dict[Tuple[int, int], Optional[Tuple[int, int]]] = {}

    def __enter__(self) -> Session:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        self.db.close()
        self._media.clear()
        self._read.clear()
        self._topics.clear()
        self._oldest_unread.clear()

    # -- who and where

    def me(self) -> Optional[int]:
        """Peer id of the logged-in user, or None when the account is logged out."""
        t = self.tree.tables.get(T_METADATA)
        value = self.tree.get(t, STATE_KEY) if t else None
        if value is None:
            return None
        try:
            state = decode_root(value)
        except TelegramError:
            return None
        return state.integer("peerId")

    def chats(self) -> Dict[int, Chat]:
        """Every user, group, channel, and secret chat Telegram stored, by peer id."""
        if self._chats is None:
            chats: Dict[int, Chat] = {}
            for peer_id, value in self.tree.items(self.peers):
                assert isinstance(peer_id, int)
                try:
                    chats[peer_id] = chat_from_peer(peer_id, decode_root(value))
                except TelegramError:
                    chats[peer_id] = Chat(peer_id, "unknown", "")
            self._chats = chats
        return self._chats

    def chat_ids_with_messages(self) -> List[int]:
        """Peers that have at least one stored message, found by seeking rather than scanning."""
        out: List[int] = []
        lower: Optional[bytes] = None
        while True:
            first = next(self.tree.items(self.messages_table, lower), None)
            if first is None:
                return out
            key = first[0]
            assert isinstance(key, bytes)
            peer = struct.unpack_from(">q", key)[0]
            out.append(peer)
            if peer == 0x7FFFFFFFFFFFFFFF:
                return out
            lower = struct.pack(">q", peer + 1)

    # -- messages

    def messages(self, chat_id: Optional[int] = None, since: Optional[datetime] = None,
                 until: Optional[datetime] = None, newest_first: bool = False,
                 limit: Optional[int] = None) -> Iterator[Message]:
        """Messages of one chat or of all chats, ordered by date, optionally within [since, until)."""
        peers = [chat_id] if chat_id is not None else self.chat_ids_with_messages()
        # Keys compare as bytes, so timestamps are bounded as unsigned 32-bit values.
        lo = min(max(int(since.timestamp()), 0), 0xFFFFFFFF) if since else 0
        hi = min(max(int(until.timestamp()), 0), 0xFFFFFFFF) if until else None
        streams = [self._chat_messages(p, lo, hi, newest_first) for p in peers]
        ordered = heapq.merge(*streams, key=lambda m: (m.timestamp, m.chat_id, m.id), reverse=newest_first)
        count = 0
        for raw in ordered:
            if limit is not None and count >= limit:
                return
            yield self._message(raw)
            count += 1

    def _chat_messages(self, peer: int, lo: int, hi: Optional[int], reverse: bool) -> Iterator[RawMessage]:
        # Keys sort by (peer, namespace, timestamp, id): merge the namespaces of this peer by time.
        streams = []
        for ns in self._namespaces(peer):
            lower = struct.pack(">qiI", peer, ns, lo)
            upper = struct.pack(">qiI", peer, ns, hi) if hi is not None else struct.pack(">qi", peer, ns + 1)
            streams.append(self._decode(self.tree.items(self.messages_table, lower, upper, reverse)))
        yield from heapq.merge(*streams, key=lambda m: (m.timestamp, m.chat_id, m.id), reverse=reverse)

    def _namespaces(self, peer: int) -> List[int]:
        out: List[int] = []
        lower = struct.pack(">q", peer)
        upper = struct.pack(">q", peer + 1) if peer < 0x7FFFFFFFFFFFFFFF else None
        while True:
            first = next(self.tree.items(self.messages_table, lower, upper), None)
            if first is None:
                return out
            key = first[0]
            assert isinstance(key, bytes)
            ns = struct.unpack_from(">i", key, 8)[0]
            out.append(ns)
            if ns == 2 ** 31 - 1:
                return out
            lower = struct.pack(">qi", peer, ns + 1)

    def _decode(self, items: Iterator[Tuple[Union[int, bytes], bytes]]) -> Iterator[RawMessage]:
        for key, value in items:
            assert isinstance(key, bytes)
            try:
                raw = parse_message(key, value)
            except TelegramError:
                self.skipped += 1
                continue
            if raw is not None:
                yield raw

    def _message(self, raw: RawMessage) -> Message:
        media = list(raw.embedded_media)
        for mid in raw.media_ids:
            o = self._media_object(mid)
            if o is not None:
                media.append(o)
        attachments = [a for a in (attachment_from_media(self.account.media, o) for o in media) if a is not None]
        incoming = bool(raw.flags & INCOMING)
        return Message(
            chat_id=raw.chat_id, namespace=raw.namespace, id=raw.id,
            date=datetime.fromtimestamp(raw.timestamp, timezone.utc), incoming=incoming,
            author_id=raw.author_id, text=raw.text, links=links_in(raw.text, raw.attributes, media),
            attachments=tuple(attachments), unread=self._unread(raw) if incoming else False,
            forwarded_from=raw.forward_author, thread_id=raw.thread_id, failed=bool(raw.flags & FAILED))

    def _media_object(self, mid: Tuple[int, int]) -> Optional[Obj]:
        if mid in self._media:
            return self._media[mid]
        o: Optional[Obj] = None
        value = self.tree.get(self.media_table, struct.pack(">iq", *mid)) if self.media_table else None
        if value:
            try:
                r = Reader(value)
                if r.u8() == 0:  # stored directly; 1 would point at a message embedding it
                    o = decode_root(r.blob())
            except TelegramError:
                o = None
        if len(self._media) > 50000:
            self._media.clear()
        self._media[mid] = o
        return o

    def _unread(self, raw: RawMessage) -> Optional[bool]:
        """Whether Telegram shows this incoming message as unread; None when it keeps no read state for it."""
        chat = self.chats().get(raw.chat_id)
        if chat is not None and chat.forum:
            topic = self._topic_states(raw.chat_id).get(raw.thread_id) if raw.thread_id is not None else None
            return None if topic is None else topic.unread_count > 0 and topic.passed(raw.timestamp, raw.id)
        state = self._read_states(raw.chat_id).get(raw.namespace)
        if state is None:
            return None
        key = (raw.chat_id, raw.namespace)
        if key not in self._oldest_unread:
            self._oldest_unread[key] = self._find_oldest_unread(raw.chat_id, raw.namespace, state)
        oldest = self._oldest_unread[key]
        return oldest is not None and (raw.timestamp, raw.id) >= oldest

    def _find_oldest_unread(self, peer: int, ns: int, state: ReadState) -> Optional[Tuple[int, int]]:
        # Telegram counts as unread the newest incoming messages past the read mark, as many as its
        # stored count; that keeps a lagging mark from turning a whole channel unread.
        oldest: Optional[Tuple[int, int]] = None
        found = 0
        upper = struct.pack(">qi", peer, ns + 1)
        for key, value in self.tree.items(self.messages_table, struct.pack(">qi", peer, ns), upper, reverse=True):
            if found >= state.unread_count:
                break
            assert isinstance(key, bytes)
            try:
                raw = parse_message(key, value)
            except TelegramError:
                continue
            if raw is None:
                continue
            if not state.passed(raw.timestamp, raw.id):
                break
            if raw.flags & INCOMING:
                oldest, found = (raw.timestamp, raw.id), found + 1
        return oldest

    def _read_states(self, chat_id: int) -> Dict[int, ReadState]:
        if chat_id not in self._read:
            value = self.tree.get(self.read_table, chat_id) if self.read_table else None
            try:
                self._read[chat_id] = parse_read_states(value) if value else {}
            except TelegramError:
                self._read[chat_id] = {}
        return self._read[chat_id]

    def _topic_states(self, chat_id: int) -> Dict[int, ReadState]:
        if chat_id not in self._topics:
            topics: Dict[int, ReadState] = {}
            if self.topics_table is not None and self.topics_table.layout != "rowid":
                # Keys: peer, date of the topic's last message, topic id, then that message's namespace and id.
                lower = struct.pack(">q", chat_id)
                upper = struct.pack(">q", chat_id + 1) if chat_id < 0x7FFFFFFFFFFFFFFF else None
                for key, value in self.tree.items(self.topics_table, lower, upper):
                    try:
                        state = parse_topic(value)
                    except TelegramError:
                        continue
                    if state is not None and isinstance(key, bytes) and len(key) == 28:
                        topics[struct.unpack_from(">q", key, 12)[0]] = state
            self._topics[chat_id] = topics
        return self._topics[chat_id]


# --------------------------------------------------------------------------------------------
# Diagnostics: look at what this module sees, without the rest of audit-content
# --------------------------------------------------------------------------------------------


def _pick(inst: Installation, record_id: Optional[str]) -> Account:
    accounts = [a for a in inst.accounts if record_id in (None, a.record_id)]
    if not accounts:
        raise TelegramError("no matching Telegram account (see: telegram.py accounts)")
    if len(accounts) > 1 and record_id is None:
        raise TelegramError("several accounts found; choose one with --account (see: telegram.py accounts)")
    return accounts[0]


def _message_json(m: Message, chats: Dict[int, Chat]) -> Dict[str, object]:
    chat = chats.get(m.chat_id)
    author = chats.get(m.author_id) if m.author_id is not None else None
    return {"chat": chat.title if chat else str(m.chat_id), "chat_id": m.chat_id, "id": m.id,
            "date": m.date.isoformat(), "incoming": m.incoming, "unread": m.unread,
            "from": author.title if author else None, "text": m.text, "links": list(m.links),
            "attachments": [{"kind": a.kind, "name": a.file_name, "mime": a.mime_type, "size": a.size,
                             "path": str(a.local_path) if a.local_path else None} for a in m.attachments]}


def main(argv: Sequence[str]) -> int:
    p = argparse.ArgumentParser(prog="telegram.py", description="Show what audit-content can read from Telegram.")
    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("accounts", help="where Telegram is and which accounts it has (default)")
    for name in ("chats", "messages"):
        sp = sub.add_parser(name)
        sp.add_argument("--account", help="account record id, from `accounts`")
        sp.add_argument("--passcode", action="store_true", help="ask for Telegram's local passcode")
        if name == "messages":
            sp.add_argument("--chat", type=int, help="peer id, from `chats`")
            sp.add_argument("--since", help="ISO date or time, for example 2026-10-01")
            sp.add_argument("--limit", type=int, default=50)
            sp.add_argument("--links", action="store_true", help="only messages with links or attachments")
    a = p.parse_args(argv)
    try:
        inst = discover()
        if a.cmd in (None, "accounts"):
            for app in inst.apps:
                print(f"app      {app.path}  {app.bundle_id} {app.version}  groups: {', '.join(app.groups) or '-'}")
            for acc in inst.accounts:
                size, modified = acc.stat()
                with Session(acc) as s:
                    me = s.me()
                    who = s.chats().get(me) if me is not None else None
                    print(f"account  {acc.record_id}  {who.title if who else 'logged out'}"
                          f"  {size / 1e6:.1f} MB  changed {datetime.fromtimestamp(modified):%Y-%m-%d %H:%M}"
                          f"\n         {acc.path}")
            for note in inst.notes:
                print(f"note     {note}")
            return 0
        passcode = getpass.getpass("Telegram passcode: ") if a.passcode else None
        with Session(_pick(inst, a.account), passcode) as s:
            chats = s.chats()
            if a.cmd == "chats":
                for peer in s.chat_ids_with_messages():
                    c = chats.get(peer, Chat(peer, "unknown", ""))
                    print(f"{c.id:>22}  {c.kind:8} {c.title}{f'  @{c.username}' if c.username else ''}")
                return 0
            since = datetime.fromisoformat(a.since).astimezone(timezone.utc) if a.since else None
            shown = 0
            for m in s.messages(a.chat, since=since, newest_first=True):
                if a.links and not (m.links or m.attachments):
                    continue
                print(json.dumps(_message_json(m, chats), ensure_ascii=False))
                shown += 1
                if shown >= a.limit:
                    break
            if s.skipped:
                print(f"note: {s.skipped} records could not be decoded and were skipped", file=sys.stderr)
            return 0
    except TelegramError as e:
        print(f"telegram.py: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
