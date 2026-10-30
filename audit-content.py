#!/usr/bin/env python3
"""audit-content: check a link or a file inside a disposable microVM before you open it.

  audit-content setup [--rebuild]   Install Apple `container` if needed, build the sandbox image (once).
  audit-content auth                Run `claude setup-token`, verify the token, store it in the Keychain.
  audit-content URL                 Check a link. The verdict arrives in about 1-2 minutes.
  audit-content --file PATH         Check a file (email attachment, archive, document, HTML page).
      --report                      Also write one self-contained HTML safe-view report to the temp dir.
      --open                        Write the report and open it in the browser.
      --json                        Print the verdict as JSON on stdout (progress stays on stderr).
      --upstream-proxy URL          Send the sandbox's internet traffic through this HTTP proxy.
      --timeout SECONDS             Total time budget (default 120).
  audit-content clean               Remove leftovers of interrupted checks.
  audit-content uninstall           Remove the image, leftovers, and the Keychain token.

Exit codes: 0 SAFE, 1 SUSPICIOUS or INCOMPLETE, 2 MALICIOUS, 3 tool error.

How a check stays contained:
  * Every check gets a fresh Apple `container` microVM (its own kernel) on a fresh host-only network,
    with a read-only root filesystem and tmpfs scratch space. `--rm` and a guest-side hard deadline
    guarantee nothing keeps running; the per-run network is deleted afterwards.
  * The VM's only route out is this script's proxy, bound to that network's gateway IP. The host
    resolves DNS and refuses loopback, private, link-local, CGNAT, and metadata addresses, so the page
    cannot reach the intranet or this Mac. Every flow is logged as evidence.
  * The agents inside the VM hold a placeholder token. The proxy injects the real Claude OAuth token
    only on the LLM route (behind a per-run secret path), so a prompt-injected agent cannot steal it.
  * Verdict = the worst of the deterministic indicators and the four specialist verdicts. Indicators
    can never be lowered by an agent, and any failure or timeout yields at least SUSPICIOUS.
"""

from __future__ import annotations

import argparse
import base64
import html
import http.client
import http.server
import ipaddress
import json
import os
import re
import secrets
import select
import shutil
import signal
import socket
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Any, Dict, List, Optional, Tuple, cast

IMAGE = "audit-content-sandbox:latest"
PREFIX = "audit-content-"
HERE = Path(__file__).resolve().parent
KEYCHAIN_ACCOUNT, KEYCHAIN_SERVICE = "audit-content", "audit-content-claude-oauth"
ANTHROPIC_HOST = "api.anthropic.com"
LEVELS = ("SAFE", "SUSPICIOUS", "MALICIOUS")
SPECIALISTS = ("web", "scripts", "files", "infra")
EXIT = {"SAFE": 0, "SUSPICIOUS": 1, "MALICIOUS": 2}
HOP_BY_HOP = {"connection", "keep-alive", "proxy-connection", "proxy-authorization", "proxy-authenticate", "te",
              "trailer", "transfer-encoding", "upgrade"}
BLOCKED_PORTS = {25, 465, 587, 2525}  # no spam relaying from the sandbox
# Chromium's own background services; no web page needs them, so the browse port refuses them.
BROWSER_SERVICES = {"update.googleapis.com", "clientservices.googleapis.com", "safebrowsing.googleapis.com",
                    "optimizationguide-pa.googleapis.com", "content-autofill.googleapis.com"}
DOWNLOAD_CAP = 768 << 20
MAX_FILE = 256 << 20

JSONObj = Dict[str, Any]
T0 = time.monotonic()


def as_dict(v: object) -> JSONObj:
    return v if isinstance(v, dict) else {}


def as_list(v: object) -> List[Any]:
    return v if isinstance(v, list) else []


def as_str(v: object, cap: int = 4000) -> str:
    return clean(v[:cap]) if isinstance(v, str) else ""


_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
_BIDI = re.compile(r"[‎‏‪-‮⁦-⁩]")


def clean(text: str) -> str:
    """Untrusted text from the VM: drop terminal control bytes, make bidi tricks visible."""
    return _BIDI.sub(lambda m: f"<U+{ord(m.group()):04X}>", _CONTROL.sub("", text))


def defang(url: str) -> str:
    parts = urllib.parse.urlsplit(url)
    if not parts.scheme or not parts.netloc:
        return re.sub(r"(?i)\bhttp", "hxxp", url)
    scheme = re.sub(r"(?i)^http", "hxxp", parts.scheme)
    rest = url.split(parts.netloc, 1)[1] if parts.netloc in url else ""
    return f"{scheme}://{parts.netloc.replace('.', '[.]')}{rest}"


def log(msg: str) -> None:
    sys.stderr.write(f"\033[2m[{time.monotonic() - T0:5.1f}s]\033[0m {msg}\n" if sys.stderr.isatty()
                     else f"[{time.monotonic() - T0:5.1f}s] {msg}\n")
    sys.stderr.flush()


def die(msg: str, code: int = 3) -> None:
    sys.stderr.write(f"audit-content: {msg}\n")
    sys.exit(code)


def run(args: List[str], timeout: float = 60, input: Optional[bytes] = None) -> Tuple[int, str]:
    try:
        p = subprocess.run(args, input=input, capture_output=True, timeout=timeout)
        return p.returncode, (p.stdout + p.stderr).decode("utf-8", "replace")
    except subprocess.TimeoutExpired:
        return -1, "timeout"
    except FileNotFoundError:
        return -2, f"{args[0]} not found"


# --------------------------------------------------------------------------------------------
# Apple `container` helpers
# --------------------------------------------------------------------------------------------

MIN_CONTAINER = (1, 6)
CONTAINER_RELEASES = "https://github.com/apple/container/releases/download/"
CONTAINER_SIGNER = re.compile(r"1\. Developer ID Installer: Apple Inc\.[^\n]*\(UPBK2H6LZM\)")  # Apple's Containerization team


def container_version() -> Optional[Tuple[int, ...]]:
    rc, out = run(["container", "--version"], timeout=20)
    m = re.search(r"version (\d+)\.(\d+)", out) if rc == 0 else None
    return (int(m.group(1)), int(m.group(2))) if m else None


def install_container() -> None:
    """Install or upgrade Apple `container` from its GitHub release, after three checks: the SHA-256 that
    GitHub publishes for the asset, Apple's Developer ID signature pinned to the Containerization team, and
    Gatekeeper's notarization verdict. The package lives in a temp dir that is deleted afterwards."""
    import hashlib
    import platform
    import urllib.request

    mac = platform.mac_ver()[0]
    if platform.machine() != "arm64" or int((mac or "0").split(".")[0]) < 26:
        die(f"audit-content needs an Apple silicon Mac with macOS 26 or later (this is {platform.machine()}, macOS {mac})")
    log("fetching the latest Apple `container` release from github.com/apple/container")
    req = urllib.request.Request("https://api.github.com/repos/apple/container/releases/latest",
                                 headers={"Accept": "application/vnd.github+json", "User-Agent": "audit-content"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            release = as_dict(json.loads(resp.read(1 << 20)))
    except (OSError, ValueError) as e:
        die(f"could not reach GitHub: {e}")
    asset = next((a for a in map(as_dict, as_list(release.get("assets")))
                  if re.fullmatch(r"container-[0-9.]+-installer-signed\.pkg", as_str(a.get("name"), 100))), {})
    url, digest = as_str(asset.get("browser_download_url"), 500), as_str(asset.get("digest"), 100)
    if not url.startswith(CONTAINER_RELEASES) or not digest.startswith("sha256:"):
        die("could not find the signed installer in the latest apple/container release")
    if run(["container", "--version"], timeout=10)[0] == 0:  # an upgrade: Apple's procedure stops services first
        running = [as_str(as_dict(c.get("configuration")).get("id"), 100) for c in list_json(["ls"])]
        if running:
            answer = input(f"Upgrading stops the container service and these running containers: "
                           f"{', '.join(running)}. Continue? [y/N] ") if sys.stdin.isatty() else ""
            if answer.strip().lower() not in ("y", "yes"):
                die("upgrade cancelled; nothing was changed")
        run(["container", "system", "stop"], timeout=120)
    with tempfile.TemporaryDirectory(prefix="audit-content-container-") as tmp:
        pkg = Path(tmp) / "container.pkg"
        sha = hashlib.sha256()
        log(f"downloading {url.rsplit('/', 1)[-1]}")
        try:
            with urllib.request.urlopen(url, timeout=60) as resp, pkg.open("wb") as f:
                while chunk := resp.read(1 << 20):
                    sha.update(chunk)
                    f.write(chunk)
        except OSError as e:
            die(f"download failed: {e}")
        if f"sha256:{sha.hexdigest()}" != digest:
            die("checksum mismatch: the download does not match the release. Not installing.")
        _, sig = run(["pkgutil", "--check-signature", str(pkg)])
        _, gk = run(["spctl", "--assess", "--type", "install", "-vv", str(pkg)])
        if not CONTAINER_SIGNER.search(sig) or "source=Notarized Developer ID" not in gk:
            die("the package is not signed and notarized by Apple's Containerization team. Not installing.")
        log("checksum, Apple signature and notarization verified; installing (macOS asks for your password)")
        if subprocess.call(["sudo", "installer", "-pkg", str(pkg), "-target", "/"]) != 0:
            die("installation failed")


def ensure_runtime(install: bool = False) -> None:
    """Make sure Apple `container` is installed, recent enough, and running. `setup` may install it."""
    version = container_version() if shutil.which("container") else None
    if version is None or version < MIN_CONTAINER:
        if not install:
            die("Apple `container` is missing or too old. Run `audit-content setup` to install it.")
        install_container()
        version = container_version()
        if version is None or version < MIN_CONTAINER:
            die("Apple `container` is still not available after installing it")
    rc, out = run(["container", "system", "status"], timeout=20)
    if rc != 0 or "running" not in out:
        log("starting the container service")
        rc, out = run(["container", "system", "start", "--enable-kernel-install"], timeout=300)
        if rc != 0:
            die(f"could not start the container service: {out.strip()[-300:]}")


def image_exists() -> bool:
    return run(["container", "image", "inspect", IMAGE], timeout=20)[0] == 0


def list_json(args: List[str]) -> List[JSONObj]:
    rc, out = run(["container", *args, "--format", "json"], timeout=30)
    try:
        return [as_dict(x) for x in as_list(json.loads(out))] if rc == 0 else []
    except ValueError:
        return []


def pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def sweep(force: bool) -> int:
    """Remove VMs and networks left behind by checks whose audit-content process no longer exists."""
    removed = 0

    def stale(name: str) -> bool:
        m = re.fullmatch(rf"{PREFIX}(\d+)-[0-9a-f]+", name)
        return m is not None and (force or not pid_alive(int(m.group(1))))

    for c in list_json(["ls", "-a"]):
        cid = as_str(as_dict(c.get("configuration")).get("id"), 200)
        if stale(cid):
            run(["container", "delete", "--force", cid], timeout=30)
            removed += 1
    for n in list_json(["network", "ls"]):
        nid = as_str(n.get("id"), 200)
        if stale(nid):
            run(["container", "network", "delete", nid], timeout=30)
            removed += 1
    return removed


# --------------------------------------------------------------------------------------------
# Egress proxy: the VM's only way out
# --------------------------------------------------------------------------------------------

@dataclass
class Flow:
    role: str
    method: str
    host: str
    port: int
    url: str = ""
    ip: str = ""
    status: str = "open"
    up: int = 0
    down: int = 0
    private: bool = False
    started: float = field(default_factory=time.monotonic)
    seconds: float = 0.0

    def block(self, reason: str) -> None:
        self.status = f"blocked: {reason}"
        self.seconds = round(time.monotonic() - self.started, 2)

    def end(self) -> None:
        if self.status == "open":
            self.status = "ok"
        self.seconds = round(time.monotonic() - self.started, 2)


class EgressProxy:
    """Three listeners on the VM network's gateway IP.

    browse  Chromium's proxy: HTTP + CONNECT to public addresses only.
    tools   Same policy for curl/git/urllib run by the triage code and the agents.
    llm     Plain HTTP from the agents' CLI; only POST /<nonce>/v1/messages*, forwarded over TLS to
            api.anthropic.com with the real OAuth token swapped in.
    """

    def __init__(self, bind_ip: str, subnet: str, token: str, upstream: Optional[Tuple[str, int]]) -> None:
        self.bind_ip, self.subnet = bind_ip, ipaddress.ip_network(subnet, strict=False)
        self.token, self.upstream = token, upstream
        self.nonce = secrets.token_urlsafe(24)
        self.flows: List[Flow] = []
        self.lock = threading.Lock()
        self.down_total = 0
        self.stopping = threading.Event()
        self.servers: List[_Server] = []

    def start(self) -> Dict[str, int]:
        ports = {}
        for role in ("browse", "tools", "llm"):
            srv = _Server((self.bind_ip, 0), self, role)
            threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.2}, daemon=True).start()
            self.servers.append(srv)
            ports[role] = srv.server_address[1]
        return ports

    def stop(self) -> None:
        self.stopping.set()
        for srv in self.servers:
            srv.shutdown()
            srv.server_close()

    def client_allowed(self, addr: str) -> bool:
        try:
            return ipaddress.ip_address(addr) in self.subnet
        except ValueError:
            return False

    def open_flow(self, role: str, method: str, host: str, port: int, url: str = "") -> Flow:
        flow = Flow(role=role, method=method, host=host[:300], port=port, url=url[:2000])
        with self.lock:
            if len(self.flows) < 5000:
                self.flows.append(flow)
        return flow

    def connect(self, flow: Flow) -> Optional[socket.socket]:
        if self.down_total > DOWNLOAD_CAP:
            flow.block("download cap reached")
            return None
        if not 0 < flow.port < 65536 or flow.port in BLOCKED_PORTS:
            flow.block(f"port {flow.port} not allowed")
            return None
        if flow.role == "browse" and flow.host.lower() in BROWSER_SERVICES:
            flow.block("Chromium background service")
            return None
        try:
            infos = socket.getaddrinfo(flow.host, flow.port, type=socket.SOCK_STREAM)
        except (socket.gaierror, UnicodeError, OSError):
            flow.block("DNS lookup failed")
            return None
        ips = list(dict.fromkeys(str(info[4][0]) for info in infos))
        for ip in ips:
            addr = ipaddress.ip_address(ip.split("%")[0])
            if (not addr.is_global or addr.is_multicast or addr.is_reserved or addr.is_loopback
                    or addr.is_link_local or addr.is_unspecified):
                flow.private = True
                flow.ip = ip
                flow.block(f"non-public address {ip}")
                return None
        last = "no address"
        for ip in ips[:4]:
            try:
                sock = self._via_upstream(ip, flow.port) if self.upstream else \
                    socket.create_connection((ip, flow.port), timeout=10)
                flow.ip = ip
                return sock
            except OSError as e:
                last = str(e)
        flow.status = f"error: {last[:120]}"
        flow.end()
        return None

    def _via_upstream(self, ip: str, port: int) -> socket.socket:
        """CONNECT to the already-vetted IP, so the upstream cannot resolve its way into the intranet."""
        assert self.upstream is not None
        sock = socket.create_connection(self.upstream, timeout=10)
        target = f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"
        sock.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
        head = b""
        while b"\r\n\r\n" not in head and len(head) < 16384:
            chunk = sock.recv(4096)
            if not chunk:
                break
            head += chunk
        if not re.match(rb"HTTP/1\.[01] 200", head):
            sock.close()
            raise OSError(f"upstream proxy refused: {head[:60]!r}")
        return sock

    def https_conn(self, host: str) -> http.client.HTTPSConnection:
        ctx = ssl.create_default_context()
        if self.upstream:
            conn = http.client.HTTPSConnection(self.upstream[0], self.upstream[1], timeout=300, context=ctx)
            conn.set_tunnel(host, 443)
            return conn
        return http.client.HTTPSConnection(host, 443, timeout=300, context=ctx)

    def relay(self, client: socket.socket, upstream: socket.socket, flow: Flow) -> None:
        try:
            while not self.stopping.is_set():
                ready, _, _ = select.select([client, upstream], [], [], 30)
                if not ready:
                    break
                for s in ready:
                    data = s.recv(65536)
                    if not data:
                        return
                    (upstream if s is client else client).sendall(data)
                    if s is client:
                        flow.up += len(data)
                    else:
                        flow.down += len(data)
                        with self.lock:
                            self.down_total += len(data)
                            if self.down_total > DOWNLOAD_CAP:
                                flow.status = "cut: download cap reached"
                                return
        except OSError:
            pass
        finally:
            upstream.close()
            flow.end()


class _Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr: Tuple[str, int], proxy: EgressProxy, role: str) -> None:
        self.proxy, self.role = proxy, role
        super().__init__(addr, _Handler)

    def verify_request(self, request: Any, client_address: Any) -> bool:
        return self.proxy.client_allowed(str(client_address[0]))


class _Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = 30

    def log_message(self, format: str, *args: Any) -> None:  # silence; flows are recorded instead
        pass

    @property
    def srv(self) -> _Server:
        return cast(_Server, self.server)

    def deny(self, code: int, reason: str) -> None:
        body = f"audit-content sandbox proxy: {reason}\n".encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def do_CONNECT(self) -> None:
        if self.srv.role == "llm":
            return self.deny(405, "CONNECT is not allowed on the LLM port")
        host, _, port_s = self.path.rpartition(":")
        flow = self.srv.proxy.open_flow(self.srv.role, "CONNECT", host.strip("[]"),
                                        int(port_s) if port_s.isdigit() else 0)
        sock = self.srv.proxy.connect(flow)
        if sock is None:
            return self.deny(403, flow.status)
        self.send_response(200, "Connection Established")
        self.end_headers()
        self.srv.proxy.relay(self.connection, sock, flow)
        self.close_connection = True

    def forward(self) -> None:
        if self.srv.role == "llm":
            return self.llm()
        parts = urllib.parse.urlsplit(self.path)
        if parts.scheme != "http" or not parts.hostname:
            return self.deny(400, "absolute http:// URL required")
        if "chunked" in self.headers.get("Transfer-Encoding", "").lower():
            return self.deny(411, "chunked request bodies are not supported")
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if 0 < length < (64 << 20) else b""
        flow = self.srv.proxy.open_flow(self.srv.role, self.command, parts.hostname, parts.port or 80, self.path)
        sock = self.srv.proxy.connect(flow)
        if sock is None:
            return self.deny(403, flow.status)
        target = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        head = [f"{self.command} {target} HTTP/1.1"]
        head += [f"{k}: {v}" for k, v in self.headers.items() if k.lower() not in HOP_BY_HOP]
        head.append("Connection: close")
        sock.sendall(("\r\n".join(head) + "\r\n\r\n").encode("latin-1", "replace") + body)
        flow.up += len(body)
        self.srv.proxy.relay(self.connection, sock, flow)
        self.close_connection = True

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = forward

    def llm(self) -> None:
        proxy = self.srv.proxy
        path, _, query = self.path.partition("?")
        prefix = f"/{proxy.nonce}"
        flow = proxy.open_flow("llm", self.command, ANTHROPIC_HOST, 443)
        if self.command != "POST" or not path.startswith(prefix + "/v1/messages"):
            flow.block("not an allowed LLM route")
            return self.deny(403, "not an allowed LLM route")
        length = int(self.headers.get("Content-Length") or 0)
        if not 0 < length <= (64 << 20):
            flow.block("bad request size")
            return self.deny(413, "bad request size")
        body = self.rfile.read(length)
        flow.up = len(body)
        headers = {k: v for k, v in self.headers.items()
                   if k.lower() not in HOP_BY_HOP | {"host", "authorization", "x-api-key", "content-length",
                                                     "accept-encoding"}}
        headers["Authorization"] = f"Bearer {proxy.token}"
        conn = proxy.https_conn(ANTHROPIC_HOST)
        sent_head = False
        try:
            conn.request("POST", path[len(prefix):] + (f"?{query}" if query else ""), body=body, headers=headers)
            resp = conn.getresponse()
            self.send_response(resp.status, resp.reason)
            for k, v in resp.getheaders():
                if k.lower() not in HOP_BY_HOP | {"content-length"}:
                    self.send_header(k, v)
            self.send_header("Connection", "close")
            self.end_headers()
            sent_head = True
            while True:
                chunk = resp.read1(65536)
                if not chunk:
                    break
                self.wfile.write(chunk)
                self.wfile.flush()
                flow.down += len(chunk)
            flow.status = f"ok {resp.status}"
        except (OSError, http.client.HTTPException) as e:
            flow.status = f"error: {str(e)[:120]}"
            if not sent_head:
                self.deny(502, "upstream error")
        finally:
            conn.close()
            flow.end()
            self.close_connection = True


# --------------------------------------------------------------------------------------------
# Credentials (macOS Keychain)
# --------------------------------------------------------------------------------------------

TOKEN_RE = re.compile(r"sk-ant-oat01-[A-Za-z0-9_\-]{20,400}")


def keychain_get() -> Optional[str]:
    env = os.environ.get("CLAUDE_CODE_OAUTH_TOKEN", "")
    if TOKEN_RE.fullmatch(env):
        return env
    rc, out = run(["security", "find-generic-password", "-a", KEYCHAIN_ACCOUNT, "-s", KEYCHAIN_SERVICE, "-w"])
    token = out.strip()
    return token if rc == 0 and TOKEN_RE.fullmatch(token) else None


def token_problem(token: str) -> Optional[str]:
    """One tiny live request; returns why Claude rejected the token, or None if it works."""
    body = json.dumps({"model": "claude-haiku-5-5", "max_tokens": 1, "messages": [{"role": "user", "content": "hi"}],
                       "system": "You are Claude Code, Anthropic's official CLI for Claude."})
    conn = http.client.HTTPSConnection(ANTHROPIC_HOST, 443, timeout=30, context=ssl.create_default_context())
    try:
        conn.request("POST", "/v1/messages", body, {"Authorization": f"Bearer {token}", "anthropic-version": "2023-06-01",
                                                    "anthropic-beta": "oauth-2025-04-20",
                                                    "content-type": "application/json"})
        resp = conn.getresponse()
        detail = resp.read(2000).decode("utf-8", "replace")
    except (OSError, http.client.HTTPException) as e:
        return f"could not reach Claude to verify it ({e})"
    finally:
        conn.close()
    return None if resp.status == 200 else f"HTTP {resp.status}: {detail[:200]}"


_ANSI = re.compile(r"\x1b(\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(\x07|\x1b\\)|[@-Z\\-_])")
_TOKEN_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")


def token_candidates(raw: str) -> List[str]:
    """Rebuild tokens from terminal output where wrapping may have split them over several lines.

    Every way of continuing across a line break is a candidate (longest first); the live check decides.
    """
    text = _ANSI.sub("", raw)
    found: List[str] = []
    for m in re.finditer(r"sk-ant-oat01-", text):
        token, i = m.group(), m.end()
        for _ in range(6):
            j = i
            while j < len(text) and text[j] in _TOKEN_CHARS:
                j += 1
            token += text[i:j]
            found.append(token)
            m2 = re.match(r"\r*\n|\r+", text[j:j + 4])  # exactly one line break: a wrap, not a new paragraph
            if m2 is None:
                break
            k = j + m2.end()
            while k < len(text) and text[k] in " \t│|║>":
                k += 1
            if k >= len(text) or text[k] not in _TOKEN_CHARS:
                break
            i = k
    unique = [t for t in dict.fromkeys(found) if TOKEN_RE.fullmatch(t)]
    return sorted(unique, key=len, reverse=True)[:6]


def run_setup_token() -> str:
    """Run `claude setup-token` in a pseudo-terminal the size of the user's, mirror it, and return its output."""
    import fcntl
    import pty
    import struct
    import termios
    import tty

    claude = shutil.which("claude")
    if claude is None:
        die("Claude Code is not installed: https://claude.com/claude-code")
    assert claude is not None
    stdin_fd, stdout_fd = sys.stdin.fileno(), sys.stdout.fileno()
    size = fcntl.ioctl(stdout_fd, termios.TIOCGWINSZ, b"\0" * 8)
    pid, master = pty.fork()
    if pid == 0:  # child: same window size as the real terminal, then become `claude setup-token`
        fcntl.ioctl(0, termios.TIOCSWINSZ, size)
        os.execv(claude, [claude, "setup-token"])
    saved = termios.tcgetattr(stdin_fd)
    seen = bytearray()
    try:
        tty.setraw(stdin_fd)
        while True:
            ready, _, _ = select.select([master, stdin_fd], [], [])
            if master in ready:
                try:
                    data = os.read(master, 65536)
                except OSError:  # the child closed the terminal: it has exited
                    break
                if not data:
                    break
                os.write(stdout_fd, data)
                seen += data
                del seen[:-(1 << 20)]
            if stdin_fd in ready:
                os.write(master, os.read(stdin_fd, 1024))
    finally:
        termios.tcsetattr(stdin_fd, termios.TCSADRAIN, saved)
        os.close(master)
        os.waitpid(pid, 0)
    return seen.decode("utf-8", "replace")


def cmd_auth() -> int:
    if sys.stdin.isatty():
        print("audit-content uses your Claude subscription through a long-lived OAuth token.\n"
              "Running `claude setup-token` now: approve it in the browser window that opens.\n")
        candidates = token_candidates(run_setup_token())
        if not candidates:
            print("\nNo token found in that output. Paste the token below (it may span several lines), "
                  "then press Enter on an empty line:")
            lines = []
            while True:
                line = input()
                if not line.strip():
                    break
                lines.append(line)
            candidates = token_candidates("\n".join(lines)) or ["".join("".join(lines).split())]
    else:
        candidates = token_candidates(sys.stdin.read(65536))  # e.g. `pbpaste | audit-content auth`
    if not candidates:
        die("no Claude OAuth token (sk-ant-oat01-...) found")
    problem = "no candidate"
    token = ""
    for token in candidates:
        found = token_problem(token)
        if found is None:
            break
        problem = found
    else:
        die(f"Claude rejected the token: {problem}")
    # `security -i` reads the command from stdin, so the token never appears in any process's argv.
    rc, out = run(["security", "-i"], input=(f"add-generic-password -U -a {KEYCHAIN_ACCOUNT} -s {KEYCHAIN_SERVICE} "
                                              f"-l {KEYCHAIN_SERVICE} -w {token}\n").encode())
    if rc != 0 or keychain_get() != token:
        die(f"could not store the token in the Keychain: {out.strip()[:200]}")
    print(f"Stored in the login Keychain (service {KEYCHAIN_SERVICE}). It never enters the sandbox.")
    return 0


# --------------------------------------------------------------------------------------------
# A check
# --------------------------------------------------------------------------------------------

@dataclass
class Target:
    url: Optional[str] = None
    path: Optional[Path] = None

    @property
    def label(self) -> str:
        return defang(self.url) if self.url else f"file {self.path.name if self.path else '?'}"


@dataclass
class Reason:
    rank: int
    severity: str
    text: str
    detail: str
    source: str


@dataclass
class Verdict:
    level: str
    incomplete: bool
    reasons: List[Reason]
    guest: JSONObj
    flows: List[Flow]
    seconds: float
    report: Optional[str] = None


def host_settings() -> Tuple[str, str]:
    tz = "UTC"
    real = os.path.realpath("/etc/localtime")
    if "zoneinfo/" in real:
        tz = real.split("zoneinfo/", 1)[1]
    rc, out = run(["defaults", "read", "-g", "AppleLocale"], timeout=5)
    m = re.match(r"([a-z]{2})[_-]([A-Z]{2})", out.strip()) if rc == 0 else None
    return tz, f"{m.group(1)}-{m.group(2)}" if m else "en-US"


def wait_bindable(ip: str, proc: subprocess.Popen[bytes], timeout: float = 20) -> None:
    """The vmnet bridge (and the gateway IP) only exists once the VM has attached to the network."""
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if proc.poll() is not None:
            raise RuntimeError("the sandbox VM exited during start-up")
        s = socket.socket()
        try:
            s.bind((ip, 0))
            return
        except OSError:
            time.sleep(0.05)
        finally:
            s.close()
    raise RuntimeError("the sandbox network did not come up")


def run_check(target: Target, timeout: float, upstream: Optional[Tuple[str, int]], report: bool, model: str,
              cpus: int, memory: str) -> Verdict:
    token = keychain_get()
    if token is None:
        die("no Claude OAuth token. Run `audit-content auth` first.")
    assert token is not None
    if not image_exists():
        die("the sandbox image is missing. Run `audit-content setup` first.")
    sweep(force=False)
    run_id = f"{PREFIX}{os.getpid()}-{secrets.token_hex(3)}"
    rc, out = run(["container", "network", "create", "--internal", "--label", "audit-content=1", run_id], timeout=30)
    if rc != 0:
        die(f"could not create the sandbox network: {out.strip()[:200]}")
    proxy: Optional[EgressProxy] = None
    proc: Optional[subprocess.Popen[bytes]] = None
    stdout_buf: List[bytes] = []
    try:
        rc, out = run(["container", "network", "inspect", run_id], timeout=30)
        net = as_dict(as_list(json.loads(out))[0]) if rc == 0 else {}
        status = as_dict(net.get("status"))
        gateway, subnet = as_str(status.get("ipv4Gateway"), 64), as_str(status.get("ipv4Subnet"), 64)
        if not gateway or not subnet:
            raise RuntimeError("could not read the sandbox network's gateway")
        log("starting a fresh microVM (read-only, host-only network)")
        proc = subprocess.Popen(
            # NET_ADMIN only lets the guest's root stage install the egress firewall; it then drops
            # every capability before any untrusted content is touched.
            ["container", "run", "--rm", "-i", "--name", run_id, "--network", run_id, "--read-only",
             "--cap-add", "CAP_NET_ADMIN", "--tmpfs", "/tmp", "--tmpfs", "/home/audit", "--shm-size", "1g",
             "--no-dns", "--init",
             "--cpus", str(cpus), "--memory", memory, "--label", "audit-content=1", "--progress", "none", IMAGE],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        wait_bindable(gateway, proc)
        proxy = EgressProxy(gateway, subnet, token, upstream)
        ports = proxy.start()
        tz, locale = host_settings()
        guest_deadline = timeout - (time.monotonic() - T0) - 4
        cfg = {"url": target.url, "file_name": target.path.name if target.path else None,
               "file_size": target.path.stat().st_size if target.path else 0, "gateway": gateway,
               "browse_port": ports["browse"], "tools_port": ports["tools"], "llm_port": ports["llm"],
               "llm_nonce": proxy.nonce, "deadline": guest_deadline, "report": report, "timezone": tz,
               "locale": locale, "model": model}
        assert proc.stdin is not None and proc.stdout is not None and proc.stderr is not None
        reader = threading.Thread(target=_drain, args=(proc.stdout, stdout_buf), daemon=True)
        reader.start()
        err_tail: List[str] = []
        threading.Thread(target=_relay_progress, args=(proc.stderr, err_tail), daemon=True).start()
        proc.stdin.write(json.dumps(cfg).encode() + b"\n")
        if target.path:
            with target.path.open("rb") as f:
                shutil.copyfileobj(f, proc.stdin, 1 << 20)
        proc.stdin.flush()  # stdin stays open: if this process dies, the guest sees EOF and stops at once
        try:
            proc.wait(timeout=guest_deadline + 15)
        except subprocess.TimeoutExpired:
            log("deadline passed: killing the VM")
            run(["container", "kill", run_id], timeout=15)
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                proc.kill()
        reader.join(timeout=10)
        raw = b"".join(stdout_buf)
        try:
            guest = as_dict(json.loads(raw)) if raw else {"error": "the VM returned no result"}
        except ValueError:
            guest = {"error": "the VM returned an unreadable result"}
        if not raw and err_tail:
            guest["error"] = f"the VM failed: {clean(' | '.join(err_tail[-3:]))[:400]}"
    finally:
        if proxy is not None:
            proxy.stop()
        if proc is not None:
            if proc.stdin is not None:
                try:
                    proc.stdin.close()
                except OSError:
                    pass
            if proc.poll() is None:
                proc.kill()
        run(["container", "delete", "--force", run_id], timeout=30)
        for _ in range(20):
            if run(["container", "network", "delete", run_id], timeout=30)[0] == 0:
                break
            time.sleep(0.3)
    return merge(guest, proxy.flows if proxy else [], time.monotonic() - T0)


def _drain(stream: IO[bytes], out: List[bytes]) -> None:
    total = 0
    while True:
        chunk = stream.read(1 << 20)
        if not chunk:
            return
        total += len(chunk)
        if total < (160 << 20):
            out.append(chunk)


def _relay_progress(stream: IO[bytes], tail: List[str]) -> None:
    for raw in stream:
        line = clean(raw.decode("utf-8", "replace").rstrip())
        if line.startswith("@@ "):
            log(line[3:][:200])
        elif line:
            tail.append(line[:300])
            del tail[:-20]


# --------------------------------------------------------------------------------------------
# Verdict: worst of deterministic indicators and specialists; failures never read as SAFE
# --------------------------------------------------------------------------------------------

SEV_RANK = {"critical": 1, "high": 2, "medium": 4, "low": 5, "info": 6}


def host_indicators(flows: List[Flow]) -> List[JSONObj]:
    out: List[JSONObj] = []
    private = [f for f in flows if f.role == "browse" and f.private]
    intranet = sorted({f"{f.host}:{f.port}" for f in private if f.ip and not ipaddress.ip_address(
        f.ip.split("%")[0]).is_loopback})
    local_ports = {f.port for f in private if f.ip and ipaddress.ip_address(f.ip.split("%")[0]).is_loopback}
    if intranet:
        out.append({"severity": "SUSPICIOUS", "title": "The page tried to reach private-network addresses "
                    "(intranet, router, or cloud metadata). The sandbox blocked it.",
                    "detail": ", ".join(intranet[:10])})
    if len(local_ports) >= 3:
        out.append({"severity": "SUSPICIOUS", "title": "The page probed ports on the visitor's own computer. "
                    "The sandbox blocked it.", "detail": ", ".join(str(p) for p in sorted(local_ports)[:20])})
    if any(f.status.startswith("cut: download cap") for f in flows):
        out.append({"severity": "SUSPICIOUS", "title": "The page pulled an unusually large amount of data; "
                    "the transfer was cut", "detail": f"cap {DOWNLOAD_CAP >> 20} MB"})
    return out


def merge(guest: JSONObj, flows: List[Flow], seconds: float) -> Verdict:
    reasons: List[Reason] = []
    level = "SAFE"
    incomplete = bool(guest.get("error"))

    def raise_to(lv: str) -> None:
        nonlocal level
        if lv in LEVELS and LEVELS.index(lv) > LEVELS.index(level):
            level = lv

    for ind in [as_dict(i) for i in as_list(guest.get("indicators"))] + host_indicators(flows):
        sev = as_str(ind.get("severity"), 20)
        if sev in ("SUSPICIOUS", "MALICIOUS"):
            raise_to(sev)
            reasons.append(Reason(0 if sev == "MALICIOUS" else 3, sev, as_str(ind.get("title"), 300),
                                  as_str(ind.get("detail"), 1500), "deterministic check"))
    specialists = as_dict(guest.get("specialists"))
    for name in SPECIALISTS:
        rec = as_dict(specialists.get(name))
        res = as_dict(rec.get("result"))
        verdict = as_str(res.get("verdict"), 20)
        if rec.get("status") != "ok" or verdict not in LEVELS:
            incomplete = True
            continue
        raise_to(verdict)
        for f in map(as_dict, as_list(res.get("findings"))[:12]):
            sev = as_str(f.get("severity"), 20)
            if sev in SEV_RANK and (sev != "info" or verdict != "SAFE"):
                reasons.append(Reason(SEV_RANK[sev], sev, as_str(f.get("title"), 300),
                                      as_str(f.get("explanation"), 1500) + "\n" + as_str(f.get("evidence"), 3000),
                                      name))
    if incomplete:
        raise_to("SUSPICIOUS")
    reasons.sort(key=lambda r: r.rank)
    return Verdict(level, incomplete, reasons, guest, flows, seconds)


# --------------------------------------------------------------------------------------------
# Output: terminal summary, JSON, one-file HTML safe-view report
# --------------------------------------------------------------------------------------------

ADVICE = {
    "SAFE": "No threat found. Opening it is low risk. Still stop if it asks for a password or a download.",
    "SUSPICIOUS": "Do not open it on a device with company access. If you need it, ask the security team.",
    "MALICIOUS": "Do not open it. Report it to the security team, and delete the message it came in.",
}


def print_summary(v: Verdict, target: Target) -> None:
    tty = sys.stdout.isatty()
    color = {"SAFE": "42;30", "SUSPICIOUS": "43;30", "MALICIOUS": "41;97"}[v.level]
    title = f" {v.level}{' (INCOMPLETE)' if v.incomplete else ''} "
    print()
    print(f"\033[1;{color}m{title}\033[0m  {target.label}  · {v.seconds:.0f}s" if tty
          else f"{title.strip()}  {target.label}  ({v.seconds:.0f}s)")
    print(f"  {ADVICE[v.level]}")
    if v.incomplete:
        print("  The analysis did not finish completely, so the result cannot be SAFE.")
    if v.guest.get("error"):
        print(f"  Problem: {as_str(v.guest.get('error'), 300)}")
    errors = [as_str(as_dict(r).get("error"), 300) for r in as_dict(v.guest.get("specialists")).values()]
    if errors and all("401" in x or "authenticat" in x.lower() for x in errors):
        print("  Claude rejected the stored token, so the AI specialists did not run. Fix: audit-content auth")
    # Deterministic indicators first, then each specialist's single strongest finding (they often overlap).
    shown = [r for r in v.reasons if r.source == "deterministic check"][:4]
    for name in SPECIALISTS:
        best = next((r for r in v.reasons if r.source == name and r.rank <= 4), None)
        if best is not None and len(shown) < 7:
            shown.append(best)
    if shown:
        print("\n  Worth knowing:" if v.level == "SAFE" else "\n  Why:")
        for r in shown:
            print(f"   - [{r.severity}] {r.text}  ({r.source})")
    specs = as_dict(v.guest.get("specialists"))
    parts = []
    for name in SPECIALISTS:
        rec = as_dict(specs.get(name))
        res = as_dict(rec.get("result"))
        parts.append(f"{name} {as_str(res.get('verdict'), 20) or as_str(rec.get('status'), 20).upper() or 'MISSING'}")
    print("\n  Specialists: " + " · ".join(parts))
    if v.level == "SAFE":
        for name in SPECIALISTS:
            summary = as_str(as_dict(as_dict(specs.get(name)).get("result")).get("summary"), 300)
            if summary:
                print(f"   - {name}: {summary}")
    final = as_str(v.guest.get("final_url"), 2000)
    if final and target.url and final.rstrip("/") != target.url.rstrip("/"):
        print(f"  Final URL: {defang(final)}")
    if target.url:
        print("  Note: the sandbox visited the link from this network. One-time links may now be used up.")
    if v.report:
        print(f"  Report: {v.report}")
    print()


def verdict_json(v: Verdict, target: Target) -> JSONObj:
    specs = as_dict(v.guest.get("specialists"))
    return {
        "verdict": v.level, "incomplete": v.incomplete, "target": target.url or str(target.path),
        "final_url": as_str(v.guest.get("final_url"), 4000), "seconds": round(v.seconds, 1),
        "reasons": [{"severity": r.severity, "title": r.text, "source": r.source} for r in v.reasons[:30]],
        "specialists": {n: {"status": as_str(as_dict(specs.get(n)).get("status"), 20),
                            "verdict": as_str(as_dict(as_dict(specs.get(n)).get("result")).get("verdict"), 20),
                            "summary": as_str(as_dict(as_dict(specs.get(n)).get("result")).get("summary"), 1000)}
                        for n in SPECIALISTS},
        "error": as_str(v.guest.get("error"), 500) or None, "report": v.report,
    }


def _image(b64: object, magic: bytes) -> Optional[str]:
    """Re-encode an image from the VM only if it really is that image type (no markup smuggling)."""
    try:
        data = base64.b64decode(b64 if isinstance(b64, str) else "", validate=True)
    except ValueError:
        return None
    return base64.b64encode(data).decode() if data.startswith(magic) else None


REPORT_CSS = """
:root{--bg:#f6f7f9;--card:#fff;--fg:#1d2330;--muted:#5d6676;--line:#e2e5ea;--code:#f0f2f5;
--safe:#1f7a4d;--susp:#a35c00;--mal:#b3261e;--safe-bg:#e3f4ea;--susp-bg:#fff1dc;--mal-bg:#fde7e5}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#111418;--card:#1a1e24;--fg:#e6e9ee;
--muted:#9aa3b2;--line:#2b313a;--code:#232831;--safe:#5fd39a;--susp:#f0b35a;--mal:#ff8a80;--safe-bg:#16301f;
--susp-bg:#33260f;--mal-bg:#3a1714}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 -apple-system,
BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}main{max-width:1100px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:0 0 4px}.hint{color:var(--muted);font-size:13px;margin:0 0 12px}
section{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px 18px;margin:14px 0}
.banner{border-radius:10px;padding:18px 20px;margin:0 0 14px;border:1px solid var(--line)}
.SAFE{background:var(--safe-bg);color:var(--safe)}.SUSPICIOUS{background:var(--susp-bg);color:var(--susp)}
.MALICIOUS{background:var(--mal-bg);color:var(--mal)}.banner p{color:var(--fg);margin:6px 0 0}
.pill{display:inline-block;border-radius:99px;padding:1px 9px;font-size:12px;font-weight:600;margin-right:6px}
table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:5px 6px;border-top:1px solid
var(--line);vertical-align:top;overflow-wrap:anywhere}th{color:var(--muted);font-weight:600}
pre,code{background:var(--code);border-radius:6px;font:12px/1.45 ui-monospace,Menlo,monospace}
pre{padding:10px;white-space:pre-wrap;overflow-wrap:anywhere;max-height:420px;overflow:auto}
details{margin:6px 0}summary{cursor:pointer;font-weight:600}.shot{width:100%;height:auto;border:1px solid var(--line);
border-radius:6px;margin:6px 0 14px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,300px),1fr));gap:12px}
.reason{border-left:4px solid var(--line);padding:4px 10px;margin:8px 0}.r0,.r1{border-color:var(--mal)}
.r2,.r3{border-color:var(--susp)}.muted{color:var(--muted)}
.kv td:first-child{width:9em;font-weight:600;color:var(--muted);overflow-wrap:normal}
"""


def write_report(v: Verdict, target: Target) -> str:
    def e(s: object) -> str:
        return html.escape(clean(str(s)))

    g = v.guest
    obs = as_dict(g.get("observations"))
    specs = as_dict(g.get("specialists"))
    out: List[str] = []
    add = out.append

    def section(title: str, hint: str) -> None:
        add(f"<section><h2>{e(title)}</h2><p class=hint>{e(hint)}</p>")

    def table(head: List[str], rows: List[List[str]]) -> None:
        add("<table class=kv>" if not any(head) else
            "<table><tr>" + "".join(f"<th>{e(h)}</th>" for h in head) + "</tr>")
        for row in rows:
            add("<tr>" + "".join(f"<td>{c}</td>" for c in row) + "</tr>")
        add("</table>")

    add(f"<div class='banner {v.level}'><h1>{v.level}{' · INCOMPLETE' if v.incomplete else ''}</h1>"
        f"<p><b>{e(target.label)}</b> · checked in {v.seconds:.0f}s · {e(time.strftime('%Y-%m-%d %H:%M'))}</p>"
        f"<p>{e(ADVICE[v.level])}</p>"
        + (f"<p>Problem during analysis: {e(as_str(g.get('error'), 400))}</p>" if g.get("error") else "")
        + "</div>")

    def reason(r: Reason) -> None:
        add(f"<div class='reason r{r.rank}'><b>[{e(r.severity)}] {e(r.text)}</b>"
            + (f"<details><summary>details</summary><pre>{e(r.detail.strip())}</pre></details>" if r.detail.strip() else "")
            + "</div>")

    section("Why", "Hard evidence from deterministic checks (no AI can overrule it), then each AI specialist's "
            "conclusion in one sentence.")
    hard = [r for r in v.reasons if r.source == "deterministic check"]
    for r in hard:
        reason(r)
    if not hard:
        add("<p class=muted>No deterministic indicator fired.</p>")
    add("<div class=grid>")
    for name in SPECIALISTS:
        rec = as_dict(specs.get(name))
        res = as_dict(rec.get("result"))
        verdict = as_str(res.get("verdict"), 20) or as_str(rec.get("status"), 20).upper() or "MISSING"
        add(f"<div><span class='pill {verdict if verdict in LEVELS else 'SUSPICIOUS'}'>{e(verdict)}</span><b>{e(name)}</b> "
            f"<span class=muted>{e(as_str(res.get('confidence'), 10))} · {e(rec.get('seconds', ''))}s</span>"
            f"<p>{e(as_str(res.get('summary'), 1000) or as_str(rec.get('error'), 500))}</p></div>")
    add("</div></section>")

    section("Specialist findings", "Each analyst's evidence. They work independently, so findings overlap on purpose: "
            "one prompt-injected analyst cannot hide what the others see.")
    for name in SPECIALISTS:
        mine = [r for r in v.reasons if r.source == name]
        add(f"<details><summary>{e(name)}: {len(mine)} finding(s)</summary>")
        for r in mine:
            reason(r)
        add("</details>")
    add("</section>")

    sv = as_dict(g.get("safe_view"))
    shots = [(as_str(as_dict(s).get("label"), 60), _image(as_dict(s).get("jpeg"), b"\xff\xd8\xff"))
             for s in as_list(sv.get("screenshots"))]
    if shots:
        section("What the page looks like", "Pictures taken inside the sandbox. They are only pixels, so "
                "nothing on them can run or be clicked.")
        for i, (label, data) in enumerate(shots):
            if data:
                add(("" if i != 1 else "<div class=grid>")
                    + f"<div><p class=muted>{e(label)}</p><img class=shot alt='{e(label)}' "
                      f"src='data:image/jpeg;base64,{data}'></div>")
        add("</div></section>" if len(shots) > 1 else "</section>")

    section("Where the link goes", "Every page the browser landed on, and the HTTPS certificate of the last one.")
    rows = [[f"<code>{e(defang(as_str(u, 2000)))}</code>"] for u in as_list(g.get("navigation"))]
    table(["Main-frame navigation"], rows or [["<span class=muted>none (file input or failed load)</span>"]])
    redirects = [[f"<code>{e(defang(as_str(as_dict(r).get('from'), 2000)))}</code>", e(as_dict(r).get("status")),
                  f"<code>{e(defang(as_str(as_dict(r).get('to'), 2000)))}</code>"] for r in as_list(g.get("redirects"))]
    if redirects:
        table(["Redirect from", "Status", "To"], redirects)
    if g.get("tls"):
        add(f"<pre>{e(json.dumps(g.get('tls'), indent=1))}</pre>")
    add("</section>")

    canary = as_dict(obs.get("canary"))
    events = [as_dict(x) for x in as_list(obs.get("events"))]
    section("What the page tried to do", "The sandbox filled login forms with fake 'canary' credentials and "
            "clicked buttons such as 'Verify' or 'Download'. It recorded every clipboard write, wallet request, "
            "dialog, permission prompt, and download.")
    items = [
        ["Canary login", e(f"submitted {canary.get('submitted', 0)} time(s) as {as_str(canary.get('email'), 100)}")
         + "".join(f"<br>seen in <code>{e(defang(as_str(as_dict(h).get('url'), 600)))}</code>"
                   for h in as_list(canary.get("seen_in")))],
        ["Clicks", "<br>".join(e(as_str(as_dict(c).get("label"), 100)) for c in as_list(obs.get("clicks"))) or "none"],
        ["Downloads", "<br>".join(e(f"{as_str(as_dict(d).get('name'), 200)} ({as_dict(d).get('size', '?')} bytes, "
                                    f"{'automatic' if as_dict(d).get('auto') else 'after click'}) sha256 "
                                    f"{as_str(as_dict(d).get('sha256'), 64)}") for d in as_list(obs.get("downloads"))) or "none"],
        ["Popups", "<br>".join(f"<code>{e(defang(as_str(p, 600)))}</code>" for p in as_list(obs.get("popups"))) or "none"],
        ["Requests", e(f"{obs.get('requests', 0)} requests, {obs.get('console_errors', 0)} script errors, "
                       f"crashed: {bool(obs.get('crashed'))}")],
    ]
    for kind, label in (("clipboard", "Clipboard writes"), ("wallet", "Wallet requests"), ("dialog", "Dialogs"),
                        ("permission", "Permission prompts")):
        vals = [ev.get("data") for ev in events if ev.get("kind") == kind]
        items.append([label, "".join(f"<pre>{e(as_str(x, 3000) if isinstance(x, str) else json.dumps(x)[:3000])}</pre>"
                                     for x in vals[:12]) or "none"])
    table(["", ""], [[e(a), b] for a, b in items])
    add("</section>")

    files = [as_dict(f) for f in as_list(g.get("files"))]
    scan = as_dict(g.get("scanners"))
    if files or as_list(g.get("archives")):
        section("Files", "Downloads, the submitted file, repository contents, and unpacked archives. They were "
                "never executed. ClamAV and YARA scanned all of them.")
        table(["File", "Type", "Size", "SHA-256", "Flags"],
              [[f"<code>{e(as_str(f.get('path'), 300))}</code>", e(as_str(f.get("mime"), 100)), e(f.get("size")),
                f"<code>{e(as_str(f.get('sha256'), 64))}</code>", e("; ".join(as_list(f.get("flags"))))]
               for f in files[:300]])
        if as_list(g.get("archives")):
            add(f"<details><summary>Archives</summary><pre>{e(json.dumps(g.get('archives'), indent=1))}</pre></details>")
        if as_list(g.get("repo")):
            add(f"<details open><summary>Auto-run and install scripts</summary><pre>{e(json.dumps(g.get('repo'), indent=1))}</pre></details>")
        add("</section>")
    add(f"<section><h2>Scanners</h2><p class=hint>Signature databases are from the last `audit-content setup`.</p>"
        f"<pre>{e(json.dumps({'clamav': scan.get('clamav'), 'yara': scan.get('yara')}, indent=1))}</pre></section>")

    docs = as_list(sv.get("documents"))
    if docs:
        section("Documents, flattened", "Each page was rendered to a picture inside the sandbox. Macros, scripts, "
                "links, and embedded files are gone.")
        for d in map(as_dict, docs):
            add(f"<details open><summary>{e(as_str(d.get('name'), 200))}</summary>")
            for page in as_list(d.get("pages"))[:15]:
                data = _image(page, b"\xff\xd8\xff")
                if data:
                    add(f"<img class=shot alt=page src='data:image/jpeg;base64,{data}'>")
            add("</details>")
        add("</section>")

    if sv.get("text") or sv.get("links"):
        section("Page text and links", "Visible text and every link on the page. Links are defanged "
                "(hxxps, [.]) and cannot be clicked.")
        add(f"<details><summary>Text</summary><pre>{e(as_str(sv.get('text'), 60000))}</pre></details>")
        links = [f"{as_str(as_dict(x).get('text'), 120)}  →  {defang(as_str(as_dict(x).get('href'), 2000))}"
                 for x in as_list(sv.get("links"))]
        add(f"<details><summary>Links ({len(links)})</summary><pre>{e(chr(10).join(links))}</pre></details></section>")

    section("Network", "Every connection the sandbox made, as seen by the host proxy. Role: browse = the page, "
            "tools = analysis lookups, llm = the AI specialists. 'Page' marks hosts the page itself requested; "
            "other browse rows are the browser's own start-up traffic. Blocked rows were refused.")
    page_hosts = set(as_dict(obs.get("hosts")))
    table(["Role", "Method", "Host", "Page", "Address", "Status", "Up", "Down"],
          [[e(f.role), e(f.method), f"<code>{e(defang(f.host))}:{f.port}</code>",
            "yes" if f.role == "browse" and f.host in page_hosts else "", e(f.ip), e(f.status), e(f.up), e(f.down)]
           for f in v.flows[:400]])
    infra = g.get("infra")
    if infra:
        add(f"<details><summary>Domain data (RDAP, DNS, certificate history)</summary><pre>{e(json.dumps(infra, indent=1))}</pre></details>")
    add("</section>")

    iocs = sorted({defang(as_str(x, 500)) for rec in specs.values()
                   for x in as_list(as_dict(as_dict(rec).get("result")).get("iocs"))})
    if iocs:
        section("Indicators to share", "Defanged; paste them into a ticket for the security team.")
        add(f"<pre>{e(chr(10).join(iocs))}</pre></section>")
    add("<p class=muted>Generated by audit-content. The sandbox visited the link from this network, so the sender may "
        f"see that it was opened, and one-time links may now be used up. Timings: {e(json.dumps(g.get('timings')))}. "
        f"Notes: {e('; '.join(as_str(n, 300) for n in as_list(g.get('notes'))))}</p>")

    doc = ("<!doctype html><html lang=en><head><meta charset=utf-8>"
           "<meta http-equiv=Content-Security-Policy content=\"default-src 'none'; img-src data:; "
           "style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\">"
           "<meta name=viewport content='width=device-width,initial-scale=1'><meta name=referrer content=no-referrer>"
           f"<title>audit-content {v.level}</title><style>{REPORT_CSS}</style></head><body><main>"
           + "\n".join(out) + "</main></body></html>")
    fd, path = tempfile.mkstemp(prefix="audit-content-", suffix=".html")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(doc)
    return path


# --------------------------------------------------------------------------------------------
# setup / clean / uninstall
# --------------------------------------------------------------------------------------------

def builder_state() -> Optional[str]:
    rows = list_json(["builder", "status"])
    return as_str(as_dict(rows[0].get("status")).get("state"), 20) if rows else None


def builder_cache_ids() -> Optional[List[str]]:
    """IDs of the BuildKit cache records inside the (running) builder VM."""
    rc, out = run(["container", "exec", "buildkit", "buildctl", "du", "-v", "--format", "{{json .}}"], timeout=60)
    try:
        ids = [as_str(as_dict(r).get("id"), 100) for r in as_list(json.loads(out))] if rc == 0 else None
    except ValueError:
        return None
    return [i for i in ids if re.fullmatch(r"[a-z0-9]+", i)] if ids is not None else None


def drop_build_cache(keep: List[str]) -> None:
    """Delete the cache records this build added (records the builder already had stay), then TRIM the
    builder's disk so macOS gets the space back: without TRIM the VM's disk file would not shrink."""
    new = sorted(set(builder_cache_ids() or []) - set(keep))
    prune = "".join(f'buildctl prune --filter "id=={i}" >/dev/null 2>&1; ' for i in new)
    # Twice: a parent record becomes prunable only after its children are gone.
    run(["container", "exec", "buildkit", "sh", "-c", f"{prune}{prune}sync; fstrim / >/dev/null 2>&1; true"],
        timeout=600)


def image_id() -> Optional[str]:
    rc, out = run(["container", "image", "inspect", IMAGE], timeout=20)
    try:
        return as_str(as_dict(as_list(json.loads(out))[0]).get("id"), 100) if rc == 0 else None
    except (ValueError, IndexError):
        return None


def cmd_setup(rebuild: bool) -> int:
    ensure_runtime(install=True)
    if image_exists() and not rebuild:
        print(f"{IMAGE} is ready. Use `audit-content setup --rebuild` to refresh tools and signatures.")
        return 0
    for f in ("Containerfile", "sandbox.py"):
        if not (HERE / f).is_file():
            die(f"{f} must sit next to audit-content.py")
    old_id = image_id()
    builder_before = builder_state()
    m = re.search(r"^FROM\s+(\S+)", (HERE / "Containerfile").read_text(), re.M)
    base = m.group(1) if m else ""
    base_before = bool(base) and run(["container", "image", "inspect", base], timeout=20)[0] == 0
    keep: Optional[List[str]] = None
    if builder_before is not None:  # an existing builder may hold someone else's cache: remember it
        if builder_before != "running":
            run(["container", "builder", "start"], timeout=120)
        keep = builder_cache_ids()
    log("building the sandbox image (about 5-10 minutes; needs internet)")
    rc = 1
    try:
        with tempfile.TemporaryDirectory(prefix="audit-content-build-") as ctx:
            for f in ("Containerfile", "sandbox.py"):
                shutil.copy2(HERE / f, ctx)
            rc = subprocess.call(["container", "build", "--no-cache", "--pull", "--progress", "plain",
                                  "-t", IMAGE, "-f", str(Path(ctx) / "Containerfile"), ctx])
    finally:
        # The build layers are not needed again (rebuilds are rare and use --no-cache): delete them.
        # A builder we created goes entirely; an existing one loses only our records and keeps its state.
        log("removing the build cache")
        if builder_before is None:
            run(["container", "builder", "delete", "--force"], timeout=60)
        else:
            if keep is not None:
                drop_build_cache(keep)
            else:
                log("could not list the builder's cache, so it was left untouched")
            if builder_before != "running":
                run(["container", "builder", "stop"], timeout=60)
        # The build also stores its base image locally; keep only what was there before.
        if base and not base_before:
            run(["container", "image", "delete", base], timeout=60)
    if rc != 0:
        die("image build failed (see the output above)")
    new_id = image_id()
    if old_id and new_id and old_id != new_id:
        run(["container", "image", "delete", old_id], timeout=60)  # also garbage-collects its unpacked snapshot
    print(f"\n{IMAGE} built. Next: `audit-content auth` (once), then `audit-content <url>`.")
    return 0


def cmd_clean() -> int:
    ensure_runtime()
    n = sweep(force=True)
    print(f"Removed {n} leftover VM(s)/network(s).")
    return 0


def cmd_uninstall() -> int:
    ensure_runtime()
    sweep(force=True)
    run(["container", "image", "delete", IMAGE], timeout=60)
    run(["security", "delete-generic-password", "-a", KEYCHAIN_ACCOUNT, "-s", KEYCHAIN_SERVICE])
    print("Removed the image, leftovers, and the Keychain token. Delete this folder to finish.")
    return 0


# --------------------------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------------------------

def parse_target(url: Optional[str], file: Optional[str]) -> Tuple[Optional[Target], Optional[str]]:
    """Returns (target, refusal). A non-web scheme is refused with an explanation instead of a VM run."""
    if file:
        p = Path(file).expanduser()
        if not p.is_file():
            die(f"no such file: {file}")
        if p.stat().st_size > MAX_FILE:
            die(f"file larger than {MAX_FILE >> 20} MB")
        return Target(path=p), None
    if not url:
        die("give a URL or --file PATH (see --help)")
    assert url is not None
    url = url.strip()
    m = re.match(r"([a-zA-Z][a-zA-Z0-9+.-]*):", url)
    if m and m.group(1).lower() not in ("http", "https") and not re.match(r"[^:/]+:\d+(/|$)", url):
        return None, (f"This is a '{m.group(1).lower()}:' link, not a web page. Links like this can start programs "
                      f"or open files on your computer. Do not open it.")
    if "://" not in url:
        url = "https://" + url
    try:
        host = urllib.parse.urlsplit(url).hostname or ""
    except ValueError:
        host = ""
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False
    # Letters of any script are allowed (IDN lookalikes must still be checkable), whitespace and flags are not.
    if not (is_ip or re.fullmatch(r"[^\s/\\@:?#\-][^\s/\\@:?#]*\.[^\s/\\@:?#]+", host)) or len(url) > 8000:
        die(f"that does not look like a valid link: {clean(url)[:200]}")
    return Target(url=url), None


def main(argv: List[str]) -> int:
    os.environ["PATH"] = os.environ.get("PATH", "/usr/bin:/bin") + ":/usr/local/bin"  # where `container` installs
    commands = {"setup", "auth", "clean", "uninstall"}
    if argv[:1] and argv[0] in commands:
        p = argparse.ArgumentParser(prog=f"audit-content {argv[0]}")
        if argv[0] == "setup":
            p.add_argument("--rebuild", action="store_true", help="rebuild to refresh tools and signatures")
        a = p.parse_args(argv[1:])
        if argv[0] == "setup":
            return cmd_setup(bool(a.rebuild))
        return {"auth": cmd_auth, "clean": cmd_clean, "uninstall": cmd_uninstall}[argv[0]]()

    p = argparse.ArgumentParser(prog="audit-content", description="Check a link or file in a disposable microVM "
                                "before opening it. Commands: setup, auth, clean, uninstall.",
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("url", nargs="?", help="the link to check")
    p.add_argument("--file", help="check a local file instead of a link")
    p.add_argument("--report", action="store_true", help="write a self-contained HTML safe-view report")
    p.add_argument("--open", action="store_true", help="write the report and open it")
    p.add_argument("--json", action="store_true", help="print the verdict as JSON")
    p.add_argument("--upstream-proxy", help="HTTP proxy for the sandbox's internet traffic (http://host:port)")
    p.add_argument("--timeout", type=float, default=120.0, help="total time budget in seconds (default 120)")
    p.add_argument("--model", default="sonnet", help=argparse.SUPPRESS)
    p.add_argument("--cpus", type=int, default=4, help=argparse.SUPPRESS)
    p.add_argument("--memory", default="6g", help=argparse.SUPPRESS)
    p.add_argument("--raw", action="store_true", help=argparse.SUPPRESS)  # debug: dump the VM's raw result
    a = p.parse_args(argv)
    target, refusal = parse_target(a.url, a.file)
    if refusal is not None:
        if a.json:
            print(json.dumps({"verdict": "SUSPICIOUS", "incomplete": False, "target": a.url, "reasons": [
                {"severity": "SUSPICIOUS", "title": refusal, "source": "deterministic check"}]}))
        else:
            print(f"\nSUSPICIOUS  {clean(a.url or '')}\n  {refusal}\n")
        return 1
    assert target is not None
    upstream: Optional[Tuple[str, int]] = None
    if a.upstream_proxy:
        up = urllib.parse.urlsplit(a.upstream_proxy if "://" in a.upstream_proxy else f"http://{a.upstream_proxy}")
        if up.scheme != "http" or up.hostname is None:
            die("--upstream-proxy must look like http://host:port")
        upstream = (str(up.hostname), up.port or 8080)
    if a.timeout < 60:
        die("--timeout must be at least 60 seconds")
    ensure_runtime()
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(3))  # run cleanup in `finally` on kill
    signal.signal(signal.SIGHUP, lambda *_: sys.exit(3))
    log(f"checking {target.label}")
    try:
        v = run_check(target, a.timeout, upstream, bool(a.report or a.open), a.model, a.cpus, a.memory)
    except RuntimeError as e:
        die(str(e))
        return 3
    except KeyboardInterrupt:
        log("interrupted; the VM and its network were removed")
        return 3
    if a.report or a.open:
        v.report = write_report(v, target)
        if a.open:
            run(["open", v.report], timeout=10)
    if a.raw:
        print(json.dumps({k: x for k, x in v.guest.items() if k != "safe_view"}, indent=1)[:200000])
    if a.json:
        print(json.dumps(verdict_json(v, target), indent=1))
    else:
        print_summary(v, target)
    return EXIT[v.level]


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
