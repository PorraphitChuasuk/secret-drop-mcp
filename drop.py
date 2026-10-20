"""One-time secret requests, the local receiver behind the tunnel, and writes to ~/.config/secrets.

A request is a random id the form posts to. It takes one secret and is then
done; an unused one expires. A secret's value is never logged, printed or
returned, only its length.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import subprocess
import threading
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from sealing import KeyPair
from tunnel import Tunnel

PAGE_URL = os.environ.get("SECRET_DROP_PAGE_URL", "https://porraphitchuasuk.github.io/secret-drop-mcp/")
PAGE_ORIGIN = "{0.scheme}://{0.netloc}".format(urllib.parse.urlsplit(PAGE_URL))
KEY_PATH = Path(os.environ.get("SECRET_DROP_KEY", "~/.config/secret-drop/key.pem")).expanduser()
SECRETS_DIR = Path(os.environ.get("SECRET_DROP_DIR", "~/.config/secrets")).expanduser()
# Optional command that sends a message straight to the user, run as: NOTIFY <text> <label> <url>.
# It must exit 0 only when sent. Then the link never has to pass through the chat.
NOTIFY = os.environ.get("SECRET_DROP_NOTIFY", "")

NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")
_POST_PATH = re.compile(r"/r/([A-Za-z0-9_-]{32})")
MAX_BODY = 64 * 1024
MAX_SECRET = 32 * 1024
MAX_FAILURES = 5
STOP_DELAY = 3  # seconds, so the last response gets out before the tunnel goes down


def _iso(t: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


@dataclass
class Request:
    id: str
    name: str
    prefix: str
    note: str
    expires_at: float
    status: str = "pending"  # pending | saved | expired | cancelled
    saved_at: float | None = None
    length: int | None = None
    failures: int = 0

    def info(self) -> dict:
        d = {"request_id": self.id, "name": self.name, "status": self.status,
             "expires_at": _iso(self.expires_at)}
        if self.status == "saved":
            d.update(saved_at=_iso(self.saved_at), length=self.length, path=str(SECRETS_DIR / self.name))
        return d


def write_secret(name: str, value: str) -> Path:
    """Atomically write SECRETS_DIR/<name> (mode 600), keeping the old value as <name>.prev."""
    SECRETS_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(SECRETS_DIR, 0o700)
    path = SECRETS_DIR / name
    tmp = SECRETS_DIR / (".%s.%s.tmp" % (name, secrets.token_hex(4)))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(value)
        f.flush()
        os.fsync(f.fileno())
    if path.exists():
        os.replace(path, SECRETS_DIR / (name + ".prev"))
    os.replace(tmp, path)
    return path


def deliver(req: Request, link: str) -> tuple[bool, str]:
    """Send the form link to the user with NOTIFY. Returns (sent, why not)."""
    if not NOTIFY:
        return False, "SECRET_DROP_NOTIFY is not set"
    text = "🔐 Claude is asking for a secret: *%s*" % req.name
    if req.note:
        text += "\n" + req.note
    text += "\nThe link works once, for %d minutes." % max(1, round((req.expires_at - time.time()) / 60))
    try:
        # Output is captured: on failure the notifier may print the link, and stdout here may be MCP's.
        r = subprocess.run([NOTIFY, text, "Open the secret form", link],
                           stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, str(e)
    if r.returncode == 0:
        return True, ""
    return False, (r.stderr.strip().splitlines() or ["%s exited %d" % (NOTIFY, r.returncode)])[-1]


def list_secrets() -> list:
    if not SECRETS_DIR.is_dir():
        return []
    out = []
    for p in sorted(SECRETS_DIR.iterdir()):
        if NAME.fullmatch(p.name) and p.is_file():
            st = p.stat()
            out.append({"name": p.name, "path": str(p), "bytes": st.st_size, "modified": _iso(st.st_mtime),
                        "has_previous": (SECRETS_DIR / (p.name + ".prev")).exists()})
    return out


class Dropbox:
    def __init__(self, keys: KeyPair | None = None, tunnel: Tunnel | None = None):
        self._key_pair = keys
        self.tunnel = tunnel or Tunnel()
        self._requests: dict[str, Request] = {}
        self._changed = threading.Condition()
        # Held across "add a request + start the tunnel" and "no pending left -> stop it".
        self._tunnel_lock = threading.Lock()
        self._server: ThreadingHTTPServer | None = None

    @property
    def keys(self) -> KeyPair:
        if self._key_pair is None:
            if not KEY_PATH.exists():
                raise RuntimeError("no key at %s - run: server.py init-key" % KEY_PATH)
            self._key_pair = KeyPair.load(KEY_PATH)
        return self._key_pair

    def create(self, name: str, prefix: str = "", note: str = "", minutes: int = 15) -> tuple[Request, str]:
        """Open a request and return it with the form link for the user."""
        if not NAME.fullmatch(name or ""):
            raise ValueError("name must be lowercase letters, digits and dashes (max 64), e.g. gchat-webhook")
        self._check_published_key()
        with self._tunnel_lock:
            req = self._add(name, prefix, note, minutes)
            try:
                url = self.tunnel.start(self._receiver_port())
            except Exception:
                with self._changed:
                    del self._requests[req.id]
                raise
        fragment = urllib.parse.urlencode(
            {"t": urllib.parse.urlsplit(url).netloc, "i": req.id, "n": name, "p": req.prefix, "m": req.note},
            quote_via=urllib.parse.quote)
        return req, PAGE_URL + "#" + fragment

    def _add(self, name: str, prefix: str, note: str, minutes: int) -> Request:
        minutes = max(1, min(int(minutes), 60))
        req = Request(id=secrets.token_urlsafe(24), name=name, prefix=prefix or "", note=note or "",
                      expires_at=time.time() + minutes * 60)
        with self._changed:
            self._requests[req.id] = req
        self._later(minutes * 60, self._expire, req.id)
        return req

    def _check_published_key(self) -> None:
        """Refuse to hand out a link if the page would encrypt to a different key."""
        url = urllib.parse.urljoin(PAGE_URL, "pubkey.json") + "?t=%d" % time.time()
        try:
            with urllib.request.urlopen(url, timeout=10) as r:
                published = json.load(r)
        except (OSError, ValueError) as e:
            raise RuntimeError("could not fetch the published key %s: %s" % (url, e)) from e
        if published.get("key") != self.keys.public_b64u:
            raise RuntimeError("%s has key %s but this server's is %s - push docs/pubkey.json and wait for Pages"
                               % (url, published.get("kid"), self.keys.kid))

    def receive(self, request_id: str, payload: dict) -> tuple[int, dict]:
        """Handle one POST from the form: (HTTP status, JSON body)."""
        with self._changed:
            req = self._requests.get(request_id)
            if req and req.status == "pending" and time.time() >= req.expires_at:
                self._finish(req, "expired")
            if not req or req.status != "pending":
                return 410, {"error": "This link has expired or was already used. Ask for a new one."}
            if payload.get("kid") != self.keys.kid:
                return 409, {"error": "This page has an old copy of the server's key. Reload it and try again."}
            try:
                value = self.keys.open(payload, req.id, req.name).strip()
            except ValueError:
                req.failures += 1
                if req.failures >= MAX_FAILURES:
                    self._finish(req, "cancelled")
                return 400, {"error": "The server couldn't decrypt that. Reload the page and try again."}
            if not value:
                return 422, {"error": "That was empty."}
            if len(value) > MAX_SECRET:
                return 413, {"error": "That's too long (max %d characters)." % MAX_SECRET}
            if req.prefix and not value.startswith(req.prefix):
                return 422, {"error": "That doesn't look right: it should start with %s" % req.prefix}
            write_secret(req.name, value)
            req.saved_at, req.length = time.time(), len(value)
            self._finish(req, "saved")
            return 200, {"ok": True, "name": req.name, "length": req.length}

    def status(self, request_id: str, wait_seconds: float = 0) -> dict:
        """The request's info; with wait_seconds, block until it's no longer pending (max 300s)."""
        deadline = time.monotonic() + max(0, min(wait_seconds, 300))
        with self._changed:
            while True:
                req = self._requests.get(request_id)
                if req is None:
                    return {"request_id": request_id, "status": "unknown",
                            "detail": "not a request of this server (each session runs its own)"}
                if req.status == "pending" and time.time() >= req.expires_at:
                    self._finish(req, "expired")
                left = deadline - time.monotonic()
                if req.status != "pending" or left <= 0:
                    return req.info()
                self._changed.wait(min(left, max(0.1, req.expires_at - time.time())))

    def cancel(self, request_id: str) -> dict:
        with self._changed:
            req = self._requests.get(request_id)
            if req and req.status == "pending":
                self._finish(req, "cancelled")
        return self.status(request_id)

    def close(self) -> None:
        self.tunnel.stop()
        if self._server:
            self._server.shutdown()

    def _expire(self, request_id: str) -> None:
        with self._changed:
            req = self._requests.get(request_id)
            if req and req.status == "pending":
                self._finish(req, "expired")

    def _finish(self, req: Request, status: str) -> None:
        """Call with self._changed held."""
        req.status = status
        self._changed.notify_all()
        self._later(STOP_DELAY, self._stop_if_idle)

    def _stop_if_idle(self) -> None:
        with self._tunnel_lock:
            with self._changed:
                if any(r.status == "pending" for r in self._requests.values()):
                    return
            self.tunnel.stop()

    @staticmethod
    def _later(seconds: float, fn, *args) -> None:
        t = threading.Timer(seconds, fn, args)
        t.daemon = True
        t.start()

    def _receiver_port(self) -> int:
        if self._server is None:
            self._server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
            self._server.box = self
            threading.Thread(target=self._server.serve_forever, daemon=True).start()
        return self._server.server_address[1]


class _Handler(BaseHTTPRequestHandler):
    server_version = "secret-drop"
    sys_version = ""

    def log_message(self, format, *args):
        pass  # request paths carry the one-time id

    def _cors(self) -> None:
        self.send_header("Access-Control-Allow-Origin", PAGE_ORIGIN)
        self.send_header("Vary", "Origin")

    def _reply(self, code: int, body: dict) -> None:
        data = json.dumps(body).encode()
        self.send_response(code)
        self._cors()
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/healthz":
            self._reply(200, {"ok": True})
        else:
            self._reply(404, {"error": "not found"})

    def do_OPTIONS(self):
        if not _POST_PATH.fullmatch(self.path):
            return self._reply(404, {"error": "not found"})
        self.send_response(204)
        self._cors()
        self.send_header("Access-Control-Allow-Methods", "POST")
        self.send_header("Access-Control-Allow-Headers", "content-type")
        self.send_header("Access-Control-Max-Age", "600")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        m = _POST_PATH.fullmatch(self.path)
        if not m:
            return self._reply(404, {"error": "not found"})
        try:
            n = int(self.headers.get("Content-Length", ""))
        except ValueError:
            n = -1
        if not 0 < n <= MAX_BODY:
            return self._reply(413, {"error": "bad or missing Content-Length"})
        try:
            payload = json.loads(self.rfile.read(n))
        except ValueError:
            payload = None
        if not isinstance(payload, dict):
            return self._reply(400, {"error": "bad request"})
        self._reply(*self.server.box.receive(m.group(1), payload))
