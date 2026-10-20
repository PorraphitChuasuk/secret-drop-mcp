"""A Cloudflare quick tunnel (https://<random>.trycloudflare.com) to the local receiver.

Needs no Cloudflare account. It only carries ciphertext (see sealing.py), and it
runs only while a request is pending.
"""
from __future__ import annotations

import collections
import os
import re
import signal
import subprocess
import threading
import time
import urllib.parse
import urllib.request

import dns.exception
import dns.message
import dns.query
import dns.rcode
import dns.resolver

_URL = re.compile(r"https://[a-z0-9-]+\.trycloudflare\.com")

# cloudflared can't exit with its parent, and PR_SET_PDEATHSIG fires when the
# spawning *thread* ends, so a shell loop kills it if this process dies uncleanly.
_WATCHDOG = ('cloudflared "$@" & c=$!; '
             'while kill -0 "$WATCH_PID" 2>/dev/null && kill -0 $c 2>/dev/null; do sleep 2; done; '
             'kill $c 2>/dev/null')


class Tunnel:
    def __init__(self):
        self._lock = threading.Lock()
        self._proc: subprocess.Popen | None = None
        self.url: str | None = None
        self.log: collections.deque[str] = collections.deque(maxlen=30)

    def start(self, port: int, timeout: float = 45) -> str:
        """Start the tunnel (or reuse a running one) and return its URL once it answers."""
        with self._lock:
            if self._proc and self._proc.poll() is None and self.url:
                return self.url
            self._stop_locked()
            try:
                self.url = self._spawn(port, time.monotonic() + timeout)
            except BaseException:
                self._stop_locked()
                raise
            return self.url

    def _spawn(self, port: int, deadline: float) -> str:
        proc = self._proc = subprocess.Popen(
            ["sh", "-c", _WATCHDOG, "sh", "tunnel", "--no-autoupdate", "--grace-period", "3s",
             "--url", "http://127.0.0.1:%d" % port],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            text=True, env=dict(os.environ, WATCH_PID=str(os.getpid())), start_new_session=True)
        registered = threading.Event()
        found: list[str] = []

        def read():
            for line in proc.stderr:
                self.log.append(line.rstrip())
                m = _URL.search(line)
                if m and not found:
                    found.append(m.group(0))
                if "Registered tunnel connection" in line:
                    registered.set()
            registered.set()  # exited

        threading.Thread(target=read, daemon=True).start()
        if not registered.wait(deadline - time.monotonic()) or proc.poll() is not None or not found:
            raise RuntimeError("cloudflared did not come up: " + " | ".join(list(self.log)[-5:]))
        url = found[0]
        # The hostname is published a few seconds after registration. Looking it up any earlier
        # gets a "no such name" that resolvers cache for minutes (here and wherever the link is
        # opened), so ask Cloudflare's nameservers directly, which cache nothing, until it exists.
        while not _published(urllib.parse.urlsplit(url).hostname):
            if time.monotonic() >= deadline:
                raise RuntimeError("%s was never published in DNS" % url)
            time.sleep(0.5)
        while time.monotonic() < deadline:
            try:
                with urllib.request.urlopen(url + "/healthz", timeout=5) as r:
                    if r.status == 200:
                        return url
            except OSError:
                pass
            time.sleep(1)
        raise RuntimeError("tunnel %s never became reachable" % url)

    def stop(self) -> None:
        with self._lock:
            self._stop_locked()

    def _stop_locked(self) -> None:
        proc, self._proc, self.url = self._proc, None, None
        if proc is None or proc.poll() is not None:
            return
        try:
            os.killpg(proc.pid, signal.SIGTERM)
            proc.wait(timeout=5)
        except ProcessLookupError:
            pass
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)


def _published(host: str) -> bool:
    """Whether trycloudflare.com's own nameservers have a record for host yet (asked non-recursively)."""
    query = dns.message.make_query(host, "A")
    query.flags = 0  # no recursion: the authoritative answer, with no cache in between
    for ip in _nameservers():
        try:
            answer = dns.query.udp(query, ip, timeout=2)
        except (OSError, dns.exception.DNSException):
            continue
        return answer.rcode() == dns.rcode.NOERROR and bool(answer.answer)
    return False


_ns_cache: list[str] = []


def _nameservers() -> list[str]:
    if not _ns_cache:
        for ns in dns.resolver.resolve("trycloudflare.com", "NS"):
            _ns_cache.extend(a.address for a in dns.resolver.resolve(ns.target, "A"))
    return _ns_cache
