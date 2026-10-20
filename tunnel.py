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
import urllib.request

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
            deadline = time.monotonic() + timeout
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
            if not registered.wait(timeout) or proc.poll() is not None or not found:
                self._stop_locked()
                raise RuntimeError("cloudflared did not come up: " + " | ".join(list(self.log)[-5:]))
            # The new hostname takes a few seconds to resolve; wait until the receiver answers through it.
            while time.monotonic() < deadline:
                try:
                    with urllib.request.urlopen(found[0] + "/healthz", timeout=5) as r:
                        if r.status == 200:
                            self.url = found[0]
                            return self.url
                except OSError:
                    pass
                time.sleep(1)
            self._stop_locked()
            raise RuntimeError("tunnel %s never became reachable" % found[0])

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
