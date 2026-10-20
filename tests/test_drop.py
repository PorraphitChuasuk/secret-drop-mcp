"""Unit tests: the page's seal.js against sealing.py, and the receiver (stdlib unittest).

    .venv/bin/python -m unittest discover -s tests
"""
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import drop  # noqa: E402
from sealing import KeyPair  # noqa: E402

_NODE_SEAL = ("import {seal} from %s; const [k, i, n, s] = process.argv.slice(1);"
              "console.log(JSON.stringify(await seal(k, i, n, s)));"
              % json.dumps((ROOT / "docs" / "seal.js").as_uri()))


def node_seal(keys: KeyPair, request_id: str, name: str, secret: str) -> dict:
    """Seal with the exact code the browser runs."""
    out = subprocess.run(["node", "--no-warnings", "--input-type=module", "-e", _NODE_SEAL,
                          keys.public_b64u, request_id, name, secret],
                         check=True, capture_output=True, text=True)
    return json.loads(out.stdout)


@unittest.skipUnless(shutil.which("node"), "node is needed to run docs/seal.js as the browser would")
class SealInterop(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.keys = KeyPair.create(Path(cls.tmp.name) / "key.pem")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_key_file_is_private(self):
        mode = stat.S_IMODE(os.stat(Path(self.tmp.name) / "key.pem").st_mode)
        self.assertEqual(mode, 0o600, "the private key must be readable by its owner only")

    def test_round_trip(self):
        secret = "https://chat.googleapis.com/v1/spaces/X/messages?key=a&token=b ✓"
        sealed = node_seal(self.keys, "r" * 32, "gchat-webhook", secret)
        self.assertEqual(self.keys.open(sealed, "r" * 32, "gchat-webhook"), secret)

    def test_bound_to_request_and_name(self):
        sealed = node_seal(self.keys, "a" * 32, "one", "s3cret")
        with self.assertRaises(ValueError, msg="replayed into another request"):
            self.keys.open(sealed, "b" * 32, "one")
        with self.assertRaises(ValueError, msg="replayed under another name"):
            self.keys.open(sealed, "a" * 32, "two")

    def test_tampered_or_wrong_key_fails(self):
        sealed = node_seal(self.keys, "a" * 32, "one", "s3cret")
        flipped = dict(sealed, ct=("A" if sealed["ct"][0] != "A" else "B") + sealed["ct"][1:])
        with self.assertRaises(ValueError):
            self.keys.open(flipped, "a" * 32, "one")
        other = KeyPair.create(Path(self.tmp.name) / "other.pem")
        with self.assertRaises(ValueError, msg="only the server's own key can open it"):
            other.open(sealed, "a" * 32, "one")


@unittest.skipUnless(shutil.which("node"), "node is needed to run docs/seal.js as the browser would")
class Receiver(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._dir, drop.SECRETS_DIR = drop.SECRETS_DIR, Path(self.tmp.name) / "secrets"
        self.keys = KeyPair.create(Path(self.tmp.name) / "key.pem")
        self.box = drop.Dropbox(keys=self.keys)

    def tearDown(self):
        drop.SECRETS_DIR = self._dir
        self.tmp.cleanup()

    def post(self, req, secret):
        return self.box.receive(req.id, dict(node_seal(self.keys, req.id, req.name, secret), kid=self.keys.kid))

    def test_saves_once_with_private_mode_and_keeps_previous(self):
        drop.write_secret("hook", "old")
        req = self.box._add("hook", "https://x/", "", 15)
        self.assertEqual(self.post(req, "  https://x/new\n")[0], 200)
        path = drop.SECRETS_DIR / "hook"
        self.assertEqual(path.read_text(), "https://x/new", "saved trimmed, without a newline")
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(drop.SECRETS_DIR.stat().st_mode), 0o700)
        self.assertEqual((drop.SECRETS_DIR / "hook.prev").read_text(), "old")
        info = self.box.status(req.id)
        self.assertEqual((info["status"], info["length"]), ("saved", len("https://x/new")))
        self.assertNotIn("https://x/new", json.dumps(info), "status must never contain the value")
        self.assertEqual(self.post(req, "https://x/again")[0], 410, "a link takes one secret only")
        self.assertEqual([s["name"] for s in drop.list_secrets()], ["hook"], ".prev and temp files aren't listed")

    def test_wrong_prefix_is_refused_and_request_stays_open(self):
        req = self.box._add("hook", "https://chat.googleapis.com/", "", 15)
        code, body = self.post(req, "https://evil.example/")
        self.assertEqual(code, 422)
        self.assertIn("should start with", body["error"])
        self.assertEqual(self.box.status(req.id)["status"], "pending")
        self.assertFalse((drop.SECRETS_DIR / "hook").exists())

    def test_stale_page_key_is_refused(self):
        req = self.box._add("hook", "", "", 15)
        sealed = dict(node_seal(self.keys, req.id, req.name, "v"), kid="0" * 16)
        self.assertEqual(self.box.receive(req.id, sealed)[0], 409)

    def test_garbage_cancels_after_repeated_failures(self):
        req = self.box._add("hook", "", "", 15)
        bad = {"v": 1, "epk": "AA", "iv": "AA", "ct": "AA", "kid": self.keys.kid}
        for _ in range(drop.MAX_FAILURES):
            self.assertEqual(self.box.receive(req.id, bad)[0], 400)
        self.assertEqual(self.box.status(req.id)["status"], "cancelled")

    def test_expiry_and_unknown(self):
        req = self.box._add("hook", "", "", 15)
        req.expires_at = time.time() - 1
        self.assertEqual(self.post(req, "v")[0], 410)
        self.assertEqual(self.box.status(req.id)["status"], "expired")
        self.assertEqual(self.box.status("x" * 32)["status"], "unknown")

    def test_rejects_bad_names(self):
        for name in ("../etc", "Hook", "a.b", "", "-x"):
            with self.assertRaises(ValueError, msg=name):
                self.box.create(name)


if __name__ == "__main__":
    unittest.main()
