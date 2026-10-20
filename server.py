#!/usr/bin/env python3
"""secret-drop MCP server.

Asks the user for a secret through a one-time web form instead of the chat. The
page (docs/, on GitHub Pages) encrypts it in the browser to this server's public
key and posts only ciphertext through a temporary Cloudflare quick tunnel, so
this server is the only place it is ever readable. It's saved to
~/.config/secrets/<name>. No tool returns a secret's value.

    server.py                   run as an MCP server (stdio)
    server.py init-key          create the key pair and write docs/pubkey.json
    server.py request NAME ...  request_secret from a shell; sends (or prints) the link, then waits
"""
from __future__ import annotations

import argparse
import asyncio
import atexit
import json
import sys
from pathlib import Path

from mcp.server.mcpserver import MCPServer

import drop
from sealing import KeyPair

mcp = MCPServer("secret-drop")
box = drop.Dropbox()
atexit.register(box.close)


@mcp.tool()
async def request_secret(name: str, prefix: str = "", note: str = "", minutes: int = 15,
                         send_link: bool = True) -> dict:
    """Ask the user for a secret (API token, password, webhook URL, ...) without it passing through the chat.

    Opens a one-time form. The user pastes the secret into it, their browser encrypts it to this
    server's key, and it's saved to ~/.config/secrets/<name> (mode 600; an older value is kept as
    <name>.prev). Never ask the user to paste a secret into the chat instead. Then wait with
    secret_status.

    The form link is sent straight to the user (e.g. to their Google Chat) and not returned:
    when `delivered` is true, just tell them it's there - don't repeat or ask for the link. Only
    when `delivered` is false is `link` returned: then give it to the user exactly as returned, in
    full, on its own line (it's long; a shortened one won't work).

    name: file name - lowercase letters, digits and dashes, e.g. "gchat-webhook".
    prefix: optional start the value must have, e.g. "https://chat.googleapis.com/"; others are refused.
    note: optional line shown with the link and on the form, e.g. what it's for or where to find it.
    minutes: how long the link stays valid, 1-60 (default 15).
    send_link: False returns the link instead of sending it, e.g. if the user says it never arrived."""
    req, link = await asyncio.to_thread(box.create, name, prefix, note, minutes)
    sent, why = await asyncio.to_thread(drop.deliver, req, link) if send_link else (False, "send_link=False")
    if sent:
        return {**req.info(), "delivered": True}
    return {**req.info(), "delivered": False, "not_delivered_because": why, "link": link}


@mcp.tool()
async def secret_status(request_id: str, wait_seconds: int = 0) -> dict:
    """Status of a request_secret request: pending, saved, expired, cancelled, or unknown.

    wait_seconds (0-300) blocks until it's no longer pending or the time is up. Once saved it
    reports the path and length, never the value. Only this session's requests are known."""
    return await asyncio.to_thread(box.status, request_id, wait_seconds)


@mcp.tool()
def cancel_secret_request(request_id: str) -> dict:
    """Cancel a pending request_secret request, so its link stops working."""
    return box.cancel(request_id)


@mcp.tool()
def list_secrets() -> list:
    """Secrets saved in ~/.config/secrets: name, path, size, modified time. Never the values."""
    return drop.list_secrets()


def _cli(argv: list[str]) -> None:
    ap = argparse.ArgumentParser(prog="server.py")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init-key", help="create the key pair (if missing) and write docs/pubkey.json")
    rq = sub.add_parser("request", help="ask for a secret; sends (or prints) the link, then waits for the result")
    rq.add_argument("name")
    rq.add_argument("--prefix", default="")
    rq.add_argument("--note", default="")
    rq.add_argument("--minutes", type=int, default=15)
    rq.add_argument("--print-link", action="store_true", help="print the link instead of sending it")
    args = ap.parse_args(argv)

    if args.cmd == "init-key":
        keys = KeyPair.load(drop.KEY_PATH) if drop.KEY_PATH.exists() else KeyPair.create(drop.KEY_PATH)
        out = Path(__file__).resolve().with_name("docs") / "pubkey.json"
        out.write_text(json.dumps(keys.public_json(), indent=2) + "\n")
        print("key %s (%s): wrote %s - commit and push it" % (keys.kid, drop.KEY_PATH, out))
        return

    req, link = box.create(args.name, args.prefix, args.note, args.minutes)
    sent, why = (False, "--print-link") if args.print_link else drop.deliver(req, link)
    print("sent the form link to the user" if sent else link, flush=True)
    info = box.status(req.id)
    while info["status"] == "pending":
        info = box.status(req.id, 300)
    print(json.dumps(info), flush=True)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        _cli(sys.argv[1:])
    else:
        mcp.run()
