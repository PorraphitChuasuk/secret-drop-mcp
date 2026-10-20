# secret-drop-mcp

A small MCP server that lets Claude **ask you for a secret** (API token,
password, webhook URL, …) **without it passing through the chat**. You get a
one-time link, paste the secret into a form, and your browser encrypts it so
that only the server that asked can read it. It's saved to
`~/.config/secrets/<name>`.

```
your browser ──loads the form──────▶ GitHub Pages (docs/: static code + the server's PUBLIC key)
     │  encrypts in the browser (WebCrypto)
     └──ciphertext only──▶ Cloudflare quick tunnel ──▶ this server (PRIVATE key decrypts, writes the file)
```

## Tools

| Tool | What it does |
|------|--------------|
| `request_secret(name, prefix?, note?, minutes?, send_link?)` | Opens a one-time form and sends its link to you (see below), or returns it. `prefix` refuses values that don't start with it; `note` is shown with the link and on the form; the link is valid 1–60 min (default 15). |
| `secret_status(request_id, wait_seconds?)` | `pending` / `saved` (path, length) / `expired` / `cancelled`. Waits up to 300 s for a change. |
| `cancel_secret_request(request_id)` | Kills a pending link. |
| `list_secrets()` | Names, sizes and dates in `~/.config/secrets`. |

**No tool ever returns a secret's value.** Secrets are written only to
`~/.config/secrets/<name>` (`name`: lowercase letters, digits, dashes), mode
600 in a 700 directory, with the previous value kept as `<name>.prev`.

## Sending the link

Set `SECRET_DROP_NOTIFY` to a command that messages you directly; it's run as
`$SECRET_DROP_NOTIFY <text> <label> <url>` and must exit 0 only when sent.
Then the link goes straight to you and isn't returned to Claude, so a long URL
never has to be retyped in the chat. Without it, or if sending fails,
`request_secret` returns the link for Claude to pass on.

## How it protects the secret

- **Encryption:** ECDH P-256 with a one-off browser key pair → HKDF-SHA256 →
  AES-256-GCM ([`docs/seal.js`](docs/seal.js), opened by
  [`sealing.py`](sealing.py)). The ciphertext is bound to its request id and
  name, so it can't be replayed into another request.
- **Cloudflare** only ever sees ciphertext. It never serves the page's code, so
  it has nothing to tamper with. The tunnel runs only while a request is
  pending, and nothing else answers through it.
- **GitHub** serves the static code and public key, and never sees the
  secret. Check the page address is `porraphitchuasuk.github.io/secret-drop-mcp`.
- **The link's `#fragment`** (tunnel host, request id, name) is never sent to
  GitHub. Each link takes one secret, refuses repeated garbage, and expires.
- Before handing out a link, the server checks that the published
  `docs/pubkey.json` matches its own key.

## Setup

```sh
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python server.py init-key        # ~/.config/secret-drop/key.pem + docs/pubkey.json
git add docs/pubkey.json && git commit -m "Publish server key" && git push
claude mcp add --scope user secret-drop -- "$PWD/.venv/bin/python" "$PWD/server.py"
# optional, to send links directly: register with an env
claude mcp add-json --scope user secret-drop \
  '{"type":"stdio","command":"'"$PWD"'/.venv/bin/python","args":["'"$PWD"'/server.py"],"env":{"SECRET_DROP_NOTIFY":"/path/to/notify"}}'
```

Needs `cloudflared` (Cloudflare's apt repo), and GitHub Pages serving `docs/`
from `main`. From a shell, `server.py request NAME [--prefix …] [--note …]`
prints the link and waits for the result.

Tests (`node` runs `docs/seal.js` exactly as the browser would):

```sh
.venv/bin/python -m unittest discover -s tests
```
