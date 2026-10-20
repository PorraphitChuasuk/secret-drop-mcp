// The form. Everything about the request comes from the link's #fragment, which
// browsers never send to GitHub: t = tunnel host, i = request id, n = name,
// p = required prefix, m = note.
import { seal } from './seal.js';

const $ = (id) => document.getElementById(id);
const q = new URLSearchParams(location.hash.slice(1));
const req = { host: q.get('t') || '', id: q.get('i') || '', name: q.get('n') || '', prefix: q.get('p') || '', note: q.get('m') || '' };

function say(text, kind = '') {
  $('status').textContent = text;
  $('status').className = kind;
}

async function main() {
  if (!/^[a-z0-9-]+\.trycloudflare\.com$/.test(req.host) || !/^[A-Za-z0-9_-]{32}$/.test(req.id)
      || !/^[a-z0-9][a-z0-9-]{0,63}$/.test(req.name)) {
    say('This link is incomplete. Ask for a new one.', 'error');
    return;
  }
  $('name').textContent = req.name;
  if (req.note) {
    $('note').textContent = req.note;
    $('note').hidden = false;
  }
  if (req.prefix) $('hint').textContent = `Starts with ${req.prefix}`;

  let key;
  try {
    key = await (await fetch('pubkey.json', { cache: 'no-store' })).json();
  } catch {
    say("Couldn't load the server's key. Reload the page.", 'error');
    return;
  }
  $('kid').textContent = key.kid;
  $('form').hidden = false;
  $('secret').focus();

  $('show').addEventListener('click', () => {
    const hidden = $('secret').type === 'password';
    $('secret').type = hidden ? 'text' : 'password';
    $('show').textContent = hidden ? 'Hide' : 'Show';
  });

  $('form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const value = $('secret').value.trim();
    if (!value) return;
    if (req.prefix && !value.startsWith(req.prefix)) {
      say(`That doesn't look right: it should start with ${req.prefix}`, 'error');
      return;
    }
    $('send').disabled = true;
    say('Encrypting and sending…');
    let sealed;
    try {
      sealed = await seal(key.key, req.id, req.name, value);
    } catch {
      say("This browser couldn't encrypt it. Try an up-to-date Safari, Chrome or Firefox.", 'error');
      $('send').disabled = false;
      return;
    }
    try {
      const r = await fetch(`https://${req.host}/r/${req.id}`, {
        method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ ...sealed, kid: key.kid }),
      });
      const body = await r.json().catch(() => ({}));
      if (r.ok) {
        $('secret').value = '';
        $('form').hidden = true;
        history.replaceState(null, '', location.pathname);
        say(`Saved on the server (${body.length} characters). You can close this page.`, 'ok');
        return;
      }
      say(body.error || `The server answered ${r.status}.`, 'error');
    } catch {
      say("Couldn't reach the server. The link may have expired; ask for a new one.", 'error');
    }
    $('send').disabled = false;
  });
}

main();
