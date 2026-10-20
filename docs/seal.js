// Seals a secret to the server's public key, so only that server can read it.
// ECDH P-256 with a one-off key pair -> HKDF-SHA256 (salted with the request id)
// -> AES-256-GCM, bound to the request with associated data. Mirrors sealing.py.
const INFO = 'secret-drop v1';
const enc = new TextEncoder();

const b64u = (buf) => {
  let s = '';
  for (const b of new Uint8Array(buf)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};
const unb64u = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));

export async function seal(publicKey, requestId, name, secret) {
  const { subtle } = globalThis.crypto;
  const ecdh = { name: 'ECDH', namedCurve: 'P-256' };
  const server = await subtle.importKey('raw', unb64u(publicKey), ecdh, false, []);
  const mine = await subtle.generateKey(ecdh, true, ['deriveBits']);
  const shared = await subtle.deriveBits({ name: 'ECDH', public: server }, mine.privateKey, 256);
  const hkdf = await subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
  const key = await subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: enc.encode(requestId), info: enc.encode(INFO) },
    hkdf, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const ct = await subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: enc.encode(`${INFO}\n${requestId}\n${name}`) },
    key, enc.encode(secret));
  return { v: 1, epk: b64u(await subtle.exportKey('raw', mine.publicKey)), iv: b64u(iv), ct: b64u(ct) };
}
