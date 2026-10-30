// Client-side encryption. Keys are derived here and never leave the browser;
// the server only receives derived auth keys, public keys and ciphertext.
//
//   master password --PBKDF2-SHA256--> secret --HKDF--> auth key (sent to server)
//                                             \-HKDF--> KEK (wraps the user's private key)
//   user ECDH P-256 key pair: public key on server, private key wrapped by KEK
//   project key (random AES-256): wrapped once per member with ECIES to their public key
//   entry  -> AES-GCM with the project key
//   file   -> AES-GCM with its own random key, stored inside the (encrypted) entry

export const KDF_ITERATIONS = 1_000_000;
const PRIVATE_KEY_AAD = 'user-private-key-v1';
const ECDH = { name: 'ECDH', namedCurve: 'P-256' };
const enc = new TextEncoder();
const dec = new TextDecoder();

export function toB64(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary);
}

export function fromB64(text) {
  return Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
}

const toHex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
export const randomBytes = (n) => crypto.getRandomValues(new Uint8Array(n));
export const randomId = () => toHex(randomBytes(16));

async function hkdf(secret, info) {
  const key = await crypto.subtle.importKey('raw', secret, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: enc.encode(info) },
    key,
    256,
  );
  return new Uint8Array(bits);
}

export function aesKey(raw) {
  return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

async function splitSecret(secret) {
  const [auth, kek] = await Promise.all([hkdf(secret, 'vault-auth-v1'), hkdf(secret, 'vault-kek-v1')]);
  return { authKey: toB64(auth), kek: await aesKey(kek) };
}

export async function deriveFromPassword(password, saltB64, iterations) {
  const base = await crypto.subtle.importKey(
    'raw', enc.encode(password.normalize('NFKC')), 'PBKDF2', false, ['deriveBits'],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: fromB64(saltB64), iterations },
    base,
    256,
  );
  return splitSecret(new Uint8Array(bits));
}

// The recovery key is 256 random bits, so it needs no slow KDF.
export function deriveFromRecovery(recoveryText) {
  const hex = recoveryText.toLowerCase().replace(/[^a-f0-9]/g, '');
  if (hex.length !== 64) throw new Error('bad_recovery_format');
  return splitSecret(Uint8Array.from(hex.match(/../g), (pair) => parseInt(pair, 16)));
}

export async function encryptBytes(key, plaintext, aad) {
  const iv = randomBytes(12);
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: enc.encode(aad) },
    key,
    plaintext,
  );
  const out = new Uint8Array(iv.length + ciphertext.byteLength);
  out.set(iv);
  out.set(new Uint8Array(ciphertext), iv.length);
  return out;
}

export async function decryptBytes(key, data, aad) {
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: data.subarray(0, 12), additionalData: enc.encode(aad) },
    key,
    data.subarray(12),
  );
  return new Uint8Array(plaintext);
}

export async function encryptJson(key, value, aad) {
  return toB64(await encryptBytes(key, enc.encode(JSON.stringify(value)), aad));
}

export async function decryptJson(key, ciphertext, aad) {
  return JSON.parse(dec.decode(await decryptBytes(key, fromB64(ciphertext), aad)));
}

// AAD binds every ciphertext to where it lives, so the server cannot swap
// entries between ids or move them into another project.
export const aad = {
  entry: (projectId, id) => `entry:${projectId}:${id}`,
  projectName: (projectId) => `project-name:${projectId}`,
  projectKey: (projectId, userId, version) => `project-key:${projectId}:${userId}:${version}`,
  file: (id) => `file:${id}`,
  share: (id) => `share:${id}`,
};

/* ---------- User key pairs ---------- */

async function wrapPrivateKey(kek, pkcs8) {
  return toB64(await encryptBytes(kek, pkcs8, PRIVATE_KEY_AAD));
}

export async function unwrapPrivateKey(kek, wrappedB64) {
  const pkcs8 = await decryptBytes(kek, fromB64(wrappedB64), PRIVATE_KEY_AAD);
  const key = await crypto.subtle.importKey('pkcs8', pkcs8, ECDH, false, ['deriveBits']);
  pkcs8.fill(0);
  return key;
}

function formatRecovery(raw) {
  return toHex(raw).toUpperCase().match(/.{4}/g).join('-');
}

// Everything a new user (first admin or invitee) sends to the server.
export async function createUserKeys(password) {
  const pair = await crypto.subtle.generateKey(ECDH, true, ['deriveBits']);
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey));
  const publicKey = toB64(new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey)));
  const salt = toB64(randomBytes(16));
  const recoveryKey = formatRecovery(randomBytes(32));

  const primary = await deriveFromPassword(password, salt, KDF_ITERATIONS);
  const recovery = await deriveFromRecovery(recoveryKey);
  const payload = {
    kdfSalt: salt,
    kdfIterations: KDF_ITERATIONS,
    authKey: primary.authKey,
    recoveryAuthKey: recovery.authKey,
    publicKey,
    wrappedPrivateKey: await wrapPrivateKey(primary.kek, pkcs8),
    recoveryWrappedPrivateKey: await wrapPrivateKey(recovery.kek, pkcs8),
  };
  pkcs8.fill(0);
  const privateKey = await crypto.subtle.importKey(
    'pkcs8', await crypto.subtle.exportKey('pkcs8', pair.privateKey), ECDH, false, ['deriveBits'],
  );
  return { payload, privateKey, recoveryKey };
}

// Re-wraps the private key under a new password. Project keys stay untouched.
export async function rewrapForPassword(currentKek, wrappedB64, newPassword) {
  const pkcs8 = await decryptBytes(currentKek, fromB64(wrappedB64), PRIVATE_KEY_AAD);
  const salt = toB64(randomBytes(16));
  const next = await deriveFromPassword(newPassword, salt, KDF_ITERATIONS);
  const payload = {
    kdfSalt: salt,
    kdfIterations: KDF_ITERATIONS,
    authKey: next.authKey,
    wrappedPrivateKey: await wrapPrivateKey(next.kek, pkcs8),
  };
  pkcs8.fill(0);
  return payload;
}

// Short, comparable identity of a public key. Compare it out of band before
// granting access, otherwise a malicious server could substitute its own key.
export async function fingerprint(publicKeyB64) {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', fromB64(publicKeyB64)));
  return toHex(digest.subarray(0, 10)).toUpperCase().match(/.{4}/g).join(' ');
}

/* ---------- ECIES: wrap a project key to a member's public key ---------- */

async function sharedKey(privateKey, publicKey, info) {
  const bits = await crypto.subtle.deriveBits({ name: 'ECDH', public: publicKey }, privateKey, 256);
  return aesKey(await hkdf(new Uint8Array(bits), `vault-ecies-v1:${info}`));
}

export async function wrapForUser(rawKey, recipientPublicB64, context) {
  const recipient = await crypto.subtle.importKey('spki', fromB64(recipientPublicB64), ECDH, false, []);
  const ephemeral = await crypto.subtle.generateKey(ECDH, false, ['deriveBits']);
  const ephPublic = new Uint8Array(await crypto.subtle.exportKey('raw', ephemeral.publicKey));
  const key = await sharedKey(ephemeral.privateKey, recipient, context);
  const sealed = await encryptBytes(key, rawKey, context);
  const out = new Uint8Array(ephPublic.length + sealed.length);
  out.set(ephPublic);
  out.set(sealed, ephPublic.length);
  return toB64(out);
}

export async function unwrapForMe(privateKey, wrappedB64, context) {
  const data = fromB64(wrappedB64);
  const ephPublic = await crypto.subtle.importKey('raw', data.subarray(0, 65), ECDH, false, []);
  const key = await sharedKey(privateKey, ephPublic, context);
  return decryptBytes(key, data.subarray(65), context);
}

/* ---------- Share links ---------- */

// The link carries the key in its fragment: #share=<id>.<key>. The server gets
// only a proof derived from the key, so knowing a share id (it appears in
// request paths and logs) is not enough to open or burn the link.
export const shareProof = async (rawKey) => toB64(await hkdf(rawKey, 'vault-share-proof-v1'));

const toB64Url = (bytes) => toB64(bytes).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
const fromB64Url = (text) => fromB64(text.replaceAll('-', '+').replaceAll('_', '/'));

export const formatShareFragment = (id, rawKey) => `share=${id}.${toB64Url(rawKey)}`;

export function parseShareFragment(hash) {
  const match = hash.match(/^#share=([a-f0-9]{32})\.([A-Za-z0-9_-]{43})$/);
  return match ? { id: match[1], rawKey: fromB64Url(match[2]) } : null;
}

export async function encryptShare(rawKey, id, value) {
  return encryptBytes(await aesKey(rawKey), enc.encode(JSON.stringify(value)), aad.share(id));
}

export async function decryptShare(rawKey, id, bytes) {
  return JSON.parse(dec.decode(await decryptBytes(await aesKey(rawKey), bytes, aad.share(id))));
}

/* ---------- Misc ---------- */

export function generatePassword(length = 24) {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*-_=+';
  const limit = 256 - (256 % alphabet.length); // rejection sampling avoids modulo bias
  let out = '';
  while (out.length < length) {
    for (const byte of randomBytes(length * 2)) {
      if (byte < limit && out.length < length) out += alphabet[byte % alphabet.length];
    }
  }
  return out;
}
