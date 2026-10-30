import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as c from '../public/crypto.js';

const password = 'correct horse battery staple';

async function login(payload, pw = password) {
  const keys = await c.deriveFromPassword(pw, payload.kdfSalt, payload.kdfIterations);
  return { ...keys, privateKey: await c.unwrapPrivateKey(keys.kek, payload.wrappedPrivateKey) };
}

test('password unwraps the private key, wrong password does not', async () => {
  const { payload } = await c.createUserKeys(password);
  const good = await c.deriveFromPassword(password, payload.kdfSalt, payload.kdfIterations);
  assert.equal(good.authKey, payload.authKey);
  await c.unwrapPrivateKey(good.kek, payload.wrappedPrivateKey);

  const bad = await c.deriveFromPassword('wrong', payload.kdfSalt, payload.kdfIterations);
  assert.notEqual(bad.authKey, payload.authKey);
  await assert.rejects(c.unwrapPrivateKey(bad.kek, payload.wrappedPrivateKey));
});

test('auth key sent to the server cannot unwrap the private key', async () => {
  const { payload } = await c.createUserKeys(password);
  const asKey = await c.aesKey(c.fromB64(payload.authKey));
  await assert.rejects(c.unwrapPrivateKey(asKey, payload.wrappedPrivateKey));
});

test('project key shared to a member opens entries; others cannot', async () => {
  const bob = await c.createUserKeys('bob long passphrase');
  const eve = await c.createUserKeys('eve long passphrase');
  const projectKeyRaw = c.randomBytes(32);
  const ctx = c.aad.projectKey('p1', 'bob', 1);
  const wrapped = await c.wrapForUser(projectKeyRaw, bob.payload.publicKey, ctx);

  const bobSession = await login(bob.payload, 'bob long passphrase');
  const opened = await c.unwrapForMe(bobSession.privateKey, wrapped, ctx);
  assert.deepEqual(opened, projectKeyRaw);

  const eveSession = await login(eve.payload, 'eve long passphrase');
  await assert.rejects(c.unwrapForMe(eveSession.privateKey, wrapped, ctx));
  // Same wrapped blob replayed under another project or version is rejected.
  await assert.rejects(c.unwrapForMe(bobSession.privateKey, wrapped, c.aad.projectKey('p2', 'bob', 1)));
  await assert.rejects(c.unwrapForMe(bobSession.privateKey, wrapped, c.aad.projectKey('p1', 'bob', 2)));

  const key = await c.aesKey(projectKeyRaw);
  const ct = await c.encryptJson(key, { secret: 1 }, c.aad.entry('p1', 'e1'));
  assert.deepEqual(await c.decryptJson(await c.aesKey(opened), ct, c.aad.entry('p1', 'e1')), { secret: 1 });

});

test('entry ciphertext is bound to project and id', async () => {
  const key = await c.aesKey(c.randomBytes(32));
  const ct = await c.encryptJson(key, { a: 1 }, c.aad.entry('p1', 'e1'));
  await assert.rejects(c.decryptJson(key, ct, c.aad.entry('p2', 'e1')));
  await assert.rejects(c.decryptJson(key, ct, c.aad.entry('p1', 'e2')));
  const bytes = c.fromB64(ct);
  bytes[bytes.length - 1] ^= 1;
  await assert.rejects(c.decryptJson(key, c.toB64(bytes), c.aad.entry('p1', 'e1')));
});

test('recovery key unwraps the private key and tolerates formatting', async () => {
  const { payload, recoveryKey } = await c.createUserKeys(password);
  const rec = await c.deriveFromRecovery(recoveryKey.toLowerCase().replaceAll('-', ' '));
  assert.equal(rec.authKey, payload.recoveryAuthKey);
  await c.unwrapPrivateKey(rec.kek, payload.recoveryWrappedPrivateKey);
});

test('password change keeps shared project keys readable', async () => {
  const user = await c.createUserKeys(password);
  const raw = c.randomBytes(32);
  const ctx = c.aad.projectKey('p', 'u', 1);
  const wrapped = await c.wrapForUser(raw, user.payload.publicKey, ctx);

  const cur = await c.deriveFromPassword(password, user.payload.kdfSalt, user.payload.kdfIterations);
  const next = await c.rewrapForPassword(cur.kek, user.payload.wrappedPrivateKey, 'a new long passphrase');
  const session = await login({ ...user.payload, ...next }, 'a new long passphrase');
  assert.deepEqual(await c.unwrapForMe(session.privateKey, wrapped, ctx), raw);
});

test('file round trip with its own key', async () => {
  const key = await c.aesKey(c.randomBytes(32));
  const data = new Uint8Array(3_000_000).fill(7);
  const ct = await c.encryptBytes(key, data, c.aad.file('f1'));
  assert.deepEqual(await c.decryptBytes(key, ct, c.aad.file('f1')), data);
  await assert.rejects(c.decryptBytes(key, ct, c.aad.file('f2')));
});

test('fingerprints are stable and distinct', async () => {
  const a = await c.createUserKeys(password);
  const b = await c.createUserKeys(password);
  assert.equal(await c.fingerprint(a.payload.publicKey), await c.fingerprint(a.payload.publicKey));
  assert.notEqual(await c.fingerprint(a.payload.publicKey), await c.fingerprint(b.payload.publicKey));
  assert.match(await c.fingerprint(a.payload.publicKey), /^[0-9A-F]{4}( [0-9A-F]{4}){4}$/);
});

test('share link round trip; a damaged link is rejected before any request', async () => {
  const raw = c.randomBytes(32);
  const id = c.randomId();
  const parsed = c.parseShareFragment(`#${c.formatShareFragment(id, raw)}`);
  assert.equal(parsed.id, id);
  assert.deepEqual(parsed.rawKey, raw);
  assert.equal(c.parseShareFragment(`#${c.formatShareFragment(id, raw)}`.slice(0, -1)), null);

  const blob = await c.encryptShare(raw, id, { title: 'x' });
  assert.deepEqual(await c.decryptShare(parsed.rawKey, id, blob), { title: 'x' });
  await assert.rejects(c.decryptShare(raw, c.randomId(), blob));
  await assert.rejects(c.decryptShare(c.randomBytes(32), id, blob));
});

test('share proof reveals nothing usable as the key', async () => {
  const raw = c.randomBytes(32);
  const id = c.randomId();
  const blob = await c.encryptShare(raw, id, { secret: 1 });
  const proof = c.fromB64(await c.shareProof(raw));
  assert.notDeepEqual(proof, raw);
  await assert.rejects(c.decryptShare(proof, id, blob));
});

test('generated passwords have the requested length and vary', () => {
  const a = c.generatePassword(32);
  assert.equal(a.length, 32);
  assert.notEqual(a, c.generatePassword(32));
});
