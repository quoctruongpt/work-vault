// Multi-user scenario against a running `wrangler dev` with an empty database:
//   BASE=http://localhost:8787 SECRET=... node --test test/api.e2e.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as c from '../public/crypto.js';

const BASE = process.env.BASE || 'http://localhost:8787';
const SECRET = process.env.SECRET;

function client() {
  let cookie = '';
  const call = async (path, { method = 'GET', body, raw } = {}) => {
    const res = await fetch(BASE + path, {
      method,
      headers: {
        origin: BASE, cookie,
        ...(body !== undefined && !raw ? { 'content-type': 'application/json' } : {}),
      },
      body: raw ? body : body === undefined ? undefined : JSON.stringify(body),
    });
    const set = res.headers.get('set-cookie');
    if (set) cookie = set.split(';')[0];
    const isFile = res.headers.get('content-type')?.includes('octet-stream');
    return { status: res.status, data: isFile ? new Uint8Array(await res.arrayBuffer()) : await res.json() };
  };
  call.cookie = () => cookie;
  return call;
}

async function session(api, email, password) {
  const kdf = (await api('/api/prelogin', { method: 'POST', body: { email } })).data;
  const keys = await c.deriveFromPassword(password, kdf.salt, kdf.iterations);
  const res = await api('/api/login', { method: 'POST', body: { email, authKey: keys.authKey } });
  assert.equal(res.status, 200);
  return { ...res.data.user, privateKey: await c.unwrapPrivateKey(keys.kek, res.data.wrappedPrivateKey) };
}

async function invite(admin, email, name, password) {
  const created = await admin('/api/users', { method: 'POST', body: { email, name } });
  assert.equal(created.status, 201);
  const api = client();
  const { payload } = await c.createUserKeys(password);
  const accepted = await api(`/api/invites/${created.data.inviteToken}/accept`, { method: 'POST', body: payload });
  assert.equal(accepted.status, 200);
  // Invite links are single use.
  const again = await client()(`/api/invites/${created.data.inviteToken}`);
  assert.equal(again.status, 404);
  return { api, id: created.data.id, publicKey: payload.publicKey, me: await session(api, email, password) };
}

async function grant(api, projectId, user, raw, role, keyVersion = 1) {
  const wrappedKey = await c.wrapForUser(raw, user.publicKey, c.aad.projectKey(projectId, user.id, keyVersion));
  return api(`/api/projects/${projectId}/members`, {
    method: 'POST', body: { userId: user.id, role, keyVersion, wrappedKey },
  });
}

test('team scenario', async () => {
  const adminApi = client();
  const adminKeys = await c.createUserKeys('admin long passphrase');

  assert.equal((await adminApi('/api/setup', {
    method: 'POST', body: { setupToken: 'wrong', email: 'admin@x.io', name: 'Admin', ...adminKeys.payload },
  })).status, 403);
  assert.equal((await adminApi('/api/setup', {
    method: 'POST', body: { setupToken: SECRET, email: 'admin@x.io', name: 'Admin', ...adminKeys.payload },
  })).status, 201);
  assert.equal((await client()('/api/setup', {
    method: 'POST', body: { setupToken: SECRET, email: 'b@x.io', name: 'B', ...adminKeys.payload },
  })).status, 409, 'second setup must fail');

  const admin = await session(adminApi, 'admin@x.io', 'admin long passphrase');

  // Unknown emails get a stable fake salt.
  const fake1 = (await client()('/api/prelogin', { method: 'POST', body: { email: 'nobody@x.io' } })).data;
  const fake2 = (await client()('/api/prelogin', { method: 'POST', body: { email: 'nobody@x.io' } })).data;
  assert.deepEqual(fake1, fake2);
  assert.equal(fake1.iterations, 1_000_000);

  const editor = await invite(adminApi, 'ed@x.io', 'Ed', 'editor long passphrase');
  const viewer = await invite(adminApi, 'vi@x.io', 'Vi', 'viewer long passphrase');
  const outsider = await invite(adminApi, 'out@x.io', 'Out', 'outsider long passphrase');

  // Non-admins cannot manage users or read the audit log.
  assert.equal((await editor.api('/api/users', { method: 'POST', body: { email: 'z@x.io', name: 'Z' } })).status, 403);
  assert.equal((await editor.api('/api/audit')).status, 403);

  // Editor creates a project.
  const pid = c.randomId();
  const raw = c.randomBytes(32);
  const key = await c.aesKey(raw);
  assert.equal((await editor.api('/api/projects', { method: 'POST', body: {
    id: pid,
    encryptedName: await c.encryptJson(key, 'Hoc10', c.aad.projectName(pid)),
    wrappedKey: await c.wrapForUser(raw, editor.publicKey, c.aad.projectKey(pid, editor.me.id, 1)),
  } })).status, 201);

  const eid = c.randomId();
  const putEntry = (api, id, k, version, value = { title: 'DB', secret: 's3cret' }) => c.encryptJson(k, value, c.aad.entry(pid, id))
    .then((ciphertext) => api(`/api/entries/${id}`, { method: 'PUT', body: { projectId: pid, ciphertext, keyVersion: version } }));
  assert.equal((await putEntry(editor.api, eid, key, 1)).status, 200);

  // Admin has no access to a project they are not in.
  assert.equal((await adminApi(`/api/projects/${pid}/entries`)).status, 403);
  assert.equal((await outsider.api(`/api/projects/${pid}/entries`)).status, 403);

  // File only readable by members.
  const fid = c.randomId();
  const fileKey = c.randomBytes(32);
  const blob = await c.encryptBytes(await c.aesKey(fileKey), new Uint8Array(5000).fill(9), c.aad.file(fid));
  assert.equal((await outsider.api(`/api/files/${fid}?project=${pid}`, { method: 'PUT', body: blob, raw: true })).status, 403);
  assert.equal((await editor.api(`/api/files/${fid}?project=${pid}`, { method: 'PUT', body: blob, raw: true })).status, 200);
  assert.equal((await outsider.api(`/api/files/${fid}`)).status, 403);

  // Grant viewer.
  const viewerUser = { id: viewer.me.id, publicKey: viewer.publicKey };
  assert.equal((await grant(editor.api, pid, viewerUser, raw, 'viewer')).status, 201);
  assert.equal((await grant(outsider.api, pid, { id: outsider.me.id, publicKey: outsider.publicKey }, raw, 'manager')).status, 403, 'non-member cannot self-grant');

  const vp = (await viewer.api('/api/me')).data.projects[0];
  assert.equal(vp.role, 'viewer');
  const vRaw = await c.unwrapForMe(viewer.me.privateKey, vp.wrappedKey, c.aad.projectKey(pid, viewer.me.id, 1));
  const listed = (await viewer.api(`/api/projects/${pid}/entries`)).data.entries;
  assert.deepEqual(await c.decryptJson(await c.aesKey(vRaw), listed[0].ciphertext, c.aad.entry(pid, eid)), { title: 'DB', secret: 's3cret' });
  assert.equal((await viewer.api(`/api/files/${fid}`)).status, 200);

  // Viewer is read-only.
  assert.equal((await putEntry(viewer.api, eid, key, 1)).status, 403);
  assert.equal((await viewer.api(`/api/entries/${eid}`, { method: 'DELETE' })).status, 403);
  assert.equal((await viewer.api(`/api/projects/${pid}`, { method: 'DELETE' })).status, 403);

  // Manager cannot demote themselves as last manager.
  assert.equal((await editor.api(`/api/projects/${pid}/members/${editor.me.id}`, { method: 'PUT', body: { role: 'viewer' } })).status, 409);

  // Remove viewer with rotation.
  const nextRaw = c.randomBytes(32);
  const nextKey = await c.aesKey(nextRaw);
  const rotateBody = {
    keyVersion: 2,
    encryptedName: await c.encryptJson(nextKey, 'Hoc10', c.aad.projectName(pid)),
    members: [{ userId: editor.me.id, wrappedKey: await c.wrapForUser(nextRaw, editor.publicKey, c.aad.projectKey(pid, editor.me.id, 2)) }],
    entries: [{ id: eid, ciphertext: await c.encryptJson(nextKey, { title: 'DB', secret: 's3cret' }, c.aad.entry(pid, eid)) }],
    removeUserId: viewer.me.id,
  };
  assert.equal((await editor.api(`/api/projects/${pid}/rotate`, { method: 'POST', body: { ...rotateBody, entries: [] } })).status, 409, 'partial rotation rejected');
  assert.equal((await editor.api(`/api/projects/${pid}/rotate`, { method: 'POST', body: rotateBody })).status, 200);

  assert.equal((await viewer.api(`/api/projects/${pid}/entries`)).status, 403);
  assert.equal((await viewer.api(`/api/files/${fid}`)).status, 403);
  // Even with a saved copy of the ciphertext, the old key no longer opens it.
  const after = (await editor.api(`/api/projects/${pid}/entries`)).data.entries;
  await assert.rejects(c.decryptJson(await c.aesKey(vRaw), after[0].ciphertext, c.aad.entry(pid, eid)));
  assert.deepEqual(await c.decryptJson(nextKey, after[0].ciphertext, c.aad.entry(pid, eid)), { title: 'DB', secret: 's3cret' });

  // Writes with the old key are refused.
  assert.equal((await putEntry(editor.api, eid, key, 1)).status, 409);

  // Disabling a member kills the session and flags rotation.
  const viewerUser2 = { id: outsider.me.id, publicKey: outsider.publicKey };
  assert.equal((await grant(editor.api, pid, viewerUser2, nextRaw, 'editor', 2)).status, 201);
  assert.equal((await adminApi(`/api/users/${outsider.me.id}/disable`, { method: 'POST', body: {} })).status, 200);
  assert.equal((await outsider.api('/api/me')).status, 401);
  assert.equal((await editor.api('/api/me')).data.projects[0].needsRotation, true);

  // Disabling the sole member needs an explicit force.
  assert.equal((await adminApi(`/api/users/${editor.me.id}/disable`, { method: 'POST', body: {} })).status, 409);
  // Admin cannot act on themselves.
  assert.equal((await adminApi(`/api/users/${admin.id}/disable`, { method: 'POST', body: {} })).status, 400);

  // --- Share links ---
  const anon = client();
  const makeShare = async (mode, value = { title: 'DB', secret: 's3cret' }, ttl = 3600) => {
    const id = c.randomId();
    const shareKey = c.randomBytes(32);
    const blob = await c.encryptShare(shareKey, id, value);
    const res = await fetch(`${BASE}/api/shares?id=${id}&project=${pid}&entry=${eid}&mode=${mode}&ttl=${ttl}`, {
      method: 'POST',
      headers: { origin: BASE, cookie: editorCookie(), 'x-share-proof': await c.shareProof(shareKey) },
      body: blob,
    });
    return { id, shareKey, status: res.status };
  };
  const editorCookie = () => editor.api.cookie();
  const open = async (s, proof) => anon(`/api/public/shares/${s.id}/open`, {
    method: 'POST', body: { proof: proof || (await c.shareProof(s.shareKey)) },
  });

  // Viewers and strangers cannot create links.
  assert.equal((await outsider.api('/api/shares')).status, 401);
  assert.equal((await anon('/api/shares')).status, 401);

  const once = await makeShare('once');
  assert.equal(once.status, 201);
  assert.equal((await anon(`/api/public/shares/${once.id}`)).data.state, 'active');
  // GET never burns it, however many times a preview bot fetches.
  await anon(`/api/public/shares/${once.id}`);

  // A wrong proof does not burn the link.
  const badProof = await open(once, c.toB64(c.randomBytes(32)));
  assert.equal(badProof.status, 404);
  assert.equal((await anon(`/api/public/shares/${once.id}`)).data.state, 'active');

  // Exactly one of many concurrent opens wins.
  const results = await Promise.all(Array.from({ length: 8 }, () => open(once)));
  const winners = results.filter((r) => r.status === 200);
  assert.equal(winners.length, 1, `statuses ${results.map((r) => r.status)}`);
  assert.ok(results.filter((r) => r.status === 410).length === 7);
  assert.deepEqual(await c.decryptShare(once.shareKey, once.id, winners[0].data), { title: 'DB', secret: 's3cret' });
  assert.equal((await open(once)).status, 410);
  assert.equal((await anon(`/api/public/shares/${once.id}`)).data.state, 'opened');

  // A public link works repeatedly until revoked, then content is gone.
  const pub = await makeShare('public');
  assert.equal((await open(pub)).status, 200);
  assert.equal((await open(pub)).status, 200);
  assert.equal((await outsider.api(`/api/shares/${pub.id}/revoke`, { method: 'POST', body: {} })).status, 401);
  assert.equal((await editor.api(`/api/shares/${pub.id}/revoke`, { method: 'POST', body: {} })).status, 200);
  assert.equal((await open(pub)).status, 410);
  assert.equal((await anon(`/api/public/shares/${pub.id}`)).data.state, 'revoked');

  // Admin can kill any link during an incident.
  const pub2 = await makeShare('public');
  assert.equal((await adminApi(`/api/shares/${pub2.id}/revoke`, { method: 'POST', body: {} })).status, 200);
  assert.equal((await open(pub2)).status, 410);

  // Invalid options are refused: one-time links cannot live 30 days.
  assert.equal((await makeShare('once', { a: 1 }, 2592000)).status, 400);

  // Deleting the entry kills its links.
  const pub3 = await makeShare('public');
  const list = (await editor.api('/api/shares')).data.shares;
  assert.equal(list.find((x) => x.id === pub3.id).state, 'active');
  assert.equal(list.find((x) => x.id === pub3.id).views, 0);
  assert.equal((await editor.api(`/api/entries/${eid}`, { method: 'DELETE' })).status, 200);
  assert.equal((await open(pub3)).status, 410);

  const events = (await adminApi('/api/audit')).data.events.map((e) => e.action);
  for (const action of ['setup', 'user.invite', 'project.create', 'member.remove', 'user.disable', 'file.download', 'share.create:once', 'share.view', 'share.revoke']) {
    assert.ok(events.includes(action), `audit has ${action}`);
  }
});
