// API + static assets. This Worker never sees plaintext: all secrets are
// encrypted in the browser (public/crypto.js) before they reach these routes.
// It enforces who may fetch which ciphertext; cryptography enforces who can read it.

const SESSION_COOKIE = '__Host-vault_session';
const SESSION_TTL = 8 * 3600;
const INVITE_TTL = 72 * 3600;
const MAX_FAILURES = 5;
const FAILURE_WINDOW = 15 * 60;
const MAX_ENTRY_BYTES = 256 * 1024;
const MAX_ROTATE_BYTES = 50 * 1024 * 1024;
const MAX_FILE_BYTES = 26 * 1024 * 1024; // 25 MB plaintext + GCM overhead
const MAX_SHARE_BYTES = 14 * 1024 * 1024; // 10 MB of files as base64 + fields
const SHARE_TTLS = { once: [3600, 86400, 604800], public: [3600, 86400, 604800, 2592000] };
const SHARE_ROW_RETENTION = 90 * 86400;
const MIN_KDF_ITERATIONS = 600_000;
const FAKE_KDF_ITERATIONS = 1_000_000;
const ID_RE = /^[a-f0-9]{32}$/;
const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,}$/;
const ROLE_RANK = { viewer: 1, editor: 2, manager: 3 };

const CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "connect-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
].join('; ');

class HttpError extends Error {
  constructor(status, code, extra = {}) {
    super(code);
    this.status = status;
    this.code = code;
    this.extra = extra;
  }
}

const now = () => Math.floor(Date.now() / 1000);
const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', ...headers },
  });

const toHex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
const randomHex = (n) => toHex(crypto.getRandomValues(new Uint8Array(n)));

async function sha256Hex(text) {
  return toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text))));
}

async function hmac(secret, text) {
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
  );
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(text)));
}

// Compares hex digests of equal length, so the length check leaks nothing.
function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const x = new TextEncoder().encode(a);
  const y = new TextEncoder().encode(b);
  return x.length === y.length && crypto.subtle.timingSafeEqual(x, y);
}

function withSecurityHeaders(response, isApi) {
  const res = new Response(response.body, response);
  res.headers.set('Content-Security-Policy', CSP);
  res.headers.set('Strict-Transport-Security', 'max-age=63072000; includeSubDomains');
  res.headers.set('X-Content-Type-Options', 'nosniff');
  res.headers.set('X-Frame-Options', 'DENY');
  res.headers.set('Referrer-Policy', 'no-referrer');
  res.headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
  res.headers.set('Cross-Origin-Opener-Policy', 'same-origin');
  res.headers.set('Cross-Origin-Resource-Policy', 'same-origin');
  // Always revalidate app code so a fixed build reaches clients immediately.
  res.headers.set('Cache-Control', isApi ? 'no-store' : 'no-cache');
  return res;
}

/* ---------- Input validation ---------- */

async function readJson(request, maxBytes = MAX_ENTRY_BYTES * 2) {
  const length = Number(request.headers.get('content-length') || 0);
  if (length > maxBytes) throw new HttpError(413, 'too_large');
  try {
    return await request.json();
  } catch {
    throw new HttpError(400, 'bad_json');
  }
}

function str(body, field, max = 8192) {
  const value = body?.[field];
  if (typeof value !== 'string' || !value || value.length > max) {
    throw new HttpError(400, 'bad_field', { field });
  }
  return value;
}

function requireKdf(body) {
  if (!Number.isInteger(body.kdfIterations) || body.kdfIterations < MIN_KDF_ITERATIONS) {
    throw new HttpError(400, 'weak_kdf');
  }
}

function requireId(id, field = 'id') {
  if (typeof id !== 'string' || !ID_RE.test(id)) throw new HttpError(400, 'bad_id', { field });
  return id;
}

function normalizeEmail(value) {
  const email = typeof value === 'string' ? value.trim().toLowerCase() : '';
  if (email.length > 254 || !EMAIL_RE.test(email)) throw new HttpError(400, 'bad_email');
  return email;
}

function cleanName(value) {
  const name = typeof value === 'string' ? value.trim() : '';
  if (!name || name.length > 100) throw new HttpError(400, 'bad_name');
  return name;
}

function requireRoleName(role) {
  if (!ROLE_RANK[role]) throw new HttpError(400, 'bad_role');
  return role;
}

// Key material every new account (first admin or invitee) uploads.
function userKeyFields(body) {
  requireKdf(body);
  return {
    kdfSalt: str(body, 'kdfSalt', 64),
    authKey: str(body, 'authKey', 128),
    recoveryAuthKey: str(body, 'recoveryAuthKey', 128),
    publicKey: str(body, 'publicKey', 512),
    wrappedPrivateKey: str(body, 'wrappedPrivateKey', 1024),
    recoveryWrappedPrivateKey: str(body, 'recoveryWrappedPrivateKey', 1024),
  };
}

/* ---------- Rate limiting ---------- */

async function assertNotLocked(env, keys) {
  for (const key of keys) {
    const row = await env.DB.prepare('SELECT failures, window_start FROM attempts WHERE key = ?').bind(key).first();
    if (!row) continue;
    const elapsed = now() - row.window_start;
    if (elapsed < FAILURE_WINDOW && row.failures >= MAX_FAILURES) {
      throw new HttpError(429, 'locked', { retryAfter: FAILURE_WINDOW - elapsed });
    }
  }
}

function recordFailure(env, keys) {
  const t = now();
  return env.DB.batch(keys.map((key) => env.DB.prepare(
    `INSERT INTO attempts (key, failures, window_start) VALUES (?1, 1, ?2)
     ON CONFLICT (key) DO UPDATE SET
       failures = CASE WHEN ?2 - window_start >= ?3 THEN 1 ELSE failures + 1 END,
       window_start = CASE WHEN ?2 - window_start >= ?3 THEN ?2 ELSE window_start END`,
  ).bind(key, t, FAILURE_WINDOW)));
}

function clearFailures(env, keys) {
  return env.DB.batch(keys.map((key) => env.DB.prepare('DELETE FROM attempts WHERE key = ?').bind(key)));
}

/* ---------- Sessions ---------- */

function readSessionToken(request) {
  const cookies = request.headers.get('cookie') || '';
  for (const part of cookies.split(';')) {
    const [name, value] = part.trim().split('=');
    if (name === SESSION_COOKIE) return value;
  }
  return null;
}

async function currentUser(request, env) {
  const token = readSessionToken(request);
  if (!token) throw new HttpError(401, 'unauthorized');
  const user = await env.DB.prepare(
    `SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id
     WHERE s.token_hash = ? AND s.expires_at > ? AND u.status = 'active'`,
  ).bind(await sha256Hex(token), now()).first();
  if (!user) throw new HttpError(401, 'unauthorized');
  return user;
}

async function createSessionCookie(env, userId) {
  const token = randomHex(32);
  await env.DB.batch([
    env.DB.prepare('DELETE FROM sessions WHERE expires_at < ?').bind(now()),
    env.DB.prepare('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)').bind(
      await sha256Hex(token), userId, now() + SESSION_TTL,
    ),
  ]);
  return `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_TTL}`;
}

const clearCookie = `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;

const publicUser = (u) => ({
  id: u.id, email: u.email, name: u.name, isAdmin: !!u.is_admin, status: u.status, publicKey: u.public_key,
});

/* ---------- Authorization ---------- */

async function membership(env, projectId, userId) {
  return env.DB.prepare('SELECT * FROM memberships WHERE project_id = ? AND user_id = ?').bind(projectId, userId).first();
}

async function requireRole(env, projectId, user, minRole) {
  const m = await membership(env, projectId, user.id);
  // Same answer for "no such project" and "not a member": no project enumeration.
  if (!m || ROLE_RANK[m.role] < ROLE_RANK[minRole]) throw new HttpError(403, 'forbidden');
  return m;
}

function requireAdmin(user) {
  if (!user.is_admin) throw new HttpError(403, 'forbidden');
}

function audit(ctx, action, projectId = null, targetId = null) {
  return ctx.env.DB.prepare(
    'INSERT INTO audit (at, user_id, action, project_id, target_id, ip_hash) VALUES (?, ?, ?, ?, ?, ?)',
  ).bind(now(), ctx.user?.id || null, action, projectId, targetId, ctx.ip).run();
}

/* ---------- Auth routes ---------- */

async function status(env) {
  const row = await env.DB.prepare('SELECT COUNT(*) AS n FROM users').first();
  return json({ initialized: row.n > 0 });
}

// Unknown, pending and disabled accounts get a deterministic fake salt, so
// this endpoint does not reveal which emails exist.
async function prelogin(request, env) {
  const body = await readJson(request);
  const email = normalizeEmail(body.email);
  const user = await env.DB.prepare(
    "SELECT kdf_salt, kdf_iterations FROM users WHERE email = ? AND status = 'active'",
  ).bind(email).first();
  if (user) return json({ salt: user.kdf_salt, iterations: user.kdf_iterations });
  const fake = (await hmac(env.SERVER_SECRET || 'unset', `salt:${email}`)).subarray(0, 16);
  return json({ salt: btoa(String.fromCharCode(...fake)), iterations: FAKE_KDF_ITERATIONS });
}

async function setup(request, env, ctx) {
  await assertNotLocked(env, [`ip:${ctx.ip}`]);
  if (!env.SERVER_SECRET) throw new HttpError(403, 'setup_disabled');
  const body = await readJson(request);
  const [given, expected] = await Promise.all([sha256Hex(str(body, 'setupToken')), sha256Hex(env.SERVER_SECRET)]);
  if (!safeEqual(given, expected)) {
    await recordFailure(env, [`ip:${ctx.ip}`]);
    throw new HttpError(403, 'bad_setup_token');
  }
  const email = normalizeEmail(body.email);
  const name = cleanName(body.name);
  const k = userKeyFields(body);
  const id = randomHex(16);
  const t = now();

  // The WHERE NOT EXISTS makes a concurrent second setup a no-op.
  const result = await env.DB.prepare(
    `INSERT INTO users (id, email, name, is_admin, status, kdf_salt, kdf_iterations, auth_hash,
       recovery_auth_hash, public_key, wrapped_private_key, recovery_wrapped_private_key, created_at, updated_at)
     SELECT ?, ?, ?, 1, 'active', ?, ?, ?, ?, ?, ?, ?, ?, ?
     WHERE NOT EXISTS (SELECT 1 FROM users)`,
  ).bind(
    id, email, name, k.kdfSalt, body.kdfIterations, await sha256Hex(k.authKey), await sha256Hex(k.recoveryAuthKey),
    k.publicKey, k.wrappedPrivateKey, k.recoveryWrappedPrivateKey, t, t,
  ).run();
  if (!result.meta.changes) throw new HttpError(409, 'already_initialized');
  await audit({ ...ctx, user: { id } }, 'setup');
  return json({ ok: true }, 201, { 'set-cookie': await createSessionCookie(env, id) });
}

async function login(request, env, ctx) {
  const body = await readJson(request);
  const email = normalizeEmail(body.email);
  const limits = [`ip:${ctx.ip}`, `acct:${await sha256Hex(email)}`];
  await assertNotLocked(env, limits);
  const authKey = str(body, 'authKey', 128);
  const recovery = body.mode === 'recovery';

  const user = await env.DB.prepare("SELECT * FROM users WHERE email = ? AND status = 'active'").bind(email).first();
  const given = await sha256Hex(authKey);
  const expected = user ? (recovery ? user.recovery_auth_hash : user.auth_hash) : '0'.repeat(64);
  if (!user || !safeEqual(given, expected)) {
    await recordFailure(env, limits);
    await audit({ ...ctx, user }, recovery ? 'login.recovery_failed' : 'login.failed');
    throw new HttpError(401, 'bad_credentials');
  }
  await clearFailures(env, limits);
  await audit({ ...ctx, user }, recovery ? 'login.recovery' : 'login');
  return json(
    {
      user: publicUser(user),
      wrappedPrivateKey: recovery ? user.recovery_wrapped_private_key : user.wrapped_private_key,
    },
    200,
    { 'set-cookie': await createSessionCookie(env, user.id) },
  );
}

async function logout(request, env) {
  const token = readSessionToken(request);
  if (token) {
    await env.DB.prepare('DELETE FROM sessions WHERE token_hash = ?').bind(await sha256Hex(token)).run();
  }
  return json({ ok: true }, 200, { 'set-cookie': clearCookie });
}

async function changePassword(request, env, ctx) {
  const user = ctx.user;
  const limits = [`ip:${ctx.ip}`, `acct:${await sha256Hex(user.email)}`];
  await assertNotLocked(env, limits);
  const body = await readJson(request);
  requireKdf(body);
  const current = await sha256Hex(str(body, 'currentAuthKey', 128));
  if (!safeEqual(current, user.auth_hash) && !safeEqual(current, user.recovery_auth_hash)) {
    await recordFailure(env, limits);
    throw new HttpError(401, 'bad_credentials');
  }
  // Every other device of this user is signed out once the password changes.
  await env.DB.batch([
    env.DB.prepare(
      'UPDATE users SET kdf_salt = ?, kdf_iterations = ?, auth_hash = ?, wrapped_private_key = ?, updated_at = ? WHERE id = ?',
    ).bind(
      str(body, 'kdfSalt', 64), body.kdfIterations, await sha256Hex(str(body, 'authKey', 128)),
      str(body, 'wrappedPrivateKey', 1024), now(), user.id,
    ),
    env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(user.id),
  ]);
  await audit(ctx, 'password.change');
  return json({ ok: true }, 200, { 'set-cookie': await createSessionCookie(env, user.id) });
}

async function me(env, user) {
  const { results } = await env.DB.prepare(
    `SELECT p.id, p.encrypted_name, p.key_version, p.needs_rotation, m.role, m.wrapped_key
     FROM memberships m JOIN projects p ON p.id = m.project_id WHERE m.user_id = ?`,
  ).bind(user.id).all();
  return json({
    user: publicUser(user),
    projects: results.map((r) => ({
      id: r.id, encryptedName: r.encrypted_name, keyVersion: r.key_version,
      needsRotation: !!r.needs_rotation, role: r.role, wrappedKey: r.wrapped_key,
    })),
  });
}

/* ---------- Invites ---------- */

async function inviteUser(env, token) {
  return env.DB.prepare(
    `SELECT u.* FROM invites i JOIN users u ON u.id = i.user_id
     WHERE i.token_hash = ? AND i.expires_at > ? AND u.status = 'pending'`,
  ).bind(await sha256Hex(token), now()).first();
}

async function getInvite(env, ctx, token) {
  await assertNotLocked(env, [`ip:${ctx.ip}`]);
  const user = await inviteUser(env, token);
  if (!user) {
    await recordFailure(env, [`ip:${ctx.ip}`]);
    throw new HttpError(404, 'invite_invalid');
  }
  return json({ email: user.email, name: user.name });
}

async function acceptInvite(request, env, ctx, token) {
  await assertNotLocked(env, [`ip:${ctx.ip}`]);
  const user = await inviteUser(env, token);
  if (!user) {
    await recordFailure(env, [`ip:${ctx.ip}`]);
    throw new HttpError(404, 'invite_invalid');
  }
  const body = await readJson(request);
  const k = userKeyFields(body);
  await env.DB.batch([
    env.DB.prepare(
      `UPDATE users SET status = 'active', kdf_salt = ?, kdf_iterations = ?, auth_hash = ?, recovery_auth_hash = ?,
         public_key = ?, wrapped_private_key = ?, recovery_wrapped_private_key = ?, updated_at = ?
       WHERE id = ? AND status = 'pending'`,
    ).bind(
      k.kdfSalt, body.kdfIterations, await sha256Hex(k.authKey), await sha256Hex(k.recoveryAuthKey),
      k.publicKey, k.wrappedPrivateKey, k.recoveryWrappedPrivateKey, now(), user.id,
    ),
    env.DB.prepare('DELETE FROM invites WHERE user_id = ?').bind(user.id),
  ]);
  await audit({ ...ctx, user }, 'invite.accept');
  return json({ ok: true }, 200, { 'set-cookie': await createSessionCookie(env, user.id) });
}

/* ---------- Users (admin) ---------- */

async function listUsers(env, user) {
  const where = user.is_admin ? '' : "WHERE status = 'active'";
  const { results } = await env.DB.prepare(`SELECT * FROM users ${where} ORDER BY name`).all();
  return json({ users: results.map(publicUser) });
}

async function issueInvite(env, userId) {
  const token = randomHex(32);
  await env.DB.batch([
    env.DB.prepare('DELETE FROM invites WHERE user_id = ?').bind(userId),
    env.DB.prepare('INSERT INTO invites (token_hash, user_id, expires_at) VALUES (?, ?, ?)').bind(
      await sha256Hex(token), userId, now() + INVITE_TTL,
    ),
  ]);
  return token;
}

async function createUser(request, env, ctx) {
  requireAdmin(ctx.user);
  const body = await readJson(request);
  const email = normalizeEmail(body.email);
  const name = cleanName(body.name);
  const id = randomHex(16);
  const t = now();
  const result = await env.DB.prepare(
    `INSERT INTO users (id, email, name, is_admin, status, created_at, updated_at)
     VALUES (?, ?, ?, ?, 'pending', ?, ?) ON CONFLICT (email) DO NOTHING`,
  ).bind(id, email, name, body.isAdmin ? 1 : 0, t, t).run();
  if (!result.meta.changes) throw new HttpError(409, 'email_exists');
  const token = await issueInvite(env, id);
  await audit(ctx, 'user.invite', null, id);
  return json({ id, inviteToken: token, expiresIn: INVITE_TTL }, 201);
}

// Projects where this user is the only manager. Losing them would leave
// nobody able to manage (or, if they are the only member, decrypt) the project.
async function soleManagerProjects(env, userId) {
  const { results } = await env.DB.prepare(
    `SELECT m.project_id,
       (SELECT COUNT(*) FROM memberships o WHERE o.project_id = m.project_id AND o.user_id != m.user_id) AS others,
       (SELECT COUNT(*) FROM memberships o WHERE o.project_id = m.project_id AND o.user_id != m.user_id AND o.role = 'manager') AS other_managers
     FROM memberships m WHERE m.user_id = ? AND m.role = 'manager'`,
  ).bind(userId).all();
  return results.filter((r) => r.other_managers === 0);
}

// Removes a user from every project without rotating keys (only members can
// rotate). Marks those projects so their managers are prompted to rotate.
async function detachUser(env, target, force) {
  const sole = await soleManagerProjects(env, target.id);
  const orphaned = sole.filter((r) => r.others === 0);
  if (orphaned.length && !force) {
    throw new HttpError(409, 'would_orphan', { projects: orphaned.length });
  }
  const statements = [];
  for (const r of sole.filter((x) => x.others > 0)) {
    // Promote the strongest remaining member so the project keeps a manager.
    statements.push(env.DB.prepare(
      `UPDATE memberships SET role = 'manager' WHERE project_id = ?1 AND user_id = (
         SELECT user_id FROM memberships WHERE project_id = ?1 AND user_id != ?2
         ORDER BY CASE role WHEN 'editor' THEN 0 ELSE 1 END LIMIT 1)`,
    ).bind(r.project_id, target.id));
  }
  statements.push(
    env.DB.prepare(
      'UPDATE projects SET needs_rotation = 1 WHERE id IN (SELECT project_id FROM memberships WHERE user_id = ?)',
    ).bind(target.id),
    env.DB.prepare('DELETE FROM memberships WHERE user_id = ?').bind(target.id),
    env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(target.id),
  );
  await env.DB.batch(statements);
  await revokeShares(env, 'created_by = ?', [target.id]);
}

async function adminTarget(env, ctx, userId) {
  requireAdmin(ctx.user);
  requireId(userId, 'userId');
  if (userId === ctx.user.id) throw new HttpError(400, 'not_on_self');
  const target = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(userId).first();
  if (!target) throw new HttpError(404, 'not_found');
  return target;
}

async function disableUser(request, env, ctx, userId) {
  const target = await adminTarget(env, ctx, userId);
  const body = await readJson(request);
  await detachUser(env, target, body.force === true);
  await env.DB.batch([
    env.DB.prepare("UPDATE users SET status = 'disabled', updated_at = ? WHERE id = ?").bind(now(), target.id),
    env.DB.prepare('DELETE FROM invites WHERE user_id = ?').bind(target.id),
  ]);
  await audit(ctx, 'user.disable', null, target.id);
  return json({ ok: true });
}

async function enableUser(env, ctx, userId) {
  const target = await adminTarget(env, ctx, userId);
  if (target.status !== 'disabled') throw new HttpError(409, 'not_disabled');
  const status = target.public_key ? 'active' : 'pending';
  await env.DB.prepare('UPDATE users SET status = ?, updated_at = ? WHERE id = ?').bind(status, now(), target.id).run();
  await audit(ctx, 'user.enable', null, target.id);
  return json({ ok: true, status });
}

// For a user who lost both password and recovery key: wipe their keys and
// send a fresh invite. Project managers must grant access again.
async function resetUser(request, env, ctx, userId) {
  const target = await adminTarget(env, ctx, userId);
  const body = await readJson(request);
  await detachUser(env, target, body.force === true);
  await env.DB.prepare(
    `UPDATE users SET status = 'pending', kdf_salt = NULL, kdf_iterations = NULL, auth_hash = NULL,
       recovery_auth_hash = NULL, public_key = NULL, wrapped_private_key = NULL,
       recovery_wrapped_private_key = NULL, updated_at = ? WHERE id = ?`,
  ).bind(now(), target.id).run();
  const token = await issueInvite(env, target.id);
  await audit(ctx, 'user.reset', null, target.id);
  return json({ inviteToken: token, expiresIn: INVITE_TTL });
}

async function listAudit(env, ctx) {
  requireAdmin(ctx.user);
  const { results } = await env.DB.prepare(
    `SELECT a.id, a.at, a.action, a.project_id, a.target_id, a.user_id, u.email
     FROM audit a LEFT JOIN users u ON u.id = a.user_id ORDER BY a.id DESC LIMIT 300`,
  ).all();
  return json({ events: results });
}

/* ---------- Projects ---------- */

async function createProject(request, env, ctx) {
  const body = await readJson(request);
  const id = requireId(body.id);
  await env.DB.batch([
    env.DB.prepare('INSERT INTO projects (id, encrypted_name, key_version, created_at) VALUES (?, ?, 1, ?)').bind(
      id, str(body, 'encryptedName', 4096), now(),
    ),
    env.DB.prepare("INSERT INTO memberships (project_id, user_id, role, wrapped_key) VALUES (?, ?, 'manager', ?)").bind(
      id, ctx.user.id, str(body, 'wrappedKey', 1024),
    ),
  ]);
  await audit(ctx, 'project.create', id);
  return json({ ok: true }, 201);
}

async function renameProject(request, env, ctx, projectId) {
  await requireRole(env, projectId, ctx.user, 'manager');
  const body = await readJson(request);
  await env.DB.prepare('UPDATE projects SET encrypted_name = ? WHERE id = ?').bind(
    str(body, 'encryptedName', 4096), projectId,
  ).run();
  await audit(ctx, 'project.rename', projectId);
  return json({ ok: true });
}

async function deleteProject(env, ctx, projectId) {
  await requireRole(env, projectId, ctx.user, 'manager');
  const { results } = await env.DB.prepare('SELECT id FROM files WHERE project_id = ?').bind(projectId).all();
  for (let i = 0; i < results.length; i += 1000) {
    await env.FILES.delete(results.slice(i, i + 1000).map((f) => f.id));
  }
  await env.DB.batch([
    env.DB.prepare('DELETE FROM files WHERE project_id = ?').bind(projectId),
    env.DB.prepare('DELETE FROM entries WHERE project_id = ?').bind(projectId),
    env.DB.prepare('DELETE FROM memberships WHERE project_id = ?').bind(projectId),
    env.DB.prepare('DELETE FROM projects WHERE id = ?').bind(projectId),
  ]);
  await revokeShares(env, 'project_id = ?', [projectId]);
  await audit(ctx, 'project.delete', projectId);
  return json({ ok: true });
}

async function listMembers(env, ctx, projectId) {
  await requireRole(env, projectId, ctx.user, 'viewer');
  const { results } = await env.DB.prepare(
    `SELECT u.id, u.email, u.name, u.public_key, m.role FROM memberships m
     JOIN users u ON u.id = m.user_id WHERE m.project_id = ? ORDER BY u.name`,
  ).bind(projectId).all();
  return json({
    members: results.map((r) => ({ userId: r.id, email: r.email, name: r.name, role: r.role, publicKey: r.public_key })),
  });
}

async function addMember(request, env, ctx, projectId) {
  await requireRole(env, projectId, ctx.user, 'manager');
  const body = await readJson(request);
  const userId = requireId(body.userId, 'userId');
  const role = requireRoleName(body.role);
  const project = await env.DB.prepare('SELECT key_version FROM projects WHERE id = ?').bind(projectId).first();
  if (body.keyVersion !== project.key_version) throw new HttpError(409, 'stale_key');
  const target = await env.DB.prepare("SELECT id FROM users WHERE id = ? AND status = 'active'").bind(userId).first();
  if (!target) throw new HttpError(404, 'not_found');
  const result = await env.DB.prepare(
    `INSERT INTO memberships (project_id, user_id, role, wrapped_key) VALUES (?, ?, ?, ?)
     ON CONFLICT (project_id, user_id) DO NOTHING`,
  ).bind(projectId, userId, role, str(body, 'wrappedKey', 1024)).run();
  if (!result.meta.changes) throw new HttpError(409, 'already_member');
  await audit(ctx, `member.add:${role}`, projectId, userId);
  return json({ ok: true }, 201);
}

async function managerCount(env, projectId) {
  const row = await env.DB.prepare(
    "SELECT COUNT(*) AS n FROM memberships WHERE project_id = ? AND role = 'manager'",
  ).bind(projectId).first();
  return row.n;
}

async function changeMemberRole(request, env, ctx, projectId, userId) {
  await requireRole(env, projectId, ctx.user, 'manager');
  requireId(userId, 'userId');
  const role = requireRoleName((await readJson(request)).role);
  const current = await membership(env, projectId, userId);
  if (!current) throw new HttpError(404, 'not_found');
  if (current.role === 'manager' && role !== 'manager' && (await managerCount(env, projectId)) < 2) {
    throw new HttpError(409, 'last_manager');
  }
  await env.DB.prepare('UPDATE memberships SET role = ? WHERE project_id = ? AND user_id = ?').bind(role, projectId, userId).run();
  await audit(ctx, `member.role:${role}`, projectId, userId);
  return json({ ok: true });
}

// Re-keys a project: new project key, re-encrypted name and entries, key
// re-wrapped for every remaining member, optionally dropping one member.
// Applied as one D1 batch (a single transaction).
async function rotateProject(request, env, ctx, projectId) {
  await requireRole(env, projectId, ctx.user, 'manager');
  const body = await readJson(request, MAX_ROTATE_BYTES);
  const project = await env.DB.prepare('SELECT key_version FROM projects WHERE id = ?').bind(projectId).first();
  const nextVersion = project.key_version + 1;
  if (body.keyVersion !== nextVersion) throw new HttpError(409, 'stale_key');

  const removeUserId = body.removeUserId ? requireId(body.removeUserId, 'removeUserId') : null;
  const { results: members } = await env.DB.prepare(
    'SELECT user_id, role FROM memberships WHERE project_id = ?',
  ).bind(projectId).all();
  if (removeUserId) {
    const removed = members.find((m) => m.user_id === removeUserId);
    if (!removed) throw new HttpError(404, 'not_found');
    if (removed.role === 'manager' && members.filter((m) => m.role === 'manager').length < 2) {
      throw new HttpError(409, 'last_manager');
    }
  }
  const expectedMembers = new Set(members.map((m) => m.user_id).filter((id) => id !== removeUserId));
  const givenMembers = Array.isArray(body.members) ? body.members : [];
  if (givenMembers.length !== expectedMembers.size || !givenMembers.every((m) => expectedMembers.has(m?.userId))) {
    throw new HttpError(409, 'members_changed');
  }

  const { results: entries } = await env.DB.prepare('SELECT id FROM entries WHERE project_id = ?').bind(projectId).all();
  const expectedEntries = new Set(entries.map((e) => e.id));
  const givenEntries = Array.isArray(body.entries) ? body.entries : [];
  if (givenEntries.length !== expectedEntries.size || !givenEntries.every((e) => expectedEntries.has(e?.id))) {
    throw new HttpError(409, 'entries_changed');
  }

  const t = now();
  const statements = [
    env.DB.prepare('UPDATE projects SET encrypted_name = ?, key_version = ?, needs_rotation = 0 WHERE id = ?').bind(
      str(body, 'encryptedName', 4096), nextVersion, projectId,
    ),
  ];
  if (removeUserId) {
    statements.push(env.DB.prepare('DELETE FROM memberships WHERE project_id = ? AND user_id = ?').bind(projectId, removeUserId));
  }
  for (const m of givenMembers) {
    statements.push(env.DB.prepare('UPDATE memberships SET wrapped_key = ? WHERE project_id = ? AND user_id = ?').bind(
      str(m, 'wrappedKey', 1024), projectId, m.userId,
    ));
  }
  for (const e of givenEntries) {
    statements.push(env.DB.prepare(
      'UPDATE entries SET ciphertext = ?, key_version = ?, updated_at = ?, updated_by = ? WHERE id = ? AND project_id = ?',
    ).bind(str(e, 'ciphertext', MAX_ENTRY_BYTES), nextVersion, t, ctx.user.id, e.id, projectId));
  }
  await env.DB.batch(statements);

  // An entry written between our checks and the batch still uses the old key.
  // Flag the project instead of failing silently.
  const stale = await env.DB.prepare(
    'SELECT COUNT(*) AS n FROM entries WHERE project_id = ? AND key_version != ?',
  ).bind(projectId, nextVersion).first();
  if (stale.n) await env.DB.prepare('UPDATE projects SET needs_rotation = 1 WHERE id = ?').bind(projectId).run();

  if (removeUserId) await revokeShares(env, 'project_id = ? AND created_by = ?', [projectId, removeUserId]);
  await audit(ctx, removeUserId ? 'member.remove' : 'project.rotate', projectId, removeUserId);
  return json({ ok: true, keyVersion: nextVersion });
}

/* ---------- Entries & files ---------- */

async function listEntries(env, ctx, projectId) {
  await requireRole(env, projectId, ctx.user, 'viewer');
  const { results } = await env.DB.prepare(
    'SELECT id, ciphertext, key_version, updated_at, updated_by FROM entries WHERE project_id = ?',
  ).bind(projectId).all();
  return json({
    entries: results.map((r) => ({
      id: r.id, ciphertext: r.ciphertext, keyVersion: r.key_version, updatedAt: r.updated_at, updatedBy: r.updated_by,
    })),
  });
}

async function putEntry(request, env, ctx, id) {
  const body = await readJson(request);
  const projectId = requireId(body.projectId, 'projectId');
  const ciphertext = str(body, 'ciphertext', MAX_ENTRY_BYTES);
  await requireRole(env, projectId, ctx.user, 'editor');
  const existing = await env.DB.prepare('SELECT project_id FROM entries WHERE id = ?').bind(id).first();
  if (existing && existing.project_id !== projectId) throw new HttpError(409, 'project_mismatch');
  const project = await env.DB.prepare('SELECT key_version FROM projects WHERE id = ?').bind(projectId).first();
  if (body.keyVersion !== project.key_version) throw new HttpError(409, 'stale_key');

  await env.DB.prepare(
    `INSERT INTO entries (id, project_id, ciphertext, key_version, updated_at, updated_by) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
     ON CONFLICT (id) DO UPDATE SET ciphertext = ?3, key_version = ?4, updated_at = ?5, updated_by = ?6`,
  ).bind(id, projectId, ciphertext, project.key_version, now(), ctx.user.id).run();
  await audit(ctx, existing ? 'entry.update' : 'entry.create', projectId, id);
  return json({ ok: true });
}

async function deleteEntry(env, ctx, id) {
  const existing = await env.DB.prepare('SELECT project_id FROM entries WHERE id = ?').bind(id).first();
  if (!existing) throw new HttpError(404, 'not_found');
  await requireRole(env, existing.project_id, ctx.user, 'editor');
  await env.DB.prepare('DELETE FROM entries WHERE id = ?').bind(id).run();
  await revokeShares(env, 'entry_id = ?', [id]);
  await audit(ctx, 'entry.delete', existing.project_id, id);
  return json({ ok: true });
}

async function putFile(request, env, ctx, id, url) {
  const projectId = requireId(url.searchParams.get('project'), 'project');
  await requireRole(env, projectId, ctx.user, 'editor');
  const declared = Number(request.headers.get('content-length') || 0);
  if (declared > MAX_FILE_BYTES) throw new HttpError(413, 'too_large');
  if (await env.DB.prepare('SELECT 1 FROM files WHERE id = ?').bind(id).first()) {
    throw new HttpError(409, 'exists');
  }
  const data = await request.arrayBuffer();
  if (!data.byteLength || data.byteLength > MAX_FILE_BYTES) throw new HttpError(413, 'too_large');
  await env.FILES.put(id, data);
  await env.DB.prepare('INSERT INTO files (id, project_id, size, created_at) VALUES (?, ?, ?, ?)').bind(
    id, projectId, data.byteLength, now(),
  ).run();
  await audit(ctx, 'file.upload', projectId, id);
  return json({ ok: true });
}

async function fileRow(env, ctx, id, minRole) {
  const row = await env.DB.prepare('SELECT project_id FROM files WHERE id = ?').bind(id).first();
  if (!row) throw new HttpError(404, 'not_found');
  await requireRole(env, row.project_id, ctx.user, minRole);
  return row;
}

async function getFile(env, ctx, id) {
  const row = await fileRow(env, ctx, id, 'viewer');
  const object = await env.FILES.get(id);
  if (!object) throw new HttpError(404, 'not_found');
  await audit(ctx, 'file.download', row.project_id, id);
  return new Response(object.body, { headers: { 'content-type': 'application/octet-stream' } });
}

async function deleteFile(env, ctx, id) {
  const row = await fileRow(env, ctx, id, 'editor');
  await env.FILES.delete(id);
  await env.DB.prepare('DELETE FROM files WHERE id = ?').bind(id).run();
  await audit(ctx, 'file.delete', row.project_id, id);
  return json({ ok: true });
}

/* ---------- Share links ---------- */

const shareObject = (id) => `share/${id}`;

async function deleteShareObjects(env, ids) {
  for (let i = 0; i < ids.length; i += 1000) {
    await env.FILES.delete(ids.slice(i, i + 1000).map(shareObject));
  }
}

// Kills every live share matching a trusted SQL condition.
async function revokeShares(env, where, binds) {
  const { results } = await env.DB.prepare(`SELECT id FROM shares WHERE purged = 0 AND ${where}`).bind(...binds).all();
  if (!results.length) return;
  await env.DB.prepare(
    `UPDATE shares SET revoked_at = COALESCE(revoked_at, ?), purged = 1 WHERE purged = 0 AND ${where}`,
  ).bind(now(), ...binds).run();
  await deleteShareObjects(env, results.map((r) => r.id));
}

function shareState(row) {
  if (row.revoked_at) return 'revoked';
  if (row.mode === 'once' && row.views > 0) return 'opened';
  if (row.expires_at <= now()) return 'expired';
  return 'active';
}

const shareInfo = (r) => ({
  id: r.id, projectId: r.project_id, entryId: r.entry_id, createdBy: r.created_by, mode: r.mode, size: r.size,
  views: r.views, createdAt: r.created_at, expiresAt: r.expires_at, openedAt: r.opened_at, state: shareState(r),
});

async function createShare(request, env, ctx, url) {
  const id = requireId(url.searchParams.get('id'));
  const projectId = requireId(url.searchParams.get('project'), 'project');
  const entryId = requireId(url.searchParams.get('entry'), 'entry');
  const mode = url.searchParams.get('mode');
  const ttl = Number(url.searchParams.get('ttl'));
  if (!SHARE_TTLS[mode]?.includes(ttl)) throw new HttpError(400, 'bad_share_options');
  const proof = request.headers.get('x-share-proof');
  if (!proof || proof.length > 128) throw new HttpError(400, 'bad_field', { field: 'proof' });

  await requireRole(env, projectId, ctx.user, 'editor');
  const entry = await env.DB.prepare('SELECT 1 FROM entries WHERE id = ? AND project_id = ?').bind(entryId, projectId).first();
  if (!entry) throw new HttpError(404, 'not_found');

  const declared = Number(request.headers.get('content-length') || 0);
  if (declared > MAX_SHARE_BYTES) throw new HttpError(413, 'too_large');
  const data = await request.arrayBuffer();
  if (!data.byteLength || data.byteLength > MAX_SHARE_BYTES) throw new HttpError(413, 'too_large');

  const t = now();
  const result = await env.DB.prepare(
    `INSERT INTO shares (id, project_id, entry_id, created_by, mode, proof_hash, size, created_at, expires_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (id) DO NOTHING`,
  ).bind(id, projectId, entryId, ctx.user.id, mode, await sha256Hex(proof), data.byteLength, t, t + ttl).run();
  if (!result.meta.changes) throw new HttpError(409, 'exists');
  await env.FILES.put(shareObject(id), data);
  await audit(ctx, `share.create:${mode}`, projectId, id);
  return json({ ok: true, expiresAt: t + ttl }, 201);
}

// Admins see every link so they can act during an incident. Others see the
// links of projects they can edit. Content stays unreadable either way.
async function listShares(env, ctx) {
  const query = ctx.user.is_admin
    ? env.DB.prepare('SELECT * FROM shares ORDER BY created_at DESC LIMIT 500')
    : env.DB.prepare(
      `SELECT s.* FROM shares s JOIN memberships m ON m.project_id = s.project_id AND m.user_id = ?
       WHERE m.role IN ('editor', 'manager') ORDER BY s.created_at DESC LIMIT 500`,
    ).bind(ctx.user.id);
  const { results } = await query.all();
  return json({ shares: results.map(shareInfo) });
}

async function revokeShare(env, ctx, id) {
  const row = await env.DB.prepare('SELECT * FROM shares WHERE id = ?').bind(id).first();
  if (!row) throw new HttpError(404, 'not_found');
  if (!ctx.user.is_admin && row.created_by !== ctx.user.id) {
    await requireRole(env, row.project_id, ctx.user, 'manager');
  }
  await revokeShares(env, 'id = ?', [id]);
  await audit(ctx, 'share.revoke', row.project_id, id);
  return json({ ok: true });
}

async function publicShareStatus(env, ctx, id) {
  const limit = [`share:${ctx.ip}`];
  await assertNotLocked(env, limit);
  const row = await env.DB.prepare('SELECT * FROM shares WHERE id = ?').bind(id).first();
  if (!row) {
    await recordFailure(env, limit);
    throw new HttpError(404, 'share_gone');
  }
  return json({ state: shareState(row), mode: row.mode, expiresAt: row.expires_at, size: row.size });
}

// Opening needs a POST with the key proof, so link previews from chat apps
// (which only GET the page) cannot use up a one-time link.
async function openShare(request, env, ctx, id) {
  const limit = [`share:${ctx.ip}`];
  await assertNotLocked(env, limit);
  const body = await readJson(request);
  const row = await env.DB.prepare('SELECT * FROM shares WHERE id = ?').bind(id).first();
  const given = await sha256Hex(str(body, 'proof', 128));
  if (!row || !safeEqual(given, row.proof_hash)) {
    await recordFailure(env, limit);
    throw new HttpError(404, 'share_gone');
  }

  const t = now();
  // The WHERE clause is the lock: of any number of concurrent opens of a
  // one-time link, exactly one UPDATE changes a row.
  const claim = await env.DB.prepare(
    `UPDATE shares SET views = views + 1, opened_at = ?1
     WHERE id = ?2 AND revoked_at IS NULL AND expires_at > ?1 AND (mode = 'public' OR views = 0)`,
  ).bind(t, id).run();
  if (!claim.meta.changes) throw new HttpError(410, 'share_gone', { state: shareState(row) });

  const object = await env.FILES.get(shareObject(id));
  if (!object) throw new HttpError(410, 'share_gone', { state: 'expired' });
  const data = await object.arrayBuffer();
  if (row.mode === 'once') {
    // Content is gone from storage before the recipient receives it.
    await env.FILES.delete(shareObject(id));
    await env.DB.prepare('UPDATE shares SET purged = 1 WHERE id = ?').bind(id).run();
  }
  await audit(ctx, 'share.view', row.project_id, id);
  return new Response(data, { headers: { 'content-type': 'application/octet-stream' } });
}

async function purgeExpiredShares(env) {
  const t = now();
  const { results } = await env.DB.prepare(
    'SELECT id FROM shares WHERE purged = 0 AND expires_at <= ? LIMIT 1000',
  ).bind(t).all();
  if (results.length) {
    await deleteShareObjects(env, results.map((r) => r.id));
    await env.DB.batch(results.map((r) => env.DB.prepare('UPDATE shares SET purged = 1 WHERE id = ?').bind(r.id)));
  }
  await env.DB.prepare('DELETE FROM shares WHERE purged = 1 AND expires_at <= ?').bind(t - SHARE_ROW_RETENTION).run();
}

/* ---------- Router ---------- */

async function route(request, env, url) {
  const { pathname } = url;
  const method = request.method;
  const ctx = { env, ip: await sha256Hex(request.headers.get('CF-Connecting-IP') || 'local'), user: null };

  if (method !== 'GET' && method !== 'HEAD' && request.headers.get('origin') !== url.origin) {
    throw new HttpError(403, 'bad_origin');
  }

  if (pathname === '/api/status' && method === 'GET') return status(env);
  if (pathname === '/api/setup' && method === 'POST') return setup(request, env, ctx);
  if (pathname === '/api/prelogin' && method === 'POST') return prelogin(request, env);
  if (pathname === '/api/login' && method === 'POST') return login(request, env, ctx);
  if (pathname === '/api/logout' && method === 'POST') return logout(request, env);

  const invite = pathname.match(/^\/api\/invites\/([a-f0-9]{64})(\/accept)?$/);
  if (invite) {
    if (!invite[2] && method === 'GET') return getInvite(env, ctx, invite[1]);
    if (invite[2] && method === 'POST') return acceptInvite(request, env, ctx, invite[1]);
  }

  const publicShare = pathname.match(/^\/api\/public\/shares\/([a-f0-9]{32})(\/open)?$/);
  if (publicShare) {
    if (!publicShare[2] && method === 'GET') return publicShareStatus(env, ctx, publicShare[1]);
    if (publicShare[2] && method === 'POST') return openShare(request, env, ctx, publicShare[1]);
  }

  ctx.user = await currentUser(request, env);
  const parts = pathname.split('/').slice(2); // drop '' and 'api'
  const [resource, id, sub, subId] = parts;

  if (resource === 'me' && parts.length === 1 && method === 'GET') return me(env, ctx.user);
  if (resource === 'password' && parts.length === 1 && method === 'POST') return changePassword(request, env, ctx);
  if (resource === 'audit' && parts.length === 1 && method === 'GET') return listAudit(env, ctx);

  if (resource === 'users') {
    if (parts.length === 1 && method === 'GET') return listUsers(env, ctx.user);
    if (parts.length === 1 && method === 'POST') return createUser(request, env, ctx);
    if (parts.length === 3 && method === 'POST' && sub === 'disable') return disableUser(request, env, ctx, id);
    if (parts.length === 3 && method === 'POST' && sub === 'enable') return enableUser(env, ctx, id);
    if (parts.length === 3 && method === 'POST' && sub === 'reset') return resetUser(request, env, ctx, id);
  }

  if (resource === 'projects') {
    if (parts.length === 1 && method === 'POST') return createProject(request, env, ctx);
    const projectId = requireId(id, 'projectId');
    if (parts.length === 2 && method === 'PUT') return renameProject(request, env, ctx, projectId);
    if (parts.length === 2 && method === 'DELETE') return deleteProject(env, ctx, projectId);
    if (sub === 'entries' && parts.length === 3 && method === 'GET') return listEntries(env, ctx, projectId);
    if (sub === 'members' && parts.length === 3 && method === 'GET') return listMembers(env, ctx, projectId);
    if (sub === 'members' && parts.length === 3 && method === 'POST') return addMember(request, env, ctx, projectId);
    if (sub === 'members' && parts.length === 4 && method === 'PUT') return changeMemberRole(request, env, ctx, projectId, subId);
    if (sub === 'rotate' && parts.length === 3 && method === 'POST') return rotateProject(request, env, ctx, projectId);
  }

  if (resource === 'shares') {
    if (parts.length === 1 && method === 'POST') return createShare(request, env, ctx, url);
    if (parts.length === 1 && method === 'GET') return listShares(env, ctx);
    if (parts.length === 3 && sub === 'revoke' && method === 'POST') return revokeShare(env, ctx, requireId(id));
  }

  if (resource === 'entries' && parts.length === 2) {
    const entryId = requireId(id);
    if (method === 'PUT') return putEntry(request, env, ctx, entryId);
    if (method === 'DELETE') return deleteEntry(env, ctx, entryId);
  }

  if (resource === 'files' && parts.length === 2) {
    const fileId = requireId(id);
    if (method === 'PUT') return putFile(request, env, ctx, fileId, url);
    if (method === 'GET') return getFile(env, ctx, fileId);
    if (method === 'DELETE') return deleteFile(env, ctx, fileId);
  }

  throw new HttpError(404, 'not_found');
}

export default {
  async scheduled(event, env) {
    await purgeExpiredShares(env);
  },

  async fetch(request, env) {
    const url = new URL(request.url);
    const isApi = url.pathname.startsWith('/api/');
    if (url.pathname === '/s') {
      // Recipient page: same app, on its own path so an access gateway in front
      // of the vault can exempt it without exposing the rest.
      return withSecurityHeaders(await env.ASSETS.fetch(new URL('/', url)), false);
    }
    if (!isApi) return withSecurityHeaders(await env.ASSETS.fetch(request), false);
    try {
      return withSecurityHeaders(await route(request, env, url), true);
    } catch (error) {
      if (error instanceof HttpError) {
        return withSecurityHeaders(json({ error: error.code, ...error.extra }, error.status), true);
      }
      // Deliberately no error logging: request context must never reach logs.
      return withSecurityHeaders(json({ error: 'server_error' }, 500), true);
    }
  },
};
