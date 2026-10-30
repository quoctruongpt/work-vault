-- Server stores only ciphertext, public keys, KDF params and hashes of derived auth keys.
CREATE TABLE users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  is_admin INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL CHECK (status IN ('pending', 'active', 'disabled')),
  kdf_salt TEXT,
  kdf_iterations INTEGER,
  auth_hash TEXT,
  recovery_auth_hash TEXT,
  public_key TEXT,
  wrapped_private_key TEXT,
  recovery_wrapped_private_key TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE invites (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users (id),
  expires_at INTEGER NOT NULL
);

CREATE TABLE sessions (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users (id),
  expires_at INTEGER NOT NULL
);
CREATE INDEX sessions_user ON sessions (user_id);

-- needs_rotation is set when a member loses access without a key rotation
-- (user disabled or reset by an admin who cannot re-encrypt the project).
CREATE TABLE projects (
  id TEXT PRIMARY KEY,
  encrypted_name TEXT NOT NULL,
  key_version INTEGER NOT NULL,
  needs_rotation INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);

CREATE TABLE memberships (
  project_id TEXT NOT NULL REFERENCES projects (id),
  user_id TEXT NOT NULL REFERENCES users (id),
  role TEXT NOT NULL CHECK (role IN ('viewer', 'editor', 'manager')),
  wrapped_key TEXT NOT NULL,
  PRIMARY KEY (project_id, user_id)
);
CREATE INDEX memberships_user ON memberships (user_id);

CREATE TABLE entries (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects (id),
  ciphertext TEXT NOT NULL,
  key_version INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  updated_by TEXT NOT NULL
);
CREATE INDEX entries_project ON entries (project_id);

CREATE TABLE files (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects (id),
  size INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX files_project ON files (project_id);

CREATE TABLE attempts (
  key TEXT PRIMARY KEY,
  failures INTEGER NOT NULL,
  window_start INTEGER NOT NULL
);

CREATE TABLE audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at INTEGER NOT NULL,
  user_id TEXT,
  action TEXT NOT NULL,
  project_id TEXT,
  target_id TEXT,
  ip_hash TEXT
);
CREATE INDEX audit_at ON audit (at);
