-- Share content lives encrypted in R2 under share/<id>. The key stays in the
-- link fragment, which never reaches the server. Rows outlive the content so
-- the list and audit trail keep working after a link dies.
CREATE TABLE shares (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  entry_id TEXT NOT NULL,
  created_by TEXT NOT NULL,
  mode TEXT NOT NULL CHECK (mode IN ('once', 'public')),
  proof_hash TEXT NOT NULL,
  size INTEGER NOT NULL,
  views INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  opened_at INTEGER,
  revoked_at INTEGER,
  purged INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX shares_project ON shares (project_id);
CREATE INDEX shares_entry ON shares (entry_id);
CREATE INDEX shares_creator ON shares (created_by);
CREATE INDEX shares_expiry ON shares (purged, expires_at);
