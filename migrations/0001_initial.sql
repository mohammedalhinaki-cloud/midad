PRAGMA foreign_keys = ON;

CREATE TABLE users (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  phone TEXT NOT NULL UNIQUE,
  role TEXT NOT NULL CHECK (role IN ('super_admin','assistant','member')),
  password_hash TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended','excluded')),
  joined_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  status_changed_at TEXT,
  deleted_at TEXT,
  created_by TEXT REFERENCES users(id),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX idx_users_role_status ON users(role,status);
CREATE INDEX idx_users_name ON users(name COLLATE NOCASE);

CREATE TABLE sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  expires_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX idx_sessions_user ON sessions(user_id);
CREATE INDEX idx_sessions_expiry ON sessions(expires_at);

CREATE TABLE login_attempts (
  id TEXT PRIMARY KEY,
  phone TEXT NOT NULL,
  attempted_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX idx_login_attempts_phone_time ON login_attempts(phone,attempted_at);

CREATE TABLE books (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  file_key TEXT NOT NULL,
  file_name TEXT NOT NULL,
  page_count INTEGER NOT NULL DEFAULT 0,
  start_page INTEGER NOT NULL DEFAULT 1,
  end_page INTEGER NOT NULL DEFAULT 0,
  pages_per_day INTEGER NOT NULL DEFAULT 3 CHECK (pages_per_day > 0),
  seconds_per_page INTEGER NOT NULL DEFAULT 60 CHECK (seconds_per_page >= 0),
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1)),
  created_by TEXT REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX idx_books_active ON books(active,created_at);

CREATE TABLE reading_days (
  id TEXT PRIMARY KEY,
  book_id TEXT REFERENCES books(id),
  starts_at TEXT NOT NULL,
  ends_at TEXT NOT NULL,
  locks_at TEXT NOT NULL,
  page_start INTEGER,
  page_end INTEGER,
  pages_json TEXT,
  paused INTEGER NOT NULL DEFAULT 0 CHECK (paused IN (0,1)),
  pause_reason TEXT,
  created_by TEXT REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  UNIQUE(book_id, starts_at)
);
CREATE INDEX idx_reading_days_range ON reading_days(starts_at,ends_at,locks_at);

CREATE TABLE reading_sessions (
  id TEXT PRIMARY KEY,
  reading_day_id TEXT NOT NULL REFERENCES reading_days(id),
  user_id TEXT NOT NULL REFERENCES users(id),
  next_page_index INTEGER NOT NULL DEFAULT 0,
  page_started_at TEXT NOT NULL,
  completed_at TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  UNIQUE(reading_day_id,user_id)
);
CREATE INDEX idx_reading_sessions_user ON reading_sessions(user_id,created_at DESC);

CREATE TABLE page_views (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES reading_sessions(id) ON DELETE CASCADE,
  page_number INTEGER NOT NULL,
  viewed_at TEXT NOT NULL,
  duration_seconds INTEGER NOT NULL,
  UNIQUE(session_id,page_number)
);
CREATE INDEX idx_page_views_session ON page_views(session_id,page_number);

CREATE TABLE reading_completions (
  id TEXT PRIMARY KEY,
  reading_day_id TEXT NOT NULL REFERENCES reading_days(id),
  user_id TEXT NOT NULL REFERENCES users(id),
  session_id TEXT NOT NULL REFERENCES reading_sessions(id),
  completed_at TEXT NOT NULL,
  late INTEGER NOT NULL DEFAULT 0 CHECK (late IN (0,1)),
  UNIQUE(reading_day_id,user_id)
);
CREATE INDEX idx_completions_user_time ON reading_completions(user_id,completed_at DESC);
CREATE INDEX idx_completions_day ON reading_completions(reading_day_id);

CREATE TABLE member_leaves (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  starts_on TEXT NOT NULL,
  ends_on TEXT NOT NULL,
  reason TEXT,
  created_by TEXT NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  CHECK(starts_on <= ends_on)
);
CREATE INDEX idx_member_leaves_dates ON member_leaves(user_id,starts_on,ends_on);

CREATE TABLE membership_events (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  event_type TEXT NOT NULL CHECK (event_type IN ('joined','excluded','reinstated','suspended','reactivated','deleted')),
  note TEXT,
  actor_id TEXT NOT NULL REFERENCES users(id),
  occurred_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX idx_membership_events_user ON membership_events(user_id,occurred_at DESC);

CREATE TABLE audit_logs (
  id TEXT PRIMARY KEY,
  actor_id TEXT NOT NULL REFERENCES users(id),
  action TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  entity_id TEXT,
  details_json TEXT NOT NULL DEFAULT '{}',
  occurred_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX idx_audit_actor ON audit_logs(actor_id,occurred_at DESC);
CREATE INDEX idx_audit_entity ON audit_logs(entity_type,entity_id,occurred_at DESC);
