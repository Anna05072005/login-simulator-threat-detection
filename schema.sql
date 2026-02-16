PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  user_id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE,
  dept TEXT NOT NULL,
  role TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
  device_id INTEGER PRIMARY KEY AUTOINCREMENT,
  device_name TEXT NOT NULL UNIQUE,
  os TEXT NOT NULL,
  browser TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_events (
  event_id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  user_id INTEGER NOT NULL,
  ip TEXT NOT NULL,
  device_id INTEGER NOT NULL,
  country TEXT NOT NULL,
  city TEXT NOT NULL,
  success INTEGER NOT NULL,
  reason TEXT,
  FOREIGN KEY(user_id) REFERENCES users(user_id),
  FOREIGN KEY(device_id) REFERENCES devices(device_id)
);

CREATE TABLE IF NOT EXISTS alerts (
  alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  severity TEXT NOT NULL,
  alert_type TEXT NOT NULL,
  user_id INTEGER,
  ip TEXT,
  details TEXT
);

CREATE INDEX IF NOT EXISTS idx_auth_events_ts ON auth_events(ts);
CREATE INDEX IF NOT EXISTS idx_auth_events_ip_success ON auth_events(ip, success);
CREATE INDEX IF NOT EXISTS idx_auth_events_user_success ON auth_events(user_id, success);
