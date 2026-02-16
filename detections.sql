PRAGMA foreign_keys = ON;

INSERT INTO alerts (ts, severity, alert_type, user_id, ip, details)
SELECT
  datetime('now'),
  CASE WHEN COUNT(*) >= 25 THEN 'high' ELSE 'medium' END,
  'brute_force_ip',
  NULL,
  ae.ip,
  printf('%d failed logins from IP (last 10 min)', COUNT(*))
FROM auth_events ae
WHERE ae.success = 0
  AND ae.ts >= datetime('now', '-10 minutes')
GROUP BY ae.ip
HAVING COUNT(*) >= 12;


INSERT INTO alerts (ts, severity, alert_type, user_id, ip, details)
SELECT
  datetime('now'),
  CASE WHEN COUNT(*) >= 18 THEN 'high' ELSE 'medium' END,
  'account_under_attack',
  ae.user_id,
  NULL,
  printf('%d failed logins for user_id=%d (last 10 min)', COUNT(*), ae.user_id)
FROM auth_events ae
WHERE ae.success = 0
  AND ae.ts >= datetime('now', '-10 minutes')
GROUP BY ae.user_id
HAVING COUNT(*) >= 8;


INSERT INTO alerts (ts, severity, alert_type, user_id, ip, details)
SELECT
  datetime('now'),
  'high',
  'password_spraying',
  NULL,
  ae.ip,
  printf('IP attempted logins on %d different users (last 10 min)', COUNT(DISTINCT ae.user_id))
FROM auth_events ae
WHERE ae.success = 0
  AND ae.ts >= datetime('now', '-10 minutes')
GROUP BY ae.ip
HAVING COUNT(DISTINCT ae.user_id) >= 5;


INSERT INTO alerts (ts, severity, alert_type, user_id, ip, details)
SELECT
  datetime('now'),
  'medium',
  'new_device_login',
  ae.user_id,
  ae.ip,
  'Login from previously unseen device'
FROM auth_events ae
WHERE ae.success = 1
  AND ae.ts >= datetime('now', '-10 minutes')
  AND NOT EXISTS (
    SELECT 1 FROM auth_events prev
    WHERE prev.user_id = ae.user_id
      AND prev.device_id = ae.device_id
      AND prev.ts < ae.ts
  );




