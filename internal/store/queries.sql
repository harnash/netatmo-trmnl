-- name: GetConfigValue :one
SELECT value FROM config WHERE key = ?;

-- name: SetConfigValue :exec
INSERT INTO config (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value;
