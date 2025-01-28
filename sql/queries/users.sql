-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email, hashed_password)
VALUES (
    gen_random_uuid(),
    NOW(),
    NOW(),
    $1,
    $2
)
RETURNING *;

-- name: Reset :exec
DELETE FROM users;

-- name: CreateChirp :one
INSERT INTO chirps (id, created_at, updated_at, body, user_id)
VALUES (
    gen_random_uuid(),
    NOW(),
    NOW(),
    $1,
    $2
)
RETURNING *;

-- name: GetChirps :many
SELECT * FROM chirps
ORDER BY created_at;

-- name: GetSingleChirp :one
SELECT * FROM chirps
WHERE id = $1;

-- name: GetUserPasswordByEmail :one
SELECT * FROM users
WHERE email = $1;

-- name: GetRTokenForUser :one
SELECT token FROM refresh_tokens
WHERE user_id = $1;

-- name: CreateRefreshToken :exec
INSERT INTO refresh_tokens (token, created_at, updated_at, user_id, expires_at)
VALUES (
    $1,
    NOW(),
    NOW(),
    $2,
    NOW() + INTERVAL '60 days' 
);

-- name: GetTokenExistenceAndValidity :one
SELECT expires_at, revoked_at FROM refresh_tokens
WHERE token = $1;

-- name: GetUserForRefreshToken :one
SELECT user_id FROM refresh_tokens
WHERE token = $1;

-- name: SetRevocationTimestampForRefreshToken :exec
UPDATE refresh_tokens
SET revoked_at = $2
WHERE token = $1;

-- name: UpdateEmailAndPasswordForUser :exec
UPDATE users
SET email = $2, hashed_password = $3
WHERE id = $1;

-- name: DeleteSingleChirpForChirpID :exec
DELETE FROM chirps
WHERE id = $1;

-- name: UpdateToChirpyRed :exec
UPDATE users
SET is_chirpy_red = true
WHERE id = $1;

-- name: GetChirpsForAuthor :many
SELECT * FROM chirps
WHERE user_id = $1
ORDER BY created_at;