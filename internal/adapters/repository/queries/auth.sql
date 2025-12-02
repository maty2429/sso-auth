-- name: CreateUser :one
INSERT INTO users (
    rut, dv, email, first_name, last_name, password_hash
) VALUES (
    $1, $2, $3, $4, $5, $6
) RETURNING *;

-- name: GetUserByEmail :one
SELECT * FROM users
WHERE email = $1 LIMIT 1;

-- name: GetUserByRut :one
SELECT * FROM users
WHERE rut = $1 LIMIT 1;

-- name: CreateRefreshToken :one
INSERT INTO refresh_tokens (
    user_id, token_hash, device_info, ip_address, expires_at
) VALUES (
    $1, $2, $3, $4, $5
) RETURNING *;

-- name: GetProjectMember :one
-- Esta es LA clave de tu seguridad (El Portero)
-- Verifica si el usuario pertenece al proyecto y devuelve su rol
SELECT pm.role_code, rd.name as role_name
FROM project_members pm
JOIN projects p ON p.id = pm.project_id
JOIN role_definitions rd ON rd.code = pm.role_code
WHERE pm.user_id = $1 
  AND p.project_code = $2 
  AND pm.is_active = TRUE
LIMIT 1;
