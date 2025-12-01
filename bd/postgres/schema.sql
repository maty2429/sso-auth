-- ===========================================
--  AUTH SERVER DATABASE SCHEMA (CORREGIDO)
-- ===========================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ===========================================
-- USERS
-- ===========================================

CREATE TABLE IF NOT EXISTS users
(
    id         UUID PRIMARY KEY            DEFAULT gen_random_uuid(),
    rut        VARCHAR(12) UNIQUE NOT NULL,
    dv         VARCHAR(1)         NOT NULL,
    first_name VARCHAR(100)       NOT NULL,
    last_name  VARCHAR(100)       NOT NULL,
    email      VARCHAR(150) UNIQUE,
    phone      VARCHAR(20),
    is_active  BOOLEAN            NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP          NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP          NOT NULL DEFAULT NOW()
    );

-- Function to update updated_at
CREATE OR REPLACE FUNCTION set_timestamp()
    RETURNS TRIGGER AS
$$
BEGIN
    NEW.updated_at = NOW();
RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger for users
DROP TRIGGER IF EXISTS trg_users_set_timestamp ON users;

CREATE TRIGGER trg_users_set_timestamp
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION set_timestamp();

-- ===========================================
-- USER CREDENTIALS
-- ===========================================

CREATE TABLE IF NOT EXISTS user_credentials
(
    user_id              UUID PRIMARY KEY
    REFERENCES users (id) ON DELETE CASCADE,
    password_hash        TEXT        NOT NULL,
    password_algo        VARCHAR(20) NOT NULL,
    last_password_change TIMESTAMP,
    failed_attempts      INT         NOT NULL DEFAULT 0,
    locked_until         TIMESTAMP,
    must_change_password BOOLEAN     NOT NULL DEFAULT FALSE
    );

-- ===========================================
-- PASSWORD HISTORY (optional)
-- ===========================================

CREATE TABLE IF NOT EXISTS password_history
(
    id            BIGSERIAL PRIMARY KEY,
    user_id       UUID        NOT NULL
    REFERENCES users (id) ON DELETE CASCADE,
    password_hash TEXT        NOT NULL,
    password_algo VARCHAR(20) NOT NULL,
    created_at    TIMESTAMP   NOT NULL DEFAULT NOW()
    );

CREATE INDEX IF NOT EXISTS idx_password_history_user_id
    ON password_history (user_id);

-- ===========================================
-- ROLES
-- ===========================================

CREATE TABLE IF NOT EXISTS roles
(
    id          SERIAL PRIMARY KEY,
    name        VARCHAR(50) UNIQUE NOT NULL,
    description TEXT
    );

-- User-role relation
CREATE TABLE IF NOT EXISTS user_roles
(
    user_id UUID NOT NULL
    REFERENCES users (id) ON DELETE CASCADE,
    role_id INT  NOT NULL
    REFERENCES roles (id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
    );

CREATE INDEX IF NOT EXISTS idx_user_roles_user_id
    ON user_roles (user_id);

CREATE INDEX IF NOT EXISTS idx_user_roles_role_id
    ON user_roles (role_id);

-- ===========================================
-- PROJECTS
-- ===========================================

CREATE TABLE IF NOT EXISTS projects
(
    id          SERIAL PRIMARY KEY,
    name        VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    created_at  TIMESTAMP           NOT NULL DEFAULT NOW()
    );

-- User-project relation
CREATE TABLE IF NOT EXISTS user_projects
(
    user_id    UUID NOT NULL
    REFERENCES users (id) ON DELETE CASCADE,
    project_id INT  NOT NULL
    REFERENCES projects (id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, project_id)
    );

CREATE INDEX IF NOT EXISTS idx_user_projects_user_id
    ON user_projects (user_id);

CREATE INDEX IF NOT EXISTS idx_user_projects_project_id
    ON user_projects (project_id);

-- ===========================================
-- PROJECT ROLES (optional)
-- ===========================================

CREATE TABLE IF NOT EXISTS project_roles
(
    id         SERIAL PRIMARY KEY,
    project_id INT NOT NULL
    REFERENCES projects (id) ON DELETE CASCADE,
    role_id    INT NOT NULL
    REFERENCES roles (id) ON DELETE CASCADE,
    UNIQUE (project_id, role_id)
    );

CREATE INDEX IF NOT EXISTS idx_project_roles_project_id
    ON project_roles (project_id);

CREATE INDEX IF NOT EXISTS idx_project_roles_role_id
    ON project_roles (role_id);

-- User-project-role assignment
CREATE TABLE IF NOT EXISTS user_project_roles
(
    user_id    UUID NOT NULL
    REFERENCES users (id) ON DELETE CASCADE,
    project_id INT  NOT NULL
    REFERENCES projects (id) ON DELETE CASCADE,
    role_id    INT  NOT NULL
    REFERENCES roles (id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, project_id, role_id)
    );

CREATE INDEX IF NOT EXISTS idx_user_project_roles_user_id
    ON user_project_roles (user_id);

CREATE INDEX IF NOT EXISTS idx_user_project_roles_project_id
    ON user_project_roles (project_id);

CREATE INDEX IF NOT EXISTS idx_user_project_roles_role_id
    ON user_project_roles (role_id);

-- ===========================================
-- AUTH CLIENTS
-- ===========================================

CREATE TABLE IF NOT EXISTS auth_clients
(
    id              UUID PRIMARY KEY             DEFAULT gen_random_uuid(),
    client_id       VARCHAR(100) UNIQUE NOT NULL,
    client_name     VARCHAR(150)        NOT NULL,
    client_secret   TEXT,
    is_confidential BOOLEAN             NOT NULL DEFAULT TRUE,
    allowed_grants  TEXT[]              NOT NULL,
    redirect_uris   TEXT[],
    created_at      TIMESTAMP           NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMP           NOT NULL DEFAULT NOW(),
    is_active       BOOLEAN             NOT NULL DEFAULT TRUE
    );

-- Trigger for auth_clients
DROP TRIGGER IF EXISTS trg_auth_clients_set_timestamp ON auth_clients;

CREATE TRIGGER trg_auth_clients_set_timestamp
    BEFORE UPDATE ON auth_clients
    FOR EACH ROW
    EXECUTE FUNCTION set_timestamp();

-- ===========================================
-- SESSIONS
-- ===========================================

CREATE TABLE IF NOT EXISTS sessions
(
    id             UUID PRIMARY KEY   DEFAULT gen_random_uuid(),
    user_id        UUID      NOT NULL
    REFERENCES users (id) ON DELETE CASCADE,
    auth_client_id UUID
    REFERENCES auth_clients (id) ON DELETE SET NULL,
    device_info    JSONB,
    ip_address     INET,
    created_at     TIMESTAMP NOT NULL DEFAULT NOW(),
    expires_at     TIMESTAMP NOT NULL,
    is_revoked     BOOLEAN   NOT NULL DEFAULT FALSE
    );

CREATE INDEX IF NOT EXISTS idx_sessions_user_id
    ON sessions (user_id);

CREATE INDEX IF NOT EXISTS idx_sessions_auth_client_id
    ON sessions (auth_client_id);

CREATE INDEX IF NOT EXISTS idx_sessions_expires_at
    ON sessions (expires_at);

-- ===========================================
-- REFRESH TOKENS
-- ===========================================

CREATE TABLE IF NOT EXISTS refresh_tokens
(
    id         UUID PRIMARY KEY   DEFAULT gen_random_uuid(),
    user_id    UUID      NOT NULL
    REFERENCES users (id) ON DELETE CASCADE,
    session_id UUID      NOT NULL
    REFERENCES sessions (id) ON DELETE CASCADE,
    token_hash TEXT      NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP NOT NULL,
    is_revoked BOOLEAN   NOT NULL DEFAULT FALSE
    );

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id
    ON refresh_tokens (user_id);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_session_id
    ON refresh_tokens (session_id);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at
    ON refresh_tokens (expires_at);

-- ===========================================
-- AUDIT LOGS
-- ===========================================

CREATE TABLE IF NOT EXISTS audit_logs
(
    id             BIGSERIAL PRIMARY KEY,
    user_id        UUID
    REFERENCES users (id) ON DELETE SET NULL,
    auth_client_id UUID
    REFERENCES auth_clients (id) ON DELETE SET NULL,
    action         VARCHAR(100) NOT NULL,
    description    TEXT,
    ip_address     INET,
    device_info    JSONB,
    created_at     TIMESTAMP NOT NULL DEFAULT NOW()
    );

CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id
    ON audit_logs (user_id);

CREATE INDEX IF NOT EXISTS idx_audit_logs_action
    ON audit_logs (action);

CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at
    ON audit_logs (created_at);

