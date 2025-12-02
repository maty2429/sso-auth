-- ==================================================================
-- 1. CONFIGURACIÓN INICIAL Y EXTENSIONES
-- ==================================================================
CREATE EXTENSION IF NOT EXISTS "pgcrypto"; -- Para UUIDs y Hashing básico

-- Función automática para actualizar el campo 'updated_at'
CREATE OR REPLACE FUNCTION trigger_set_timestamp()
    RETURNS TRIGGER AS
$$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ==================================================================
-- 2. USUARIOS (Identidad Global)
-- ==================================================================
CREATE TABLE users
(
    id                        uuid PRIMARY KEY DEFAULT gen_random_uuid(),

    -- IDENTIFICACIÓN (RUT Chileno desglosado pero buscable)
    rut                       integer             NOT NULL,  -- Cuerpo: 12345678
    dv                        char(1)             NOT NULL,  -- Dígito: '9', 'K' (Validar mayúscula en backend)
    -- Columna Generada: Permite buscar WHERE full_rut = '12345678-9'
    full_rut                  varchar(15) GENERATED ALWAYS AS (rut::text || '-' || dv) STORED,

    email                     varchar(150) UNIQUE NOT NULL,
    first_name                varchar(100)        NOT NULL,
    last_name                 varchar(100)        NOT NULL,

    -- SEGURIDAD
    password_hash             text                NOT NULL,

    -- Protección contra fuerza bruta
    failed_attempts           smallint         DEFAULT 0,
    locked_until              timestamp,                     -- Si es NOT NULL y > NOW(), no dejar entrar

    -- Recuperación de cuenta
    recovery_token            varchar(100),
    recovery_token_expires_at timestamp,

    -- ESTADO
    is_active                 boolean          DEFAULT TRUE, -- FALSE = Baneado de TODA la plataforma
    last_login_at             timestamp,
    created_at                timestamp        DEFAULT NOW(),
    updated_at                timestamp        DEFAULT NOW(),

    -- Restricciones
    CONSTRAINT uq_users_rut UNIQUE (rut),
    CONSTRAINT uq_users_full_rut UNIQUE (full_rut)
);

-- Trigger para updated_at
CREATE TRIGGER set_timestamp_users
    BEFORE UPDATE
    ON users
    FOR EACH ROW
EXECUTE FUNCTION trigger_set_timestamp();

-- Índices de búsqueda rápida
CREATE INDEX idx_users_email ON users (email);
CREATE INDEX idx_users_full_rut ON users (full_rut);

-- ==================================================================
-- 3. PROYECTOS (Los "Inquilinos")
-- ==================================================================
CREATE TABLE projects
(
    id           int GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    project_code varchar(50) UNIQUE NOT NULL, -- Ej: 'PRJ-CONSTRUCCION-01'
    name         varchar(100)       NOT NULL,
    description  text,
    is_active    boolean   DEFAULT TRUE,      -- Si es FALSE, nadie entra al proyecto
    created_at   timestamp DEFAULT NOW(),
    updated_at   timestamp DEFAULT NOW()
);

CREATE INDEX idx_projects_code ON projects (project_code);

-- ==================================================================
-- 4. CATÁLOGO DE ROLES (Diccionario)
-- ==================================================================
-- Define qué significa cada número. Útil para el Frontend.
CREATE TABLE role_definitions
(
    code        smallint PRIMARY KEY, -- 10, 50, 99
    name        varchar(50) NOT NULL, -- 'Lector', 'Editor', 'Admin'
    description text
);

-- Insertamos los roles estándar
INSERT INTO role_definitions (code, name, description)
VALUES (10, 'Lector', 'Solo puede ver datos, sin editar'),
       (50, 'Operador', 'Puede editar datos operativos'),
       (99, 'Administrador', 'Control total del proyecto');

-- ==================================================================
-- 5. MIEMBROS DE PROYECTO (La relación Usuario-Proyecto)
-- ==================================================================
CREATE TABLE project_members
(
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    uuid     NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    project_id int      NOT NULL REFERENCES projects (id) ON DELETE CASCADE,

    -- El Rol se guarda como número para velocidad
    role_code  smallint NOT NULL REFERENCES role_definitions (code),

    is_active  boolean          DEFAULT TRUE, -- Soft ban específico del proyecto
    joined_at  timestamp        DEFAULT NOW(),

    -- REGLA: Un usuario solo puede tener 1 rol principal por proyecto
    CONSTRAINT uq_member_project UNIQUE (user_id, project_id)
);

CREATE INDEX idx_members_user ON project_members (user_id);
CREATE INDEX idx_members_project ON project_members (project_id);

-- ==================================================================
-- 6. SEGURIDAD MÓVIL (Refresh Tokens)
-- ==================================================================
-- Vital para que la App Móvil no pida login a cada rato.
CREATE TABLE refresh_tokens
(
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     uuid      NOT NULL REFERENCES users (id) ON DELETE CASCADE,

    token_hash  text      NOT NULL,             -- Hash del token (nunca guardar el token crudo)
    family_id   uuid,                           -- Opcional: Para rotación de tokens (seguridad avanzada)

    device_info varchar(255),                   -- 'Android 14 - Samsung S23'
    ip_address  inet,

    is_revoked  boolean          DEFAULT FALSE, -- TRUE = Cerrar sesión remotamente
    expires_at  timestamp NOT NULL,
    created_at  timestamp        DEFAULT NOW()
);

CREATE INDEX idx_refresh_tokens_user ON refresh_tokens (user_id);
CREATE INDEX idx_refresh_tokens_hash ON refresh_tokens (token_hash);

-- ==================================================================
-- 7. AUDITORÍA (Logs)
-- ==================================================================
CREATE TABLE audit_logs
(
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id     uuid        REFERENCES users (id) ON DELETE SET NULL,
    project_id  int         REFERENCES projects (id) ON DELETE SET NULL,

    action      varchar(50) NOT NULL, -- 'LOGIN_SUCCESS', 'LOGIN_FAILED', 'PROJECT_CREATE'
    description text,
    ip_address  inet,
    user_agent  text,

    meta_data   jsonb,                -- Detalles técnicos extra en formato JSON

    created_at  timestamp DEFAULT NOW()
);

-- Índices para reportes de auditoría
CREATE INDEX idx_audit_user ON audit_logs (user_id);
CREATE INDEX idx_audit_project ON audit_logs (project_id);
CREATE INDEX idx_audit_created ON audit_logs (created_at);
