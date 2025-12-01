## Auth Server (Go)

Base para un servidor de autenticación siguiendo Clean/Hexagonal. Incluye estructura de carpetas, dependencias recomendadas y ejemplo de configuración.

### Estructura

- `cmd/auth-server`: punto de entrada, inicia dependencias y HTTP.
- `internal/config`: carga de configuración con Viper.
- `internal/domain`: entidades puras, contratos de repositorios y servicios de negocio.
- `internal/security`: hashing Argon2id, JWT y rate limiting.
- `internal/storage/postgres`: conexión y stubs de repositorio sobre PostgreSQL.
- `internal/handlers/http`: router Chi y wiring de endpoints REST (`/auth/login`, `/auth/refresh`, `/auth/logout`).
- `internal/auth/*`: handlers de casos de uso.

### Dependencias clave

- Router: `github.com/go-chi/chi/v5`
- Hash: `golang.org/x/crypto/argon2`
- JWT: `github.com/golang-jwt/jwt/v5`
- Postgres: `github.com/jackc/pgx/v5`
- Validación: `github.com/go-playground/validator/v10`
- Logs: `github.com/rs/zerolog`
- Configuración: `github.com/spf13/viper`
- Rate limiting: `github.com/redis/go-redis/v9` + `github.com/ulule/limiter/v3`

### Configuración

Usa `configs/config.example.yaml` o `.env.example` como base. Variables principales:

- `database.url`: cadena de conexión PostgreSQL.
- `jwt.access_secret` / `jwt.refresh_secret`: claves HMAC para firmar access/refresh.
- `redis.addr`: habilita rate limiting si se provee.

### Pendientes abiertos (implementación futura)
- OIDC token exchange real (`/auth/web/token`), códigos de autorización persistentes, validación de `client_secret` y grants, emisión de access/refresh/ID tokens.
- Endpoint de logout global con revocación de refresh por sesión/usuario y blacklist completa (user/session).
- Integrar `CredentialRepository` en la lógica de login: failed_attempts, locked_until, historial de contraseñas y validadores de RUT/contraseña/device.
- Middleware de roles/permisos y rate limit por RUT/IP/device en handlers.
- Auditoría enriquecida (ip/device_info/client_id) y repos de audit con metadata estructurada.
- Repos/servicios para roles/proyectos completos en tokens (ya se consultan roles/proyectos pero falta enlazar permisos).
- Validación de redirect_uri/client_id contra catálogo en Postgres para todos los flujos.

### Próximos pasos sugeridos

1. Implementar SQL real en los repositorios (`internal/storage/postgres/*`), alineado al modelo de BD dado.
2. Añadir migraciones (por ejemplo con `golang-migrate`) para crear tablas `users`, `user_credentials`, `roles`, `sessions`, etc.
3. Completar validaciones y errores de negocio en `AuthService` y handlers.
4. Añadir middleware de auditoría y logging estructurado por request.
