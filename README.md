# Curupira 🛡️

A comprehensive **OAuth2 + OpenID Connect Identity Provider** built in Rust, compliant with RFC 9700 security best practices.

## Features

- **OAuth2 Authorization Code Flow** with **PKCE** (RFC 7636) - mandatory for all clients
- **OpenID Connect** support with ID tokens and UserInfo endpoint
- **Multi-tenant** architecture with per-application RSA keypairs
- **JWT tokens** signed with RS256 and proper key rotation support
- **Role-based Access Control (RBAC)** with application-specific roles
- **FusionAuth-compatible** endpoints for easy migration
- **Secure session management** with CSRF protection
- **API key authentication** for token and introspect endpoints
- **Comprehensive security** following RFC 9700 recommendations

## Architecture

### Endpoints

- `GET /.well-known/jwks.json` - JSON Web Key Set
- `GET /.well-known/openid-configuration` - OIDC Discovery
- `GET /oauth2/authorize` - Authorization endpoint (with consent UI)
- `POST /oauth2/token` - Token exchange endpoint
- `GET /oauth2/userinfo` - OIDC UserInfo endpoint  
- `POST /oauth2/introspect` - RFC 7662 Token Introspection
- `GET /oauth2/logout` - End session endpoint
- `GET /login` & `POST /login` - Authentication UI
- `GET /register` & `POST /register` - User registration UI
- `POST /consent` - Consent handling

### Security Features

✅ **PKCE Required** - All authorization code flows require PKCE with S256  
✅ **Strict Redirect URI Validation** - Exact string matching  
✅ **CSRF Protection** - All forms include CSRF tokens  
✅ **Secure Sessions** - HttpOnly, SameSite=Lax cookies  
✅ **Argon2id Password Hashing** - Strong password security  
✅ **RS256 JWT Signing** - Per-application keypairs  
✅ **API Key Authentication** - Required for sensitive endpoints  
✅ **Multi-tenant Isolation** - Tenant-scoped queries  

## Quick Start

### Prerequisites

- Rust 1.75+ 
- PostgreSQL 12+
- Docker (optional, for database)

### 1. Database Setup

Start PostgreSQL with Docker:

```bash
docker-compose up -d postgres
```

Or use your existing PostgreSQL instance and create a database:

```sql
CREATE DATABASE authdb;
```

### 2. Configuration

Copy the environment template:

```bash
cp .env.example .env
```

Generate a session secret:

```bash
openssl rand -base64 32
```

Update `.env` with your configuration:

```env
# Required - Generate with openssl rand -base64 32
SESSION_SECRET=your-generated-secret-here

# Update with your domain
ISSUER=http://localhost:8080
COOKIE_DOMAIN=localhost

# Update with your database URL
DATABASE_URL=postgres://postgres:changeme@localhost:5432/authdb
```

### 3. Run the Application

Build and run:

```bash
cargo run
```

The server will start on `http://localhost:8080` and automatically:
- Run database migrations
- Create the default tenant and test application
- Generate RSA keypairs for JWT signing
- Create a test user account

### 4. Test the Setup

Check the health endpoint:

```bash
curl http://localhost:8080/health
```

View JWKS:

```bash
curl http://localhost:8080/.well-known/jwks.json
```

## Usage Examples

### Complete OAuth2 Flow

#### 1. Generate PKCE Parameters

```bash
# Generate code verifier (base64url-encoded random string)
CODE_VERIFIER=$(openssl rand -base64 32 | tr -d "=" | tr "/+" "_-")

# Generate code challenge (SHA256 hash of verifier)
CODE_CHALLENGE=$(echo -n $CODE_VERIFIER | openssl dgst -sha256 -binary | base64 | tr -d "=" | tr "/+" "_-")

echo "Code Verifier: $CODE_VERIFIER"
echo "Code Challenge: $CODE_CHALLENGE"
```

#### 2. Authorization Request (Browser)

Navigate to:

```
http://localhost:8080/oauth2/authorize?client_id=dacf1e1b-eb0f-45b8-8e9d-2b73cd7bba35&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fapi%2Fauth%2Fcallback%2Ffusionauth&scope=openid%20email%20profile&state=xyz123&code_challenge=YOUR_CODE_CHALLENGE&code_challenge_method=S256&nonce=n-0S6_WzA2Mj
```

This will:
1. Show login page (use `test@dwcorp.com.br` / `password123`)
2. Show consent page  
3. Redirect back with authorization code

#### 3. Token Exchange

```bash
curl -X POST http://localhost:8080/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-API-Key: 9c2f4e6a-8b3d-4e7f-9a1b-2c3d4e5f6789" \
  -d "grant_type=authorization_code&code=YOUR_AUTH_CODE&redirect_uri=http://localhost:3000/api/auth/callback/fusionauth&client_id=dacf1e1b-eb0f-45b8-8e9d-2b73cd7bba35&code_verifier=$CODE_VERIFIER"
```

Response:
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjEyZmVmNGRhLTdkYzYtNDI1ZC04ZDY1LTgyYjdmZjBjYzJmOCJ9...",
  "id_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjEyZmVmNGRhLTdkYzYtNDI1ZC04ZDY1LTgyYjdmZjBjYzJmOCJ9...",
  "refresh_token": "random-opaque-token",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

#### 4. UserInfo Request

```bash
curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  http://localhost:8080/oauth2/userinfo
```

Response:
```json
{
  "sub": "550e8400-e29b-41d4-a716-446655440002",
  "email": "test@dwcorp.com.br",
  "email_verified": true,
  "name": "Test User",
  "given_name": "Test",
  "family_name": "User",
  "tenant": "550e8400-e29b-41d4-a716-446655440000",
  "roles": ["admin", "user"]
}
```

#### 5. Token Introspection

```bash
curl -X POST \
  -H "X-API-Key: 9c2f4e6a-8b3d-4e7f-9a1b-2c3d4e5f6789" \
  -d "token=YOUR_ACCESS_TOKEN" \
  http://localhost:8080/oauth2/introspect
```

Response:
```json
{
  "active": true,
  "scope": "openid email profile",
  "client_id": "dacf1e1b-eb0f-45b8-8e9d-2b73cd7bba35",
  "sub": "550e8400-e29b-41d4-a716-446655440002",
  "token_type": "access_token",
  "exp": 1234567890,
  "iat": 1234560000,
  "iss": "http://localhost:8080"
}
```

#### 6. Refresh Token

```bash
curl -X POST http://localhost:8080/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-API-Key: 9c2f4e6a-8b3d-4e7f-9a1b-2c3d4e5f6789" \
  -d "grant_type=refresh_token&refresh_token=YOUR_REFRESH_TOKEN"
```

#### 7. Logout

```bash
curl "http://localhost:8080/oauth2/logout?post_logout_redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fapi%2Fauth%2Fsignout&client_id=dacf1e1b-eb0f-45b8-8e9d-2b73cd7bba35"
```

## Default Test Data

The application seeds with:

- **Tenant**: `dwcorp` (DW Corp LTDA)
- **Application**: 
  - Client ID: `dacf1e1b-eb0f-45b8-8e9d-2b73cd7bba35`
  - API Key: `9c2f4e6a-8b3d-4e7f-9a1b-2c3d4e5f6789`
  - Redirect URIs: `http://localhost:3000/api/auth/callback/fusionauth`
- **Test User**: 
  - Email: `test@dwcorp.com.br`
  - Password: `password123`
  - Roles: `admin`, `user`

## Database Schema

The system uses a multi-tenant PostgreSQL schema:

- `tenants` - Organizations/companies
- `applications` - OAuth2 clients with per-app RSA keypairs  
- `users` - End users within tenants
- `roles` - Named roles per tenant
- `application_roles` - Which roles each app can grant
- `user_roles` - Role assignments per user
- `auth_codes` - Short-lived authorization codes
- `refresh_tokens` - Long-lived refresh tokens  
- `sessions` - User sessions with CSRF tokens

## Development

### Running Tests

```bash
cargo test
```

### Database Migrations

**Important**: You must run migrations before building the application, as SQLx validates queries at compile time.

#### Automatic Migrations (Recommended)
Migrations are automatically applied when the application starts:

```bash
cargo run --bin curupira
```

#### Manual Migrations
To run migrations manually:

```bash
# Install sqlx CLI (one-time setup)
cargo install sqlx-cli --no-default-features --features postgres

# Run all pending migrations
sqlx migrate run

# Verify migration status
sqlx migrate info

# Revert last migration (if needed)
sqlx migrate revert
```

#### Migration Workflow
1. **First setup**: Start database → Run migrations → Build application
2. **Development**: Create new migrations → Run migrations → Test
3. **Troubleshooting**: If compile errors about missing tables, run migrations first

### Key Generation

Generate new RSA keypairs for applications:

```bash
cargo run --bin keygen --features bin
```

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `APP_HOST` | No | `0.0.0.0` | Server bind address |
| `APP_PORT` | No | `8080` | Server port |
| `ISSUER` | No | `http://auth.dwcorp.com.br` | OAuth2 issuer URL |
| `DATABASE_URL` | No | `postgres://user:pass@localhost:5432/authdb` | PostgreSQL connection |
| `COOKIE_DOMAIN` | No | `.dwcorp.com.br` | Session cookie domain |
| `SESSION_SECRET` | **Yes** | - | Base64 session encryption key |
| `DEFAULT_ACCESS_TTL_SECS` | No | `3600` | Access token lifetime |
| `DEFAULT_REFRESH_TTL_MINS` | No | `43200` | Refresh token lifetime |
| `REQUIRE_API_KEY` | No | `true` | Require API keys for token endpoints |

## Production Deployment

### Security Checklist

- [ ] Generate strong `SESSION_SECRET` (32+ bytes)
- [ ] Use HTTPS in production (`ISSUER` should be `https://`)
- [ ] Set `COOKIE_DOMAIN` to your domain
- [ ] Use strong database credentials
- [ ] Enable database SSL/TLS
- [ ] Configure proper firewall rules
- [ ] Regular backup of database
- [ ] Monitor for failed authentication attempts
- [ ] Set up log rotation and monitoring

### Performance

- Use connection pooling for PostgreSQL
- Set appropriate token TTLs for your use case
- Run regular cleanup jobs for expired tokens/sessions:

```sql
-- Add to your maintenance scripts
DELETE FROM auth_codes WHERE expires_at < NOW();
DELETE FROM refresh_tokens WHERE expires_at < NOW() OR revoked = true;
DELETE FROM sessions WHERE expires_at < NOW();
```

## FusionAuth Migration

This implementation is designed to be FusionAuth-compatible:

1. Use the same endpoint URLs
2. Same JWT structure and claims
3. Same client_id format (UUID)
4. Same redirect URI validation
5. Compatible token introspection responses

Simply update your FusionAuth configuration to point to Curupira endpoints.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality  
4. Ensure all tests pass
5. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Security

If you discover a security vulnerability, please send an email to security@dwcorp.com.br. All security vulnerabilities will be promptly addressed.

---

Built with ❤️ in Rust, following OAuth2/OIDC specifications and RFC 9700 security best practices.

