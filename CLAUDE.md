You are a senior Rust engineer. Build an OAuth2 + OpenID Connect **Identity Provider** (IdP) with Authorization Code + **PKCE** using **Axum** for HTTP, **Cargo Leptos** (SSR) for the consent UI, **SQLx** (PostgreSQL) for storage, and **JOSE/JWT** for token signing & JWKS. The service must be **FusionAuth-compatible** at the endpoint level and support **multi-tenant**, **applications**, **per-app keys**, **users**, **roles**, and associations (roles↔apps↔tenants, users↔roles per tenant). Also expose **.well-known/jwks.json** and (bonus) **.well-known/openid-configuration**.

Follow this spec exactly.

## Tech & crates

- Runtime: Rust stable.
- HTTP: `axum`, `tower`, `tower-cookies`, `tower-http`.
- Templating/UI: `leptos`, `leptos_axum` (SSR).
- DB: `sqlx` (Postgres, runtime-tokio, macros), `sqlx::migrate!`.
- Crypto/JWT/JWK: prefer `josekit` (JWK/JWKS/JWT, RSA + RS256), or `jsonwebtoken` + a small JWK helper. Use `rand`, `sha2`, `pbkdf2`/`argon2` for password hashing (prefer `argon2`).
- OAuth2 helpers: `oauth2` crate may be used for **client-side federation** (optional), but this IdP must implement its own OAuth2/OIDC server endpoints. (Do **not** depend on oxide-auth; implement flows explicitly.)
- Misc: `serde`, `serde_json`, `time`, `uuid`, `thiserror`, `anyhow`, `tracing`, `dotenvy`.

## Configuration (.env)

```
APP_HOST=0.0.0.0
APP_PORT=8080
ISSUER=http://auth.dwcorp.com.br
DATABASE_URL=postgres://user:pass@localhost:5432/authdb
COOKIE_DOMAIN=.dwcorp.com.br
SESSION_SECRET=<32+ random bytes base64>
DEFAULT_ACCESS_TTL_SECS=3600
DEFAULT_REFRESH_TTL_MINS=43200
REQUIRE_API_KEY=true
```

## FusionAuth-compatible integration details (must be honored)

- Authorization endpoint: `GET /oauth2/authorize`
- Token endpoint: `POST /oauth2/token`
- Userinfo: `GET /oauth2/userinfo`
- Introspect: `POST /oauth2/introspect`
- Logout (end-session): `GET /oauth2/logout`
- JWKS: `GET /.well-known/jwks.json`
- (Bonus) Discovery: `GET /.well-known/openid-configuration`
- Issuer: `http://auth.dwcorp.com.br`
- JWT TTL: 3600s (access & ID tokens)
- Refresh TTL: 43200 minutes (30 days)
- Access/ID token `kid`: support provided key id format (e.g., `12fef4da-7dc6-425d-8d65-82b7ff0cc2f8`)
- Authorized redirect (dev seed): `http://localhost:3000/api/auth/callback/fusionauth`
- Logout redirect (dev seed): `http://localhost:3000/api/auth/signout`
- When `REQUIRE_API_KEY=true`, the **token** and **introspect** endpoints must accept `X-API-Key: <app_api_key>` or `Authorization: API-Key <key>` and fail otherwise.

## Data model (SQLx + Postgres)

Create migrations for:

```
tenants(id uuid pk, slug text unique not null, name text not null, created_at timestamptz)
applications(id uuid pk, tenant_id uuid fk->tenants, client_id uuid unique not null, client_secret text null,
             name text not null, redirect_uris text[] not null, post_logout_redirect_uris text[] default '{}',
             jwk_kid uuid not null, jwk_private_pem text not null, jwk_public_jwk jsonb not null,
             api_key text unique not null, enabled boolean default true, created_at timestamptz)

users(id uuid pk, tenant_id uuid fk->tenants, email citext unique not null, email_verified boolean default false,
      password_hash text not null, given_name text, family_name text, created_at timestamptz, disabled boolean default false)

roles(id uuid pk, tenant_id uuid fk->tenants, name text not null, unique(tenant_id, name))

application_roles(application_id uuid fk->applications, role_id uuid fk->roles, primary key(application_id, role_id))

user_roles(user_id uuid fk->users, role_id uuid fk->roles, primary key(user_id, role_id))

auth_codes(code text pk, client_id uuid not null, tenant_id uuid not null, user_id uuid not null,
           redirect_uri text not null, scope text[] not null, code_challenge text not null,
           code_challenge_method text not null, nonce text null, state text null,
           created_at timestamptz, expires_at timestamptz, consumed boolean default false)

refresh_tokens(token text pk, client_id uuid not null, tenant_id uuid not null, user_id uuid not null,
               scope text[] not null, created_at timestamptz, expires_at timestamptz, revoked boolean default false)

sessions(id uuid pk, user_id uuid, tenant_id uuid, csrf text not null, created_at timestamptz, expires_at timestamptz)
```

- Use `citext` extension.
- Indexes: `users(email)`, `auth_codes(expires_at)`, `refresh_tokens(user_id, expires_at)`, etc.
- Seed one tenant, one application with:

  - `client_id = dacf1e1b-eb0f-45b8-8e9d-2b73cd7bba35`
  - `redirect_uris = {'http://localhost:3000/api/auth/callback/fusionauth'}`
  - `post_logout_redirect_uris = {'http://localhost:3000/api/auth/signout'}`
  - `jwk_kid = 12fef4da-7dc6-425d-8d65-82b7ff0cc2f8`
  - generate RSA keypair (2048+), store PEM private, JWK public in DB, store `api_key`

- Create a test user (with Argon2 hash) and a few roles; associate roles to app and user.

## HTTP routes (Axum)

Mount:

```
GET  /.well-known/jwks.json
GET  /.well-known/openid-configuration         (bonus)
GET  /oauth2/authorize                         (Auth Code + PKCE, shows consent via Leptos)
POST /oauth2/token                             (exchanges code, returns access_token, id_token, refresh_token)
POST /oauth2/introspect                        (active/introspection per RFC 7662)
GET  /oauth2/userinfo                          (OIDC userinfo; auth via bearer)
GET  /oauth2/logout                            (end session + optional redirect)

-- App pages (Leptos SSR)
GET  /login                                    (username/password + optional external IdP login)
POST /login
GET  /register
POST /register
GET  /consent                                  (rendered from /oauth2/authorize decision step)
POST /consent
```

### /oauth2/authorize (GET)

- Params: `client_id`, `redirect_uri`, `response_type=code`, `scope`, `state`, `code_challenge`, `code_challenge_method=S256`, `nonce` (for OIDC), `prompt` (login/consent), `redirect_uri` must match app’s whitelist (exact match).
- Flow:

  1. Verify client, redirect URI, app enabled.
  2. If no user session, redirect to `/login` preserving original params.
  3. Show consent page (Leptos) listing app name, tenant, requested scopes, and roles (if applicable).
  4. On “Allow”: issue short-lived auth code (e.g., 5 minutes), store `code_challenge`/method, `nonce`, `scope`, `user_id`, `tenant_id`, `client_id`, `redirect_uri`.
  5. Redirect: `redirect_uri?code=<code>&state=<state>`.

### Consent UI (Leptos SSR)

- Components:

  - `LoginForm` (email/password + CSRF)
  - `ConsentForm` (shows app, tenant, scopes; buttons Approve/Deny)

- Server Actions:

  - Login (verify password via Argon2; establish session cookie: HttpOnly, SameSite=Lax, Secure when HTTPS)
  - Consent decision posts back to `/oauth2/authorize` completing redirect

- Provide CSRF protection for all forms, store in `sessions.csrf`.

### /oauth2/token (POST)

- Headers: if `REQUIRE_API_KEY=true`, require `X-API-Key` or `Authorization: API-Key <key>`.

- grant_type `authorization_code` with `code`, `redirect_uri`, `client_id`, `code_verifier`.

- Steps:

  1. Validate API key belongs to `client_id`.
  2. Load auth code; verify not consumed, not expired; check `redirect_uri` matches the one in the code.
  3. **PKCE**: compute `base64url(SHA256(code_verifier))` and compare with stored `code_challenge` when method S256.
  4. Mark code as consumed.
  5. Issue tokens:

     - **access_token** (JWT, RS256) with claims: `iss`, `sub`, `aud` (client_id), `scope`, `exp`, `iat`, `jti`, `tenant`, plus standard OIDC fields if needed.
     - **id_token** (JWT, RS256) with `iss`, `sub`, `aud`, `exp`, `iat`, `nonce`, `email`, `email_verified`, `name`, `given_name`, `family_name`.
     - **refresh_token** (opaque random) persisted with TTL = 30 days.

  6. Response JSON:

     ```
     {
       "access_token": "...",
       "id_token": "...",
       "refresh_token": "...",
       "token_type": "Bearer",
       "expires_in": 3600
     }
     ```

- grant_type `refresh_token`: verify token, not revoked/expired, issue new access/id token; rotate refresh token.

### /oauth2/userinfo (GET)

- Require Bearer access token; verify signature (per app key), expiration, audience.
- Return OIDC userinfo: `sub`, `email`, `email_verified`, `name`, `given_name`, `family_name`, `tenant`, `roles` (intersection of user roles that are associated to the client application).

### /oauth2/introspect (POST)

- Require API key when configured.
- Form: `token=<access or refresh>`; For JWT access tokens: verify signature/exp and return RFC 7662 fields:

  ```
  { "active": true, "scope": "...", "client_id": "...", "sub": "...",
    "token_type": "access_token", "exp": 1234567890, "iat": 1234560000, "iss": "..." }
  ```

- For refresh tokens: check DB, `active` when not revoked and not expired.

### /oauth2/logout (GET)

- End user session (cookie clear) and optionally redirect to `post_logout_redirect_uri` if it’s on the app’s whitelist.

### /.well-known/jwks.json (GET)

- Aggregate **all active applications’** public JWKs (keys used for signing ID/Access tokens). Each JWK must include `kid`, `kty`, `n`, `e`, `alg=RS256`, `use=sig`. Filter out disabled apps and retired keys.

### /.well-known/openid-configuration (GET) — bonus

- Provide standard discovery metadata: `issuer`, `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`, `jwks_uri`, `response_types_supported`, `id_token_signing_alg_values_supported`, `scopes_supported`, `claims_supported`, `token_endpoint_auth_methods_supported` (`none`, `api_key`), `code_challenge_methods_supported` (`S256`).

## Security requirements

- **PKCE required** for public clients; reject when absent.
- Enforce exact `redirect_uri` match against app whitelist.
- Sessions: HttpOnly cookies, `Secure` in production, `SameSite=Lax`.
- Password hashing: Argon2id with strong params.
- Token signing: **RS256**; set `kid` header to app’s `jwk_kid`.
- Clock skew tolerance: 60s.
- Scope handling: basic `openid email profile` initially.
- RBAC: include `roles` claim (array) filtered to roles that the application has been granted.
- Multi-tenant isolation in all queries.
- Input validation & consistent error JSON (OAuth2 spec error fields).

## Key management (per application)

- On app creation, generate RSA keypair (>=2048), persist:

  - `jwk_private_pem` (encrypted at rest if possible)
  - `jwk_public_jwk` (JSON form)
  - `jwk_kid` (uuid)

- Sign tokens for an app using **that app’s** key; publish in JWKS.
- Provide a migration/CLI to **rotate keys**: create new pair, update `jwk_kid`, overlap JWKS for grace period.

## User registration & roles

- `/register` creates user in a tenant; email unique (citext).
- Associate default role(s) per tenant.
- Admin CLI endpoints (or protected HTTP) to:

  - create tenant
  - create application (with redirect URIs list and post_logout list)
  - create roles per tenant
  - grant roles to application
  - assign roles to user

- Expose minimal admin API guarded by an admin API key in headers.

## File layout

```
/src
  main.rs
  config.rs
  web/mod.rs
  web/routes.rs
  web/consent.rs          (Leptos components/pages)
  web/login.rs
  oauth/mod.rs
  oauth/authorize.rs
  oauth/token.rs
  oauth/userinfo.rs
  oauth/introspect.rs
  oauth/jwks.rs
  oauth/discovery.rs
  security/jwt.rs
  security/pkce.rs
  security/password.rs
  db/mod.rs
  db/models.rs
  db/queries.rs
/migrations
```

## Implementation details (critical)

1. **Authorize handler**:

   - Parse & validate query params; load app by `client_id`; ensure `redirect_uri` in app.redirect_uris.
   - Require `response_type=code`.
   - PKCE: require `code_challenge_method=S256` & `code_challenge` (43–128 chars), store both.
   - If not logged in → SSR login page, then continue.
   - Show SSR consent (scopes list); on approve → create `auth_codes` row (random url-safe base64 code) with 5-minute expiry; redirect back with `code` & `state`.

2. **Token handler**:

   - If `REQUIRE_API_KEY`: verify `X-API-Key` (exact match to app.api_key).
   - For `authorization_code`:

     - Lookup code, ensure not consumed & not expired.
     - Verify `client_id`, `redirect_uri` equals stored.
     - PKCE verification: `S256(code_verifier)` equals stored `code_challenge` (base64url no padding).
     - Mark consumed.
     - Build claims, sign `access_token` & `id_token` with app private key (`kid` header).
     - Create & persist `refresh_token` (opaque random 128-bit+).

   - For `refresh_token`: rotate if desired; issue new AT/IDT.

3. **JWT**:

   - RS256 via `josekit`; `iss = ISSUER`, `aud = client_id`, `sub = user_id`, `exp = now + 3600`, `iat = now`, `jti = uuid`.
   - Include `nonce` (if provided), `scope`, `tenant`, `roles`, `email`, `email_verified`, `given_name`, `family_name`.

4. **JWKS**: return `{ "keys": [ ... ] }` with public JWKs and their `kid`s.

5. **Userinfo**: extract bearer, verify signature by locating app via `aud` → select its public key; enforce `exp`/`nbf`/`iss`/`aud`.

6. **Introspect**: accept JWT or refresh token; report `active` plus standard fields.

7. **Logout**: clear session; if `post_logout_redirect_uri` present & allowed → redirect.

## Leptos SSR pages (minimum)

- `/login`: email + password, error handling, CSRF.
- `/consent`: app name, tenant name, requested scopes, Approve/Deny.

## Testing (add integration tests)

- Happy paths: login → authorize+consent → token → userinfo → introspect.
- Error paths: bad redirect_uri, missing PKCE, expired code, wrong API key, invalid audience.
- JWKS matches `kid` in tokens; verification succeeds with returned JWK.

## Example queries (curl)

```bash
# 1) Authorize (user logs in + consents via browser)
GET /oauth2/authorize?client_id=dacf1e1b-eb0f-45b8-8e9d-2b73cd7bba35&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fapi%2Fauth%2Fcallback%2Ffusionauth&scope=openid%20email%20profile&state=xyz&code_challenge=<CHALLENGE>&code_challenge_method=S256&nonce=n-0S6_WzA2Mj

# 2) Token (exchange with PKCE + API key)
curl -X POST http://auth.dwcorp.com.br/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-API-Key: <app_api_key>" \
  -d "grant_type=authorization_code&code=<code>&redirect_uri=http://localhost:3000/api/auth/callback/fusionauth&client_id=dacf1e1b-eb0f-45b8-8e9d-2b73cd7bba35&code_verifier=<VERIFIER>"

# 3) Userinfo
curl -H "Authorization: Bearer <access_token>" http://auth.dwcorp.com.br/oauth2/userinfo

# 4) Introspect
curl -X POST -H "X-API-Key: <app_api_key>" -d "token=<access_token>" http://auth.dwcorp.com.br/oauth2/introspect

# 5) JWKS
curl http://auth.dwcorp.com.br/.well-known/jwks.json
```

## Acceptance criteria (DoD)

- All endpoints above implemented and pass integration tests.
- Auth Code + **PKCE (S256)** enforced; redirect URIs strictly validated.
- Tokens are **RS256** with correct `kid`; JWKS publishes matching public keys.
- Access/ID TTL = 3600s; refresh TTL = 43200 minutes.
- Multi-tenant + per-app keys functional; RBAC appears in `roles` claim and `/userinfo`.
- Consent UI works via Leptos SSR; CSRF safe; secure cookies.
- `REQUIRE_API_KEY` enforced on `/oauth2/token` and `/oauth2/introspect`.
- Migrations + seed generate:

  - tenant, app with `client_id = dacf1e1b-eb0f-45b8-8e9d-2b73cd7bba35`
  - redirect URIs from the spec
  - `jwk_kid = 12fef4da-7dc6-425d-8d65-82b7ff0cc2f8`
  - valid RSA keypair and API key
  - one test user and roles

- Lints pass, logs with `tracing`, and README documents env, run, and curl tests.

## Stretch (optional)

- OIDC discovery endpoint.
- Key rotation CLI.
- External IdP login button using `oauth2` crate to federate (e.g., as upstream provider), mapping incoming claims to local user/tenant.

---

If anything above is ambiguous, prefer correctness to convenience and implement according to the OAuth2/OIDC specs (RFC 6749, 7636, 7517, 7518, 7519, 7662, OIDC Core).
