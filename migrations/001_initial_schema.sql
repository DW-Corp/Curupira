-- Enable extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "citext";

-- Tenants table
CREATE TABLE tenants (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    slug TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Applications table
CREATE TABLE applications (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id UUID UNIQUE NOT NULL DEFAULT uuid_generate_v4(),
    client_secret TEXT,
    name TEXT NOT NULL,
    redirect_uris TEXT[] NOT NULL,
    post_logout_redirect_uris TEXT[] DEFAULT '{}',
    jwk_kid UUID NOT NULL DEFAULT uuid_generate_v4(),
    jwk_private_pem TEXT NOT NULL,
    jwk_public_jwk JSONB NOT NULL,
    api_key TEXT UNIQUE NOT NULL,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email CITEXT UNIQUE NOT NULL,
    email_verified BOOLEAN DEFAULT false,
    password_hash TEXT NOT NULL,
    given_name TEXT,
    family_name TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    disabled BOOLEAN DEFAULT false
);

-- Roles table
CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    UNIQUE(tenant_id, name)
);

-- Application roles (many-to-many)
CREATE TABLE application_roles (
    application_id UUID REFERENCES applications(id) ON DELETE CASCADE,
    role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY(application_id, role_id)
);

-- User roles (many-to-many)
CREATE TABLE user_roles (
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY(user_id, role_id)
);

-- Auth codes table
CREATE TABLE auth_codes (
    code TEXT PRIMARY KEY,
    client_id UUID NOT NULL,
    tenant_id UUID NOT NULL,
    user_id UUID NOT NULL,
    redirect_uri TEXT NOT NULL,
    scope TEXT[] NOT NULL,
    code_challenge TEXT NOT NULL,
    code_challenge_method TEXT NOT NULL,
    nonce TEXT,
    state TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed BOOLEAN DEFAULT false
);

-- Refresh tokens table
CREATE TABLE refresh_tokens (
    token TEXT PRIMARY KEY,
    client_id UUID NOT NULL,
    tenant_id UUID NOT NULL,
    user_id UUID NOT NULL,
    scope TEXT[] NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked BOOLEAN DEFAULT false
);

-- Sessions table
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    csrf TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);

-- Create indexes for performance
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_tenant_id ON users(tenant_id);
CREATE INDEX idx_applications_client_id ON applications(client_id);
CREATE INDEX idx_applications_api_key ON applications(api_key);
CREATE INDEX idx_auth_codes_expires_at ON auth_codes(expires_at);
CREATE INDEX idx_auth_codes_client_id ON auth_codes(client_id);
CREATE INDEX idx_refresh_tokens_user_id_expires_at ON refresh_tokens(user_id, expires_at);
CREATE INDEX idx_refresh_tokens_client_id ON refresh_tokens(client_id);
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX idx_roles_tenant_id ON roles(tenant_id);
CREATE INDEX idx_application_roles_role_id ON application_roles(role_id);
CREATE INDEX idx_user_roles_role_id ON user_roles(role_id);
