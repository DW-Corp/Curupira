-- Fix nullable constraints to match Rust model expectations
-- SQLx requires exact type matching between database schema and Rust models

-- Update any NULL values to appropriate defaults before adding constraints

-- Tenants: created_at should default to NOW()
UPDATE tenants SET created_at = NOW() WHERE created_at IS NULL;
ALTER TABLE tenants ALTER COLUMN created_at SET DEFAULT NOW();
ALTER TABLE tenants ALTER COLUMN created_at SET NOT NULL;

-- Applications: enabled should default to true, created_at to NOW()
UPDATE applications SET enabled = true WHERE enabled IS NULL;
UPDATE applications SET created_at = NOW() WHERE created_at IS NULL;
ALTER TABLE applications ALTER COLUMN enabled SET DEFAULT true;
ALTER TABLE applications ALTER COLUMN enabled SET NOT NULL;
ALTER TABLE applications ALTER COLUMN created_at SET DEFAULT NOW();
ALTER TABLE applications ALTER COLUMN created_at SET NOT NULL;

-- Users: email_verified defaults to false, disabled defaults to false, created_at to NOW()
UPDATE users SET email_verified = false WHERE email_verified IS NULL;
UPDATE users SET disabled = false WHERE disabled IS NULL;
UPDATE users SET created_at = NOW() WHERE created_at IS NULL;
ALTER TABLE users ALTER COLUMN email_verified SET DEFAULT false;
ALTER TABLE users ALTER COLUMN email_verified SET NOT NULL;
ALTER TABLE users ALTER COLUMN disabled SET DEFAULT false;
ALTER TABLE users ALTER COLUMN disabled SET NOT NULL;
ALTER TABLE users ALTER COLUMN created_at SET DEFAULT NOW();
ALTER TABLE users ALTER COLUMN created_at SET NOT NULL;

-- Auth codes: consumed defaults to false, timestamps should be set
UPDATE auth_codes SET consumed = false WHERE consumed IS NULL;
UPDATE auth_codes SET created_at = NOW() WHERE created_at IS NULL;
-- expires_at should already be set, but ensure it's not null
ALTER TABLE auth_codes ALTER COLUMN consumed SET DEFAULT false;
ALTER TABLE auth_codes ALTER COLUMN consumed SET NOT NULL;
ALTER TABLE auth_codes ALTER COLUMN created_at SET DEFAULT NOW();
ALTER TABLE auth_codes ALTER COLUMN created_at SET NOT NULL;
ALTER TABLE auth_codes ALTER COLUMN expires_at SET NOT NULL;

-- Refresh tokens: revoked defaults to false, timestamps should be set  
UPDATE refresh_tokens SET revoked = false WHERE revoked IS NULL;
UPDATE refresh_tokens SET created_at = NOW() WHERE created_at IS NULL;
-- expires_at should already be set, but ensure it's not null
ALTER TABLE refresh_tokens ALTER COLUMN revoked SET DEFAULT false;
ALTER TABLE refresh_tokens ALTER COLUMN revoked SET NOT NULL;
ALTER TABLE refresh_tokens ALTER COLUMN created_at SET DEFAULT NOW();
ALTER TABLE refresh_tokens ALTER COLUMN created_at SET NOT NULL;
ALTER TABLE refresh_tokens ALTER COLUMN expires_at SET NOT NULL;

-- Sessions: timestamps should be set
UPDATE sessions SET created_at = NOW() WHERE created_at IS NULL;
-- expires_at should already be set when creating sessions
ALTER TABLE sessions ALTER COLUMN created_at SET DEFAULT NOW();
ALTER TABLE sessions ALTER COLUMN created_at SET NOT NULL;
ALTER TABLE sessions ALTER COLUMN expires_at SET NOT NULL;