-- Fix array column constraints to match Rust model expectations
-- SQLx requires exact type matching between database schema and Rust models

-- Applications: redirect_uris and post_logout_redirect_uris should be non-null arrays
-- Update any NULL values to empty arrays before adding constraints
UPDATE applications SET redirect_uris = '{}' WHERE redirect_uris IS NULL;
UPDATE applications SET post_logout_redirect_uris = '{}' WHERE post_logout_redirect_uris IS NULL;

-- Add NOT NULL constraints
ALTER TABLE applications ALTER COLUMN redirect_uris SET NOT NULL;
ALTER TABLE applications ALTER COLUMN post_logout_redirect_uris SET NOT NULL;

-- Set defaults for new rows
ALTER TABLE applications ALTER COLUMN redirect_uris SET DEFAULT '{}';
ALTER TABLE applications ALTER COLUMN post_logout_redirect_uris SET DEFAULT '{}';

-- Auth codes: scope should be non-null array
UPDATE auth_codes SET scope = '{}' WHERE scope IS NULL;
ALTER TABLE auth_codes ALTER COLUMN scope SET NOT NULL;
ALTER TABLE auth_codes ALTER COLUMN scope SET DEFAULT '{}';

-- Refresh tokens: scope should be non-null array  
UPDATE refresh_tokens SET scope = '{}' WHERE scope IS NULL;
ALTER TABLE refresh_tokens ALTER COLUMN scope SET NOT NULL;
ALTER TABLE refresh_tokens ALTER COLUMN scope SET DEFAULT '{}';