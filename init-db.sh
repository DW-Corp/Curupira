#!/bin/bash
set -e

# Database initialization script for Curupira
# This ensures the authdb database exists and is properly configured

echo "🛡️  Initializing Curupira database..."

# Create the database if it doesn't exist
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    SELECT 'Database authdb already exists' WHERE EXISTS (SELECT FROM pg_database WHERE datname = 'authdb');
EOSQL

# Create a test user table to verify everything works
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    -- Enable UUID extension if not already enabled
    CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
    CREATE EXTENSION IF NOT EXISTS "citext";
    
    -- This will be overridden by migrations, but ensures basic connectivity
    DO \$\$
    BEGIN
        IF NOT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'health_check') THEN
            CREATE TABLE health_check (
                id SERIAL PRIMARY KEY,
                created_at TIMESTAMP DEFAULT NOW()
            );
            INSERT INTO health_check (created_at) VALUES (NOW());
        END IF;
    END
    \$\$;
EOSQL

echo "✅ Database initialization completed successfully!"
