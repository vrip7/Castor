-- PostgreSQL Initialization Script
-- Security hardening and initial setup

-- Revoke public access
REVOKE ALL ON SCHEMA public FROM PUBLIC;

-- Create application schema
CREATE SCHEMA IF NOT EXISTS auth;

-- Grant permissions to application user
GRANT USAGE ON SCHEMA auth TO castor;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA auth TO castor;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA auth TO castor;
ALTER DEFAULT PRIVILEGES IN SCHEMA auth GRANT ALL ON TABLES TO castor;
ALTER DEFAULT PRIVILEGES IN SCHEMA auth GRANT ALL ON SEQUENCES TO castor;

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Set search path
ALTER DATABASE castor SET search_path TO auth, public;

-- Create audit log table for tracking all changes
CREATE TABLE IF NOT EXISTS auth.audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    table_name VARCHAR(100) NOT NULL,
    operation VARCHAR(10) NOT NULL,
    old_data JSONB,
    new_data JSONB,
    changed_by VARCHAR(255),
    changed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    ip_address INET,
    user_agent TEXT
);

-- Create index on audit log
CREATE INDEX idx_audit_log_table_name ON auth.audit_log(table_name);
CREATE INDEX idx_audit_log_changed_at ON auth.audit_log(changed_at);
CREATE INDEX idx_audit_log_operation ON auth.audit_log(operation);

-- Function to automatically audit changes
CREATE OR REPLACE FUNCTION auth.audit_trigger_func()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO auth.audit_log (table_name, operation, new_data, changed_at)
        VALUES (TG_TABLE_NAME, TG_OP, row_to_json(NEW)::jsonb, NOW());
        RETURN NEW;
    ELSIF TG_OP = 'UPDATE' THEN
        INSERT INTO auth.audit_log (table_name, operation, old_data, new_data, changed_at)
        VALUES (TG_TABLE_NAME, TG_OP, row_to_json(OLD)::jsonb, row_to_json(NEW)::jsonb, NOW());
        RETURN NEW;
    ELSIF TG_OP = 'DELETE' THEN
        INSERT INTO auth.audit_log (table_name, operation, old_data, changed_at)
        VALUES (TG_TABLE_NAME, TG_OP, row_to_json(OLD)::jsonb, NOW());
        RETURN OLD;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Grant execute on audit function
GRANT EXECUTE ON FUNCTION auth.audit_trigger_func() TO castor;

-- Set statement timeout for this database
ALTER DATABASE castor SET statement_timeout = '60s';
ALTER DATABASE castor SET lock_timeout = '10s';

-- Prevent unauthorized schema modifications
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
