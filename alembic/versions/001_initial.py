"""Initial migration - Create all tables

Revision ID: 001
Revises: 
Create Date: 2024-01-01 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '001_initial'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create schema
    op.execute('CREATE SCHEMA IF NOT EXISTS auth')
    
    # Create extensions
    op.execute('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"')
    op.execute('CREATE EXTENSION IF NOT EXISTS "pgcrypto"')
    
    # Create enums
    op.execute("""
        DO $$ BEGIN
            CREATE TYPE auth.userstatus AS ENUM (
                'active', 'inactive', 'pending_verification', 'suspended', 'deactivated'
            );
        EXCEPTION
            WHEN duplicate_object THEN null;
        END $$;
    """)
    
    op.execute("""
        DO $$ BEGIN
            CREATE TYPE auth.userrole AS ENUM (
                'super_admin', 'admin', 'user', 'service', 'read_only'
            );
        EXCEPTION
            WHEN duplicate_object THEN null;
        END $$;
    """)
    
    op.execute("""
        DO $$ BEGIN
            CREATE TYPE auth.auditaction AS ENUM (
                'user_login', 'user_logout', 'login_failure', 'token_refresh',
                'user_created', 'user_updated', 'user_deleted', 'user_status_changed', 'user_role_changed',
                'password_change', 'password_reset_request', 'password_reset',
                'email_verified',
                'mfa_setup_initiated', 'mfa_setup_failed', 'mfa_enabled', 'mfa_disabled', 'mfa_verified', 'mfa_failed', 'mfa_backup_code_used', 'mfa_backup_codes_regenerated',
                'api_key_created', 'api_key_updated', 'api_key_revoked', 'api_key_rotated', 'api_key_used',
                'session_created', 'session_revoked', 'session_expired',
                'suspicious_activity', 'rate_limit_exceeded', 'access_denied'
            );
        EXCEPTION
            WHEN duplicate_object THEN null;
        END $$;
    """)
    
    op.execute("""
        DO $$ BEGIN
            CREATE TYPE auth.securityeventseverity AS ENUM (
                'low', 'medium', 'high', 'critical'
            );
        EXCEPTION
            WHEN duplicate_object THEN null;
        END $$;
    """)
    
    # Create users table
    op.create_table(
        'users',
        sa.Column('id', postgresql.UUID(as_uuid=True), server_default=sa.text('uuid_generate_v4()'), nullable=False),
        sa.Column('email', sa.String(255), nullable=False),
        sa.Column('username', sa.String(50), nullable=False),
        sa.Column('email_verified', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('email_verified_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('email_verification_token', sa.String(64), nullable=True),
        sa.Column('email_verification_sent_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('password_hash', sa.String(255), nullable=False),
        sa.Column('password_changed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('password_reset_token', sa.String(255), nullable=True),
        sa.Column('password_reset_sent_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('first_name_encrypted', sa.LargeBinary(), nullable=True),
        sa.Column('last_name_encrypted', sa.LargeBinary(), nullable=True),
        sa.Column('phone_encrypted', sa.LargeBinary(), nullable=True),
        sa.Column('status', postgresql.ENUM('active', 'inactive', 'pending_verification', 'suspended', 'deactivated', name='userstatus', schema='auth', create_type=False), nullable=False, server_default='pending_verification'),
        sa.Column('role', postgresql.ENUM('super_admin', 'admin', 'user', 'service', 'read_only', name='userrole', schema='auth', create_type=False), nullable=False, server_default='user'),
        sa.Column('mfa_enabled', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('mfa_secret', sa.String(64), nullable=True),
        sa.Column('mfa_enabled_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('failed_login_attempts', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('locked_until', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_failed_login', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_login', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_login_ip', sa.String(45), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('NOW()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('NOW()'), nullable=False),
        sa.PrimaryKeyConstraint('id', name='pk_users'),
        sa.UniqueConstraint('email', name='uq_users_email'),
        sa.UniqueConstraint('username', name='uq_users_username'),
        schema='auth'
    )
    op.create_index('ix_users_id', 'users', ['id'], schema='auth')
    op.create_index('ix_users_email', 'users', ['email'], schema='auth')
    op.create_index('ix_users_username', 'users', ['username'], schema='auth')
    op.create_index('ix_users_email_lower', 'users', [sa.text('LOWER(email)')], schema='auth')
    op.create_index('ix_users_username_lower', 'users', [sa.text('LOWER(username)')], schema='auth')
    op.create_index('ix_users_status', 'users', ['status'], schema='auth')
    op.create_index('ix_users_role', 'users', ['role'], schema='auth')
    op.create_index('ix_users_created_at', 'users', ['created_at'], schema='auth')
    
    # Create sessions table
    op.create_table(
        'sessions',
        sa.Column('id', postgresql.UUID(as_uuid=True), server_default=sa.text('uuid_generate_v4()'), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('token_family', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('revoked', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_activity', sa.DateTime(timezone=True), nullable=True),
        sa.Column('ip_address', sa.String(45), nullable=True),
        sa.Column('user_agent', sa.String(500), nullable=True),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('revoked_reason', sa.String(255), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('NOW()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('NOW()'), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['auth.users.id'], name='fk_sessions_user_id_users', ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id', name='pk_sessions'),
        schema='auth'
    )
    op.create_index('ix_sessions_id', 'sessions', ['id'], schema='auth')
    op.create_index('ix_sessions_user_id', 'sessions', ['user_id'], schema='auth')
    op.create_index('ix_sessions_token_family', 'sessions', ['token_family'], schema='auth')
    op.create_index('ix_sessions_revoked', 'sessions', ['revoked'], schema='auth')
    op.create_index('ix_sessions_expires_at', 'sessions', ['expires_at'], schema='auth')
    op.create_index('ix_sessions_user_revoked', 'sessions', ['user_id', 'revoked'], schema='auth')
    op.create_index('ix_sessions_created_at', 'sessions', ['created_at'], schema='auth')
    
    # Create api_keys table
    op.create_table(
        'api_keys',
        sa.Column('id', postgresql.UUID(as_uuid=True), server_default=sa.text('uuid_generate_v4()'), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('key_prefix', sa.String(12), nullable=False),
        sa.Column('key_hash', sa.String(128), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('scopes', postgresql.ARRAY(sa.String()), nullable=False, server_default='{}'),
        sa.Column('allowed_ips', postgresql.ARRAY(sa.String()), nullable=False, server_default='{}'),
        sa.Column('allowed_origins', postgresql.ARRAY(sa.String()), nullable=False, server_default='{}'),
        sa.Column('rate_limit_per_minute', sa.Integer(), nullable=False, server_default='60'),
        sa.Column('rate_limit_per_hour', sa.Integer(), nullable=False, server_default='1000'),
        sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_used_ip', sa.String(45), nullable=True),
        sa.Column('usage_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('previous_key_hash', sa.String(128), nullable=True),
        sa.Column('rotation_deadline', sa.DateTime(timezone=True), nullable=True),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('revoked_reason', sa.String(255), nullable=True),
        sa.Column('revoked_by', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('extra_data', postgresql.JSONB(), nullable=False, server_default='{}'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('NOW()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('NOW()'), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['auth.users.id'], name='fk_api_keys_user_id_users', ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id', name='pk_api_keys'),
        sa.UniqueConstraint('key_hash', name='uq_api_keys_key_hash'),
        schema='auth'
    )
    op.create_index('ix_api_keys_id', 'api_keys', ['id'], schema='auth')
    op.create_index('ix_api_keys_user_id', 'api_keys', ['user_id'], schema='auth')
    op.create_index('ix_api_keys_prefix', 'api_keys', ['key_prefix'], schema='auth')
    op.create_index('ix_api_keys_hash', 'api_keys', ['key_hash'], schema='auth')
    op.create_index('ix_api_keys_is_active', 'api_keys', ['is_active'], schema='auth')
    op.create_index('ix_api_keys_user_active', 'api_keys', ['user_id', 'is_active'], schema='auth')
    op.create_index('ix_api_keys_created_at', 'api_keys', ['created_at'], schema='auth')
    
    # Create audit_logs table
    op.create_table(
        'audit_logs',
        sa.Column('id', postgresql.UUID(as_uuid=True), server_default=sa.text('uuid_generate_v4()'), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('action', postgresql.ENUM('user_login', 'user_logout', 'login_failure', 'token_refresh', 'user_created', 'user_updated', 'user_deleted', 'user_status_changed', 'user_role_changed', 'password_change', 'password_reset_request', 'password_reset', 'email_verified', 'mfa_setup_initiated', 'mfa_setup_failed', 'mfa_enabled', 'mfa_disabled', 'mfa_verified', 'mfa_failed', 'mfa_backup_code_used', 'mfa_backup_codes_regenerated', 'api_key_created', 'api_key_updated', 'api_key_revoked', 'api_key_rotated', 'api_key_used', 'session_created', 'session_revoked', 'session_expired', 'suspicious_activity', 'rate_limit_exceeded', 'access_denied', name='auditaction', schema='auth', create_type=False), nullable=False),
        sa.Column('severity', postgresql.ENUM('low', 'medium', 'high', 'critical', name='securityeventseverity', schema='auth', create_type=False), nullable=False, server_default='low'),
        sa.Column('resource_type', sa.String(50), nullable=True),
        sa.Column('resource_id', sa.String(255), nullable=True),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('ip_address', sa.String(45), nullable=True),
        sa.Column('user_agent', sa.Text(), nullable=True),
        sa.Column('request_id', sa.String(64), nullable=True),
        sa.Column('correlation_id', sa.String(64), nullable=True),
        sa.Column('context', postgresql.JSONB(), nullable=False, server_default='{}'),
        sa.Column('success', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('geo_country', sa.String(2), nullable=True),
        sa.Column('geo_city', sa.String(255), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('NOW()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('NOW()'), nullable=False),
        sa.PrimaryKeyConstraint('id', name='pk_audit_logs'),
        schema='auth'
    )
    op.create_index('ix_audit_logs_id', 'audit_logs', ['id'], schema='auth')
    op.create_index('ix_audit_logs_user_id', 'audit_logs', ['user_id'], schema='auth')
    op.create_index('ix_audit_logs_action', 'audit_logs', ['action'], schema='auth')
    op.create_index('ix_audit_logs_severity', 'audit_logs', ['severity'], schema='auth')
    op.create_index('ix_audit_logs_resource_type', 'audit_logs', ['resource_type'], schema='auth')
    op.create_index('ix_audit_logs_request_id', 'audit_logs', ['request_id'], schema='auth')
    op.create_index('ix_audit_logs_correlation_id', 'audit_logs', ['correlation_id'], schema='auth')
    op.create_index('ix_audit_logs_created_at', 'audit_logs', ['created_at'], schema='auth')
    
    # Create mfa_devices table
    op.create_table(
        'mfa_devices',
        sa.Column('id', postgresql.UUID(as_uuid=True), server_default=sa.text('uuid_generate_v4()'), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('name', sa.String(255), nullable=False, server_default='Authenticator'),
        sa.Column('device_type', sa.String(50), nullable=False, server_default='totp'),
        sa.Column('secret_encrypted', sa.LargeBinary(), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('is_primary', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('verified_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('backup_codes_hash', sa.LargeBinary(), nullable=True),
        sa.Column('backup_codes_remaining', sa.String(2), nullable=False, server_default='10'),
        sa.Column('failed_attempts', sa.String(3), nullable=False, server_default='0'),
        sa.Column('locked_until', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('NOW()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('NOW()'), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['auth.users.id'], name='fk_mfa_devices_user_id_users', ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id', name='pk_mfa_devices'),
        schema='auth'
    )
    op.create_index('ix_mfa_devices_id', 'mfa_devices', ['id'], schema='auth')
    op.create_index('ix_mfa_devices_user_id', 'mfa_devices', ['user_id'], schema='auth')
    op.create_index('ix_mfa_devices_user_active', 'mfa_devices', ['user_id', 'is_active'], schema='auth')
    op.create_index('ix_mfa_devices_created_at', 'mfa_devices', ['created_at'], schema='auth')
    
    # Create mfa_backup_codes table
    op.create_table(
        'mfa_backup_codes',
        sa.Column('id', postgresql.UUID(as_uuid=True), server_default=sa.text('uuid_generate_v4()'), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('code_hash', sa.String(255), nullable=False),
        sa.Column('used', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('used_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('NOW()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('NOW()'), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['auth.users.id'], name='fk_mfa_backup_codes_user_id_users', ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id', name='pk_mfa_backup_codes'),
        schema='auth'
    )
    op.create_index('ix_mfa_backup_codes_id', 'mfa_backup_codes', ['id'], schema='auth')
    op.create_index('ix_mfa_backup_codes_user_id', 'mfa_backup_codes', ['user_id'], schema='auth')
    op.create_index('ix_mfa_backup_codes_used', 'mfa_backup_codes', ['used'], schema='auth')
    op.create_index('ix_mfa_backup_codes_user_used', 'mfa_backup_codes', ['user_id', 'used'], schema='auth')
    op.create_index('ix_mfa_backup_codes_created_at', 'mfa_backup_codes', ['created_at'], schema='auth')
    
    # Create password_history table
    op.create_table(
        'password_history',
        sa.Column('id', postgresql.UUID(as_uuid=True), server_default=sa.text('uuid_generate_v4()'), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('password_hash', sa.String(255), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('NOW()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('NOW()'), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['auth.users.id'], name='fk_password_history_user_id_users', ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id', name='pk_password_history'),
        schema='auth'
    )
    op.create_index('ix_password_history_id', 'password_history', ['id'], schema='auth')
    op.create_index('ix_password_history_user_id', 'password_history', ['user_id'], schema='auth')
    op.create_index('ix_password_history_user_created', 'password_history', ['user_id', 'created_at'], schema='auth')
    op.create_index('ix_password_history_created_at', 'password_history', ['created_at'], schema='auth')
    
    # Create login_attempts table
    op.create_table(
        'login_attempts',
        sa.Column('id', postgresql.UUID(as_uuid=True), server_default=sa.text('uuid_generate_v4()'), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('email_hash', sa.String(64), nullable=False),
        sa.Column('success', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('failure_reason', sa.String(100), nullable=True),
        sa.Column('ip_address', sa.String(45), nullable=False),
        sa.Column('user_agent', sa.String(500), nullable=True),
        sa.Column('geo_country', sa.String(2), nullable=True),
        sa.Column('geo_city', sa.String(255), nullable=True),
        sa.Column('mfa_used', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('NOW()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('NOW()'), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['auth.users.id'], name='fk_login_attempts_user_id_users', ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id', name='pk_login_attempts'),
        schema='auth'
    )
    op.create_index('ix_login_attempts_id', 'login_attempts', ['id'], schema='auth')
    op.create_index('ix_login_attempts_user_id', 'login_attempts', ['user_id'], schema='auth')
    op.create_index('ix_login_attempts_email_hash', 'login_attempts', ['email_hash'], schema='auth')
    op.create_index('ix_login_attempts_ip_address', 'login_attempts', ['ip_address'], schema='auth')
    op.create_index('ix_login_attempts_success', 'login_attempts', ['success'], schema='auth')
    op.create_index('ix_login_attempts_user_created', 'login_attempts', ['user_id', 'created_at'], schema='auth')
    op.create_index('ix_login_attempts_ip_created', 'login_attempts', ['ip_address', 'created_at'], schema='auth')
    op.create_index('ix_login_attempts_created_at', 'login_attempts', ['created_at'], schema='auth')
    
    # Create audit trigger function
    op.execute("""
        CREATE OR REPLACE FUNCTION auth.update_updated_at_column()
        RETURNS TRIGGER AS $$
        BEGIN
            NEW.updated_at = NOW();
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
    """)
    
    # Create triggers for updated_at
    for table in ['users', 'sessions', 'api_keys', 'audit_logs', 'mfa_devices', 'mfa_backup_codes', 'password_history', 'login_attempts']:
        op.execute(f"""
            CREATE TRIGGER update_{table}_updated_at
            BEFORE UPDATE ON auth.{table}
            FOR EACH ROW
            EXECUTE FUNCTION auth.update_updated_at_column();
        """)


def downgrade() -> None:
    # Drop triggers
    for table in ['users', 'sessions', 'api_keys', 'audit_logs', 'mfa_devices', 'mfa_backup_codes', 'password_history', 'login_attempts']:
        op.execute(f"DROP TRIGGER IF EXISTS update_{table}_updated_at ON auth.{table}")
    
    # Drop function
    op.execute("DROP FUNCTION IF EXISTS auth.update_updated_at_column()")
    
    # Drop tables
    op.drop_table('login_attempts', schema='auth')
    op.drop_table('password_history', schema='auth')
    op.drop_table('mfa_backup_codes', schema='auth')
    op.drop_table('mfa_devices', schema='auth')
    op.drop_table('audit_logs', schema='auth')
    op.drop_table('api_keys', schema='auth')
    op.drop_table('sessions', schema='auth')
    op.drop_table('users', schema='auth')
    
    # Drop enums
    op.execute("DROP TYPE IF EXISTS auth.securityeventseverity")
    op.execute("DROP TYPE IF EXISTS auth.auditaction")
    op.execute("DROP TYPE IF EXISTS auth.userrole")
    op.execute("DROP TYPE IF EXISTS auth.userstatus")
    
    # Drop schema
    op.execute("DROP SCHEMA IF EXISTS auth CASCADE")
