"""
Application configuration management.
Loads and validates all configuration from environment variables.
"""

import secrets
from functools import lru_cache
from typing import List, Optional

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class DatabaseSettings(BaseSettings):
    """Database configuration settings."""
    
    model_config = SettingsConfigDict(env_prefix="DATABASE_")
    
    host: str = Field(default="localhost", description="Database host")
    port: int = Field(default=5432, ge=1, le=65535, description="Database port")
    name: str = Field(default="castor", description="Database name")
    user: str = Field(default="castor", description="Database user")
    password: str = Field(..., min_length=12, description="Database password")
    pool_size: int = Field(default=20, ge=5, le=100, description="Connection pool size")
    max_overflow: int = Field(default=10, ge=0, le=50, description="Max overflow connections")
    pool_timeout: int = Field(default=30, ge=10, le=120, description="Pool timeout in seconds")
    pool_recycle: int = Field(default=1800, ge=300, le=7200, description="Connection recycle time")
    
    @property
    def async_url(self) -> str:
        """Get async database URL."""
        return f"postgresql+asyncpg://{self.user}:{self.password}@{self.host}:{self.port}/{self.name}"
    
    @property
    def sync_url(self) -> str:
        """Get sync database URL for migrations."""
        return f"postgresql+psycopg2://{self.user}:{self.password}@{self.host}:{self.port}/{self.name}"


class RedisSettings(BaseSettings):
    """Redis configuration settings."""
    
    model_config = SettingsConfigDict(env_prefix="REDIS_")
    
    host: str = Field(default="localhost", description="Redis host")
    port: int = Field(default=6379, ge=1, le=65535, description="Redis port")
    password: str = Field(..., min_length=12, description="Redis password")
    db: int = Field(default=0, ge=0, le=15, description="Redis database number")
    ssl: bool = Field(default=False, description="Enable SSL for Redis")
    
    @property
    def url(self) -> str:
        """Get Redis URL."""
        protocol = "rediss" if self.ssl else "redis"
        return f"{protocol}://:{self.password}@{self.host}:{self.port}/{self.db}"


class JWTSettings(BaseSettings):
    """JWT configuration settings."""
    
    model_config = SettingsConfigDict(env_prefix="JWT_")
    
    secret_key: str = Field(..., min_length=64, description="JWT secret key")
    algorithm: str = Field(default="HS512", description="JWT algorithm")
    access_token_expire_minutes: int = Field(default=15, ge=5, le=60)
    refresh_token_expire_days: int = Field(default=7, ge=1, le=30)
    issuer: str = Field(default="castor-auth-api", description="JWT issuer")
    audience: str = Field(default="castor-services", description="JWT audience")
    
    @field_validator("algorithm")
    @classmethod
    def validate_algorithm(cls, v: str) -> str:
        """Validate JWT algorithm."""
        allowed = {"HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}
        if v not in allowed:
            raise ValueError(f"Algorithm must be one of {allowed}")
        return v


class PasswordSettings(BaseSettings):
    """Password policy settings."""
    
    model_config = SettingsConfigDict(env_prefix="PASSWORD_")
    
    min_length: int = Field(default=12, ge=8, le=128, description="Minimum password length")
    require_uppercase: bool = Field(default=True, description="Require uppercase letters")
    require_lowercase: bool = Field(default=True, description="Require lowercase letters")
    require_digit: bool = Field(default=True, description="Require digits")
    require_special: bool = Field(default=True, description="Require special characters")
    hash_rounds: int = Field(default=12, ge=10, le=20, description="Argon2 hash rounds")
    expiry_days: int = Field(default=90, ge=30, le=365, description="Password expiry in days")


class RateLimitSettings(BaseSettings):
    """Rate limiting configuration."""
    
    model_config = SettingsConfigDict(env_prefix="RATE_LIMIT_")
    
    per_minute: int = Field(default=60, ge=10, le=1000)
    per_hour: int = Field(default=1000, ge=100, le=10000)
    burst: int = Field(default=10, ge=5, le=100)
    login_per_minute: int = Field(default=5, ge=3, le=20, alias="LOGIN_RATE_LIMIT_PER_MINUTE")
    registration_per_hour: int = Field(default=10, ge=5, le=50, alias="REGISTRATION_RATE_LIMIT_PER_HOUR")


class SecuritySettings(BaseSettings):
    """Security configuration settings."""
    
    model_config = SettingsConfigDict(env_prefix="")
    
    secret_key: str = Field(..., min_length=64, alias="SECRET_KEY")
    encryption_key: str = Field(..., min_length=32, alias="ENCRYPTION_KEY")
    encryption_salt: Optional[str] = Field(default=None, alias="ENCRYPTION_SALT")
    
    # Account security
    account_lockout_threshold: int = Field(default=5, ge=3, le=10, alias="ACCOUNT_LOCKOUT_THRESHOLD")
    account_lockout_duration_minutes: int = Field(default=30, ge=15, le=1440, alias="ACCOUNT_LOCKOUT_DURATION_MINUTES")
    session_concurrent_limit: int = Field(default=5, ge=1, le=20, alias="SESSION_CONCURRENT_LIMIT")
    
    # CORS
    cors_origins: List[str] = Field(default=["https://localhost"], alias="CORS_ORIGINS")
    cors_allow_credentials: bool = Field(default=True, alias="CORS_ALLOW_CREDENTIALS")
    cors_allow_methods: List[str] = Field(default=["GET", "POST", "PUT", "DELETE", "PATCH"], alias="CORS_ALLOW_METHODS")
    cors_allow_headers: List[str] = Field(default=["*"], alias="CORS_ALLOW_HEADERS")
    
    # Security headers
    hsts_max_age: int = Field(default=31536000, alias="HSTS_MAX_AGE")
    hsts_include_subdomains: bool = Field(default=True, alias="HSTS_INCLUDE_SUBDOMAINS")
    hsts_preload: bool = Field(default=True, alias="HSTS_PRELOAD")
    content_security_policy: str = Field(default="default-src 'self'", alias="CONTENT_SECURITY_POLICY")
    x_frame_options: str = Field(default="DENY", alias="X_FRAME_OPTIONS")
    x_content_type_options: str = Field(default="nosniff", alias="X_CONTENT_TYPE_OPTIONS")
    referrer_policy: str = Field(default="strict-origin-when-cross-origin", alias="REFERRER_POLICY")
    
    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors_origins(cls, v):
        """Parse CORS origins from string or list."""
        if isinstance(v, str):
            import json
            try:
                return json.loads(v)
            except json.JSONDecodeError:
                return [origin.strip() for origin in v.split(",")]
        return v


class MFASettings(BaseSettings):
    """Multi-factor authentication settings."""
    
    model_config = SettingsConfigDict(env_prefix="MFA_")
    
    issuer: str = Field(default="CastorAuth", description="MFA issuer name")
    enabled: bool = Field(default=True, description="Enable MFA globally")
    enforcement: str = Field(default="optional", description="MFA enforcement level")
    
    @field_validator("enforcement")
    @classmethod
    def validate_enforcement(cls, v: str) -> str:
        """Validate MFA enforcement level."""
        allowed = {"disabled", "optional", "required"}
        if v not in allowed:
            raise ValueError(f"Enforcement must be one of {allowed}")
        return v


class APIKeySettings(BaseSettings):
    """API key configuration."""
    
    model_config = SettingsConfigDict(env_prefix="API_KEY_")
    
    length: int = Field(default=64, ge=32, le=128, description="API key length")
    prefix: str = Field(default="cstr_", description="API key prefix")
    hash_algorithm: str = Field(default="sha512", description="Hash algorithm for storing keys")


class LoggingSettings(BaseSettings):
    """Logging configuration."""
    
    model_config = SettingsConfigDict(env_prefix="LOG_")
    
    level: str = Field(default="INFO", description="Log level")
    format: str = Field(default="json", description="Log format")
    file_path: str = Field(default="/var/log/castor/auth.log", alias="LOG_FILE_PATH")
    audit_file_path: str = Field(default="/var/log/castor/audit.log", alias="AUDIT_LOG_FILE_PATH")
    security_file_path: str = Field(default="/var/log/castor/security.log", alias="SECURITY_LOG_FILE_PATH")
    
    @field_validator("level")
    @classmethod
    def validate_level(cls, v: str) -> str:
        """Validate log level."""
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        v_upper = v.upper()
        if v_upper not in allowed:
            raise ValueError(f"Log level must be one of {allowed}")
        return v_upper


class Settings(BaseSettings):
    """Main application settings."""
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"
    )
    
    # Application settings
    app_name: str = Field(default="Castor", alias="APP_NAME")
    app_version: str = Field(default="1.0.0", alias="APP_VERSION")
    app_env: str = Field(default="production", alias="APP_ENV")
    debug: bool = Field(default=False, alias="DEBUG")
    api_prefix: str = Field(default="/api/v1", alias="API_PREFIX")
    
    # Server settings
    host: str = Field(default="0.0.0.0", alias="HOST")
    port: int = Field(default=6297, ge=1, le=65535, alias="PORT")
    workers: int = Field(default=4, ge=1, le=32, alias="WORKERS")
    
    # Metrics
    metrics_enabled: bool = Field(default=True, alias="METRICS_ENABLED")
    metrics_port: int = Field(default=9090, alias="METRICS_PORT")
    
    # Audit
    audit_enabled: bool = Field(default=True, alias="AUDIT_ENABLED")
    audit_retention_days: int = Field(default=365, alias="AUDIT_RETENTION_DAYS")
    
    # Nested settings
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    redis: RedisSettings = Field(default_factory=RedisSettings)
    jwt: JWTSettings = Field(default_factory=JWTSettings)
    password: PasswordSettings = Field(default_factory=PasswordSettings)
    rate_limit: RateLimitSettings = Field(default_factory=RateLimitSettings)
    security: SecuritySettings = Field(default_factory=SecuritySettings)
    mfa: MFASettings = Field(default_factory=MFASettings)
    api_key: APIKeySettings = Field(default_factory=APIKeySettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)
    
    @field_validator("app_env")
    @classmethod
    def validate_env(cls, v: str) -> str:
        """Validate environment."""
        allowed = {"development", "staging", "production"}
        if v not in allowed:
            raise ValueError(f"Environment must be one of {allowed}")
        return v
    
    @model_validator(mode="after")
    def validate_production_settings(self):
        """Validate settings for production environment."""
        if self.app_env == "production":
            if self.debug:
                raise ValueError("Debug mode must be disabled in production")
            # Allow wildcard "*" as a valid production CORS config (explicit opt-in)
            # Only reject if the only origin is localhost without explicit wildcard
            cors_origins = self.security.cors_origins
            if cors_origins and len(cors_origins) == 1:
                origin = cors_origins[0].lower()
                if "localhost" in origin and origin != "*":
                    raise ValueError("CORS origins must be properly configured for production")
        return self
    
    @property
    def is_production(self) -> bool:
        """Check if running in production."""
        return self.app_env == "production"


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()


# Create module-level settings instance for direct import
settings = get_settings()
