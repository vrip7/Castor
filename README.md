# VRIP7 API

## Overview
Production-grade, enterprise-level authentication API with end-to-end encryption and comprehensive security measures.

## Security Features
- End-to-end encryption using AES-256-GCM
- SQL injection protection via parameterized queries (SQLAlchemy ORM)
- DDoS protection with rate limiting (Redis-backed)
- Secure API key generation with cryptographic randomness
- MITM attack prevention with TLS 1.3, HSTS, certificate pinning
- Comprehensive logging and audit trails
- Role-based access control (RBAC)
- Multi-factor authentication (TOTP)
- Account lockout policies
- Password complexity enforcement
- Session management with concurrent session limits
- Request signing and validation
- Security headers (CSP, X-Frame-Options, etc.)

## Tech Stack
- **Framework**: FastAPI
- **Database**: PostgreSQL with SQLAlchemy
- **Cache/Rate Limiting**: Redis
- **Containerization**: Docker & Docker Compose
- **Password Hashing**: Argon2id
- **Encryption**: AES-256-GCM, RSA
- **Tokens**: JWT with RS256/HS512

## Quick Start

### Prerequisites
- Docker and Docker Compose
- OpenSSL for certificate generation

### Development Setup
```bash
# Copy environment file
cp .env.example .env

# Generate secure keys
python scripts/generate_keys.py

# Start services
docker-compose up -d

# Run migrations
docker-compose exec api alembic upgrade head
```

### Production Deployment
```bash
# Use production compose file
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

## API Documentation
- Swagger UI: `https://auth.api.vrip7.com/docs`
- ReDoc: `https://auth.api.vrip7.com/redoc`
- OpenAPI JSON: `https://auth.api.vrip7.com/openapi.json`

## Environment Variables
See `.env.example` for all configuration options.

## License
Proprietary - All Rights Reserved
