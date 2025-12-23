# Castor Auth API

## Overview
Production-grade, enterprise-level authentication API with end-to-end encryption and comprehensive security measures.

## Security Features
- End-to-end encryption using AES-256-GCM
- SQL injection protection via parameterized queries (SQLAlchemy ORM)
- DDoS protection with rate limiting (Redis-backed)
- Secure API key generation with cryptographic randomness
- MITM attack prevention with TLS 1.3, HSTS
- Comprehensive logging and audit trails
- Role-based access control (RBAC)
- Multi-factor authentication (TOTP)
- Account lockout policies
- Password complexity enforcement
- Session management with concurrent session limits
- Security headers (CSP, X-Frame-Options, etc.)

## Tech Stack
- **Framework**: FastAPI
- **Database**: PostgreSQL 16 with SQLAlchemy 2.0
- **Cache/Rate Limiting**: Redis
- **Containerization**: Docker & Docker Compose
- **Password Hashing**: Argon2id
- **Encryption**: AES-256-GCM
- **Tokens**: JWT with HS512

## Quick Start

### Prerequisites
- Docker and Docker Compose
- Python 3.11+ (for local development)

### Development Setup
```bash
# Copy environment file
cp .env.example .env

# Generate secure keys (update values in .env)
openssl rand -hex 64  # For SECRET_KEY and JWT_SECRET_KEY
openssl rand -hex 32  # For ENCRYPTION_KEY

# Start services
docker-compose up -d

# Run migrations
docker-compose exec api alembic upgrade head
```

### Local Development (without Docker)
```bash
# Install dependencies
pip install -r requirements.txt

# Run the server
python run.py --reload
```

## API Documentation
Once running, access the API documentation at:
- Swagger UI: `http://localhost:6297/docs`
- ReDoc: `http://localhost:6297/redoc`
- OpenAPI JSON: `http://localhost:6297/openapi.json`

## Environment Variables
See `.env.example` for all configuration options.

## License
Proprietary - All Rights Reserved
