# Build stage
FROM python:3.12-slim-bookworm AS builder

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies
COPY requirements.txt .
RUN pip install --upgrade pip setuptools wheel && \
    pip install -r requirements.txt


# Production stage
FROM python:3.12-slim-bookworm AS production

# Security: Create non-root user
RUN groupadd --gid 1000 castor && \
    useradd --uid 1000 --gid castor --shell /bin/bash --create-home castor

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    dumb-init \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean \
    && rm -rf /var/cache/apt/archives/*

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1 \
    PYTHONHASHSEED=random \
    PATH="/opt/venv/bin:$PATH" \
    PYTHONPATH=/app \
    APP_HOME=/app

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv

# Create application directory and log directories
RUN mkdir -p ${APP_HOME} /var/log/castor && \
    chown -R castor:castor ${APP_HOME} /var/log/castor

WORKDIR ${APP_HOME}

# Copy application code
COPY --chown=castor:castor ./app ./app
COPY --chown=castor:castor ./alembic ./alembic
COPY --chown=castor:castor ./alembic.ini ./alembic.ini
COPY --chown=castor:castor ./docker/entrypoint.sh ./entrypoint.sh

# Set proper permissions
RUN chmod -R 550 ${APP_HOME} && \
    chmod -R 770 /var/log/castor && \
    chmod +x ./entrypoint.sh

# Switch to non-root user
USER castor

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Expose port
EXPOSE 8000

# Use dumb-init as PID 1 to handle signals properly
ENTRYPOINT ["/usr/bin/dumb-init", "--", "./entrypoint.sh"]

# Default command (can be overridden)
CMD []
