#!/bin/bash
set -e

# Set Python path to include the app directory
export PYTHONPATH="/app:${PYTHONPATH}"

# Wait for database to be ready
echo "Waiting for database..."
while ! nc -z ${DATABASE_HOST} ${DATABASE_PORT}; do
    sleep 1
done
echo "Database is ready!"

# Wait for Redis to be ready
echo "Waiting for Redis..."
while ! nc -z ${REDIS_HOST} ${REDIS_PORT}; do
    sleep 1
done
echo "Redis is ready!"

# Run database migrations
echo "Running database migrations..."
alembic upgrade head

# Start the application
echo "Starting application..."
exec gunicorn app.main:app \
    --bind 0.0.0.0:${PORT} \
    --workers ${WORKERS} \
    --worker-class uvicorn.workers.UvicornWorker \
    --timeout ${TIMEOUT} \
    --keep-alive ${KEEP_ALIVE} \
    --max-requests ${MAX_REQUESTS} \
    --max-requests-jitter ${MAX_REQUESTS_JITTER} \
    --access-logfile - \
    --error-logfile - \
    --capture-output \
    --enable-stdio-inheritance
