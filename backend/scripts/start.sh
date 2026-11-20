#!/bin/sh
# Container entrypoint: optionally migrate, then serve.
set -e
if [ "${RUN_MIGRATIONS_ON_START:-true}" = "true" ]; then
  echo "Running database migrations..."
  alembic upgrade head || {
    echo "Migration failed. Set MIGRATION_DATABASE_URL to the database owner role," >&2
    echo "or run migrations yourself and set RUN_MIGRATIONS_ON_START=false." >&2
    exit 1
  }
fi
exec uvicorn app.main:app \
  --host 0.0.0.0 --port "${PORT:-8000}" \
  --proxy-headers --forwarded-allow-ips "${FORWARDED_ALLOW_IPS:-127.0.0.1}" \
  --no-server-header
