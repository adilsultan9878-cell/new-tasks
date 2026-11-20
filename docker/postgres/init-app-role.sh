#!/bin/sh
# Runs once when the Postgres volume is first initialised (docker-entrypoint-initdb.d).
# Creates the least-privileged runtime role the API connects as, so Row-Level Security applies.
set -e
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -v app_password="$SENTINEL_APP_DB_PASSWORD" -f /sql/create_app_role.sql
