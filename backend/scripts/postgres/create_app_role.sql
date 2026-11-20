-- Creates the least-privileged runtime role used by the API (DATABASE_URL).
--
-- Why: PostgreSQL superusers and roles with BYPASSRLS ignore Row-Level Security. Running the API
-- as this dedicated role makes the tenant-isolation policies an enforced second layer.
--
-- Usage (as an admin/owner, e.g. the Supabase "postgres" user or the Docker superuser):
--   psql "$ADMIN_DATABASE_URL" -v app_password='a-long-random-password' -f create_app_role.sql
-- Safe to re-run; run it again after new migrations if default privileges do not apply.

SELECT format(
    'CREATE ROLE sentinel_app LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS',
    :'app_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sentinel_app') \gexec

GRANT USAGE ON SCHEMA public TO sentinel_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO sentinel_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO sentinel_app;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO sentinel_app;

-- Tables created later by this admin role (i.e. by future migrations) are granted automatically.
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO sentinel_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO sentinel_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO sentinel_app;
