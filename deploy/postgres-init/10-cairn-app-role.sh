#!/bin/sh
# Create the role CAIRN's web tier connects as, and hand it the database.
#
# Why this exists. POSTGRES_USER is the superuser the postgres image creates on
# first start. The web container used to connect as that superuser, and the
# database restore feature executes an uploaded dump with whatever privileges
# that connection has. As superuser that includes COPY ... FROM PROGRAM, which
# is command execution on the database host. The application never needs
# superuser for anything it does, so it no longer gets it.
#
# What the app role is: a LOGIN role with no SUPERUSER, CREATEDB, CREATEROLE or
# REPLICATION. It owns the CAIRN database, the public schema and every object in
# it, which is exactly enough to run migrations, back up, and restore (the
# restore preamble drops and recreates the public schema, which needs ownership,
# not superuser).
#
# When it runs.
#   Fresh volume: automatically, once, from /docker-entrypoint-initdb.d.
#   Existing deployment: by hand, once. It is idempotent, and on a database that
#   already has tables it transfers their ownership to the app role:
#
#     docker compose up -d postgres
#     docker compose exec postgres sh /docker-entrypoint-initdb.d/10-cairn-app-role.sh
#     docker compose up -d --build
#
# Requires CAIRN_DB_USER and CAIRN_DB_PASSWORD in the postgres container's
# environment (docker-compose.yml passes them through from .env).
set -e

: "${CAIRN_DB_USER:=cairn_app}"
: "${CAIRN_DB_PASSWORD:?CAIRN_DB_PASSWORD is required for the CAIRN app role}"
: "${POSTGRES_USER:?}"
: "${POSTGRES_DB:=$POSTGRES_USER}"

if [ "$CAIRN_DB_USER" = "$POSTGRES_USER" ]; then
    echo "CAIRN_DB_USER must differ from POSTGRES_USER; the point is that the app is not the superuser." >&2
    exit 1
fi

psql -v ON_ERROR_STOP=1 --no-psqlrc \
     --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
     -v app_user="$CAIRN_DB_USER" -v app_pw="$CAIRN_DB_PASSWORD" -v db="$POSTGRES_DB" <<'SQL'
-- Role: create if missing, then (re)assert its attributes and password either way.
SELECT format('CREATE ROLE %I LOGIN', :'app_user')
 WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'app_user') \gexec
SELECT format(
    'ALTER ROLE %I WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD %L',
    :'app_user', :'app_pw') \gexec

SELECT format('ALTER DATABASE %I OWNER TO %I', :'db', :'app_user') \gexec

-- A restore performed while the app ran as superuser recreated the public
-- schema owned by that superuser. The app role has to own it to restore again.
SELECT format('ALTER SCHEMA public OWNER TO %I', :'app_user') \gexec

-- Existing objects. Tables first: moving a table moves the sequences its
-- serial columns own. Free-standing sequences and views are handled after.
SELECT format('ALTER TABLE public.%I OWNER TO %I', c.relname, :'app_user')
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') \gexec
SELECT format('ALTER SEQUENCE public.%I OWNER TO %I', c.relname, :'app_user')
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = 'public' AND c.relkind = 'S'
   AND NOT EXISTS (SELECT 1 FROM pg_depend d
                    WHERE d.objid = c.oid AND d.deptype IN ('a', 'i')) \gexec
SELECT format('ALTER VIEW public.%I OWNER TO %I', c.relname, :'app_user')
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = 'public' AND c.relkind = 'v' \gexec
SQL

echo "CAIRN app role '$CAIRN_DB_USER' is ready and owns database '$POSTGRES_DB'."
