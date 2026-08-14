# ─── Build stage ──────────────────────────────────────────────────────────────
# gcc and the headers exist only to compile psycopg2's C extension. They have no
# business in a running incident-response console, so they stay in this stage and
# never reach the image that serves traffic.
FROM python:3.12-alpine AS build

RUN apk add --no-cache gcc musl-dev libffi-dev postgresql-dev

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ─── Runtime stage ────────────────────────────────────────────────────────────
FROM python:3.12-alpine

# pg_dump / psql for database backup and restore, and libpq for psycopg2.
# No compiler, no headers.
RUN apk add --no-cache postgresql-client libpq

COPY --from=build /install /usr/local

# Run as a non-root account.
#
# Everything in this container that touches the network, parses an upload, or
# shells out to psql runs as this uid. The same container holds the
# CrowdStrike/Proofpoint credentials in its environment and mounts the evidence
# volume. Running all of that as root meant any code-execution bug in a
# dependency landed as root, in an image that also shipped a C compiler.
RUN addgroup -S cairn && adduser -S -G cairn cairn

WORKDIR /app

# .dockerignore keeps .env, .git and local databases out of the image.
# docker-compose supplies the environment at runtime via env_file.
COPY --chown=cairn:cairn . .

# Writable location for pre-restore safety snapshots and uploaded evidence files.
#
# NOTE ON UPGRADING AN EXISTING DEPLOYMENT: docker-compose mounts the named
# volume cairn_data over /app/data. A volume created while this image ran as root
# is owned by root, and this uid cannot write to it. The failure is quiet —
# evidence_storage._storage_root() falls back to /tmp, uploads keep working, and
# evidence stops surviving a restart with only a log warning to say so. Chown the
# volume once before cutting over:
#
#   docker compose run --rm --user root web chown -R cairn:cairn /app/data
#
# A fresh deployment inherits the ownership set here and needs no such step.
RUN mkdir -p /app/data/pre-restore /app/data/evidence \
 && chown -R cairn:cairn /app/data

USER cairn

# EXPOSE does not expand shell-style defaults, so it takes a literal.
# The actual bind port comes from $PORT at runtime (see CMD). It must stay above
# 1024 — a non-root process cannot bind a privileged port.
EXPOSE 5000

# Single worker — APScheduler runs inside the worker process.
# With Postgres the DB itself handles concurrent connections safely.
# If you scale workers, move the scheduler to a dedicated process.
# timeout 600 — must exceed the longest blocking operation (psql restore).
# Gunicorn SIGABRT fires at --timeout and kills subprocess.run mid-pipe.
CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${PORT:-5000} --workers 1 --timeout 600 run:app"]
