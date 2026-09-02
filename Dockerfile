# ─── Build stage ──────────────────────────────────────────────────────────────
# gcc and the headers exist only to compile psycopg2's C extension. They have no
# business in a running incident-response console, so they stay in this stage and
# never reach the image that serves traffic.
#
# The base tag pins the Alpine line, not just the Python line. That matters for
# more than reproducibility: the postgresql16-* packages below exist only on the
# Alpine branches that carry them, and an unpinned `python:3.12-alpine` will move
# branches under you on some future rebuild.
FROM python:3.12-alpine3.21 AS build

# PostgreSQL client packages are pinned to major version 16, to match the server
# in docker-compose.yml (postgres:16-alpine).
#
# The unversioned names `postgresql-dev` and `postgresql-client` do not exist in
# Alpine 3.21 — there is no package by either literal name. They resolve only
# through `provides`, and the provider is whichever major version Alpine
# currently designates the default, which is 17. That skew is not hypothetical:
# app/routes/settings.py strips `SET transaction_timeout` from restore input
# because pg_dump 17 emits it and a PG16 server rejects it. That filter exists to
# paper over exactly this mismatch. Pinning the client to 16 removes the reason
# for it, and stops a future Alpine default of 18 introducing a new statement the
# filter does not know about — which would surface as a failed restore, at the
# worst possible moment to discover one.
RUN apk add --no-cache gcc musl-dev libffi-dev postgresql16-dev

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ─── Runtime stage ────────────────────────────────────────────────────────────
FROM python:3.12-alpine3.21

# pg_dump / psql for backup and restore, and libpq for psycopg2. No compiler, no
# headers. Same major-version pin as the build stage — psycopg2 is compiled
# against 16's libpq above and should not run against a different one here.
RUN apk add --no-cache postgresql16-client libpq

COPY --from=build /install /usr/local

# Run as a non-root account.
#
# Everything in this container that touches the network, parses an upload, or
# shells out to psql runs as this uid. The same container holds the CrowdStrike
# and Proofpoint credentials in its environment and mounts the evidence volume.
# Running all of that as root meant any code-execution bug in a dependency landed
# as root, in an image that also shipped a C compiler.
#
# The uid and gid are pinned deliberately. BusyBox `adduser -S` otherwise takes
# the first free system id, which is stable for one base image but not guaranteed
# across base image updates. Since the cairn_data volume is chowned to this id, an
# id that shifts on a rebuild reproduces the root-owned-volume failure described
# below — silently, because the fallback path still reports success to the user.
RUN addgroup -g 10001 -S cairn \
 && adduser -u 10001 -S -G cairn cairn

WORKDIR /app

# .dockerignore keeps .env, .git, local databases and *.md out of the image —
# including CODE_REVIEW.md, which describes unpatched issues and must not be baked
# into a layer. docker-compose supplies the environment at runtime via env_file.
COPY --chown=cairn:cairn . .

# Writable location for pre-restore safety snapshots and uploaded evidence files.
#
# NOTE ON UPGRADING AN EXISTING DEPLOYMENT: docker-compose mounts the named volume
# cairn_data over /app/data. A volume created while this image ran as root is
# owned by root, and uid 10001 cannot write to it. The failure is quiet, and was
# reproduced during review: evidence_storage._storage_root() catches the OSError,
# logs a warning, and returns /tmp. Uploads keep reporting success in the UI and
# stop surviving a restart. Chown the volume once, before cutting over:
#
#   docker compose run --rm --user root web chown -R 10001:10001 /app/data
#
# A fresh deployment inherits the ownership set here and needs no such step.
RUN mkdir -p /app/data/pre-restore /app/data/evidence \
 && chown -R cairn:cairn /app/data

USER cairn

# Documentation only — EXPOSE does not expand shell-style defaults and publishes
# nothing. 5002 matches the PORT default in docker-compose.yml; the real bind
# comes from $PORT at runtime (see CMD). It must stay above 1024, because a
# non-root process cannot bind a privileged port.
EXPOSE 5002

# Single worker — APScheduler runs inside the worker process.
# With Postgres the DB itself handles concurrent connections safely.
# If you scale workers, move the scheduler to a dedicated process.
# timeout 600 — must exceed the longest blocking operation (psql restore).
# Gunicorn SIGABRT fires at --timeout and kills subprocess.run mid-pipe.
CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${PORT:-5000} --workers 1 --timeout 600 run:app"]
