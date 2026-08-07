FROM python:3.12-alpine

# psycopg2 build deps + pg_dump / psql for database backup/restore
RUN apk add --no-cache \
    gcc musl-dev libffi-dev \
    postgresql-dev \
    postgresql-client

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# .dockerignore keeps .env, .git and local databases out of the image.
# docker-compose supplies the environment at runtime via env_file.
COPY . .

# Writable location for pre-restore safety snapshots and uploaded evidence files.
RUN mkdir -p /app/data/pre-restore /app/data/evidence

# EXPOSE does not expand shell-style defaults, so it takes a literal.
# The actual bind port comes from $PORT at runtime (see CMD).
EXPOSE 5000

# Single worker — APScheduler runs inside the worker process.
# With Postgres the DB itself handles concurrent connections safely.
# If you scale workers, move the scheduler to a dedicated process.
# timeout 600 — must exceed the longest blocking operation (psql restore).
# Gunicorn SIGABRT fires at --timeout and kills subprocess.run mid-pipe.
CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${PORT:-5000} --workers 1 --timeout 600 run:app"]
