#!/usr/bin/env bash
#
# CAIRN update: bring a running deployment up to the latest code on main.
#
# Run it on the server, from the CAIRN folder:
#
#     ./update.sh            check, back up, update, rebuild, verify
#     ./update.sh --check    show what would change; changes nothing
#     ./update.sh --yes      same as the first, without the confirmation prompt
#
# What it does, in order. It stops at the first problem and says why.
#
#   1. Preflight. Must be on branch main, with no local edits to tracked files,
#      and Docker running the CAIRN stack.
#   2. Fetch. Shows the version you have, the version available, and the
#      commits in between.
#   3. Migration check. Reads the database's current schema revision and makes
#      sure the incoming code knows it. If it does not (the database was moved
#      forward by code that is no longer on main), it stops before anything is
#      changed, because CAIRN would refuse to start afterwards.
#   4. Backup. A compressed pg_dump of the database into backups/, readable by
#      this user only. The update does not continue without it.
#   5. Update. git pull (fast-forward only), fresh base images, rebuild.
#      Database migrations run as CAIRN starts, or explicitly here when
#      AUTO_UPGRADE_DB=false.
#   6. Verify. Waits for CAIRN to answer, then reports the version, Alpine,
#      Python, PostgreSQL and Caddy versions, and the database revision.
#
# Even with no new code, a run still pulls fresh postgres and caddy images and
# rebuilds on the current Python base, so it is also the way to pick up their
# security fixes. Run it at least monthly for that reason alone.
#
# It never deletes a backup, never rolls the database back on its own, and
# never touches .env. If something goes wrong after the pull, it prints the
# commands to go back.

set -Eeuo pipefail

BRANCH="main"
BACKUP_DIR="backups"
HEALTH_WAIT_SECONDS="${CAIRN_HEALTH_WAIT:-180}"

CHECK_ONLY=false
ASSUME_YES=false
for arg in "$@"; do
  case "$arg" in
    --check) CHECK_ONLY=true ;;
    --yes|-y) ASSUME_YES=true ;;
    -h|--help) awk 'NR>1 && /^#/ {sub(/^# ?/, ""); print; next} NR>1 {exit}' "$0"; exit 0 ;;
    *) echo "Unknown option: $arg (try --help)" >&2; exit 2 ;;
  esac
done

# ── Output ───────────────────────────────────────────────────────────────────
if [ -t 1 ]; then
  BOLD=$'\e[1m'; RED=$'\e[31m'; GREEN=$'\e[32m'; YELLOW=$'\e[33m'; RESET=$'\e[0m'
else
  BOLD=""; RED=""; GREEN=""; YELLOW=""; RESET=""
fi
step() { printf '\n%s== %s%s\n' "$BOLD" "$1" "$RESET"; }
ok()   { printf '   %sOK%s  %s\n' "$GREEN" "$RESET" "$1"; }
info() { printf '       %s\n' "$1"; }
warn() { printf '   %s!%s   %s\n' "$YELLOW" "$RESET" "$1"; }
stop() {
  printf '\n%sSTOPPED:%s %s\n' "$RED" "$RESET" "$1" >&2
  shift
  for line in "$@"; do printf '         %s\n' "$line" >&2; done
  printf '\nNothing was changed by this step.\n' >&2
  exit 1
}

# After the pull, a failure means the code has changed. Say how to go back.
PREV_COMMIT=""
BACKUP_FILE=""
on_error() {
  local code=$?
  if [ -n "$PREV_COMMIT" ]; then
    printf '\n%sThe update did not finish.%s The code was updated, so to go back:\n' "$RED" "$RESET" >&2
    printf '   git checkout %s\n' "$PREV_COMMIT" >&2
    printf '   docker compose up -d --build\n' >&2
    if [ -n "$BACKUP_FILE" ]; then
      printf '\nThe database backup taken before the update is:\n   %s\n' "$BACKUP_FILE" >&2
      printf 'Restore it from Admin > Settings > Database only if the database itself is damaged.\n' >&2
    fi
    printf 'Afterwards, return to main with: git checkout %s\n' "$BRANCH" >&2
  fi
  exit "$code"
}
trap on_error ERR

compose() { docker compose "$@"; }

# Read one value from .env without sourcing it (sourcing would execute it).
env_value() {
  local key="$1" default="$2" line
  line=$(grep -E "^[[:space:]]*${key}=" .env 2>/dev/null | tail -n 1 || true)
  line="${line#*=}"; line="${line%\"}"; line="${line#\"}"; line="${line%\'}"; line="${line#\'}"
  printf '%s' "${line:-$default}"
}

psql_value() {
  compose exec -T postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAc "$0"' "$1" 2>/dev/null \
    | tr -d '[:space:]'
}

# ── 1. Preflight ─────────────────────────────────────────────────────────────
step "Preflight"

cd "$(dirname "$0")"
[ -f docker-compose.yml ] && [ -f VERSION ] && [ -d migrations/versions ] \
  || stop "This does not look like the CAIRN folder." "Run it from the folder that holds docker-compose.yml."
[ -f .env ] || stop "No .env file here." "CAIRN's settings live in .env; copy .env.example and fill it in first."
command -v git >/dev/null || stop "git is not installed."
command -v docker >/dev/null || stop "docker is not installed."
docker compose version >/dev/null 2>&1 || stop "'docker compose' is not available." "CAIRN needs Docker Compose v2."
docker info >/dev/null 2>&1 || stop "Docker is not running, or this user cannot reach it." "Try again with sudo, or add this user to the docker group."
ok "Docker and git available"

current_branch=$(git rev-parse --abbrev-ref HEAD)
if [ "$current_branch" != "$BRANCH" ]; then
  stop "This folder is on branch '$current_branch', not '$BRANCH'." \
       "Updates come from $BRANCH. Switching branches can leave the database ahead of" \
       "the code, so it is not done automatically. Check what that branch changed first."
fi
ok "On branch $BRANCH"

if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
  git status --short --untracked-files=no >&2
  stop "There are local edits to tracked files (listed above)." \
       "A pull could overwrite or conflict with them. Commit them, or put them back" \
       "with 'git checkout -- <file>', then run this again."
fi
ok "No local edits to tracked files"

# Captured first, then searched. Piping straight into `grep -q` lets grep exit
# early, and under pipefail that reads as a failure whenever compose is still
# writing: a check that passes or fails on timing alone.
running_services=$(compose ps --status running --services 2>/dev/null || true)
if ! grep -qx postgres <<< "$running_services"; then
  stop "The postgres container is not running." "Start CAIRN with 'docker compose up -d' first, so the database can be backed up."
fi
ok "Database container running"

# ── 2. What is available ────────────────────────────────────────────────────
step "Checking for updates"

git fetch --quiet origin "$BRANCH" || stop "Could not reach the git remote." "Check the network and that 'git fetch' works here."

local_commit=$(git rev-parse HEAD)
remote_commit=$(git rev-parse "origin/$BRANCH")
current_version=$(tr -d '[:space:]' < VERSION)
remote_version=$(git show "origin/$BRANCH:VERSION" 2>/dev/null | tr -d '[:space:]' || echo "unknown")

info "Installed: v${current_version} (${local_commit:0:7})"
info "Available: v${remote_version} (${remote_commit:0:7})"

if ! git merge-base --is-ancestor "$local_commit" "$remote_commit"; then
  stop "This folder has commits that are not on origin/$BRANCH." \
       "A fast-forward update is not possible. Push them, or look at 'git log origin/$BRANCH..HEAD'."
fi

code_changes=false
if [ "$local_commit" != "$remote_commit" ]; then
  code_changes=true
  echo
  info "Incoming changes:"
  git log --format='         %h %s' "$local_commit..$remote_commit"
else
  ok "Code is current. Images will still be refreshed."
fi

# ── 3. Will the database accept the new code? ───────────────────────────────
step "Checking database migrations"

db_revision=$(psql_value "select version_num from alembic_version" || true)
if [ -z "$db_revision" ]; then
  warn "Could not read the database's schema revision. A brand-new database has none."
  info "If this is an existing deployment, stop here and check the postgres container."
else
  info "Database is at revision $db_revision"
  if ! git grep -q -E "^revision *= *['\"]${db_revision}['\"]" "origin/$BRANCH" -- migrations/versions; then
    stop "The database is at revision $db_revision, which the code on $BRANCH does not contain." \
         "Code that is no longer on $BRANCH moved the database forward (a removed feature" \
         "branch, for example). CAIRN on $BRANCH would refuse to start against it." \
         "Roll the database back with the code that created that revision before updating."
  fi
  ok "The incoming code knows this revision"
fi

if $CHECK_ONLY; then
  printf '\n%s--check:%s nothing was changed.\n' "$BOLD" "$RESET"
  exit 0
fi

if ! $ASSUME_YES; then
  [ -t 0 ] || stop "No terminal to confirm at." "Run it with --yes to update without the prompt."
  echo
  read -r -p "Back up the database and update to v${remote_version}? [y/N] " reply
  case "$reply" in y|Y|yes|YES) ;; *) echo "Cancelled. Nothing was changed."; exit 0 ;; esac
fi

# ── 4. Backup ────────────────────────────────────────────────────────────────
step "Backing up the database"

umask 077
mkdir -p "$BACKUP_DIR"
stamp=$(date -u +%Y%m%dT%H%M%SZ)
# The process ID keeps two runs in the same second from writing the same name.
# A backup is never overwritten.
BACKUP_FILE="$BACKUP_DIR/cairn-v${current_version}-${stamp}-$$.sql.gz"
[ -e "$BACKUP_FILE" ] && stop "A backup named $BACKUP_FILE already exists." "Run the update again."

if ! compose exec -T postgres sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB"' | gzip > "$BACKUP_FILE"; then
  rm -f "$BACKUP_FILE"
  BACKUP_FILE=""
  stop "The database backup failed." "The update did not start. Check 'docker compose logs postgres'."
fi
if [ "$(gzip -dc "$BACKUP_FILE" | head -c 200000 | grep -c 'PostgreSQL database dump' || true)" -lt 1 ]; then
  stop "The backup file does not look like a database dump: $BACKUP_FILE" "The update did not start."
fi
ok "Saved $BACKUP_FILE ($(du -h "$BACKUP_FILE" | cut -f1))"
info "It holds case data. It stays on this server, readable by this user only."

# ── 5. Update ────────────────────────────────────────────────────────────────
step "Updating"

if $code_changes; then
  PREV_COMMIT="$local_commit"
  git pull --ff-only --quiet origin "$BRANCH"
  ok "Code updated to v$(tr -d '[:space:]' < VERSION)"
fi

info "Pulling current postgres and caddy images..."
compose pull --quiet postgres caddy
ok "Images pulled"

info "Rebuilding CAIRN on the current Python base image (this takes a few minutes)..."
compose build --pull --quiet web
ok "Image built"

compose up -d --remove-orphans
ok "Containers started"

if [ "$(env_value AUTO_UPGRADE_DB true | tr '[:upper:]' '[:lower:]')" = "false" ]; then
  info "AUTO_UPGRADE_DB=false, so running the migrations now..."
  compose exec -T web flask db upgrade
  ok "Migrations applied"
fi

# ── 6. Verify ────────────────────────────────────────────────────────────────
step "Verifying"

deadline=$(( $(date +%s) + HEALTH_WAIT_SECONDS ))
until compose exec -T web sh -c 'wget -q -T 5 -O /dev/null "http://127.0.0.1:${PORT:-5000}/health"' \
  >/dev/null 2>&1; do
  if [ "$(date +%s)" -ge "$deadline" ]; then
    compose logs --tail 40 web >&2 || true
    printf '\n%sCAIRN did not answer within %s seconds.%s Its last log lines are above.\n' \
      "$RED" "$HEALTH_WAIT_SECONDS" "$RESET" >&2
    false   # hands over to on_error, which prints how to go back
  fi
  sleep 3
done
ok "CAIRN is answering"

running_version=$(compose exec -T web cat VERSION 2>/dev/null | tr -d '[:space:]' || echo "?")
alpine=$(compose exec -T web cat /etc/alpine-release 2>/dev/null | tr -d '[:space:]' || echo "?")
python=$(compose exec -T web python --version 2>/dev/null | awk '{print $2}' || echo "?")
pgver=$(compose exec -T postgres postgres --version 2>/dev/null | awk '{print $3}' || echo "?")
caddyver=$(compose exec -T caddy caddy version 2>/dev/null | awk '{print $1}' || echo "?")
new_revision=$(psql_value "select version_num from alembic_version" || echo "?")

PREV_COMMIT=""   # past this point there is nothing to roll back

printf '\n%sCAIRN v%s is running.%s\n' "$GREEN" "$running_version" "$RESET"
info "Alpine      $alpine"
info "Python      $python"
info "PostgreSQL  $pgver"
info "Caddy       $caddyver"
info "Database    revision $new_revision"
info "Backup      $BACKUP_FILE"
echo
info "Sign in and check the sidebar shows v${running_version}. If SSO is in use, sign in with it once."
