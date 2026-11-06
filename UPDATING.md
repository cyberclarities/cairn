# Updating CAIRN

This is the operator's guide to keeping a CAIRN server current. Updating is one command,
`./update.sh`, run on the server from the CAIRN folder. The rest of this document covers the
first run, what the script does, what to do when it stops, and how to go back.

---

## 1. Before you start

- **Run it as the user that owns the CAIRN folder,** not with `sudo`. That user needs to reach
  Docker, so add it to the `docker` group once (`sudo usermod -aG docker <user>`, then log out and
  back in). Running git as root in another user's folder causes ownership errors later.
- **The server stays on branch `main`.** Updates come from `main` on GitHub. Feature branches are
  tested elsewhere, not on the production server.
- **Do not edit tracked files on the server.** Settings live in `.env`, which git ignores. Any other
  local edit makes the script stop, because a pull could overwrite it.
- **CAIRN must be running** (`docker compose up -d`), so the database can be backed up first.

---

## 2. The first run on a server

A server that predates `update.sh` does not have the script yet. Get it with one manual pull,
then run it:

```bash
cd /path/to/cairn
git pull
./update.sh
```

This one time the code is pulled before the backup is taken. That is safe: the database does not
change until the rebuild starts CAIRN on the new code, and the backup happens before that.

---

## 3. A routine update

```bash
./update.sh --check    # what would change; changes nothing
./update.sh            # back up, update, rebuild, verify
```

The script works in six steps and stops at the first problem, saying why:

1. **Preflight.** Branch is `main`, no local edits, Docker and the database are running.
2. **What is available.** The version you have, the version on GitHub, and the commits between.
3. **Migration check.** The database's schema revision must be one the incoming code knows.
4. **Backup.** A compressed copy of the whole database into `backups/`. No backup, no update.
5. **Update.** Pull the code, pull fresh `postgres` and `caddy` images, rebuild CAIRN on the
   current Python base image, start it. Database migrations run as CAIRN starts.
6. **Verify.** Wait for CAIRN to answer, then report what is running:

```
CAIRN v1.2.3 is running.
       Alpine      3.24.4
       Python      3.12.16
       PostgreSQL  16.15
       Caddy       v2.11.7
       Database    revision f1c3a8e5d240
       Backup      backups/cairn-v1.2.2-20261106T213558Z-4812.sql.gz
```

Then sign in. The version under the logo in the sidebar should match. If a release note says SSO
changed, sign in with SSO once to confirm it.

### Run it monthly, even with nothing new

When there is no new code, the script still pulls fresh `postgres` and `caddy` images and rebuilds
on the current Python base. That is how those layers pick up their security fixes. To schedule
it, add a line with `crontab -e` as the CAIRN user:

```
PATH=/usr/local/bin:/usr/bin:/bin
0 3 1 * * cd /path/to/cairn && ./update.sh --yes >> backups/update.log 2>&1
```

`--yes` skips the confirmation prompt, which a scheduled run cannot answer. Read
`backups/update.log` after each run; a stop is recorded there with its reason.

---

## 4. When the script stops

Every stop happens before anything is changed, and the message says what it found. What to do for
each one:

| Message starts with | What it means | What to do |
|---|---|---|
| **This folder is on branch '...', not 'main'** | The server was switched to another branch. | Find out what that branch changed before leaving it. If it added a database migration, see §4.1 first. Then `git checkout main`. |
| **There are local edits to tracked files** | Someone edited code on the server. | Look at `git diff`. If the edit belongs in CAIRN, make it on your workstation and push it. Then discard it here with `git checkout -- <file>`. |
| **This folder has commits that are not on origin/main** | Someone committed on the server. | Push them from the server, or move them to your workstation. Do not reset them away without reading `git log origin/main..HEAD`. |
| **The database is at revision ..., which the code on main does not contain** | Code that is no longer on `main` moved the database forward. CAIRN on `main` would refuse to start. | See §4.1. |
| **The postgres container is not running** | CAIRN is down. | `docker compose up -d`, then run the script again. |
| **The database backup failed** | `pg_dump` did not complete. | `docker compose logs postgres`. Check free disk space with `df -h .`. |
| **This does not look like the CAIRN folder** or **No .env file here** | Run from the wrong folder, or a fresh checkout. | `cd` to the folder with `docker-compose.yml` and `.env`. |
| **Docker is not running, or this user cannot reach it** or **'docker compose' is not available** | Docker is stopped, Compose v2 is missing, or the user is not in the `docker` group. | Start Docker, install the Compose plugin, or see §1. |
| **No terminal to confirm at** | Run from a script or scheduler without `--yes`. | Add `--yes`. |
| **Could not reach the git remote** | Network or GitHub credentials. | Check that `git fetch` works on its own. |

### 4.1 The database is ahead of the code

This happens when a feature branch that added a database migration ran on the server and was then
removed. The script names the revision it found. There are two ways back.

**If the branch still exists on the server**, use its code to step the database back, then return
to `main`:

```bash
git checkout <that-branch>
docker compose up -d --build
# Open the branch's migration file for the revision the script named:
#   migrations/versions/<revision>_*.py
# Its down_revision line is the revision to step back to. If that one is also missing from main,
# repeat with its file until you reach a revision that exists on main.
docker compose exec web flask db downgrade <revision-on-main>
git checkout main
./update.sh
```

**If the branch is gone**, restore a backup taken before that branch first ran (§6). The backup's
file name carries the version it was taken from.

---

## 5. When an update fails part way

If CAIRN does not answer within three minutes of the rebuild, the script prints CAIRN's last log
lines. When the run had pulled new code, it also prints the exact commands to return to the
version you had, including the commit to check out. They look like this:

```bash
git checkout <previous-commit>
docker compose up -d --build
```

That puts the previous code back. It does not touch the database. If the failed version had
already migrated the database, the previous code may refuse to start against it; in that case
restore the backup the script took (§6).

Once things are steady, return the folder to `main` with `git checkout main`, and do not run the
update again until the cause is fixed.

---

## 6. Backups

### What the script keeps

Every run writes one compressed backup to `backups/`, named for the version it was taken from:

```
backups/cairn-v1.2.2-20261106T213558Z-4812.sql.gz
```

- Readable by the CAIRN user only. Each one is a complete copy of the case data.
- Never committed to git (`.gitignore`) and never copied into the image (`.dockerignore`).
- **Never deleted automatically.** Check the space they use with `du -sh backups`, and prune them
  on the same schedule as any other copy of case data. Keep at least the most recent few.

### Restoring one

**If CAIRN is running,** use **Admin > Settings > Database > Restore** and upload the file. That
path checks the file first and takes a safety snapshot before it replaces anything. Copy the file
to your workstation first if you are restoring through the browser.

**If CAIRN will not start,** restore from the server's command line. This replaces the whole
database with the backup, so be sure it is the right file. Run it with the code at the version in
the backup's name (§5), so the schema matches.

```bash
# 1. Stop CAIRN so nothing is connected to the database.
docker compose stop web

# 2. Recreate the database, owned by the CAIRN app role as on a fresh install.
docker compose exec -T postgres sh -c \
  'dropdb -U "$POSTGRES_USER" "$POSTGRES_DB" && createdb -U "$POSTGRES_USER" -O "$CAIRN_DB_USER" "$POSTGRES_DB"'

# 3. Load the backup. Progress lines are discarded; errors still show, and the first one stops it.
gzip -dc backups/<file>.sql.gz | docker compose exec -T postgres sh -c \
  'psql -v ON_ERROR_STOP=1 -q -U "$POSTGRES_USER" -d "$POSTGRES_DB"' > /dev/null

# 4. Start CAIRN again.
docker compose up -d --build
```

These steps were rehearsed on PostgreSQL 16 against a database built by CAIRN's own migrations,
with the same two roles as a real deployment. After the restore the data and schema revision came
back, every table was owned by the app role again, and CAIRN started and wrote to it normally.

---

## 7. Checking a server by hand

The script reports all of this at the end of a run. To check without updating:

```bash
cat VERSION
git log --oneline -1
docker compose exec web sh -c 'cat /etc/alpine-release; python --version'
docker compose exec postgres postgres --version
docker compose exec caddy caddy version
docker compose exec postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAc "select version_num from alembic_version"'
```

---

## 8. Publishing a new version

For whoever changes the code, before pushing to `main`:

1. **Version.** `VERSION` is `MAJOR.MINOR.PATCH`. PATCH goes up by one with each set of changes.
   MAJOR.MINOR changes only when the owner decides a release; PATCH then starts again at 0. See
   `CLAUDE.md`.
2. **Tests.** Run the suite against a scratch PostgreSQL, as described in the test files.
3. **Vulnerabilities.** `pip-audit -r requirements.txt` (`pip install pip-audit`) should report nothing. If it reports
   something, upgrade the package and record why in a comment beside the pin.
4. **SBOM.** Update `SBOM.md` when components change, and regenerate the SPDX manifest from a clean
   copy of the tracked files so `.git` and local files stay out of it. `sbom-tool` is a single
   download from [microsoft/sbom-tool releases](https://github.com/microsoft/sbom-tool/releases);
   the current manifest was made with 4.1.5.

   ```bash
   rm -rf /tmp/cairn-sbom && mkdir -p /tmp/cairn-sbom/src /tmp/cairn-sbom/out
   git archive HEAD | tar -x -C /tmp/cairn-sbom/src
   rm -rf /tmp/cairn-sbom/src/_manifest
   sbom-tool generate -b /tmp/cairn-sbom/src -bc /tmp/cairn-sbom/src \
     -pn Cairn -pv "$(cat VERSION)" -ps "Cyber Clarities" \
     -nsb https://cyberclarities.com/cairn/sbom -mi SPDX:3.0 -m /tmp/cairn-sbom/out
   cp /tmp/cairn-sbom/out/_manifest/spdx_3.0/* _manifest/spdx_3.0/
   ```

   Run it after the last change is committed, so the hashes match what was pushed, then commit
   the manifest on its own.
5. **Threat-intel lookups.** After deploying, `docker compose exec -T web python - < tools/ti_selftest.py`
   confirms each configured provider still answers.
