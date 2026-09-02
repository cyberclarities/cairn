"""Add Asset entity and case_assets link; backfill from Case.affected_systems

Revision ID: c3f7a91b4e2d
Revises: 8a2f4e6b9c1d
Create Date: 2026-09-02

Cairn had no structured Asset entity — the comment on TimelineEvent.affected_assets
said so outright. Affected systems were newline-separated free text on the case,
so every case carried its own private copy of a hostname: nothing joined across
cases, nothing could be typed, nothing could be counted.

This migration is additive and lossless by construction.

  - cases.affected_systems is READ, never written and never dropped. Every
    original string an analyst typed stays exactly where it was. The backfill is
    a parse of somebody else's free text, which is a guess; the column is the
    only record of what was actually meant, so it stays until the asset lists
    have been checked against it on real cases.
  - downgrade() drops the two new tables and touches nothing else, so a rollback
    returns the database to precisely its previous state.
  - upgrade() is idempotent. Assets are looked up by normalized_name before
    insert and links use ON CONFLICT DO NOTHING, so a re-run after a partial
    failure adds nothing twice.

Asset types are NOT guessed from the strings. An asset labelled "Server" because
its name contained "srv" is worse than one labelled nothing, because the first
looks like a decision somebody made. Everything lands unclassified and the UI
surfaces it for triage.
"""
from alembic import op
import sqlalchemy as sa

revision = "c3f7a91b4e2d"
down_revision = "8a2f4e6b9c1d"
branch_labels = None
depends_on = None

NAME_MAX = 256


def _normalize(name):
    """
    Must stay in agreement with common.normalize_asset_name.

    Duplicated rather than imported on purpose: a migration has to keep producing
    the same result years from now, and importing application code ties it to
    whatever that function becomes later.
    """
    return " ".join((name or "").split()).casefold()


def upgrade():
    op.create_table(
        "assets",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=256), nullable=False),
        sa.Column("normalized_name", sa.String(length=256), nullable=False),
        sa.Column("asset_type", sa.String(length=64), nullable=True),
        sa.Column("criticality", sa.String(length=32), nullable=True),
        sa.Column("owner", sa.String(length=256), nullable=True),
        sa.Column("location", sa.String(length=256), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.Column("created_by_id", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_assets_normalized_name", "assets", ["normalized_name"], unique=True)
    op.create_index("ix_assets_asset_type", "assets", ["asset_type"])

    op.create_table(
        "case_assets",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("case_id", sa.Integer(), nullable=False),
        sa.Column("asset_id", sa.Integer(), nullable=False),
        sa.Column("role", sa.String(length=64), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("added_at", sa.DateTime(), nullable=True),
        sa.Column("added_by_id", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["added_by_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("case_id", "asset_id", name="uq_case_assets_case_asset"),
    )
    op.create_index("ix_case_assets_case_id", "case_assets", ["case_id"])
    op.create_index("ix_case_assets_asset_id", "case_assets", ["asset_id"])

    _backfill(op.get_bind())


def _backfill(conn):
    """
    Parse every case's affected_systems into linked Asset rows.

    Line splitting matches common.parse_affected_systems: one system per line,
    blanks dropped, order preserved. Deduplication is case-insensitive here where
    that function's is not, because two cases writing "DC01" and "dc01" have to
    reach one asset or the entity earns nothing over the text it replaces.
    """
    cases = conn.execute(
        sa.text(
            "SELECT id, affected_systems FROM cases "
            "WHERE affected_systems IS NOT NULL AND btrim(affected_systems) <> ''"
            " ORDER BY id"
        )
    ).fetchall()

    ts = sa.text("SELECT now() AT TIME ZONE 'utc'")
    now = conn.execute(ts).scalar()

    known = {}          # normalized name -> assets.id
    linked = created = 0

    for case_id, blob in cases:
        seen_here = set()
        for line in blob.splitlines():
            name = line.strip()
            if not name:
                continue
            norm = _normalize(name)
            if not norm or norm in seen_here:
                continue
            seen_here.add(norm)

            # A line longer than the column is almost certainly prose rather than
            # a hostname, but it is still something a person wrote and it is not
            # this migration's place to throw it away. The name is truncated and
            # the whole original line is preserved in description.
            full = name
            truncated = len(name) > NAME_MAX
            if truncated:
                name = name[:NAME_MAX]
                norm = _normalize(name)
                if not norm or norm in seen_here:
                    continue
                seen_here.add(norm)

            asset_id = known.get(norm)
            if asset_id is None:
                row = conn.execute(
                    sa.text("SELECT id FROM assets WHERE normalized_name = :n"),
                    {"n": norm},
                ).fetchone()
                if row:
                    asset_id = row[0]
                else:
                    asset_id = conn.execute(
                        sa.text(
                            "INSERT INTO assets "
                            "(name, normalized_name, is_active, description, created_at, updated_at) "
                            "VALUES (:name, :norm, true, :descr, :ts, :ts) RETURNING id"
                        ),
                        {
                            "name": name,
                            "norm": norm,
                            "descr": (
                                "Imported from case affected_systems. Original line "
                                "exceeded the name column and was truncated; full text:\n" + full
                                if truncated else None
                            ),
                            "ts": now,
                        },
                    ).scalar()
                    created += 1
                known[norm] = asset_id

            result = conn.execute(
                sa.text(
                    "INSERT INTO case_assets (case_id, asset_id, added_at) "
                    "VALUES (:c, :a, :ts) ON CONFLICT ON CONSTRAINT "
                    "uq_case_assets_case_asset DO NOTHING"
                ),
                {"c": case_id, "a": asset_id, "ts": now},
            )
            # rowcount, not an unconditional increment: ON CONFLICT DO NOTHING
            # makes this a no-op on a re-run, and a migration that reports work it
            # did not do is worse than one that reports nothing.
            linked += result.rowcount or 0

    print(
        f"  asset backfill: {len(cases)} cases scanned, {created} assets created, "
        f"{linked} case-asset links written. New assets land unclassified by "
        f"design — asset_type is left NULL for triage rather than guessed from "
        f"the hostname. cases.affected_systems was read and not modified."
    )


def downgrade():
    # cases.affected_systems was only ever read, so dropping these two tables
    # returns the database to exactly its previous state. Nothing to restore.
    op.drop_index("ix_case_assets_asset_id", table_name="case_assets")
    op.drop_index("ix_case_assets_case_id", table_name="case_assets")
    op.drop_table("case_assets")
    op.drop_index("ix_assets_asset_type", table_name="assets")
    op.drop_index("ix_assets_normalized_name", table_name="assets")
    op.drop_table("assets")
