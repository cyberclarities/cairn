"""Add ioc_enrichments — third-party intelligence lookups against an IOC

Revision ID: d7e1c5a83b40
Revises: c3f7a91b4e2d
Create Date: 2026-09-03

One row per (indicator, provider). The unique constraint is the point: an
analyst who re-runs VirusTotal against the same hash should replace what that
provider said, not stack a second answer beside the first. The route upserts
on that pair.

Every row is a record that CAIRN disclosed an indicator to somebody outside
this deployment, which is why queried_by_id and queried_at are on the row and
not only in the audit log. The audit log answers "what did we do"; this table
has to answer "who asked, when, and what came back" from inside the case,
months later, in a report.

queried_by_id is ON DELETE SET NULL rather than CASCADE. Deleting a user must
not delete the evidence that a lookup happened.

raw_response is Text holding JSON rather than JSONB. The payload is never
queried into — it is read back whole for one indicator at a time — and Text
keeps the column readable in a pg_dump an operator may have to eyeball.

Additive only. downgrade() drops the table and touches nothing else.
"""
from alembic import op
import sqlalchemy as sa

revision = "d7e1c5a83b40"
down_revision = "c3f7a91b4e2d"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "ioc_enrichments" in inspector.get_table_names():
        return

    op.create_table(
        "ioc_enrichments",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("ioc_id", sa.Integer(), nullable=False),
        sa.Column("provider", sa.String(length=32), nullable=False),
        # ok | error | unsupported | skipped
        sa.Column("status", sa.String(length=16), nullable=False, server_default="ok"),
        # malicious | suspicious | benign | unknown
        sa.Column("verdict", sa.String(length=16), nullable=True),
        sa.Column("score", sa.Integer(), nullable=True),
        sa.Column("summary", sa.String(length=512), nullable=True),
        sa.Column("permalink", sa.String(length=1024), nullable=True),
        sa.Column("raw_response", sa.Text(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("queried_at", sa.DateTime(), nullable=True),
        sa.Column("queried_by_id", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["ioc_id"], ["iocs.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["queried_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("ioc_id", "provider", name="uq_ioc_enrichment_provider"),
    )
    op.create_index("ix_ioc_enrichments_ioc_id", "ioc_enrichments", ["ioc_id"])
    op.create_index("ix_ioc_enrichments_provider", "ioc_enrichments", ["provider"])
    op.create_index("ix_ioc_enrichments_verdict", "ioc_enrichments", ["verdict"])
    op.create_index("ix_ioc_enrichments_queried_at", "ioc_enrichments", ["queried_at"])


def downgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "ioc_enrichments" not in inspector.get_table_names():
        return
    op.drop_index("ix_ioc_enrichments_queried_at", table_name="ioc_enrichments")
    op.drop_index("ix_ioc_enrichments_verdict", table_name="ioc_enrichments")
    op.drop_index("ix_ioc_enrichments_provider", table_name="ioc_enrichments")
    op.drop_index("ix_ioc_enrichments_ioc_id", table_name="ioc_enrichments")
    op.drop_table("ioc_enrichments")
