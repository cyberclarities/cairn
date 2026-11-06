"""Add case_notes and case_note_revisions

Revision ID: f1c3a8e5d240
Revises: d7e1c5a83b40
Create Date: 2026-11-06

Notes and actions recorded against a case, and the prior versions of each note
kept when it is edited. See CaseNote and CaseNoteRevision in app/models.py.

Foreign keys:
  case_id            -> cases.id            no action; the ORM cascades a case
                                           delete, the same as timeline events
  timeline_event_id  -> timeline_events.id  ON DELETE SET NULL; deleting the
                                           timeline entry keeps the note
  user references                           ON DELETE SET NULL; deleting a user
                                           keeps what they wrote
  case_note_revisions.note_id               ON DELETE CASCADE; history goes with
                                           its note

Additive only. downgrade() drops both tables and touches nothing else.
"""
from alembic import op
import sqlalchemy as sa

revision = "f1c3a8e5d240"
down_revision = "d7e1c5a83b40"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    tables = sa.inspect(bind).get_table_names()

    if "case_notes" not in tables:
        op.create_table(
            "case_notes",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("case_id", sa.Integer(), nullable=False),
            sa.Column("kind", sa.String(length=16), nullable=False, server_default="note"),
            sa.Column("body", sa.Text(), nullable=False),
            sa.Column("written_at", sa.DateTime(), nullable=False),
            sa.Column("written_by_id", sa.Integer(), nullable=True),
            sa.Column("occurred_at", sa.DateTime(), nullable=True),
            sa.Column("occurred_timezone", sa.String(length=64), nullable=True),
            sa.Column("status", sa.String(length=8), nullable=True),
            sa.Column("owner_id", sa.Integer(), nullable=True),
            sa.Column("completed_at", sa.DateTime(), nullable=True),
            sa.Column("completed_by_id", sa.Integer(), nullable=True),
            sa.Column("timeline_event_id", sa.Integer(), nullable=True),
            sa.Column("updated_at", sa.DateTime(), nullable=True),
            sa.Column("updated_by_id", sa.Integer(), nullable=True),
            sa.ForeignKeyConstraint(["case_id"], ["cases.id"]),
            sa.ForeignKeyConstraint(["written_by_id"], ["users.id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(["owner_id"], ["users.id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(["completed_by_id"], ["users.id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(["updated_by_id"], ["users.id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(["timeline_event_id"], ["timeline_events.id"], ondelete="SET NULL"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_case_notes_case_id", "case_notes", ["case_id"])
        op.create_index("ix_case_notes_written_at", "case_notes", ["written_at"])
        op.create_index("ix_case_notes_status", "case_notes", ["status"])
        op.create_index("ix_case_notes_timeline_event_id", "case_notes", ["timeline_event_id"])

    if "case_note_revisions" not in tables:
        op.create_table(
            "case_note_revisions",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("note_id", sa.Integer(), nullable=False),
            sa.Column("kind", sa.String(length=16), nullable=False),
            sa.Column("body", sa.Text(), nullable=False),
            sa.Column("occurred_at", sa.DateTime(), nullable=True),
            sa.Column("occurred_timezone", sa.String(length=64), nullable=True),
            sa.Column("edited_at", sa.DateTime(), nullable=False),
            sa.Column("edited_by_id", sa.Integer(), nullable=True),
            sa.ForeignKeyConstraint(["note_id"], ["case_notes.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["edited_by_id"], ["users.id"], ondelete="SET NULL"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_case_note_revisions_note_id", "case_note_revisions", ["note_id"])


def downgrade():
    tables = sa.inspect(op.get_bind()).get_table_names()
    if "case_note_revisions" in tables:
        op.drop_index("ix_case_note_revisions_note_id", table_name="case_note_revisions")
        op.drop_table("case_note_revisions")
    if "case_notes" in tables:
        for ix in ("timeline_event_id", "status", "written_at", "case_id"):
            op.drop_index(f"ix_case_notes_{ix}", table_name="case_notes")
        op.drop_table("case_notes")
