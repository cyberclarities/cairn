"""Add AAR report fields, case deviations, and recommendations

Revision ID: 8a2f4e6b9c1d
Revises: 4593c0568b26
Create Date: 2026-08-10 15:05:00.000000

Adds the fields needed to close the gaps found reviewing the case-report
export against the Incident Management Plan (Phase VI — Lessons Learned):
method of discovery, recovery sufficiency assessment, IMP severity
classification (Functional x Informational Impact), lessons-learned
meeting record, and two new child tables for deviations from standard
procedure and recommendations. Every new column is nullable — existing
cases render the report with "not yet documented" placeholders rather
than requiring a backfill.
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '8a2f4e6b9c1d'
down_revision = '4593c0568b26'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('cases', schema=None) as batch_op:
        batch_op.add_column(sa.Column('method_of_discovery', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('root_cause', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('recovery_assessment', sa.Text(), nullable=True))
        # Sufficient / Partially Sufficient / Insufficient — see config.RECOVERY_ASSESSMENTS
        batch_op.add_column(sa.Column('recovery_sufficient', sa.String(length=32), nullable=True))
        # None / Limited / Moderate / Critical — IMP Phase II impact axes
        batch_op.add_column(sa.Column('imp_functional_impact', sa.String(length=16), nullable=True))
        batch_op.add_column(sa.Column('imp_informational_impact', sa.String(length=16), nullable=True))
        batch_op.add_column(sa.Column('lessons_learned_date', sa.Date(), nullable=True))
        batch_op.add_column(sa.Column('lessons_learned_attendees', sa.Text(), nullable=True))
        # Free-form notes from the Lessons Learned meeting (IMP Phase VI), guided
        # by that section's required questions at the form level rather than
        # split into a rigid What-Went-Well / What-Could-Improve schema.
        batch_op.add_column(sa.Column('lessons_learned_notes', sa.Text(), nullable=True))

    op.create_table(
        'case_deviations',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('case_id', sa.Integer(), nullable=False),
        sa.Column('deviation', sa.Text(), nullable=False),
        sa.Column('standard_procedure', sa.Text(), nullable=True),
        sa.Column('justification', sa.Text(), nullable=True),
        sa.Column('approved_by', sa.String(length=128), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('created_by_id', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['case_id'], ['cases.id'], ),
        sa.ForeignKeyConstraint(['created_by_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('case_deviations', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_case_deviations_case_id'), ['case_id'], unique=False)

    op.create_table(
        'recommendations',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('case_id', sa.Integer(), nullable=False),
        sa.Column('text', sa.Text(), nullable=False),
        # Remediation / Compensating Control / Risk Acceptance — IMP Phase VI
        # requires every recommendation to resolve to one of these.
        sa.Column('disposition', sa.String(length=32), nullable=False, server_default='Remediation'),
        sa.Column('owner', sa.String(length=128), nullable=True),
        sa.Column('target_date', sa.Date(), nullable=True),
        sa.Column('risk_treatment_ref', sa.String(length=64), nullable=True),
        # Open / Complete
        sa.Column('status', sa.String(length=16), nullable=False, server_default='Open'),
        # Required when disposition = 'Risk Acceptance' — the IMP requires a
        # documented justification for accepting rather than fixing a gap.
        sa.Column('risk_acceptance_justification', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('created_by_id', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['case_id'], ['cases.id'], ),
        sa.ForeignKeyConstraint(['created_by_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('recommendations', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_recommendations_case_id'), ['case_id'], unique=False)


def downgrade():
    with op.batch_alter_table('recommendations', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_recommendations_case_id'))
    op.drop_table('recommendations')

    with op.batch_alter_table('case_deviations', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_case_deviations_case_id'))
    op.drop_table('case_deviations')

    with op.batch_alter_table('cases', schema=None) as batch_op:
        batch_op.drop_column('lessons_learned_notes')
        batch_op.drop_column('lessons_learned_attendees')
        batch_op.drop_column('lessons_learned_date')
        batch_op.drop_column('imp_informational_impact')
        batch_op.drop_column('imp_functional_impact')
        batch_op.drop_column('recovery_sufficient')
        batch_op.drop_column('recovery_assessment')
        batch_op.drop_column('root_cause')
        batch_op.drop_column('method_of_discovery')
