"""Indexed release history on the existing append-only tenant ledger."""

from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("CREATE INDEX IF NOT EXISTS ix_records_system_history ON records "
               "(organization_id, kind, (payload->>'system_id'), created_at DESC, id DESC)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_records_evidence_run ON records "
               "(organization_id, (payload->>'run_id')) WHERE kind='evidence_record'")


def downgrade():
    op.drop_index("ix_records_evidence_run", table_name="records")
    op.drop_index("ix_records_system_history", table_name="records")
