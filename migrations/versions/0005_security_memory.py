"""Index retained semantic facts without indexing raw customer observation bodies."""

from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_records_security_facts ON records USING gin ((payload->'security_facts') jsonb_path_ops) WHERE kind='trial_capture'"
    )


def downgrade():
    op.execute("DROP INDEX IF EXISTS ix_records_security_facts")
