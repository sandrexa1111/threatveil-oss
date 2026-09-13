"""Permit only the migration identity's explicitly scoped organization erasure."""

from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""CREATE OR REPLACE FUNCTION tv_immutable() RETURNS trigger
    LANGUAGE plpgsql AS $$ BEGIN
      IF TG_OP = 'DELETE' AND current_user = 'threatveil_admin'
         AND session_user = 'threatveil_admin'
         AND OLD.organization_id::text = current_setting('tv.erase_org', true)
         AND OLD.organization_id = tv_org() THEN
        RETURN OLD;
      END IF;
      RAISE EXCEPTION 'security memory is append-only';
    END $$""")


def downgrade():
    op.execute("""CREATE OR REPLACE FUNCTION tv_immutable() RETURNS trigger
    LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'security memory is append-only'; END $$""")
