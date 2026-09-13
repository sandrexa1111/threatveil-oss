"""Operator-only business store and an explicit operator read path.

operator_records keeps internal commercial measurement (staff time, organization
classification, prospects, offers and commercial proof). The runtime role can
never reach it: every grant except the owner's is revoked, and row security
admits only the owning migration identity.

Operator reads across tenants are SELECT-only policies for the same identity,
active only in a transaction that explicitly sets tv.operator_read. The runtime
role gains nothing: the policies name the migration identity, not PUBLIC.
"""

from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None

OPERATOR_READ = ("records", "record_edges", "organizations", "memberships", "accounts")


def upgrade():
    op.execute("""CREATE TABLE operator_records (
        id uuid PRIMARY KEY,
        kind varchar(40) NOT NULL,
        organization_id uuid NULL,
        payload jsonb NOT NULL,
        created_by varchar(120) NOT NULL,
        created_at timestamptz NOT NULL DEFAULT now())""")
    op.execute("CREATE INDEX ix_operator_records_kind ON operator_records (kind, created_at)")
    op.execute("CREATE INDEX ix_operator_records_org ON operator_records (organization_id, kind, created_at)")
    # Append-only, with the same narrowly scoped organization erasure as tenant memory.
    op.execute("CREATE TRIGGER immutable BEFORE UPDATE OR DELETE ON operator_records "
               "FOR EACH ROW EXECUTE FUNCTION tv_immutable()")
    op.execute("ALTER TABLE operator_records ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE operator_records FORCE ROW LEVEL SECURITY")
    op.execute("""DO $$ DECLARE r record; BEGIN
      EXECUTE format('CREATE POLICY operator_only ON operator_records TO %I USING (true) WITH CHECK (true)', current_user);
      REVOKE ALL ON operator_records FROM PUBLIC;
      FOR r IN SELECT DISTINCT grantee FROM information_schema.role_table_grants
               WHERE table_schema = current_schema() AND table_name = 'operator_records'
                 AND grantee NOT IN (current_user, 'PUBLIC') LOOP
        EXECUTE format('REVOKE ALL ON operator_records FROM %I', r.grantee);
      END LOOP;
    END $$""")
    for table in OPERATOR_READ:
        op.execute(f"""DO $$ BEGIN
          EXECUTE format('CREATE POLICY operator_read ON {table} FOR SELECT TO %I '
                         'USING (current_setting(''tv.operator_read'', true) = ''on'')', current_user);
        END $$""")


def downgrade():
    for table in OPERATOR_READ:
        op.execute(f"DROP POLICY IF EXISTS operator_read ON {table}")
    op.execute("DROP TABLE operator_records")
