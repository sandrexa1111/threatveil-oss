"""Append-only tenant memory and least-privilege runtime state."""

from alembic import op
from threatveil.db import Base

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    Base.metadata.create_all(bind)
    op.execute(
        "CREATE FUNCTION tv_org() RETURNS uuid LANGUAGE sql STABLE AS $$ SELECT NULLIF(current_setting('tv.org_id', true),'')::uuid $$"
    )
    op.execute(
        "CREATE FUNCTION tv_user() RETURNS uuid LANGUAGE sql STABLE AS $$ SELECT NULLIF(current_setting('tv.user_id', true),'')::uuid $$"
    )
    for table in ["records", "record_edges", "target_state", "run_state", "accounts", "run_leases"]:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant ON {table} USING (organization_id=tv_org()) WITH CHECK (organization_id=tv_org())"
        )
    op.execute("ALTER TABLE organizations ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE organizations FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY org ON organizations USING (id=tv_org() OR owner_user_id=tv_user()) WITH CHECK (owner_user_id=tv_user())"
    )
    op.execute("ALTER TABLE memberships ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE memberships FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY membership ON memberships USING (user_id=tv_user() OR organization_id=tv_org()) WITH CHECK (organization_id=tv_org())"
    )
    op.execute("ALTER TABLE invitations ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE invitations FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY invitation ON invitations USING (organization_id=tv_org() OR token_hash=NULLIF(current_setting('tv.invite',true),'')) WITH CHECK (organization_id=tv_org())"
    )
    op.execute(
        "CREATE FUNCTION tv_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'security memory is append-only'; END $$"
    )
    for table in ["records", "record_edges"]:
        op.execute(
            f"CREATE TRIGGER immutable BEFORE UPDATE OR DELETE ON {table} FOR EACH ROW EXECUTE FUNCTION tv_immutable()"
        )
    op.execute("REVOKE ALL ON SCHEMA public FROM PUBLIC")
    op.execute("GRANT USAGE ON SCHEMA public TO threatveil_app")
    op.execute("GRANT SELECT,INSERT ON records,record_edges TO threatveil_app")
    op.execute(
        "GRANT SELECT,INSERT,UPDATE,DELETE ON users,organizations,memberships,login_sessions,target_state,run_state,accounts,webhook_events,invitations,outbox,run_leases TO threatveil_app"
    )
    op.execute("GRANT EXECUTE ON FUNCTION tv_org(),tv_user() TO threatveil_app")


def downgrade():
    raise RuntimeError("Destructive downgrade requires an explicit backup/deletion plan")
