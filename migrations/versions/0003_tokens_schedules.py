from alembic import op
from threatveil.db import ApiToken, Schedule

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade():
    for model in [ApiToken, Schedule]:
        model.__table__.create(op.get_bind(), checkfirst=True)
        op.execute(f"GRANT SELECT,INSERT,UPDATE,DELETE ON {model.__tablename__} TO threatveil_app")
    op.execute("ALTER TABLE schedules ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE schedules FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY tenant ON schedules USING (organization_id=tv_org()) WITH CHECK (organization_id=tv_org())"
    )


def downgrade():
    raise RuntimeError("Destructive downgrade requires explicit review")
