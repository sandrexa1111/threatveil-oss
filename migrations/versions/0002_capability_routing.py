from alembic import op
from threatveil.db import CapabilityRoute, LeaseNonce, RateBucket, CustomerRoute

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade():
    for model in [CapabilityRoute, LeaseNonce, RateBucket, CustomerRoute]:
        model.__table__.create(op.get_bind(), checkfirst=True)
        op.execute(f"GRANT SELECT,INSERT,UPDATE,DELETE ON {model.__tablename__} TO threatveil_app")


def downgrade():
    raise RuntimeError("Destructive downgrade requires explicit review")
