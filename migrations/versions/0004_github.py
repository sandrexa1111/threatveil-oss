from alembic import op
from threatveil.db import GitHubBinding

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade():
    GitHubBinding.__table__.create(op.get_bind(), checkfirst=True)
    op.execute("GRANT SELECT,INSERT,UPDATE,DELETE ON github_bindings TO threatveil_app")


def downgrade():
    raise RuntimeError("Destructive downgrade requires explicit review")
