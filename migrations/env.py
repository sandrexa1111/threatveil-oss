from alembic import context
from sqlalchemy import create_engine
from threatveil.config import settings
from threatveil.db import Base

url = settings().admin_database_url
if not url:
    raise RuntimeError(
        "TV_ADMIN_DATABASE_URL is required for migrations; never use runtime credentials"
    )
with create_engine(url).connect() as connection:
    context.configure(connection=connection, target_metadata=Base.metadata)
    with context.begin_transaction():
        context.run_migrations()
