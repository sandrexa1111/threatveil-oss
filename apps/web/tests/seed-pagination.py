"""Local browser-fixture setup; not exposed by the product or deployed API."""

import json
import os
import sys
from pathlib import Path
from uuid import UUID

root = Path(__file__).resolve().parents[3]
local_config = root / ".local/database.env"
if not local_config.exists():
    raise RuntimeError("Pagination browser fixture requires the explicitly provisioned local database")
for line in local_config.read_text().splitlines():
    if line.startswith("TV_DATABASE_URL="):
        os.environ["TV_DATABASE_URL"] = line.split("=", 1)[1].strip("\"'")
os.environ["TV_ENV"] = "test"
os.environ["TV_LOCAL_AUTH"] = "true"

from threatveil.config import settings  # noqa: E402
from threatveil.db import add_record, get_record, transaction  # noqa: E402

settings.cache_clear()
data = json.load(sys.stdin)
organization_id = UUID(data["organization_id"])
with transaction(org_id=organization_id) as session:
    system = get_record(session, organization_id, UUID(data["system_id"]), "system")
    source = get_record(session, organization_id, UUID(data["property_id"]), "property")
    for index in range(205):
        add_record(session, organization_id, "property", {
            "system_id": str(system.id), "title": f"Browser pagination fixture {index:03}",
            "approved": False, "definition": source.payload["definition"],
        }, {"system": system.id})
print("Seeded 205 local pagination drafts")
