"""Erase an owner-requested local organization using the migration role."""

import argparse
import json

from threatveil.erasure import erase_local_organization

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--organization", required=True)
parser.add_argument("--request", required=True)
parser.add_argument("--confirm-organization", required=True)
args = parser.parse_args()
result = erase_local_organization(args.organization, args.request, args.confirm_organization)
print(json.dumps({key: result[key] for key in ("status", "organization_id", "request_id", "record_count", "limitations")}, indent=2))
