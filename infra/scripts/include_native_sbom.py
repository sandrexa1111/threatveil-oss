"""Include the verified upstream native component in Syft's SPDX 2.3 output."""

import argparse
import json
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--sbom", type=Path, required=True)
parser.add_argument("--native", type=Path, required=True)
args = parser.parse_args()
sbom = json.loads(args.sbom.read_text())
native = json.loads(args.native.read_text())
component = native["components"][0]
if sbom["spdxVersion"] != "SPDX-2.3" or component["name"] != "sqlite" or component["version"] != "3.53.4":
    raise SystemExit("Unexpected SBOM format or native component")
package_id = "SPDXRef-upstream-sqlite-3-53-4"
if any(package["SPDXID"] == package_id for package in sbom["packages"]):
    raise SystemExit("Native component already present; refusing duplicate augmentation")
sbom["packages"].append({
    "SPDXID": package_id, "name": "sqlite", "versionInfo": component["version"],
    "downloadLocation": component["externalReferences"][0]["url"], "filesAnalyzed": False,
    "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION",
    "checksums": [{"algorithm": "SHA256", "checksumValue": component["hashes"][0]["content"]}],
    "sourceInfo": "Verified upstream amalgamation; exact loaded native binary hash. Image: " + native["metadata"]["component"]["purl"],
    "externalRefs": [
        {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": component["purl"]},
        {"referenceCategory": "SECURITY", "referenceType": "cpe23Type", "referenceLocator": component["cpe"]},
    ],
})
sbom["relationships"].append({"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": package_id})
sbom["creationInfo"]["creators"].append("Tool: ThreatVeil native component inclusion 1")
args.sbom.write_text(json.dumps(sbom, indent=2))
print("Verified SQLite component included in SPDX inventory")
