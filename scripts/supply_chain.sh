#!/usr/bin/env bash
# Local supply-chain pass: secret scan, SBOM, dependency advisories.
#
# The secret scan runs against exactly the file set that would be committed (tracked plus
# untracked-not-ignored), never against .local/, node_modules/, .venv/ or downloaded provider
# binaries — scanning those produces hundreds of false findings from demo digests and vendored
# Go modules, which is how a real finding gets missed.
#
# Tools are expected in .local/security-bin (gitleaks, syft, osv-scanner). Nothing is
# downloaded here, and nothing leaves the machine except osv-scanner's advisory lookups.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${TV_SECURITY_BIN:-$ROOT/.local/security-bin}"
OUT="${OUT:-$ROOT/.local/supply-chain}"
mkdir -p "$OUT"
cd "$ROOT"

need() { [ -x "$BIN/$1" ] || { echo "missing tool: $BIN/$1"; exit 2; }; }
need gitleaks; need syft; need osv-scanner

echo "== secret scan (committable files only)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
git ls-files -co --exclude-standard -z | rsync -0a --files-from=- . "$WORK/"
COMMITTABLE="$(git ls-files -co --exclude-standard | wc -l | tr -d ' ')"
"$BIN/gitleaks" dir "$WORK" --no-banner --redact --exit-code 0 \
  --report-path "$OUT/gitleaks.json" >"$OUT/gitleaks.log" 2>&1 || true
LEAKS="$(python3 -c "import json,pathlib;p=pathlib.Path('$OUT/gitleaks.json');print(len(json.loads(p.read_text() or '[]')))")"
echo "files scanned: $COMMITTABLE; findings: $LEAKS"

echo "== SBOM (CycloneDX)"
"$BIN/syft" scan "dir:$ROOT" -q \
  --exclude './.local/**' --exclude './**/node_modules/**' --exclude './.venv/**' \
  --exclude './infra/.terraform/**' \
  -o "cyclonedx-json=$OUT/sbom-cyclonedx.json"
python3 - "$OUT/sbom-cyclonedx.json" <<'PY'
import json, sys
from collections import Counter
document = json.load(open(sys.argv[1]))
kinds = Counter((c.get("purl", "") or "").split(":")[1].split("/")[0] if c.get("purl") else "file"
                for c in document["components"])
print(f"components: {len(document['components'])} {dict(kinds)} (CycloneDX {document['specVersion']})")
PY

echo "== dependency advisories"
"$BIN/osv-scanner" scan source --lockfile uv.lock --lockfile pnpm-lock.yaml \
  --format json --output-file "$OUT/osv.json" >"$OUT/osv.log" 2>&1 || true
python3 - "$OUT/osv.json" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
document = json.loads(path.read_text() or "{}") if path.exists() else {}
found = [(package["package"]["name"], package["package"]["version"], vulnerability["id"])
         for result in document.get("results", []) for package in result.get("packages", [])
         for vulnerability in package.get("vulnerabilities", [])]
print(f"advisories: {len(found)}")
for name, version, identifier in found[:20]:
    print(f" - {name} {version} {identifier}")
PY

echo "== accepted revision"
git rev-parse HEAD 2>/dev/null || echo "no commit yet"
echo "reports in $OUT"
[ "$LEAKS" = "0" ] || { echo "SECRET SCAN FAILED"; exit 1; }
