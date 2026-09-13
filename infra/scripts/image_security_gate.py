"""Scan an exact local image, prove bounded VEX conditions, and retain raw findings."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
from urllib.parse import unquote


VERSIONS = {"libncursesw6": "6.5+20250216-2", "libtinfo6": "6.5+20250216-2", "libuuid1": "2.41.5-0+deb13u1"}
ABSENT_COMPONENTS = {
    "CVE-2025-69720": {"libncursesw6", "libtinfo6"},
    "CVE-2026-76642": {"libuuid1"}, "CVE-2026-78408": {"libuuid1"},
    "CVE-2026-78409": {"libuuid1"}, "CVE-2026-78410": {"libuuid1"},
}
REVIEW_EXPIRES = datetime(2026, 9, 14, tzinfo=timezone.utc)
PROBE = """
import hashlib,json,os,sqlite3,sys
from pathlib import Path
assert os.getuid()==10001
assert sys.version_info[:3]==(3,13,15)
assert sqlite3.sqlite_version=='3.53.4'
directories=('/bin','/sbin','/usr/bin','/usr/sbin','/usr/local/bin','/app/.venv/bin')
absent=('infocmp','mount','nsenter','pip','uv','sh','bash')
assert all(not (Path(directory)/name).exists() for name in absent for directory in directories)
assert not list(Path('/usr/lib').rglob('libmount.so*'))
for directory in directories:
    assert not list(Path(directory).glob('mount.*'))
library=Path('/usr/local/lib/libsqlite3.so.0')
bom=json.loads(Path('/usr/local/share/threatveil/sqlite.cdx.json').read_text())
component=bom['components'][0]
assert component['version']=='3.53.4'
binary_hash=hashlib.sha256(library.read_bytes()).hexdigest()
assert component['hashes']==[{'alg':'SHA-256','content':binary_hash}]
assert {'name':'threatveil:source-sha3-256','value':'67f423e9ebbbdc473cbc4772c872ee6b89f31fde4ed0279a5c25d5f65c043a16'} in component['properties']
loaded={line.split()[-1] for line in Path('/proc/self/maps').read_text().splitlines() if 'libsqlite3' in line}
assert loaded=={str(library)}
connection=sqlite3.connect(':memory:')
connection.execute('CREATE VIRTUAL TABLE probe USING fts5(body)')
connection.execute('INSERT INTO probe VALUES (?)',('synthetic verification',))
assert connection.execute('SELECT count(*) FROM probe WHERE probe MATCH ?',('verification',)).fetchone()[0]==1
print(json.dumps({'uid':os.getuid(),'python':sys.version.split()[0],'sqlite':sqlite3.sqlite_version,'sqlite_binary_sha256':binary_hash,'absent_executables':list(absent),'sqlite_fts5_smoke':'PASS','upstream_sqlite_component':component}))
"""


def findings(report):
    return [item for result in report.get("Results", []) for item in result.get("Vulnerabilities") or []]


def key(item):
    return item["VulnerabilityID"], item["PkgName"], item["InstalledVersion"], item["PkgIdentifier"]["PURL"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_./:@-]*", args.image):
        parser.error("Expected an image reference without options or whitespace")
    docker = shutil.which("docker")
    trivy = str(Path(".local/security-bin/trivy").resolve())
    if not docker or not Path(trivy).is_file():
        parser.error("Docker and the checksum-verified scanner are required")
    args.output_dir.mkdir(parents=True, exist_ok=True)

    def command(*argv, check=True):
        # Fixed Docker/Trivy executables, validated image reference, argv only; no shell.
        # nosemgrep: local.semgrep-rules.python.lang.security.audit.dangerous-subprocess-use-audit
        return subprocess.run(argv, text=True, capture_output=True, check=check, timeout=600)  # noqa: S603

    image_id = json.loads(command(docker, "image", "inspect", args.image).stdout)[0]["Id"]
    raw_path = args.output_dir / "raw.json"
    sbom_path = args.output_dir / "trivy.cdx.json"
    empty_ignore = args.output_dir / "empty.ignore"
    empty_ignore.write_text("")
    scan = [trivy, "image", "--image-src", "docker", "--disable-telemetry", "--scanners", "vuln", "--severity", "HIGH,CRITICAL", "--ignore-unfixed=false", "--ignorefile", str(empty_ignore)]
    command(*scan, "--format", "json", "--output", str(raw_path), args.image)
    command(*scan, "--format", "cyclonedx", "--output", str(sbom_path), args.image)
    raw = json.loads(raw_path.read_text())
    product = json.loads(sbom_path.read_text())["metadata"]["component"]["purl"]
    if raw["Metadata"]["ImageID"] != image_id or image_id not in unquote(product):
        raise SystemExit("Scan/SBOM image identity mismatch; refusing VEX")
    evidence = json.loads(command(docker, "run", "--rm", "--network", "none", "--entrypoint", "python", image_id, "-c", PROBE).stdout)
    evidence.update({"image_id": image_id, "image_purl": product, "review_expires": REVIEW_EXPIRES.isoformat()})
    (args.output_dir / "applicability-evidence.json").write_text(json.dumps(evidence, indent=2))
    (args.output_dir / "sqlite.cdx.json").write_text(json.dumps({
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {"component": {"type": "container", "name": args.image, "purl": product}},
        "components": [evidence["upstream_sqlite_component"]],
    }, indent=2))
    now = datetime.now(timezone.utc)
    allowed = [item for item in findings(raw)
               if item["PkgName"] in ABSENT_COMPONENTS.get(item["VulnerabilityID"], set())
               and item["InstalledVersion"] == VERSIONS[item["PkgName"]]
               and item["PkgIdentifier"]["PURL"].startswith("pkg:deb/debian/" + item["PkgName"] + "@")]
    if allowed and now >= REVIEW_EXPIRES:
        raise SystemExit("Component-absence review expired; raw vulnerabilities remain blocking")
    statements = [{
        "vulnerability": {"name": item["VulnerabilityID"]},
        "products": [{"@id": product, "subcomponents": [{"@id": item["PkgIdentifier"]["PURL"]}]}],
        "status": "not_affected", "justification": "vulnerable_code_not_present",
        "impact_statement": "Only the exact library package is delivered; the affected infocmp/mount/nsenter executable and mount library are absent. See retained runtime evidence and docs/security/VEX_APPLICABILITY_REVIEW.md. Review expires 2026-09-14.",
    } for item in allowed]
    vex = {"@context": "https://openvex.dev/ns/v0.2.0", "@id": "urn:threatveil:vex:" + hashlib.sha256(product.encode()).hexdigest(),
           "author": "ThreatVeil security engineering", "timestamp": now.isoformat(), "version": 1, "statements": statements}
    vex_path = args.output_dir / "image.openvex.json"
    vex_path.write_text(json.dumps(vex, indent=2))
    final_path = args.output_dir / "filtered.json"
    result = command(*scan, "--vex", str(vex_path), "--show-suppressed", "--format", "json", "--output", str(final_path), "--exit-code", "1", args.image, check=False)
    if not final_path.is_file():
        raise SystemExit("Final scanner did not produce a report; gate failed")
    final = json.loads(final_path.read_text())
    if final["Metadata"]["ImageID"] != image_id:
        raise SystemExit("Final scanner evaluated a different image")
    remaining = findings(final)
    raw_keys, remaining_keys, allowed_keys = map(set, ([key(v) for v in findings(raw)], [key(v) for v in remaining], [key(v) for v in allowed]))
    if raw_keys - remaining_keys != allowed_keys or remaining_keys - raw_keys:
        raise SystemExit("VEX filtered unexpected findings or failed to match exact components")
    if json.loads(command(docker, "image", "inspect", args.image).stdout)[0]["Id"] != image_id:
        raise SystemExit("Image tag changed during verification")
    summary = {"image_id": image_id, "raw_records": len(findings(raw)), "component_absent_records": len(allowed),
               "remaining_records": len(remaining), "result": "PASS" if result.returncode == 0 and not remaining else "FAIL"}
    (args.output_dir / "decision.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary))
    if result.returncode or remaining:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
