# Software supply-chain gates

The CI configuration uses GitHub Actions pinned to verified commit SHAs. Python resolves exclusively from `uv.lock`; JavaScript uses frozen `pnpm-lock.yaml`. Terraform pins the CLI/provider and commits provider checksums for Linux and macOS. Python, Node and uv container bases are pinned by OCI digest; PostgreSQL's CI service image is also pinned.

Configured gates:

| Tool | Gate / output |
|---|---|
| Gitleaks 8.30.1 | Redacted scan of committed Git history; secret findings fail CI |
| Semgrep 1.176.0 | ERROR-severity Python/JavaScript security rules; rule repository pinned to commit `40b8c63f75dc7c22c8a77482d73bfb864b146f7e` |
| OSV-Scanner 2.5.1 | Scan both application lockfiles; unwaived vulnerability findings fail CI |
| Trivy 0.74.0 | HIGH/CRITICAL gate; Python uses image-bound, package-bound, assertion-guarded VEX only for six absent-executable records; exact publish images scanned before push |
| Syft 1.51.1 | SPDX JSON SBOM for each image, retained as a CI artifact for 14 days |
| Terraform | Formatting, validation and offline mock tests for private defaults, bounded runner and forbidden grants |
| Runtime image checks | Assert Python UID/GID 10001 and web UID/GID 65532; native dependency/service imports and isolated HTTP compatibility |

The binary installer downloads only exact pinned releases, checks recorded SHA256 values from publisher release metadata, and extracts only the expected executable. It never uses a download-to-shell pipeline or arbitrary archive extraction. Scanner vulnerability databases remain current data rather than frozen application dependencies. A scanner outage fails its gate; it is not silently interpreted as clean.

No broad ignore file, ignore-unfixed option or blanket `continue-on-error` is configured. The six current VEX dispositions and their enforced 14 September 2026 review expiry are documented in [the applicability review](VEX_APPLICABILITY_REVIEW.md). They do not exempt SQLite or newly discovered findings. Triage findings before release. If a necessary bounded exception is later approved, record package/rule/CVE, affected version, exploitability rationale, owner, compensating control and expiration; use the scanner's narrow exception mechanism. Never disable a whole scanner to make delivery green. Pin updates require rerunning the same tests and scans.

The build context excludes secrets, `.local`, Git metadata, caches, reference packs and documents. Customer data must never enter build arguments. The Firebase `NEXT_PUBLIC_*` arguments are deliberately public web-app metadata. No customer/provider credentials, workload keys or bootstrap capabilities belong in image layers.

CI has no production credentials. Pull-request jobs never receive GCP federation or customer secrets. Dev delivery requires a reviewed GitHub environment and exact main-branch federation; the old repository is not configured. The CI deployment identity is privileged because replacing API/broker code can access their granted data—environment protection is a security boundary, not administrative decoration.

The web runtime uses pinned official distroless Node 24 Debian 13. Python retains the current official CPython 3.13.15 binary/stdlib from its matching Debian 13 build image on pinned distroless cc Debian 13. Interpreter paths and virtual-environment links remain unchanged. `prepare_python_runtime.py` preserves base-provided libraries and adds only required missing libraries with their original dpkg metadata, so their vulnerabilities remain visible. The headless runtime excludes Tk and package managers. SQLite is compiled from checksum-verified upstream 3.53.4 in a separate stage to fix its actual FTS5 vulnerabilities. Its upstream component and binary hash are included explicitly in CycloneDX and SPDX. Build-only compiler packages come from signed Debian repositories; byte-for-byte reproducibility of that compiler stage is not claimed. See the publisher's [distroless scope](https://github.com/GoogleContainerTools/distroless).

`infra/scripts/smoke_images.py` checks native imports and HTTP behavior with no external network or credentials. Its Python HTTP probe explicitly skips the SQL startup hook; the real PostgreSQL/RLS checks run separately in the Python CI job. It does not claim managed database or cloud connectivity. CI additionally runs Ruff, the TypeScript SDK's actual unit tests, type checking, production web compilation and synthetic browser acceptance against a local API/PostgreSQL pair.

Local scanner and image execution is now available through the project Colima profile. [The dated scan record](SCAN_RESULTS_2026-09-07.md) records passing checks, six retained raw library findings and their guarded absent-component dispositions. It also states native SQLite scanner-feed limitations. These local ARM64 image results are not a completed Linux AMD64 GitHub run; CI must build and scan its exact images. Dev delivery also produces SBOMs and repeats smoke/scanner gates on its exact publish images before pushing.

Artifact signing/provenance is deferred until the image delivery pipeline has run successfully. Current configuration does not claim signed application artifacts, certifications or zero vulnerabilities. GitHub execution and GCP deployment remain unverified because their credentials/new repository are not available.
