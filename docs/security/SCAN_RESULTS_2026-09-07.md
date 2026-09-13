# Local supply-chain validation — 7 September 2026

The tested Python image passes its guarded HIGH/CRITICAL release gate: six raw library-package findings receive exact, verified absent-component dispositions; zero findings remain after those dispositions. The actual SQLite vulnerabilities were patched with verified upstream SQLite 3.53.4, with no SQLite exception. The web image passes its direct HIGH/CRITICAL scan. Both images were rebuilt after the application source freeze and freshly scanned. Their exact identifiers and the image-derived Python source manifest are recorded below. No image was published or deployed.

## Actual local results

| Check | Observed result and scope |
|---|---|
| Terraform 1.16.1 / Google provider 7.46.1 | Formatting and provider validation pass; seven offline mocked infrastructure tests pass. No cloud provisioning or IAM enforcement claim. |
| actionlint 1.7.12 and Ruff | Both workflows validate; owned infrastructure Python passes Ruff. Application acceptance is recorded separately. |
| Gitleaks 8.30.1 | Six explicit directory scans pass with zero findings: `src`, `apps/web/src`, `tests`, `infra/scripts`, `.github`, `scripts`. This repository has no commits yet, so no local Git-history scan is claimed. |
| Semgrep 1.176.0, pinned ERROR security rules | 96 application/infrastructure files scanned; zero findings and zero parsing errors. The JSX parser warning was fixed and the scan repeated. Narrow inline dispositions cover audited subprocess invocations with fixed commands, validated inputs, separate argv and no shell. |
| OSV 2.5.1 | Lockfile scan exits 0: zero findings across 89 Python and 187 pnpm resolved packages. Actual cryptography 47.0.0 advisories were fixed by locking 50.0.1. |
| Python image build | Pass locally, Linux ARM64: official CPython 3.13.15 on distroless cc Debian 13. |
| Web image build | Pass locally, Linux ARM64: Node 24 on distroless Debian 13. |
| Runtime compatibility | NumPy/gRPC/psycopg/cryptography and service imports pass. Isolated Python/web HTTP probes pass. Python's SQL startup hook is explicitly skipped for this networkless ABI probe; real PostgreSQL startup/RLS is a separate application test. |
| Runtime inventory | Python 3.13.15; SQLite 3.53.4 loaded from the verified replacement library; real FTS5 insert/query passes; UID 10001. infocmp/mount/nsenter/pip/uv/sh/bash and libmount are absent from the examined runtime paths. |
| Trivy 0.74.0 Python | Guarded PASS: six raw HIGH records, six exact absent-component dispositions, zero remaining. No CRITICAL or application-package records. |
| Trivy 0.74.0 web | Direct PASS: zero HIGH/CRITICAL OS or Node findings. Lower severities are outside this gate. |
| Syft 1.51.1 / native inventory | Both SPDX 2.3 inventories generated. Python inventory explicitly includes the source-built SQLite component. Both SPDX files and the SQLite CycloneDX 1.6 component document pass their official JSON schemas. |
| Gate negative checks | Wrong image digest leaves six findings blocking; an added harmless `/usr/bin/mount` marker prevents VEX issuance; an old SQLite runtime prevents VEX issuance. |

Runtime bases have no shell or package manager. CPython's unsupported Tk GUI extension is excluded. The assembler preserves distroless libraries and copies only missing required libraries with original dpkg metadata; it does not erase inventory. A separate build stage compiles upstream SQLite after publisher checksum verification. Build-only compiler packages come from signed Debian repositories, but their versions are not fully locked; this is not a claim of bit-reproducible builds.

## Exact tested image snapshots

| Local tag | Trivy/Docker image ID |
|---|---|
| `threatveil-python:final` | `sha256:8d19c64dd39da00f1e444766478835a37dfc4cff5ecb63a1787b5abb02b33d1f` |
| `threatveil-web:final` | `sha256:0403c3492aca39dd35c52d4c3a1971e8095e05bba1a3e38edff975ddc4517f0f` |

These are local image identifiers, not published Artifact Registry references. Earlier experimental tags are superseded. Source files inside the Python snapshot were hashed directly from the immutable image into `.local/security-reports/python-frozen-source-manifest.json`; that manifest's SHA256 is `c9689d094960cd0c0b1f006a7d3cfd503504dc5ccc7287a6ac8fd7991b4259ae`. Every Python source/migration/build-input file in that manifest matched the frozen working tree after the build. Subsequent changes require rebuilding and fresh validation. ARM64 validation does not certify CI's Linux AMD64 image.

## Exact applicability dispositions

The six records cover five unique CVEs: CVE-2025-69720 against `libncursesw6` and `libtinfo6` 6.5+20250216-2, plus CVE-2026-76642/78408/78409/78410 against `libuuid1` 2.41.5-0+deb13u1. Primary-source affected components, file-absence evidence and rationale are in [the applicability review](VEX_APPLICABILITY_REVIEW.md). The vulnerable CLI/libmount components are absent; non-root execution alone is not the disposition.

`image_security_gate.py` issues OpenVEX statements only after fresh assertions against the exact image digest, exact package versions and approved component-absence predicates. It checks that the scanner removes exactly those records. New findings, failed prerequisites and review expiry remain blocking. The enforced review expiry is **14 September 2026 UTC**. No blanket ignore or ignore-unfixed mode is active. This is build-pipeline verification, not remote attestation against a compromised builder.

SQLite CVE-2026-11822 and CVE-2026-11824 are fixed by upstream 3.53.4, with checks of source hashes, actual mapped binary hash/version and FTS5 operation. Its native library SHA256 in this ARM64 image is `8b391b5818e9f9cf5d35c5386b433701449dcb10a27733486c1f95d5c3061413`. Stock Trivy/Syft did not automatically inventory this generic native replacement, so a verified CycloneDX component and explicit SPDX augmentation preserve it. This inventory does not provide comprehensive native SQLite vulnerability-feed coverage; future SQLite advisories require upstream review. A clean generic-package scan alone is insufficient. [SQLite release](https://www.sqlite.org/releaselog/3_53_4.html), [publisher checksums](https://www.sqlite.org/download.html).

## Build-input anchors and reproduction

| File at image build | SHA256 |
|---|---|
| `uv.lock` | `dd16659b404f822cbd0b0dbe255f44cba5891970c44578cb9d2b206a40d49aeb` |
| `pnpm-lock.yaml` | `f13dc0024f711b85751a5e8d59e6b23a23433ed230816b6d80ca7a67097b209b` |
| `Dockerfile.python` | `546fdf5c817f96a5b29c08442cac27e4505852829bff775a765aed384dda2253` |
| `Dockerfile.web` | `461e4c8cc52319f14acbf702e15ef195948f5286c6f52f86b74271c5c2457f55` |

Raw local evidence is in `.local/security-reports/`: `python-frozen-gate/{raw,filtered,trivy.cdx,image.openvex,sqlite.cdx,applicability-evidence,decision}.json`, `trivy-web-frozen.json`, `python-frozen.spdx.json`, `web-frozen.spdx.json`, `osv-frozen.json`, `semgrep-frozen.json`, `gitleaks-*-frozen.json` and `build-*-final.log`. Negative gate artifacts are retained under `python-final-gate/`. Reports contain software inventory and synthetic fixtures; keep customer traces out of these artifacts.

Use `infra/scripts/install_security_tools.py` for checksum-verified scanner binaries. Docker uses the project Colima profile at `DOCKER_HOST=unix://$HOME/.colima/threatveil/docker.sock` with `DOCKER_CONFIG=$PWD/.local/docker`. Run `smoke_images.py` against selected tags, `image_security_gate.py` for Python, and the direct web Trivy and SBOM commands from `.github/workflows/ci.yml`. Vulnerability databases are live data; later results may differ for identical images. CI and dev delivery run fresh checks against their exact images and retain raw/filtered/SBOM evidence.

## Still unverified

No GitHub workflow has executed in a new remote repository. No image has been pushed, no GCP inventory performed, no infrastructure applied, and no Cloud Run/SQL/Secrets/Storage/Tasks/Scheduler integration or IAM denial test has run. Cloud backup restoration, alert delivery, Identity Platform login and effective inherited IAM remain acceptance work once access is supplied. No public exposure or service purchase occurred.
