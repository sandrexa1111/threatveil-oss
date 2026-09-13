# Supply chain and reproducible builds

A product whose job is to say *"this is exactly what is running"* has to be able to say it about
itself.

## 1. What pins what

| Layer | Pinned by | Enforced where |
|---|---|---|
| Python dependencies | `uv.lock` (versions + hashes, 89 packages) | `uv sync --locked` in the container acceptance run and in the image build |
| Web dependencies | `pnpm-lock.yaml` (187 packages) | `pnpm install --frozen-lockfile` |
| Container images | `sha256` digest, never a tag | `infra/variables.tf` rejects any image reference without `@sha256:` |
| Terraform provider | version-pinned in `infra/versions.tf` plus the provider lock | `terraform init -backend=false` |
| Migration schema | the alembic head, reported by `/v1/build-info` | the API refuses to serve against an unexpected schema state in the readiness check |
| Plan catalog and claim templates | a dated version string in the data file | reported by `/v1/build-info` |

## 2. Build provenance: what `/v1/build-info` answers

```json
{
  "source_revision": "…", "image_digest": "…@sha256:…", "build_time": "…",
  "migration_head": "0008", "schema_applied": "0008",
  "catalog_version": "2026-09-12.2", "claim_templates_version": "2026-09-12.1",
  "assurance_packs": {"support_refund": "0.1.0 (DRAFT)", "…": "…"}
}
```

- `TV_SOURCE_REVISION` and `TV_BUILD_TIME` are `ARG`s in `Dockerfile.python`, baked at build time.
- `TV_IMAGE_DIGEST` comes from Terraform, which already requires digest-pinned images.
- Any value the deployment did not bind reports `UNKNOWN` rather than a guess.

An `UNKNOWN` here is a deployment finding, not a cosmetic gap: it means nobody can say which
source produced the running service.

## 3. Reproducing a build

```bash
# 1. the accepted revision
git rev-parse HEAD

# 2. the Python image, with provenance baked in
docker build -f Dockerfile.python \
  --build-arg SOURCE_REVISION="$(git rev-parse HEAD)" \
  --build-arg BUILD_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -t threatveil-api:local .

# 3. the web image
docker build -f Dockerfile.web -t threatveil-web:local .

# 4. the digest to deploy (never a tag)
docker inspect --format '{{index .RepoDigests 0}}' threatveil-api:local
```

What is reproducible and what is not, honestly:

- **Reproducible:** the dependency set (lockfiles with hashes), the application source (the
  revision), the schema (the migration head), and the catalog/template/pack versions.
- **Not bit-for-bit reproducible:** image layers embed timestamps and base-image content that
  changes when the base is rebuilt. The digest is therefore the identity of an image, not a
  proof that two builds of one revision are identical.
- **Not yet done:** signed build provenance (SLSA-style attestation of the build itself). The
  product signs its *evidence*; it does not yet sign its *own artefacts*. That is a deliberate
  ordering, and it is listed in the post-deployment roadmap.

## 4. The local supply-chain pass

```bash
scripts/supply_chain.sh      # secret scan + SBOM + dependency advisories
```

It scans **exactly the file set that would be committed** (`git ls-files -co
--exclude-standard`). This matters: scanning the whole working tree reports hundreds of
findings from `.local/` demo digests and vendored Terraform provider Go modules, and a real
finding then drowns in them.

Result of the run recorded for this wave:

| Check | Tool | Result |
|---|---|---|
| Secrets | gitleaks 8.30.1 | **0 findings** across 469 committable files |
| SBOM | syft 1.51.1 | 315 components (105 PyPI, 187 npm, plus source files), CycloneDX 1.7 |
| Advisories | osv-scanner | **0 known vulnerabilities** across 276 locked packages (89 Python, 187 npm) |

The advisory result is a signal, not a guarantee: the freshness of the advisory database at scan
time cannot be verified offline, and a clean scan says nothing about unreported vulnerabilities.

## 5. What is deliberately not in version control

`.gitignore` keeps out: `.venv/`, `node_modules/`, `.next/`, `.terraform/`, `.local/` (all local
artefacts, demo output, signing material and downloaded tools), `*.tfstate*`, `*.tfvars`
(except examples), `.env` (except `.env.example`), `*.log`, `._*` (macOS AppleDouble files) and
`*.pdf`.

Nothing ignored is required to build the product; everything ignored is either generated,
machine-local or secret.

## 6. The accepted revision

The first accepted revision of this source is recorded in
`docs/history/THREATVEIL_FINAL_PRE_GCP_MAXIMUM_READINESS_REPORT.md` with its SHA, the test counts that were
green at that commit, and the supply-chain results above.

**It has not been pushed anywhere.** The repository has no remote, and adding one is a founder
decision, not an implementation detail.
