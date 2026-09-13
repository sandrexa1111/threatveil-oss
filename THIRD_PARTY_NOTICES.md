# Third-party notices

The ThreatVeil repository contains no vendored third-party source code, fonts, images or
vendor logos. Dependencies are declared in `pyproject.toml`, `apps/web/package.json` and
`src/threatveil/sdk/typescript/package.json`, pinned in `uv.lock` and `pnpm-lock.yaml`, and
downloaded at install or build time. Each dependency remains under its own license.

This summary was produced on 2026-09-13 from installed package metadata. It is informational,
not legal advice; the license files shipped inside each package are authoritative.

## Python (runtime and development, `uv.lock`)

Almost all packages use permissive licenses: MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause,
ISC, PSF-2.0 or MIT-0. Notable exceptions:

| Package | License | Notes |
|---|---|---|
| `psycopg`, `psycopg-binary` | LGPL-3.0-only | Used unmodified as a library. `psycopg-binary` bundles `libpq` and OpenSSL builds. |
| `certifi` | MPL-2.0 | Mozilla CA bundle, unmodified. |
| `tqdm` | MPL-2.0 AND MIT | Transitive, unmodified. |
| `google-crc32c` | Apache-2.0 (metadata incomplete) | Transitive through Google Cloud clients. |

## JavaScript (`pnpm-lock.yaml`)

Mostly Apache-2.0, MIT, BSD-3-Clause and ISC. Notable exceptions:

| Package | License | Notes |
|---|---|---|
| `@img/sharp-libvips-*` | LGPL-3.0-or-later | Optional native image library pulled in by Next.js; used unmodified. |
| `lightningcss`, `lightningcss-*` | MPL-2.0 | CSS build tooling (Tailwind), build time only. |
| `caniuse-lite` | CC-BY-4.0 | Browser-support data used at build time. |

## Container images

`Dockerfile.python` and `Dockerfile.web` build on pinned upstream images:

- `gcr.io/distroless/cc-debian13` and `gcr.io/distroless/nodejs24-debian13` (Debian packages
  under their respective licenses);
- `python:3.13-slim-trixie` (CPython, PSF-2.0) and `node:24-trixie-slim` (Node.js, MIT) as
  build stages;
- `ghcr.io/astral-sh/uv` (MIT OR Apache-2.0) at build time only;
- SQLite (public domain), compiled from the checksum-pinned amalgamation.

`compose.yaml` additionally uses `postgres:17-alpine` (PostgreSQL License). The threatveil.com
site (`website/`) is served by `nginxinc/nginx-unprivileged` (nginx, BSD-2-Clause) and rendered at
build time with Python-Markdown (BSD-3-Clause). If you
**redistribute built images**, you take on the notice obligations of everything inside them,
including the LGPL and MPL components above. Generating an SBOM (`syft`, as CI does) is the
practical way to enumerate them.

## Trademarks

Product names such as Claude Code, MCP, LangGraph, CrewAI, OpenAI, GitHub, Google Cloud,
Stripe, HubSpot and Resend appear only to describe interoperability. They belong to their
owners, and their use implies no endorsement. The UI deliberately uses neutral monograms
instead of vendor logos.
