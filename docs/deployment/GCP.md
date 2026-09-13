# GCP delivery and activation

Status, 7 September 2026: Terraform formatting, provider validation and seven offline mocked infrastructure tests pass. Both current runtime images build locally; native imports and isolated Python/web HTTP compatibility probes pass. Secret, SAST and lockfile scans pass. The web HIGH/CRITICAL scan passes directly; the Python gate retains six raw library findings and accepts only verified absent-component dispositions bound to its exact image and package versions. Actual SQLite vulnerabilities were patched with upstream 3.53.4. See [the scan record and native-feed limitations](../security/SCAN_RESULTS_2026-09-07.md). No GCP project has been inspected or provisioned. Cloud IAM denials, managed login, deployment, restore, GitHub execution and real Cloud Run execution remain unverified.

## Inventory before provisioning

The founder must supply the actual project, region and access. `europe-west1` is a configurable development default, not an asserted residency decision. Run from the repository root:

```sh
uv run python infra/scripts/inventory_gcp.py --project APPROVED_PROJECT --region APPROVED_REGION
```

The script performs only read operations and stores private local JSON under `.local/gcp-inventory/`. It requests resource configuration, names, IAM, enabled APIs, SQL, storage, secrets metadata, jobs, queues and repositories; it does not access secret versions. Incomplete inventory exits unsuccessfully. Resolve missing visibility before planning creation.

For each existing resource, document owner, environment, usage, deletion protection and whether another Terraform state manages it. Reuse healthy resources. Do not import an object simultaneously into two states. Set `sql_instance_name`, `evidence_bucket_name`, `database_secret_ids` and `name_prefix` to the reviewed existing names where appropriate. Import existing resources before planning, for example:

```sh
terraform -chdir=infra import google_sql_database_instance.postgres projects/PROJECT/instances/INSTANCE
terraform -chdir=infra import google_storage_bucket.evidence BUCKET
terraform -chdir=infra import 'google_secret_manager_secret.database["api"]' projects/PROJECT/secrets/SECRET
```

Use the provider's documented import identifier for other resource kinds. Adopt existing settings first; do not combine ownership adoption with a destructive configuration change. `prevent_destroy`, SQL deletion protection and bucket `force_destroy=false` are deliberate guards, not substitutes for reviewing every plan.

## Initialize infrastructure and database

Terraform 1.16.1 and Google provider 7.46.1 are pinned; the provider lock contains Linux amd64 and Darwin arm64 checksums. Use an approved existing GCS state bucket with uniform access, public access prevention and versioning. State access is privileged. The backend bucket must exist before initialization and is not created recursively by this configuration.

```sh
terraform -chdir=infra init -backend-config=bucket=APPROVED_STATE_BUCKET -backend-config=prefix=threatveil/dev
terraform -chdir=infra plan -var-file=dev.tfvars -out=../.local/dev.tfplan
```

Copy the example variables into ignored `infra/dev.tfvars`. Keep `deploy_services=false`, `public_web_enabled=false` and `enable_scheduler=false` initially. Apply only the reviewed plan after access and any required founder approval. Terraform does not create a project, attach billing, create customer credentials, rotate existing secrets or purchase third-party subscriptions.

Cloud SQL PostgreSQL 17 uses an authenticated Cloud SQL connector, encrypted connections, no authorized IP networks, disk growth capped at 100 GB, seven retained backups and point-in-time recovery. Its public IP is connector-accessible; this is not a private-VPC deployment. Ordinary direct PostgreSQL clients must not be permitted through an authorized-network rule. Production HA requires a separately reviewed regional profile.

Terraform creates database and secret containers, never secret values. For a newly reviewed empty database, use the Cloud SQL Auth Proxy with an authorized operator account and put its bootstrap connection string in protected `TV_CLOUD_BOOTSTRAP_DSN`. Then:

```sh
uv run python infra/scripts/bootstrap_cloud_database.py --connection-name PROJECT:REGION:INSTANCE --initialize-empty-database
```

The script refuses existing ThreatVeil roles, a nonempty public schema or an existing local bootstrap directory. It writes `.local/cloud-database-secrets/{api,broker,migration}.txt` with mode 0600 before changing roles, then applies database DDL in one transaction. It does not rotate credentials. If the commit response is lost, retain these files and reconcile actual database state before retrying. Add each file as a version of its matching Secret Manager container with `gcloud secrets versions add SECRET --data-file=FILE`; do not print values or place them in tfvars. API and broker currently use the same non-owner `threatveil_app` SQL role behind separate service identities/secret containers; this is not a claim of database privilege separation between these trusted components. Migration uses `threatveil_admin`. Apply migrations through the reviewed authenticated connection before first service activation; later migrations use the dedicated migration job.

Existing databases need a reviewed role/grant reconciliation instead of the initialization script. Verify runtime NOSUPERUSER/NOBYPASSRLS, no ownership of tables, no membership in the migration role, tenant-safe foreign keys and forced RLS before enabling customer execution.

## Deploy services early, privately

Enable Identity Platform and the approved Google sign-in provider, register the exact authorized domain, and configure the Firebase web application. The client configuration is public application metadata, not a service credential; restrict its API key appropriately. `api_secret_bindings` maps optional integration environment names to exact existing secrets. The broker alone gets access to `customer_secret_ids`; the list is explicit and never a project-wide secret grant.

Transactional revenue delivery uses the separate `revenue_delivery` object, not API-only secret bindings. It is disabled by default. To configure an explicitly approved Resend integration, supply its existing `resend_secret_id`, verified plain sender `email_from` and `resend_enabled=true`. For HubSpot, supply `hubspot_secret_id`, an existing numeric `hubspot_owner_id` and `hubspot_enabled=true`. Secret **values** remain in Secret Manager. The API and broker receive matching enabled/from/owner configuration and only those exact enabled secret references. The API currently checks credential presence to report routing readiness; broker maintenance performs the actual delivery. These trusted components therefore share those narrowly scoped provider credentials. No such fields or access are passed to runner, launcher, web or migration. Generic `api_secret_bindings` rejects revenue keys so readiness cannot be configured on only one side.

Preconfiguring provider secret names while their flags remain false creates no revenue secret grants or mounts. Turning a flag off removes its references and grants on the next reviewed deployment; it cannot revoke credentials already read by an old revision or undo a provider request. For urgent revocation, disable/rotate at the provider, drain affected revisions and reconcile pending/uncertain outbox work. Secret-level IAM is additive; inventory must detect any inherited broader grant. Ensure the Resend sender is verified and the HubSpot app has reviewed contact scopes, existing owner and the documented ThreatVeil routing fields before enabling. Seven offline Terraform tests now cover private defaults, exact API/broker configuration, runner exclusion, disabled/preconfigured secrets and invalid partial/API-only configuration. No credentials were supplied and no provider delivery or effective cloud IAM behavior was tested.

Build immutable image digests and set `images.python`, `images.web`, reviewed `web_origin` and `deploy_services=true`. API, broker, launcher and web are separate Cloud Run services. The runner is a shared single-task Cloud Run Job; migrations have a separate administrator job. Both runtime images use official distroless Debian 13 bases without shells or package managers; Python runs as UID 10001 and web as UID 65532. The web command is `/nodejs/bin/node apps/web/server.js`. Services scale to zero, with bounded maximum instances; runner retries are zero and its maximum duration is ten minutes.

Every service requires IAM authentication by default. The HTTPS URLs are internet-addressable; IAM privacy does not imply private network ingress. Web invokes API with a Google token for the API URL. Broker uses the custom audience `threatveil-broker`; launcher uses `threatveil-launcher`. Application code also verifies the expected caller identity and exact capability/lease. IAM invocation alone is insufficient authorization for a run.

Cloud Tasks delivers bounded retryable dispatch notifications. Launcher reads the broker's authorized outbox endpoints, gets a single-use bootstrap capability, and launches only the shared job. The API has queue-enqueue permission and can attach only the dedicated task-delivery identity. Scheduler reconciliation is opt-in after the real dispatch recovery tests. Notification policies are disabled until verified Monitoring channels are supplied; a configured alert with no recipient is not operational monitoring.

Reconciliation's broker HTTP client timeout is 300 seconds because maintenance can perform ten sequential deliveries; other broker calls retain 30-second timeouts. Terraform configures broker requests at 360 seconds, launcher requests and Scheduler attempts at 600 seconds, and ordinary web/API requests at 120 seconds. Dispatch stops starting new outbox items after a 180-second budget and leaves the rest pending. An already-started item may finish after that budget; each Cloud Run launch has a 30-second timeout with automatic API retries disabled. HTTP client timeouts are per network phase, not a strict process deadline. Platform deadlines may still end a response while container work continues, so lost responses and duplicates require the existing outbox/capability/fence recovery rules. These bounds and the untouched-outbox behavior pass local unit tests; real managed deadline behavior remains unverified. [Cloud Run timeout semantics](https://docs.cloud.google.com/run/docs/configuring/request-timeout), [Scheduler attempt deadlines](https://docs.cloud.google.com/scheduler/docs/reference/rest/v1/projects.locations.jobs).

Set `public_web_enabled=true` only after founder review of public exposure, real sign-in, origin/CSRF behavior and tenant tests. No equivalent public switch exists for API, broker or launcher.

## CI to GCP dev

Use a new repository; do not connect the old ThreatVeil repository. Configure a protected `gcp-dev` GitHub environment with founder approval and main-branch restrictions. Federation additionally binds the exact repository, main ref, `workflow_dispatch` event and environment subject. No service-account JSON keys are used.

Repository/environment variables: `GCP_PROJECT`, `GCP_REGION`, `GCP_SERVICE_PREFIX`, `GCP_IMAGE_REPOSITORY`, `GCP_WORKLOAD_IDENTITY_PROVIDER`, `GCP_BUILD_SERVICE_ACCOUNT`, `GCP_DEPLOY_SERVICE_ACCOUNT`, and the four `NEXT_PUBLIC_FIREBASE_*` build variables.

`GCP dev delivery` first runs CI. It rebuilds and scans the exact images to publish, pushes unique immutable tags, resolves digests, and optionally updates already-provisioned dev resources. Publication and deployment identities are distinct. The deploy identity can update the four approved services and the runner/migration jobs, act as only their existing service accounts, and execute only the migration job. It is a privileged code-delivery principal; compromise can replace trusted code. Protect the workflow and environment accordingly.

This delivery workflow does not apply infrastructure or publish the site. Terraform remains the resource configuration authority. After a successful delivery, record the new image digests in the environment's protected tfvars so a later plan cannot roll back to old images. Database changes must remain compatible with still-running revisions; a migration failure stops delivery. No automatic downgrade of database migrations is attempted. Real GCP image-pull, identity, operator token, IAM and connector behavior remain untested until access is available.

## Required cloud acceptance before staging

1. Managed sign-in, same-origin proxy, CSRF, role enforcement and two-tenant API/database isolation pass using cloud service identities.
2. Run ID plus shared identity without bootstrap is denied; wrong run, expired/reused bootstrap, wrong identity/audience, lease replay, stale fences and cross-organization evidence/credentials are denied.
3. Runner IAM fails SQL connector, Storage listing, Secret Manager, job inspection/launch and identity impersonation attempts. Its sole broker invoker grant cannot retrieve another assignment.
4. Duplicate Tasks delivery and Cloud Run launch, lost bootstrap response, worker death, cancellation and ambiguous external side effects preserve idempotency and trial history.
5. The instrumented vulnerable/fixed/regressed/missing-witness/bad-fix cases produce their expected distinct outcomes and exact-candidate release decisions through the real shared job.
6. Target transport denies metadata/private destinations, DNS rebinding, redirects, routing headers and oversized/decompression responses. This is transport-level SSRF protection; default runner networking is not containment of arbitrary hostile code.
7. Redaction, evidence digest/immutable creation, raw-trace lifecycle, deletion visibility, queue/error alerts and alert delivery are exercised. Retention includes the configured seven-day Storage soft-delete recovery window; deletion is not immediate physical purge.
8. Restore a backup to an isolated dev instance, verify role/RLS behavior and representative evidence references, measure recovery time, then approve cleanup. Do not call configured backups a tested restore.

Record each result, principal, image digest and environment without storing bootstrap tokens or customer payloads in test logs. A configured deployment is not a deployed, tested or customer-ready environment.

Primary references: [Cloud Run execution overrides](https://docs.cloud.google.com/run/docs/reference/rest/v2/projects.locations.jobs/run), [service-account ID tokens](https://docs.cloud.google.com/docs/authentication/token-types#service_account_id_tokens), [environment-variable exposure](https://docs.cloud.google.com/run/docs/configuring/jobs/environment-variables), [Cloud SQL role behavior](https://docs.cloud.google.com/sql/docs/postgres/create-manage-users), [Google Terraform provider](https://registry.terraform.io/providers/hashicorp/google/7.46.1/docs).
