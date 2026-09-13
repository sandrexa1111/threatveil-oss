# Runner and control-plane trust boundaries

The job's shared Google identity authenticates a class of worker. It does not identify one Cloud Run execution. `CLOUD_RUN_EXECUTION`, task indexes, caller-supplied organization IDs and public run IDs are correlation data, never authorization.

| Principal | Configured authority | Explicitly absent |
|---|---|---|
| Web | Invoke API | SQL, evidence, secrets, jobs |
| API | Runtime SQL, create/read evidence, exact integration secrets, enqueue Tasks | Runner job launch and customer credential secret access |
| Broker | Runtime SQL, create/read evidence, exact registered customer secrets; explicitly enabled revenue-provider secrets | Job launch/configuration and impersonation |
| Launcher | Invoke broker; run shared job with overrides | SQL, Storage, Secret Manager, job configuration and inspection |
| Runner | Invoke broker | SQL, bucket listing/read/write, Secret Manager, job permissions, impersonation |
| Task delivery / Scheduler | Invoke launcher | SQL, secrets, evidence and jobs |
| Migration | SQL connector and migration URL secret | Customer credentials and evidence |
| CI build | Publish images in one repository | SQL, customer credentials and deployment |
| CI deploy | Update approved services/jobs; act as their identities; execute migration | Direct customer-secret grants and arbitrary infrastructure provisioning |

These are the Terraform grants, not a verified effective-IAM inventory. Existing project/folder/organization roles, groups or service-account impersonation can widen them. Inspect inherited effective permissions before launch. Remove default broad grants and service-account keys through a separately reviewed remediation, not an automatic destructive sweep.

Revenue delivery is disabled by default. When explicitly configured, API readiness and broker maintenance share only the exact enabled Resend/HubSpot secret references and matching sender/owner settings. No revenue secrets, delivery flags or routing settings enter the shared runner environment. This is intentional credential access for two trusted components, not privilege separation between them. [Deployment and revocation procedure](../deployment/GCP.md).

## Assignment capability

The approved launch exception passes `run_id` and a random 256-bit bootstrap token, never provider credentials, in an execution-specific override. The server stores a digest bound to organization, run, attempt, specification digest, expected worker identity, fixed broker audience and an expiry of at most five minutes. Atomic redemption creates one short-lived run lease and fence. Recovery requires the same claim nonce and ephemeral worker key; replacement invalidates the old fence. Every spec, credential, evidence, heartbeat and completion endpoint validates the active assignment.

An IAM-authenticated worker without a valid capability must obtain nothing. A guessed public ID must not create an existence oracle. The broker chooses credential references and object keys from the frozen spec, not from arbitrary worker paths. A static provider key delivered to the worker does not become short-lived when its broker lease expires; prefer delegated credentials and broker-mediated operations and disclose residual exposure.

Bootstrap values in Cloud Run execution configuration may be visible to privileged project viewers or through control-plane observability. Restrict those permissions, use no request-body logging, redact tokens, redeem promptly and retain only the digest in ordinary application state. An operator who can observe an unconsumed bootstrap and impersonate the worker can race redemption. This design does not defend against a compromised cloud administrator, broker or deployment principal.

## Execution limits

The hosted P0 runner executes vetted ThreatVeil adapters and evaluators. It does not install customer code, run arbitrary imported scripts, accept container images or load customer Python packages. The qualified observation and immutable evidence contracts are application properties, not remote attestation that a compromised worker is honest.

The adapter transport validates and pins permitted destinations and denies metadata/private addresses. This blocks requests made through that transport. A fully compromised container can use its own network stack; the default Cloud Run job here has no network-level Internet deny policy. Metadata is accessible to the trusted identity client. Its token alone conveys no run authority. Do not market Python URL checks as a sandbox for hostile code.

Dedicated customer/private-VPC execution is a later deployment class. Untrusted code execution would require a separately verified sandbox and egress boundary before activation. Cloud Run sidecars alone do not create separate workload identities. Cloud Run sandbox launcher is currently Preview and is not silently adopted as a production security boundary.

## Evidence and verification limits

The trusted API/broker can create and read evidence in the evidence bucket. The worker has no direct Storage role. Application authorization must map one lease to exact evidence objects, verify size/digest and reject stale writes. Bucket IAM does not implement per-tenant access for a broadly trusted broker.

The current API and broker use the same PostgreSQL runtime role. Tenant context, endpoint authorization and capability checks are essential. Local tests can prove these code paths; only deployment against actual IAM and cloud services establishes their cloud enforcement. Run the separate cloud acceptance list in `docs/deployment/GCP.md` before staging.
