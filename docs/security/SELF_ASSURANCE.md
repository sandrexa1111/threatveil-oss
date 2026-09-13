# ThreatVeil's internal security properties

The internal suite checks the real application and non-owner PostgreSQL role. Synthetic fixtures are deliberate and provider interception is explicit. These tests run in the configured CI pipeline; no remote CI run or cloud enforcement is claimed yet.

| Property | Executable local coverage |
|---|---|
| Organization A cannot read, reference, execute or report Organization B's records | `tests/integration/test_product.py`, `tests/security/test_tokens.py` |
| Missing tenant context returns no tenant data; runtime role cannot bypass RLS; evidence cannot be rewritten | `tests/integration/test_product.py` |
| Viewers cannot execute; scoped execution tokens cannot administer; revoked membership takes effect | `tests/integration/test_product.py`, `tests/security/test_tokens.py` |
| Unverified, expired or revoked targets cannot execute or retain release eligibility | `tests/integration/test_product.py`, `tests/security/test_broker.py`, `tests/integration/test_adverse_memory.py` |
| Adapter requests cannot reach metadata/private addresses or broaden the registered destination | `tests/security/test_targets.py` |
| Shared service identity alone cannot claim a run; bootstrap/nonce/fence replays fail | `tests/security/test_broker.py` |
| Runner cannot resolve another assignment's credential or call launcher operations | `tests/security/test_broker.py`, `tests/security/test_credentials.py` |
| Source signatures bind collector roles, content, exact candidate and assigned sample; a self-report cannot qualify itself | `tests/security/test_observer_crypto.py`, `tests/integration/test_observers.py` |
| Partial/duplicated evidence cannot satisfy a complete experiment; confirmed failure survives interruption | `tests/integration/test_captures.py`, `tests/security/test_broker.py` |
| Later sampled PASS cannot erase a qualified failure for the same artifact, including concurrent capture/finalization | `tests/integration/test_adverse_memory.py` |
| Cross-organization raw evidence is denied; expired objects cannot silently substitute evidence | `tests/security/test_evidence_storage.py`, `tests/integration/test_security_memory.py` |
| Malicious evidence is escaped in reports; exception logs do not disclose payloads or credentials | `tests/integration/test_product.py`, `tests/security/test_observability.py` |
| A bad fix cannot qualify by disabling the legitimate task | `tests/core/test_engine.py`, `tests/integration/test_product.py`, browser acceptance |
| Fork/wrong-audience workflow identity cannot release; gate requires exact observed candidate | `tests/security/test_github.py` |
| Payment replay/test/manual/failed events cannot manufacture paid status; usage cannot bypass reservations | `tests/integration/test_billing.py`, `tests/integration/test_entitlements.py`, `tests/security/test_maintenance.py` |
| Invitation retries preserve bounded delivery identity and customer roles; CRM receives only consented allowed fields | `tests/integration/test_revenue_delivery.py` |

Run `TV_ENV=test TV_LOCAL_AUTH=true uv run pytest` from the repository root after starting the local database and applying migrations. The actual consequential demo also runs through the production evaluator and API/UI, preserving failure → useful fix → historical regression evidence. `uv run threatveil demo --output NEW_FILE.json` runs its standalone form without a database or provider.

This is an executable application-security suite, not a claim that the hosted product has independently certified its own infrastructure. Actual runner IAM denial, cloud storage isolation, identity exchange, managed job recovery and backup restoration require the [cloud acceptance exercises](../deployment/GCP.md). Transport metadata rejection does not deny the trusted identity client's metadata access or contain an arbitrary compromised process; see [runner boundaries](RUNNER_IAM.md).
