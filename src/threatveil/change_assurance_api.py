"""Connected assurance journey, bounded authorization and honest enforcement state."""

from copy import deepcopy
from datetime import datetime, timedelta
from uuid import UUID, uuid4
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import Field
from sqlalchemy import select, text

from .auth import Actor, SECURITY, actor, require
from .change_assurance import (
    PROFILE, EnvironmentInput, EnvelopeInput, RelationshipInput, StateInput,
    TargetBindingInput, TransitionInput, Versioned, history, projection, save_envelope,
    save_environment, save_state, save_transition, scoped,
)
from .core.contracts import digest
from .db import Record, RunState, TargetState, add_record, audit, get_record, now, serialize, transaction
from .release_integrity import _properties, lock_system, current_release_assessment

router = APIRouter(prefix="/v1/change-assurance", tags=["change-assurance"])


def _support_digest(current):
    keys = ("property_id", "evidence_id", "applicability", "security", "legitimate_task", "supported")
    return digest([{key: p[key] for key in keys} for p in sorted(current["properties"], key=lambda p: p["property_id"])])


def _exception_status(session, org, release):
    """Exception status is separate from every underlying security assessment."""
    from .release_integrity import active_exceptions
    values = release.payload
    if not values["exceptions"]:
        return "NONE"
    plan = get_record(session, org, values["plan_id"], "proof_plan")
    reader = Actor(UUID(values["evaluated_by"]), org, "security", "", "", "", "historical_read")
    try:
        active_exceptions(session, reader, plan, [e["id"] for e in values["exceptions"]])
        return "ACTIVE"
    except HTTPException as exc:
        return "EXPIRED" if exc.detail == "Exception expired" else "REVOKED"


@router.post("/environments", status_code=201)
def environment(body: EnvironmentInput, a: Actor = Depends(actor)):
    require(a)
    with transaction(a.user_id, a.org_id) as session:
        return serialize(save_environment(session, a.org_id, body, a.user_id))


@router.post("/envelopes", status_code=201)
def envelope(body: EnvelopeInput, a: Actor = Depends(actor)):
    require(a, SECURITY)
    with transaction(a.user_id, a.org_id) as session:
        return serialize(save_envelope(session, a.org_id, body, a.user_id))


@router.post("/target-bindings", status_code=201)
def target_binding(body: TargetBindingInput, a: Actor = Depends(actor)):
    require(a, SECURITY)
    with transaction(a.user_id, a.org_id) as session:
        scoped(session, a.org_id, body.environment_id, "environment", body.system_id)
        scoped(session, a.org_id, body.target_id, "target", body.system_id)
        lock_system(session, a.org_id, body.system_id)
        return serialize(add_record(session, a.org_id, "environment_target_binding",
            {**body.model_dump(mode="json"), "reviewed_by": str(a.user_id),
             "authority_basis": "CUSTOMER_ACCEPTED", "running_deployment_identified": False},
            {"system": body.system_id, "environment": body.environment_id, "target": body.target_id}))


@router.post("/states", status_code=201)
def state(body: StateInput, a: Actor = Depends(actor)):
    require(a)
    with transaction(a.user_id, a.org_id) as session:
        return serialize(save_state(session, a.org_id, body, a.user_id))


@router.post("/transitions", status_code=201)
def transition(body: TransitionInput, a: Actor = Depends(actor)):
    require(a)
    with transaction(a.user_id, a.org_id) as session:
        return serialize(save_transition(session, a.org_id, body, a.user_id))


@router.post("/relationships", status_code=201)
def relationship(body: RelationshipInput, a: Actor = Depends(actor)):
    require(a, SECURITY)
    with transaction(a.user_id, a.org_id) as session:
        scoped(session, a.org_id, body.environment_id, "environment", body.system_id)
        for identifier in (body.source_id, body.target_id):
            row = get_record(session, a.org_id, identifier)
            if str(row.id) != str(body.system_id) and row.payload.get("system_id") != str(body.system_id):
                raise HTTPException(422, "Relationship endpoints must belong to this system")
            if row.payload.get("environment_id") not in (None, str(body.environment_id)):
                raise HTTPException(422, "Relationship endpoints must share an environment")
        if body.source_id == body.target_id:
            raise HTTPException(422, "A relationship cannot create self-authority")
        return serialize(add_record(session, a.org_id, "relationship_assertion",
            {**body.model_dump(mode="json"), "acquisition": "DECLARED",
             "authority_basis": "CUSTOMER_ACCEPTED", "reviewed_by": str(a.user_id),
             "grants_permissions": False, "positive_reuse_authority": False},
            {"system": body.system_id, "environment": body.environment_id,
             "source": body.source_id, "target": body.target_id}))


@router.get("/states/{identifier}/current")
def current(identifier: UUID, a: Actor = Depends(actor)):
    with transaction(a.user_id, a.org_id) as session:
        return projection(session, a.org_id, get_record(session, a.org_id, identifier, "system_state"))


class CaseInput(Versioned):
    state_id: UUID
    release_id: UUID
    audience: str = Field(min_length=3, max_length=200)
    expected_prior_epoch: int = Field(default=0, ge=0)
    request_nonce: str = Field(min_length=12, max_length=120)
    unknown_action: Literal["WARN", "BLOCK", "REQUIRE_APPROVAL"] = "REQUIRE_APPROVAL"


def clearance_status(session, org, row, *, current=None):
    """Whether a clearance still speaks for the system, recomputed now.

    This ignores the signed statement's own short lifetime, which `_decision_status`
    checks first. SUPERSEDED means the system was observed to change after issuance:
    a later observed state, or an observed source change that moved this
    clearance's support. REASSESS means support moved without an observed change
    (evidence, source continuity or release eligibility). EXPIRED means the reviewed
    authority or the exact-state observation it relied on has lapsed. The historical
    record is never altered.
    """
    value = row.payload
    events = history(session, org, "status_event", value["system_id"], value["environment_id"])
    if any(e.payload.get("authorization_id") == str(row.id) for e in events):
        return "REVOKED"
    transitions = history(session, org, "change_event", value["system_id"], value["environment_id"])
    if any(t.created_at > row.created_at and t.payload["transition"] == "OBSERVED"
           and t.payload["after_state_id"] != value["state_id"] for t in transitions):
        return "SUPERSEDED"
    state_row = get_record(session, org, value["state_id"], "system_state")
    if current is None or current.get("state_id") != str(state_row.id):
        current = projection(session, org, state_row)
    stamp = now()
    envelope_row = get_record(session, org, state_row.payload["envelope_id"], "permission_envelope")
    observed_until = state_row.payload.get("observation_expires_at")
    if datetime.fromisoformat(envelope_row.payload["expires_at"]) <= stamp or (
            observed_until and datetime.fromisoformat(observed_until) <= stamp):
        return "EXPIRED"
    if _support_digest(current) != value["support_digest"]:
        if any(datetime.fromisoformat(entry["recorded_at"]) > row.created_at
               for p in current["properties"] for entry in p.get("affected_by", [])):
            return "SUPERSEDED"
        return "REASSESS"
    release = get_record(session, org, value["release_id"], "release")
    if current_release_assessment(session, org, release)["underlying_action"] != "ALLOW" and value["action"] == "ALLOW":
        return "REASSESS"
    return "CURRENT"


def _decision_status(session, org, row, *, current=None):
    """A consumer must never act on a signed statement past its own lifetime."""
    if datetime.fromisoformat(row.payload["expires_at"]) <= now():
        return "EXPIRED"
    return clearance_status(session, org, row, current=current)


@router.post("/decisions", status_code=201)
def decide(body: CaseInput, a: Actor = Depends(actor)):
    require(a, SECURITY)
    with transaction(a.user_id, a.org_id) as session:
        state_row = get_record(session, a.org_id, body.state_id, "system_state")
        value = state_row.payload
        lock_system(session, a.org_id, value["system_id"])
        previous = history(session, a.org_id, "authorization_decision", value["system_id"], value["environment_id"])
        repeated = next((r for r in previous if r.payload["request_nonce"] == body.request_nonce), None)
        if repeated:
            if repeated.payload["request_digest"] != digest(body):
                raise HTTPException(409, "Authorization nonce already binds a different request")
            return serialize(repeated)
        release = scoped(session, a.org_id, body.release_id, "release", value["system_id"])
        if release.payload["candidate"] != value["candidate"] or release.payload["candidate_fingerprint_digest"] != value["fingerprint_digest"]:
            raise HTTPException(422, "Release belongs to a different candidate or operating configuration")
        current = projection(session, a.org_id, state_row)
        current["exception"] = _exception_status(session, a.org_id, release)
        active = current_release_assessment(session, a.org_id, release)
        ids = sorted(p["property_id"] for p in current["properties"])
        if ids != sorted(p["property_id"] for p in release.payload["properties"]):
            raise HTTPException(409, "Release omits a current approved property; obtain the complete decision")
        case = add_record(session, a.org_id, "assurance_case", {"schema_version": PROFILE,
            "system_id": value["system_id"], "environment_id": value["environment_id"],
            "state_id": str(state_row.id), "envelope_id": value["envelope_id"],
            "release_id": str(release.id), "approved_property_ids": ids, "projection": current,
            "assumptions": [value["coverage"]], "exceptions": release.payload["exceptions"],
            "policy": release.payload["policy"], "policy_digest": digest(release.payload["policy"])},
            {"system": value["system_id"], "environment": value["environment_id"],
             "state": state_row.id, "envelope": value["envelope_id"], "release": release.id})
        action = "ALLOW" if current["all_supported"] and active["underlying_action"] == "ALLOW" else (
            "BLOCK" if current["security"] == "FAIL" or current["legitimate_task"] == "FAILURE" else body.unknown_action)
        stamp = now()
        envelope_row = get_record(session, a.org_id, value["envelope_id"], "permission_envelope")
        expiry = min(stamp + timedelta(minutes=5), datetime.fromisoformat(envelope_row.payload["expires_at"]))
        if value.get("observation_expires_at"):
            expiry = min(expiry, datetime.fromisoformat(value["observation_expires_at"]))
        # An expired support set may produce an adverse record, never a live ALLOW.
        if expiry <= stamp:
            expiry = stamp + timedelta(seconds=1)
        identifier = uuid4()
        decision = {"schema_version": PROFILE, "signature_profile": "dsse-in-toto-ed25519/v1",
            "algorithm": "Ed25519", "issuer": "threatveil", "id": str(identifier),
            "organization_id": str(a.org_id), "system_id": value["system_id"],
            "environment_id": value["environment_id"], "state_id": str(state_row.id),
            "state_digest": value["state_digest"], "envelope_digest": value["envelope_digest"],
            "case_id": str(case.id), "case_digest": digest(case.payload), "release_id": str(release.id),
            "policy_digest": digest(release.payload["policy"]), "policy_epoch": envelope_row.payload["policy_epoch"],
            "support_digest": _support_digest(current),
            "audience": body.audience, "expected_prior_epoch": body.expected_prior_epoch,
            "request_nonce": body.request_nonce, "request_digest": digest(body), "action": action,
            "security": current["security"], "legitimate_task": current["legitimate_task"],
            "exception": current["exception"],
            "not_before": stamp.isoformat(), "expires_at": expiry.isoformat(),
            "status_uri": f"/v1/change-assurance/decisions/{identifier}",
            "limitations": current["limitations"] + ["This statement does not grant IAM permissions or prove enforcement."]}
        from .release_signing import signing_key
        from .sdk.change_records import sign_change_record
        receipt = sign_change_record(decision, signing_key())
        row = add_record(session, a.org_id, "authorization_decision", {**decision, "envelope": receipt},
            {"system": value["system_id"], "environment": value["environment_id"],
             "state": state_row.id, "case": case.id, "release": release.id}, record_id=identifier)
        audit(session, a.org_id, a.user_id, "change_assurance.decided", row.id)
        return serialize(row)


@router.get("/decisions/{identifier}")
def decision_detail(identifier: UUID, a: Actor = Depends(actor)):
    with transaction(a.user_id, a.org_id) as session:
        row = get_record(session, a.org_id, identifier, "authorization_decision")
        requests = history(session, a.org_id, "enforcement_request", row.payload["system_id"], row.payload["environment_id"])
        acknowledgements = history(session, a.org_id, "enforcement_acknowledgement", row.payload["system_id"], row.payload["environment_id"])
        ack = next((r for r in acknowledgements if r.payload["authorization_id"] == str(identifier)), None)
        requested = any(r.payload["authorization_id"] == str(identifier) for r in requests)
        return {**serialize(row), "current_status": _decision_status(session, a.org_id, row),
            "enforcement": ack.payload["status"] if ack else "REQUESTED" if requested else "NOT_REQUESTED",
            "acknowledgement": serialize(ack) if ack else None}


class EnforcementInput(Versioned):
    authorization_id: UUID
    environment_id: UUID
    state_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    audience: str = Field(min_length=3, max_length=200)
    expected_prior_epoch: int = Field(ge=0)
    request_nonce: str = Field(min_length=12, max_length=120)
    mechanism: Literal["synthetic_compare_and_set", "external_request"]


@router.post("/enforcement", status_code=201)
def enforce(body: EnforcementInput, a: Actor = Depends(actor)):
    require(a, SECURITY)
    with transaction(a.user_id, a.org_id) as session:
        row = get_record(session, a.org_id, body.authorization_id, "authorization_decision")
        value = row.payload
        lock_system(session, a.org_id, value["system_id"])
        if any(str(getattr(body, k)) != str(value[k]) for k in (
            "environment_id", "state_digest", "audience", "expected_prior_epoch", "request_nonce")):
            raise HTTPException(409, "Enforcement subject, audience, epoch or nonce differs from the signed decision")
        requests = history(session, a.org_id, "enforcement_request", value["system_id"], value["environment_id"])
        repeated = next((r for r in requests if r.payload["authorization_id"] == str(row.id)), None)
        if repeated:
            if repeated.payload["request_digest"] != digest(body):
                raise HTTPException(409, "Decision already requested through another enforcement mechanism")
            return serialize(repeated)
        if _decision_status(session, a.org_id, row) != "CURRENT" or value["action"] != "ALLOW":
            raise HTTPException(409, "Only a current exact ALLOW can request activation")
        from .sdk.change_records import verify_change_record
        from .release_signing import signing_key
        verify_change_record(value["envelope"], signing_key().public_key(), organization_id=a.org_id,
            system_id=value["system_id"], environment_id=body.environment_id,
            state_digest=body.state_digest, audience=body.audience, at=now())
        env = get_record(session, a.org_id, body.environment_id, "environment")
        if body.mechanism == "synthetic_compare_and_set":
            state_row = get_record(session, a.org_id, value["state_id"], "system_state")
            target = get_record(session, a.org_id, state_row.payload["target_id"], "target")
            if env.payload["purpose"] != "SANDBOX" or target.payload.get("fixture_profile") != "finance-v1":
                raise HTTPException(403, "Synthetic enforcement only operates the labeled finance sandbox")
        else:
            from .commercial import require_capability
            require_capability(session, a.org_id, "enforcement.production")
        acknowledged = history(session, a.org_id, "enforcement_acknowledgement", value["system_id"], value["environment_id"])
        epoch = acknowledged[0].payload["applied_epoch"] if acknowledged else 0
        if epoch != body.expected_prior_epoch:
            raise HTTPException(409, "Operating epoch changed before activation")
        request = add_record(session, a.org_id, "enforcement_request", {**body.model_dump(mode="json"),
            "system_id": value["system_id"], "status": "REQUESTED", "request_digest": digest(body),
            "delivery_status": "LOCAL" if body.mechanism == "synthetic_compare_and_set" else "AWAITING_QUALIFIED_ENFORCER"},
            {"system": value["system_id"], "environment": body.environment_id, "authorization": row.id})
        if body.mechanism == "synthetic_compare_and_set":
            add_record(session, a.org_id, "enforcement_acknowledgement", {
                "schema_version": PROFILE, "system_id": value["system_id"], "environment_id": value["environment_id"],
                "authorization_id": str(row.id), "request_id": str(request.id), "status": "ACKNOWLEDGED",
                "actual_state_digest": body.state_digest, "applied_epoch": epoch + 1,
                "audience": body.audience, "observed_at": now().isoformat(), "authority": "SYNTHETIC_LOCAL",
                "mechanism": body.mechanism, "limitations": ["Atomic activation of the local sandbox registry only; no external deployment was changed."]},
                {"system": value["system_id"], "environment": body.environment_id,
                 "request": request.id, "authorization": row.id})
        return serialize(request)


class StatusInput(Versioned):
    reason: str = Field(min_length=10, max_length=2000)


@router.post("/decisions/{identifier}/revoke", status_code=201)
def revoke(identifier: UUID, body: StatusInput, a: Actor = Depends(actor)):
    require(a, SECURITY)
    with transaction(a.user_id, a.org_id) as session:
        row = get_record(session, a.org_id, identifier, "authorization_decision")
        lock_system(session, a.org_id, row.payload["system_id"])
        return serialize(add_record(session, a.org_id, "status_event", {
            **body.model_dump(mode="json"), "system_id": row.payload["system_id"],
            "environment_id": row.payload["environment_id"], "authorization_id": str(row.id),
            "status": "REVOKED", "issuer": str(a.user_id)}, {"authorization": row.id}))


class AcceptanceInput(Versioned):
    authorization_id: UUID
    consumer: str = Field(min_length=1, max_length=200)
    verification_profile: str = Field(min_length=1, max_length=200)
    accepted: bool
    limitations: list[str] = Field(min_length=1, max_length=30)


@router.post("/consumer-acceptance", status_code=201)
def accept(body: AcceptanceInput, a: Actor = Depends(actor)):
    require(a)
    with transaction(a.user_id, a.org_id) as session:
        row = get_record(session, a.org_id, body.authorization_id, "authorization_decision")
        return serialize(add_record(session, a.org_id, "consumer_acceptance", {
            **body.model_dump(mode="json"), "system_id": row.payload["system_id"],
            "environment_id": row.payload["environment_id"], "record_digest": digest(row.payload["envelope"]),
            "recorded_by": str(a.user_id), "authority": "CUSTOMER_RECORDED_ACCEPTANCE",
            "independent_consumer_verified": False}, {"authorization": row.id}))


class FinanceSetup(Versioned):
    name: str = Field(default="Finance Agent", min_length=1, max_length=120)
    owner: str = Field(min_length=1, max_length=200)
    confirm_synthetic_scope: Literal[True]


@router.post("/finance/setup", status_code=201)
def finance_setup(body: FinanceSetup, a: Actor = Depends(actor)):
    require(a, SECURITY)
    from .commercial import require_system_capacity
    from .entitlements import require_property_capacity
    from .core.finance import finance_properties
    with transaction(a.user_id, a.org_id) as session:
        previous = session.scalar(select(Record).where(Record.organization_id == a.org_id,
            Record.kind == "finance_setup").order_by(Record.created_at.desc()).limit(1))
        if previous:
            return serialize(previous)
        require_system_capacity(session, a.org_id)
        system = add_record(session, a.org_id, "system", {"schema_version": PROFILE,
            "name": body.name, "description": "Synthetic finance workflow with tenant-bound committed SQL effects.",
            "owner": body.owner, "access": ["synthetic invoices", "synthetic beneficiaries"],
            "actions": ["beneficiary.update", "invoice.update"], "fingerprint": {"components": []},
            "fixture_profile": "finance-v1", "demo": True})
        env = save_environment(session, a.org_id, EnvironmentInput(system_id=system.id,
            name="Finance sandbox", purpose="SANDBOX", owner=body.owner,
            boundary="Isolated synthetic tenant A and B records; no real money or customer system"), a.user_id)
        authority = save_envelope(session, a.org_id, EnvelopeInput(system_id=system.id,
            environment_id=env.id, principals=["synthetic-tenant-a/finance-agent"],
            actions=["beneficiary.update", "invoice.update"],
            resources=["synthetic-tenant-a/vendor-1", "synthetic-tenant-a/invoice-1"],
            constraints=["Finance approval required for beneficiary changes", "Tenant A resources only",
                         "Authorized invoice updates must remain useful"],
            expires_at=now()+timedelta(days=30)), a.user_id)
        target = add_record(session, a.org_id, "target", {"system_id": str(system.id),
            "name": "Synthetic finance SQL ledger", "adapter": "synthetic_procurement",
            "fixture_profile": "finance-v1", "execution_class": "DIGITAL_SANDBOX",
            "authorization_note": "Explicit synthetic finance fixture; isolated local rows only",
            "credential_reference_ids": []}, {"system": system.id})
        session.add(TargetState(organization_id=a.org_id, target_id=target.id,
            challenge_hash=digest(str(uuid4())), verified_at=now(), expires_at=now()+timedelta(days=30)))
        add_record(session, a.org_id, "environment_target_binding", {"schema_version": PROFILE,
            "system_id": str(system.id), "environment_id": str(env.id), "target_id": str(target.id),
            "reviewed_by": str(a.user_id), "review_note": "Owner accepted the explicit synthetic package boundary",
            "authority_basis": "SYNTHETIC_PACKAGE", "running_deployment_identified": False},
            {"system": system.id, "environment": env.id, "target": target.id})
        properties = []
        for definition in finance_properties():
            require_property_capacity(session, a.org_id)
            prop = add_record(session, a.org_id, "property", {"system_id": str(system.id),
                "title": definition["title"], "description": definition["description"],
                "definition": definition, "approved": True, "version": 1, "demo": True}, {"system": system.id})
            add_record(session, a.org_id, "binding", {"system_id": str(system.id),
                "property_id": str(prop.id), "approved_by": str(a.user_id), "demo": True},
                {"system": system.id, "property": prop.id})
            properties.append(str(prop.id))
        gateway = _install_synthetic_gateway(session, a.org_id, a.user_id, system.id, env.id)
        result = add_record(session, a.org_id, "finance_setup", {"schema_version": PROFILE,
            "system_id": str(system.id), "environment_id": str(env.id), "envelope_id": str(authority.id),
            "target_id": str(target.id), "property_ids": properties, "owner": body.owner,
            "gateway_installation_id": str(gateway.id),
            "scope": "Synthetic SQL finance package; no external connection or deployment claimed",
            "confirmed_by": str(a.user_id)}, {"system": system.id, "environment": env.id, "envelope": authority.id,
                                              "target": target.id, "gateway": gateway.id})
        audit(session, a.org_id, a.user_id, "onboarding.boundary_confirmed", system.id)
        return serialize(result)


GATEWAY_NAME = "Finance tool gateway (synthetic MCP)"
GATEWAY_BASELINE = {"beneficiary.update": {"approval_required": True, "tenant_bound": True},
                    "invoice.update": {"approval_required": False, "tenant_bound": True}}
GATEWAY_TOOLS = {"beneficiary.update": "Update a synthetic vendor's payment beneficiary",
                 "invoice.update": "Update a synthetic invoice status",
                 "payment.execute": "Execute a synthetic payment run"}


def gateway_payload(authorization):
    """The labelled synthetic tool gateway's declared catalog. Never a customer system."""
    return {"protocol_version": "2026-07-28", "supported_versions": ["2026-07-28", "2025-11-25"],
            "complete": True, "server_info": {"name": "synthetic-finance-tool-gateway", "version": "1"},
            "tools": [{"name": name, "description": GATEWAY_TOOLS.get(name, name),
                       "inputSchema": {"type": "object"}} for name in sorted(authorization)],
            "authorization": {"tools": authorization}}


def _gateway_authorization(facts):
    from .source_semantics import split_pointer

    rebuilt = {}
    for path, value in (facts.get("authorization") or {}).items():
        parts = split_pointer(path)
        if len(parts) == 4 and parts[:2] == ["authorization", "tools"]:
            rebuilt.setdefault(parts[2], {})[parts[3]] = value
    return rebuilt or deepcopy(GATEWAY_BASELINE)


def _install_synthetic_gateway(session, org, user, system_id, environment_id):
    """Connect the synthetic package's tool gateway and its package-reviewed mappings.

    It is an IMPORT source: never presented as a live connection. The mappings are
    labelled SYNTHETIC_PACKAGE and name exactly which gateway facts correspond to
    which claim dependencies, so a later gateway change reaches only those claims.
    """
    from .change_assurance import save_mapping
    from .connectors import create_installation, ingest
    from .connectors.contracts import BatchInput
    from .integrations.intake import component_id
    from .source_semantics import pointer

    installation = create_installation(
        session, org, user, system_id=system_id, environment_id=environment_id, connector_id="mcp",
        mode="IMPORT", roles=["DISCOVER", "CHANGE"], values={}, credential_id=None,
        expires_at=now() + timedelta(days=90), name=GATEWAY_NAME)
    ingest(session, org, user, installation.id, BatchInput(
        event_id=f"finance-gateway:{installation.id}:1", payload=gateway_payload(deepcopy(GATEWAY_BASELINE)),
        valid_at=now(), sequence=1))
    identity = installation.payload["source_identity"]
    mappings = [
        (pointer("authorization", "tools", "beneficiary.update", "approval_required"), ["permissions:finance-approval"]),
        (pointer("authorization", "tools", "beneficiary.update", "tenant_bound"), ["permissions:tenant-boundary"]),
        (pointer("authorization", "tools", "invoice.update", "approval_required"), ["permissions:invoice-update"]),
        (pointer("authorization", "tools", "invoice.update", "tenant_bound"), ["permissions:tenant-boundary"]),
        ("tool:" + component_id(f"{identity}:beneficiary.update"), ["tool:erp.beneficiary"]),
        ("tool:" + component_id(f"{identity}:invoice.update"), ["tool:erp.invoice"]),
    ]
    for subject, targets in mappings:
        save_mapping(session, org, user, system_id=system_id, environment_id=environment_id,
                     installation_id=installation.id, subject=subject, maps_to=targets,
                     review_note="Synthetic finance package: reviewed correspondence between a gateway fact "
                                 "and the claim dependency it controls",
                     authority_basis="SYNTHETIC_PACKAGE")
    return installation


class FinanceChange(Versioned):
    system_id: UUID
    change: Literal["beneficiary_approval_relaxed", "invoice_tenant_binding_removed",
                    "payment_tool_added", "gateway_restored"]
    idempotency_key: str = Field(min_length=12, max_length=80)


@router.post("/finance/simulate-change", status_code=201)
def finance_simulate_change(body: FinanceChange, a: Actor = Depends(actor)):
    """Change the labelled synthetic tool gateway, outside any repository.

    Only the finance-v1 sandbox is reachable and only these enumerated changes exist.
    Nothing here accepts a payload, addresses a customer system or records evidence:
    it produces an imported source observation the assurance engine must interpret.
    """
    require(a, SECURITY)
    from .connectors import ingest, previous_batch
    from .connectors.contracts import BatchInput

    with transaction(a.user_id, a.org_id) as session:
        system = get_record(session, a.org_id, body.system_id, "system")
        if system.payload.get("fixture_profile") != "finance-v1":
            raise HTTPException(422, "This action requires the explicitly approved finance fixture")
        lock_system(session, a.org_id, system.id)
        earlier = next((r for r in history(session, a.org_id, "finance_change", system.id)
                        if r.payload["idempotency_key"] == body.idempotency_key), None)
        if earlier:
            if earlier.payload["change"] != body.change:
                raise HTTPException(409, "Change key already binds another synthetic change")
            return serialize(earlier)
        setup = history(session, a.org_id, "finance_setup", system.id)[0].payload
        environment = get_record(session, a.org_id, setup["environment_id"], "environment")
        if environment.payload["purpose"] != "SANDBOX":
            raise HTTPException(403, "Synthetic changes only operate the labelled finance sandbox")
        installation_id = setup.get("gateway_installation_id") or next(
            (str(r.id) for r in history(session, a.org_id, "connector_installation", system.id, environment.id)
             if r.payload["name"] == GATEWAY_NAME), None)
        if installation_id is None:
            installation_id = str(_install_synthetic_gateway(session, a.org_id, a.user_id, system.id, environment.id).id)
        prior = previous_batch(session, a.org_id, installation_id)
        authorization = _gateway_authorization((prior.payload.get("facts") or {}) if prior else {})
        if body.change == "beneficiary_approval_relaxed":
            authorization.setdefault("beneficiary.update", {})["approval_required"] = False
        elif body.change == "invoice_tenant_binding_removed":
            authorization.setdefault("invoice.update", {})["tenant_bound"] = False
        elif body.change == "payment_tool_added":
            authorization["payment.execute"] = {"approval_required": True, "tenant_bound": True}
        else:
            authorization = deepcopy(GATEWAY_BASELINE)
        sequence = ((prior.payload.get("sequence") or 0) + 1) if prior else 1
        batch = ingest(session, a.org_id, a.user_id, UUID(installation_id), BatchInput(
            event_id=f"finance-change:{body.idempotency_key}", payload=gateway_payload(authorization),
            valid_at=now(), sequence=sequence))
        change = session.scalar(select(Record).where(
            Record.organization_id == a.org_id, Record.kind == "source_change",
            Record.payload["batch_id"].astext == str(batch.id)))
        record = add_record(session, a.org_id, "finance_change", {
            "schema_version": PROFILE, "system_id": str(system.id), "environment_id": str(environment.id),
            "change": body.change, "idempotency_key": body.idempotency_key, "batch_id": str(batch.id),
            "change_id": str(change.id) if change else None, "installation_id": installation_id,
            "limitations": ["Synthetic gateway configuration only; no customer system, provider or money involved.",
                            "The observation is IMPORTED and UNREVIEWED; it carries no evidence of behavior."]},
            {"system": system.id, "batch": batch.id})
        audit(session, a.org_id, a.user_id, "finance.synthetic_change", record.id)
        return serialize(record)


class FinanceAssessment(Versioned):
    system_id: UUID
    version: Literal["fixed", "regressed", "bad_fix", "missing_witness"] = "fixed"
    idempotency_key: str = Field(min_length=12, max_length=80)


@router.post("/finance/assess", status_code=201)
def finance_assess(body: FinanceAssessment, response: Response, a: Actor = Depends(actor)):
    """Sandbox assessment, hosted-capable.

    Execution always goes through the ordinary run path, so the hosted deployment
    keeps its broker/worker isolation: the API process never executes a fixture.
    Because the worker is asynchronous, this endpoint is resumable — call it again
    with the same idempotency key until it returns the completed assessment.
    """
    require(a, SECURITY)
    # Serialize this workflow independently of the kernel's system locks.
    # Nested run transactions retain their normal locking and immutable receipts.
    with transaction(a.user_id, a.org_id) as guard:
        guard.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
                      {"key": f"finance-assessment:{a.org_id}:{body.system_id}"})
        return _finance_assess(body, a, response)


def _api_executes_runs() -> bool:
    """Only local development executes verification inside the API process.

    A deployed environment dispatches to the isolated worker instead. That
    boundary is why this workflow is asynchronous rather than one-click.
    """
    from .config import settings

    return settings().is_local


def _pending_runs(session, org_id, run_ids):
    """A run contributes evidence only once it has settled with a persisted result."""
    pending = []
    for identifier in run_ids:
        state = session.get(RunState, (org_id, UUID(identifier)))
        if state is None or not state.settled or state.result_id is None:
            pending.append({"run_id": identifier, "status": state.status if state else "UNKNOWN"})
    return pending


def _finance_assess(body: FinanceAssessment, a: Actor, response: Response):
    from fastapi import BackgroundTasks
    from .api import create_run, execute_run, run_detail
    from .schemas import RunInput
    from .release_integrity import create_plan, create_release, PlanInput, ReleaseInput, ReleasePolicy
    with transaction(a.user_id, a.org_id) as session:
        system = get_record(session, a.org_id, body.system_id, "system")
        if system.payload.get("fixture_profile") != "finance-v1":
            raise HTTPException(422, "This action requires the explicitly approved finance fixture")
        setup = dict(history(session, a.org_id, "finance_setup", system.id)[0].payload)
        setup["envelope_id"] = str(history(session, a.org_id, "permission_envelope", system.id, setup["environment_id"])[0].id)
        existing = next((r for r in history(session, a.org_id, "finance_assessment", system.id)
                         if r.payload["idempotency_key"] == body.idempotency_key), None)
        if existing:
            if existing.payload["version"] != body.version:
                raise HTTPException(409, "Assessment key already binds another operating configuration")
            return serialize(existing)
        prior = history(session, a.org_id, "system_state", system.id, setup["environment_id"])
        prior_id = prior[0].id if prior else None
    with transaction(a.user_id, a.org_id) as session:
        checkpoint = next((r for r in history(session, a.org_id, "finance_assessment_prepared", body.system_id)
                           if r.payload["idempotency_key"] == body.idempotency_key), None)
        prepared = checkpoint.payload if checkpoint else None
        if prepared and prepared["version"] != body.version:
            raise HTTPException(409, "Assessment key already binds another operating configuration")
        dispatched = next((r.payload for r in history(session, a.org_id, "finance_assessment_dispatched", body.system_id)
                           if r.payload["idempotency_key"] == body.idempotency_key), None)
        if dispatched and dispatched["version"] != body.version:
            raise HTTPException(409, "Assessment key already binds another operating configuration")
    if prepared is None:
        if dispatched is None:
            # One run per approved claim, through the ordinary authorized run path.
            run_ids = []
            for index, pid in enumerate(setup["property_ids"]):
                created = create_run(RunInput(system_id=body.system_id, property_id=pid, target_id=setup["target_id"],
                    version=body.version, trials=2, variant_count=1,
                    idempotency_key=f"{body.idempotency_key}:{index}"), BackgroundTasks(), a)
                run_ids.append(str(created["id"]))
                if _api_executes_runs():
                    # Local development has no separate worker process.
                    execute_run(a.org_id, UUID(created["id"]))
            with transaction(a.user_id, a.org_id) as session:
                dispatched = add_record(session, a.org_id, "finance_assessment_dispatched", {
                    "schema_version": PROFILE, "system_id": str(body.system_id),
                    "environment_id": setup["environment_id"], "version": body.version,
                    "idempotency_key": body.idempotency_key, "run_ids": run_ids,
                }, {"system": body.system_id}).payload
        run_ids = dispatched["run_ids"]
        with transaction(a.user_id, a.org_id) as session:
            pending = _pending_runs(session, a.org_id, run_ids)
        if pending:
            # Nothing is concluded from an unfinished execution.
            response.status_code = 202
            return {"schema_version": PROFILE, "system_id": str(body.system_id),
                    "environment_id": setup["environment_id"], "version": body.version,
                    "idempotency_key": body.idempotency_key, "status": "RUNNING",
                    "run_ids": run_ids, "pending": pending,
                    "next_action": "Verification is running. Request this assessment again with the "
                                   "same idempotency key to read the completed decision.",
                    "limitations": ["An unfinished run establishes no security conclusion."]}
        runs = [run_detail(UUID(identifier), a) for identifier in run_ids]
        first = runs[0]
        plan = create_plan(PlanInput(system_id=body.system_id, candidate=first["candidate"],
            fingerprint=first["fingerprint"], trials_per_variant=2), a)
        released = create_release(ReleaseInput(plan_id=plan["id"], policy=ReleasePolicy(mode="WARN")), a)
        with transaction(a.user_id, a.org_id) as session:
            lock_system(session, a.org_id, body.system_id)
            evidence = next(r for r in history(session, a.org_id, "evidence_record", body.system_id)
                            if r.payload["run_id"] == first["id"])
            state_row = save_state(session, a.org_id, StateInput(system_id=body.system_id,
                environment_id=setup["environment_id"], envelope_id=setup["envelope_id"],
                candidate=first["candidate"], fingerprint=first["fingerprint"], evidence_id=evidence.id,
                coverage="Three synthetic finance claims, explicit tenant rows and paired useful invoice action"), a.user_id)
            transition_row = save_transition(session, a.org_id, TransitionInput(system_id=body.system_id,
                environment_id=setup["environment_id"], before_state_id=prior_id, after_state_id=state_row.id,
                transition="OBSERVED", change_type="APPROVAL_POLICY_CHANGED" if body.version == "regressed" else "CONFIGURATION_CHANGED",
                reason="Synthetic operating policy changed outside any repository or GitHub integration"), a.user_id)
            values = {"state_id": str(state_row.id), "transition_id": str(transition_row.id)}
            acknowledgements = history(session, a.org_id, "enforcement_acknowledgement", body.system_id, setup["environment_id"])
            prior_epoch = acknowledgements[0].payload["applied_epoch"] if acknowledgements else 0
            prepared = add_record(session, a.org_id, "finance_assessment_prepared", {
                "system_id": str(body.system_id), "environment_id": setup["environment_id"],
                "idempotency_key": body.idempotency_key, "version": body.version,
                "run_ids": [r["id"] for r in runs], "plan_id": plan["id"], "release_id": released["id"],
                "expected_prior_epoch": prior_epoch, **values}, {"system": body.system_id}).payload
    authorization = decide(CaseInput(state_id=prepared["state_id"], release_id=prepared["release_id"],
        audience="synthetic-finance-activation", expected_prior_epoch=prepared["expected_prior_epoch"],
        request_nonce=body.idempotency_key, unknown_action="REQUIRE_APPROVAL"), a)
    with transaction(a.user_id, a.org_id) as session:
        record = add_record(session, a.org_id, "finance_assessment", {"schema_version": PROFILE,
            "system_id": str(body.system_id), "environment_id": setup["environment_id"],
            "version": body.version, "idempotency_key": body.idempotency_key,
            "run_ids": prepared["run_ids"], "plan_id": prepared["plan_id"], "release_id": prepared["release_id"],
            "authorization_id": authorization["id"], "action": authorization["action"],
            "security": authorization["security"], "legitimate_task": authorization["legitimate_task"],
            "state_id": prepared["state_id"], "transition_id": prepared["transition_id"]},
            {"system": body.system_id, "environment": setup["environment_id"],
                "authorization": authorization["id"], "state": prepared["state_id"]})
        return serialize(record)


@router.get("/systems/{system_id}")
def journey(system_id: UUID, a: Actor = Depends(actor)):
    with transaction(a.user_id, a.org_id) as session:
        system = get_record(session, a.org_id, system_id, "system")
        environments = history(session, a.org_id, "environment", system_id)
        result = []
        for environment in environments:
            eid = environment.id
            states = history(session, a.org_id, "system_state", system_id, eid)
            decisions = history(session, a.org_id, "authorization_decision", system_id, eid)
            acknowledgements = history(session, a.org_id, "enforcement_acknowledgement", system_id, eid)
            current = projection(session, a.org_id, states[0]) if states else None
            from .connectors import source_health
            sources = source_health(session, a.org_id, system_id, eid)
            stage = "CONNECTED" if any(s["connected"] for s in sources) else "DECLARED"
            if current and states[0].payload["provenance"] == "QUALIFIED_TEST_EXECUTION":
                stage = "OBSERVED"
            latest_decision = decisions[0] if decisions else None
            if current and latest_decision:
                linked_release = get_record(session, a.org_id, latest_decision.payload["release_id"], "release")
                current["exception"] = _exception_status(session, a.org_id, linked_release)
            decision_status = _decision_status(session, a.org_id, latest_decision) if latest_decision else None
            ack = next((r for r in acknowledgements if latest_decision and r.payload["authorization_id"] == str(latest_decision.id)), None)
            requests = history(session, a.org_id, "enforcement_request", system_id, eid)
            requested = next((r for r in requests if latest_decision and r.payload["authorization_id"] == str(latest_decision.id)), None)
            if (current and current["all_supported"] and latest_decision and ack
                and latest_decision.payload["state_id"] == current["state_id"]
                and latest_decision.payload["state_digest"] == current["state_digest"]
                and ack.payload["actual_state_digest"] == current["state_digest"]
                and decision_status == "CURRENT"):
                stage = "PROTECTED"
            envelopes = history(session, a.org_id, "permission_envelope", system_id, eid)
            result.append({"environment": serialize(environment), "stage": stage,
                "envelope": serialize(envelopes[0]) if envelopes else None,
                "current": current, "state": serialize(states[0]) if states else None,
                "sources": sources, "decision": {**serialize(latest_decision), "current_status": decision_status} if latest_decision else None,
                "enforcement": ack.payload["status"] if ack else "REQUESTED" if requested else "NOT_REQUESTED",
                "transitions": [serialize(r) for r in history(session, a.org_id, "change_event", system_id, eid)[:30]],
                "limitations": ["Protected refers only to this accepted workflow and boundary.",
                    "Synthetic protection is not a customer or cloud acceptance result."]})
        return {"system": serialize(system), "environments": result,
            "properties": [serialize(p) for p in _properties(session, a.org_id, system_id)],
            "assessments": [serialize(r) for r in history(session, a.org_id, "finance_assessment", system_id)[:30]],
            "next_action": "Define an environment and business boundary" if not environments else
                "Review properties and establish the baseline" if not any(r["current"] for r in result) else
                "Inspect the current decision and enforcement acknowledgement"}
