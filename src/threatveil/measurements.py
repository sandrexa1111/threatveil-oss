"""Tenant operational measurements and explicit, independent data-use consent.

No raw evidence, prompts, resource names, exception strings or request bodies enter
measurement records. Optional usage reports never become assurance authorities.
"""

from collections import Counter
from typing import Literal
from uuid import UUID, uuid5

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import func, select

from .auth import Actor, OWNERS, actor, require
from .db import Account, Record, add_record, get_record, now, transaction

router = APIRouter(prefix="/v1/measurements", tags=["measurements"])
CONSENT_DEFAULT = {"product_analytics": False, "research": False, "cross_customer_learning": False}


class QuotaExceeded(HTTPException):
    def __init__(self, resource, used, limit, org_id, plan):
        self.measurement = {"organization_id": org_id, "resource": resource,
                            "used": used, "limit": limit, "plan": plan}
        super().__init__(402, {"code": "entitlement_limit", "resource": resource,
            "used": used, "limit": limit, "upgrade_url": "/app/billing",
            "message": "Plan allowance reached. Existing records and security conclusions are retained."})


def quota_exception_handler(request: Request, error: QuotaExceeded):
    """Runs after the denied operation rolls back, never while its account is locked."""
    values = error.measurement
    try:
        with transaction(org_id=values["organization_id"]) as session:
            from .commercial import catalog

            known = {p.id for p in catalog().plans} | {"pilot", "starter", "growth", "unassigned"}
            add_record(session, values["organization_id"], "service_metric", {
                "schema_version": "service-metric-v1", "name": "quota.reached",
                "plan": values["plan"] if values["plan"] in known else "custom",
                "resource": values["resource"], "used": values["used"], "limit": values["limit"],
                "source": "SERVER_ENFORCED", "data_class": "SERVICE_OPERATION",
                "request_id": request.scope.get("tv_request_id"),
            })
    except Exception:
        # Loss of optional accounting must not allow the rejected operation or
        # log sensitive exception text. The normal 402 response is preserved.
        from .observability import event

        event("measurement.persist_failed", "WARNING")
    return JSONResponse(status_code=402, content={"detail": error.detail})


class Consent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    product_analytics: bool = False
    research: bool = False
    cross_customer_learning: bool = False
    contract_reference: str | None = Field(default=None, max_length=120)

    @model_validator(mode="after")
    def explicit_rights(self):
        if (self.research or self.cross_customer_learning) and not (self.contract_reference or "").strip():
            raise ValueError("Research and cross-customer permission require an explicit contract reference")
        return self


def consent(session, org_id):
    row = session.scalar(select(Record).where(Record.organization_id == org_id,
                         Record.kind == "measurement_consent")
                         .order_by(Record.created_at.desc(), Record.id.desc()).limit(1))
    return {**CONSENT_DEFAULT, **(row.payload if row else {}),
            "service_operation": True, "research_pipeline_enabled": False,
            "cross_customer_pipeline_enabled": False, "training_pipeline_enabled": False}


@router.get("/consent")
def get_consent(a: Actor = Depends(actor)):
    with transaction(a.user_id, a.org_id) as session:
        return consent(session, a.org_id)


@router.post("/consent", status_code=201)
def set_consent(body: Consent, a: Actor = Depends(actor)):
    require(a, OWNERS)
    with transaction(a.user_id, a.org_id) as session:
        session.get(Account, a.org_id, with_for_update=True)
        add_record(session, a.org_id, "measurement_consent", {
            **body.model_dump(), "schema_version": "measurement-consent-v1",
            "approved_by": str(a.user_id), "recorded_at": now().isoformat(),
        })
        return consent(session, a.org_id)


class ProductMeasurement(BaseModel):
    model_config = ConfigDict(extra="forbid")
    idempotency_key: str = Field(min_length=8, max_length=120)
    name: Literal["onboarding.started", "onboarding.step_completed", "upgrade.requested",
                  "decision.used", "support.work_recorded", "verification.cost_recorded"]
    feature: Literal["protected_systems", "environments", "verification", "retention",
                     "automation", "collaboration", "governance", "observers", "other"] = "other"
    connector: Literal["github", "mcp", "otel", "gcp_cloud_run", "openai_agents",
                       "anthropic_hooks", "cyclonedx", "sarif", "none"] = "none"
    stage: Literal["connect", "define", "protect", "baseline", "watch", "decide", "none"] = "none"
    action: Literal["ALLOW", "WARN", "BLOCK", "REQUIRE_APPROVAL", "NONE"] = "NONE"
    system_id: UUID | None = None
    minutes: int | None = Field(default=None, ge=0, le=100000)
    cost_microusd: int | None = Field(default=None, ge=0, le=1000000000000)


@router.post("/events", status_code=201)
def product_measurement(body: ProductMeasurement, a: Actor = Depends(actor)):
    require(a)
    if body.name in {"support.work_recorded", "verification.cost_recorded"}:
        require(a, OWNERS)
    with transaction(a.user_id, a.org_id) as session:
        # Serialize consent revocation with optional collection; a prior opt-in
        # cannot authorize events after an owner's revocation commits.
        account = session.get(Account, a.org_id, with_for_update=True)
        if not consent(session, a.org_id)["product_analytics"]:
            raise HTTPException(409, "Optional product analytics is not enabled for this organization")
        if body.system_id:
            get_record(session, a.org_id, body.system_id, "system")
        identifier = uuid5(a.org_id, "product-measurement:" + body.idempotency_key)
        request_data = body.model_dump(mode="json")
        existing = session.get(Record, identifier)
        if existing:
            if existing.payload["measurement"] != request_data:
                raise HTTPException(409, "Measurement idempotency key binds different data")
            return {"id": str(existing.id), "duplicate": True}
        from .commercial import catalog

        known = {p.id for p in catalog().plans} | {"pilot", "starter", "growth", "unassigned"}
        row = add_record(session, a.org_id, "product_metric", {
            "schema_version": "product-metric-v1", "measurement": request_data,
            "plan": account.plan if account.plan in known else "custom",
            "data_class": "OPTIONAL_PRODUCT_ANALYTICS", "source": "CUSTOMER_REPORTED",
            "assurance_authority": False,
        }, record_id=identifier)
        return {"id": str(row.id), "accepted": True, "assurance_authority": False}


def _number(value):
    try:
        result = int(value)
        return max(0, result)
    except (TypeError, ValueError):
        return 0


def _distribution(session, org, kind, expression, allowed):
    counts = Counter()
    for value, count in session.execute(select(expression, func.count()).where(
            Record.organization_id == org, Record.kind == kind).group_by(expression)):
        counts[value if value in allowed else "UNKNOWN"] += count
    return dict(counts)


def summary(session, org):
    """Aggregates service records in-tenant; names/evidence/record bodies are omitted."""
    counts = dict(session.execute(select(Record.kind, func.count()).where(
        Record.organization_id == org).group_by(Record.kind)).all())
    result_values = session.execute(select(Record.payload["usage"]["units"].as_string(),
        Record.payload["duration_ms"].as_string()).where(Record.organization_id == org,
        Record.kind == "result"))
    units, duration_ms = 0, 0
    for units_value, duration_value in result_values:
        units += _number(units_value)
        duration_ms += _number(duration_value)
    system_created = dict(session.execute(select(Record.id, Record.created_at).where(
        Record.organization_id == org, Record.kind == "system")).all())
    case_system = Record.payload["system_id"].as_string()
    first_supported = session.execute(select(case_system,
        func.min(Record.created_at)).where(Record.organization_id == org,
        Record.kind == "assurance_case", Record.payload["projection"]["all_supported"].as_string() == "true")
        .group_by(case_system))
    elapsed = []
    for identifier, stamp in first_supported:
        created = system_created.get(UUID(identifier))
        if created:
            elapsed.append(max(0, round((stamp - created).total_seconds())))
    quota = []
    expressions = (Record.payload["plan"].as_string(), Record.payload["resource"].as_string())
    for plan, resource, count in session.execute(select(*expressions, func.count()).where(
            Record.organization_id == org, Record.kind == "service_metric",
            Record.payload["name"].as_string() == "quota.reached").group_by(*expressions)):
        quota.append({"plan": plan, "resource": resource, "count": count})
    optional = Counter()
    upgrade_features = Counter()
    reported_minutes, reported_cost = 0, 0
    for payload in session.scalars(select(Record.payload["measurement"]).where(
            Record.organization_id == org, Record.kind == "product_metric")):
        optional[payload["name"]] += 1
        if payload["name"] == "upgrade.requested":
            upgrade_features[payload["feature"]] += 1
        if payload["name"] == "support.work_recorded":
            reported_minutes += _number(payload.get("minutes"))
        if payload["name"] == "verification.cost_recorded":
            reported_cost += _number(payload.get("cost_microusd"))
    # Use the current semantic evaluator, never an onboarding checkbox or user
    # analytics event, to count supported operating boundaries.
    from .change_assurance import projection, history
    from .change_assurance_api import _decision_status

    state_system = Record.payload["system_id"].as_string()
    state_environment = Record.payload["environment_id"].as_string()
    latest_states = (select(Record).where(Record.organization_id == org, Record.kind == "system_state")
                     .distinct(state_system, state_environment)
                     .order_by(state_system, state_environment, Record.created_at.desc(), Record.id.desc()))
    total_boundaries = session.scalar(select(func.count()).select_from(latest_states.subquery())) or 0
    rows = list(session.scalars(latest_states.limit(1000)))
    support = Counter()
    applicability = Counter()
    source_blockers = Counter()
    supported_real, supported_synthetic = set(), set()
    protected_real, protected_synthetic = set(), set()
    for row in rows:
        current = projection(session, org, row)
        support["supported" if current["all_supported"] else "requires_review"] += 1
        for prop in current["properties"]:
            applicability[prop["applicability"]] += 1
        for source in current["source_health"]:
            if source.get("freshness") != "CURRENT" and source.get("status") != "IMPORTED":
                source_blockers[source.get("connector_id", "unknown")] += 1
        if current["all_supported"]:
            system = get_record(session, org, current["system_id"], "system")
            synthetic = bool(system.payload.get("demo") or system.payload.get("fixture_profile"))
            (supported_synthetic if synthetic
             else supported_real).add(str(system.id))
            decisions = history(session, org, "authorization_decision", system.id, current["environment_id"])
            latest = decisions[0] if decisions else None
            acks = history(session, org, "enforcement_acknowledgement", system.id, current["environment_id"])
            if (latest and latest.payload["action"] == "ALLOW"
                and latest.payload["state_id"] == str(row.id)
                and latest.payload["state_digest"] == current["state_digest"]
                and _decision_status(session, org, latest) == "CURRENT"
                and any(ack.payload["authorization_id"] == str(latest.id)
                        and ack.payload["status"] == "ACKNOWLEDGED"
                        and ack.payload["actual_state_digest"] == current["state_digest"] for ack in acks)):
                (protected_synthetic if synthetic else protected_real).add(str(system.id))
    return {
        "schema_version": "measurements-v1", "as_of": now().isoformat(),
        "data_scope": "TENANT_SERVICE_OPERATION", "consent": consent(session, org),
        "systems": {"registered": counts.get("system", 0), "second_system_added": counts.get("system", 0) >= 2,
                    "currently_supported_customer_systems": len(supported_real),
                    "currently_supported_synthetic_systems": len(supported_synthetic),
                    "currently_protected_customer_systems": len(protected_real),
                    "currently_protected_synthetic_systems": len(protected_synthetic)},
        "current_assurance": {"boundaries_scanned": len(rows), "total_boundaries": total_boundaries,
            "complete": len(rows) == total_boundaries, "boundary_support": dict(support),
            "property_applicability": dict(applicability), "connector_blockers": dict(source_blockers)},
        "changes": {"canonical_transitions": counts.get("change_event", 0),
                    "source_changes": counts.get("source_change", 0),
                    "release_comparisons": counts.get("change_set", 0)},
        "onboarding": {"systems_with_a_first_supported_case": len(elapsed),
            "registration_to_first_supported_case_seconds": {
                "minimum": min(elapsed) if elapsed else None,
                "mean": round(sum(elapsed) / len(elapsed)) if elapsed else None},
            "basis": "Historical first supported assurance case after system registration, including synthetic scopes; not current protection."},
        "verification": {"requested_runs": counts.get("run", 0), "result_records": counts.get("result", 0),
            "consumed_execution_units": units, "recorded_duration_ms": duration_ms,
            "security": _distribution(session, org, "result", Record.payload["security_verdict"].as_string(), {"PASS", "FAIL", "INCONCLUSIVE"}),
            "legitimate_task": _distribution(session, org, "result", Record.payload["task_outcome"].as_string(), {"SUCCESS", "FAILURE", "UNKNOWN"})},
        "decisions": {"authorization_actions": _distribution(session, org, "authorization_decision",
            Record.payload["action"].as_string(), {"ALLOW", "WARN", "BLOCK", "REQUIRE_APPROVAL"}),
            "enforcement_requests": counts.get("enforcement_request", 0),
            "enforcement_acknowledgements": counts.get("enforcement_acknowledgement", 0),
            "consumer_acceptances": counts.get("consumer_acceptance", 0)},
        "commercial": {"limit_events": quota, "billing_events": counts.get("billing_event", 0),
                       "reported_upgrade_features": dict(upgrade_features)},
        "optional_reports": {"counts": dict(optional), "reported_support_minutes": reported_minutes,
                             "reported_verification_cost_microusd": reported_cost},
        "limitations": ["Supported means current bounded evidence under the semantic evaluator; synthetic systems are separate.",
            "A decision record or optional reported use is not proof of a customer's external decision.",
            "Optional support and cost reports are self-reported, not provider invoices or measured labor.",
            "No cross-customer export, research processing or model training pipeline is enabled.",
            "Current-boundary scans are limited to 1000; complete=false means counts are lower bounds."],
    }


@router.get("")
def get_summary(a: Actor = Depends(actor)):
    with transaction(a.user_id, a.org_id) as session:
        return summary(session, a.org_id)
