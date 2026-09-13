"""The Business Effect Observer Contract: what a ground-truth observer must declare,
how it becomes qualified, and what its facts are allowed to mean.

An observer answers one question: did the business effect commit in the system of
record? That answer is worth only as much as the contract behind it, so a definition
must state its system of record, the resource it watches, the effects it can see, how
it correlates an attempt to a record, how it reads, what a commit means there, its
observation window, its coverage limits and its failure semantics.

Qualification is earned by passing a fixed harness and being reviewed by a person, it
is bound to the exact contract, and it goes stale. An unqualified observer can record
facts, and those facts can never become qualified evidence.

Two invariants hold everywhere:
  * missing evidence is never evidence of no effect;
  * a compensation never erases a commit that happened.
"""

import re
from datetime import datetime, timedelta, timezone
from typing import Literal
from uuid import UUID, uuid5

from fastapi import APIRouter, Depends, HTTPException
from pydantic import Field, field_validator, model_validator

from .auth import SECURITY, Actor, actor, require
from .change_assurance import history
from .core.contracts import digest
from .schemas import Input
from .db import Record, add_record, audit, get_record, now, transaction

router = APIRouter(tags=["observer-platform"])
PROFILE = "business-effect-observer/v1"
# What an observer may report about one attempted consequential action.
FACTS = ("ATTEMPTED", "AUTHORIZED", "DISPATCHED", "COMMITTED", "DENIED", "COMPENSATED", "UNKNOWN")
FACT_MEANING = {
    "ATTEMPTED": "The agent tried to cause this effect. Nothing about the outcome follows.",
    "AUTHORIZED": "A control permitted the attempt. Permission is not a committed effect.",
    "DISPATCHED": "The request reached the system of record. Acceptance is not a commit.",
    "COMMITTED": "The system of record durably holds the effect.",
    "DENIED": "A control refused the attempt before any effect could commit.",
    "COMPENSATED": "A committed effect was later reversed. The commit still happened.",
    "UNKNOWN": "The observer cannot establish what happened. This is never 'no effect'.",
}
STATES = ("UNQUALIFIED", "QUALIFICATION_PENDING", "QUALIFIED", "REVOKED", "STALE")
STATE_MEANING = {
    "UNQUALIFIED": "No qualification has been attempted. Facts are recorded; they are not evidence.",
    "QUALIFICATION_PENDING": "A qualification attempt exists but did not pass every scenario, or awaits review.",
    "QUALIFIED": "Passed every harness scenario for this exact contract and was reviewed by a person.",
    "REVOKED": "Qualification was withdrawn. Historical facts remain; new ones are not evidence.",
    "STALE": "Qualification expired, or the contract changed after it was granted. Re-qualify it.",
}
# Every scenario must be answered exactly this way. One deviation fails qualification.
SCENARIOS = (
    ("POSITIVE_COMMIT", "A committed effect is observed and correlated.", "COMMITTED"),
    ("DENIED", "A control refused the attempt.", "DENIED"),
    ("NO_EFFECT", "The attempt left no record, and the observer covers commits for this resource.", "DENIED"),
    ("COMPENSATED", "A commit was later reversed.", "COMPENSATED"),
    ("MISSING_CORRELATION", "No correlation value reached the system of record.", "UNKNOWN"),
    ("STALE", "The only candidate record falls outside the observation window.", "UNKNOWN"),
    ("MULTIPLE_MATCHES", "More than one record matches the correlation value.", "UNKNOWN"),
    ("OUTAGE", "The system of record is unreachable.", "UNKNOWN"),
    ("WRONG_TENANT", "A matching record belongs to another tenant.", "UNKNOWN"),
    ("INSUFFICIENT_COVERAGE", "The effect is outside what this observer can see.", "UNKNOWN"),
)
SCENARIO_NAMES = tuple(name for name, _, _ in SCENARIOS)
REQUIRED_ANSWER = {name: answer for name, _, answer in SCENARIOS}
MAX_WINDOW_SECONDS = 86_400
IDENTIFIER = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")
LABEL = re.compile(r"^[^\x00-\x1f]{2,120}$")


Strict = Input


class Correlation(Strict):
    method: Literal["CORRELATION_ID", "IDEMPOTENCY_KEY", "RESOURCE_VERSION", "TIME_WINDOW"]
    field: str = Field(min_length=1, max_length=120)
    note: str = Field(min_length=10, max_length=500)

    @model_validator(mode="after")
    def honest_about_time(self):
        if self.method == "TIME_WINDOW" and "cannot" not in self.note.lower():
            raise ValueError("A time-window correlation must state what it cannot distinguish")
        return self


class ReadMethod(Strict):
    kind: Literal["READ_ONLY_SQL", "HTTP_READ", "LOG_READ", "MANUAL_EXPORT"]
    detail: str = Field(min_length=10, max_length=500)
    writes: Literal[False] = False


class CommitSemantics(Strict):
    durability: Literal["COMMITTED_TRANSACTION", "APPEND_ONLY_LOG", "EVENTUALLY_CONSISTENT", "UNKNOWN"]
    note: str = Field(min_length=10, max_length=500)


class FailureSemantics(Strict):
    # The only safe answers. An observer may never report absence as "no effect".
    on_unavailable: Literal["UNKNOWN"] = "UNKNOWN"
    on_ambiguous: Literal["UNKNOWN"] = "UNKNOWN"
    on_missing_record: Literal["UNKNOWN", "DENIED"]
    note: str = Field(min_length=10, max_length=500)

    @model_validator(mode="after")
    def absence_requires_coverage(self):
        if self.on_missing_record == "DENIED" and "covers" not in self.note.lower():
            raise ValueError("Reading absence as DENIED requires stating the commit coverage that justifies it")
        return self


class ObserverDefinitionInput(Strict):
    environment_id: UUID
    name: str = Field(min_length=3, max_length=120)
    system_of_record: str = Field(min_length=2, max_length=120)
    resource: str = Field(min_length=2, max_length=120)
    observed_effects: list[Literal[FACTS]] = Field(min_length=1, max_length=7)  # type: ignore[valid-type]
    actions: list[str] = Field(min_length=1, max_length=20)
    correlation: Correlation
    read_method: ReadMethod
    commit_semantics: CommitSemantics
    observation_window_seconds: int = Field(ge=1, le=MAX_WINDOW_SECONDS)
    coverage_limits: list[str] = Field(min_length=1, max_length=20)
    failure_semantics: FailureSemantics
    requalify_days: int = Field(default=90, ge=1, le=365)

    @field_validator("actions", "coverage_limits")
    @classmethod
    def bounded_text(cls, value):
        for item in value:
            if not isinstance(item, str) or not LABEL.fullmatch(item.strip()):
                raise ValueError("Each entry must be short, printable text")
        return [item.strip() for item in value]

    @model_validator(mode="after")
    def absence_needs_commit_coverage(self):
        if self.failure_semantics.on_missing_record == "DENIED" and "COMMITTED" not in self.observed_effects:
            raise ValueError("An observer that cannot see commits may never read absence as DENIED")
        return self


class QualificationInput(Strict):
    contract_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    harness_version: str = Field(min_length=1, max_length=40)
    results: dict[str, str] = Field(min_length=len(SCENARIOS), max_length=len(SCENARIOS))
    evidence_reference: str = Field(min_length=3, max_length=300)
    review_note: str = Field(min_length=20, max_length=2000)

    @field_validator("results")
    @classmethod
    def every_scenario(cls, value):
        if set(value) != set(SCENARIO_NAMES):
            raise ValueError("Every harness scenario must be reported")
        for name, answer in value.items():
            if answer not in FACTS:
                raise ValueError(f"{name} reported an answer outside the observer vocabulary")
        return value


class ObservationInput(Strict):
    correlation_value: str = Field(min_length=1, max_length=200)
    effect: Literal[FACTS]  # type: ignore[valid-type]
    action: str = Field(min_length=1, max_length=120)
    resource_reference: str = Field(min_length=1, max_length=200)
    observed_at: datetime
    record_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    compensates: str | None = Field(default=None, max_length=200)
    note: str = Field(default="", max_length=500)
    idempotency_key: str = Field(min_length=8, max_length=120)

    @field_validator("observed_at")
    @classmethod
    def aware(cls, value):
        if value.tzinfo is None:
            raise ValueError("An observation time requires a timezone")
        return value


def contract_digest(payload):
    """The exact contract a qualification is bound to."""
    fields = ("system_of_record", "resource", "observed_effects", "actions", "correlation", "read_method",
              "commit_semantics", "observation_window_seconds", "coverage_limits", "failure_semantics")
    return digest({field: payload.get(field) for field in fields})


def qualification_state(session, org, definition, *, at=None):
    """The observer's qualification right now, with the reason it holds."""
    at = at or now()
    system_id = definition.payload["system_id"]
    if any(r.payload.get("definition_id") == str(definition.id)
           for r in history(session, org, "observer_revocation", system_id)):
        return {"state": "REVOKED", "meaning": STATE_MEANING["REVOKED"], "qualified_at": None,
                "expires_at": None, "contract_digest": definition.payload["contract_digest"]}
    attempts = [r for r in history(session, org, "observer_qualification", system_id)
                if r.payload.get("definition_id") == str(definition.id)]
    passed = next((r for r in attempts if r.payload["outcome"] == "PASSED"
                   and r.payload["contract_digest"] == definition.payload["contract_digest"]), None)
    if passed is None:
        state = "QUALIFICATION_PENDING" if attempts else "UNQUALIFIED"
        return {"state": state, "meaning": STATE_MEANING[state], "qualified_at": None, "expires_at": None,
                "contract_digest": definition.payload["contract_digest"],
                "attempts": len(attempts)}
    expires = passed.created_at.astimezone(timezone.utc) + timedelta(days=definition.payload["requalify_days"])
    state = "QUALIFIED" if expires > at else "STALE"
    return {"state": state, "meaning": STATE_MEANING[state],
            "qualified_at": passed.created_at.astimezone(timezone.utc).isoformat(),
            "expires_at": expires.isoformat(), "contract_digest": definition.payload["contract_digest"],
            "qualification_id": str(passed.id), "attempts": len(attempts)}


def definition_view(session, org, definition):
    payload = definition.payload
    qualification = qualification_state(session, org, definition)
    return {"id": str(definition.id), "system_id": payload["system_id"], "environment_id": payload["environment_id"],
            "name": payload["name"], "system_of_record": payload["system_of_record"], "resource": payload["resource"],
            "observed_effects": payload["observed_effects"], "actions": payload["actions"],
            "correlation": payload["correlation"], "read_method": payload["read_method"],
            "commit_semantics": payload["commit_semantics"],
            "observation_window_seconds": payload["observation_window_seconds"],
            "coverage_limits": payload["coverage_limits"], "failure_semantics": payload["failure_semantics"],
            "requalify_days": payload["requalify_days"], "contract_digest": payload["contract_digest"],
            "qualification": qualification, "produces_evidence": qualification["state"] == "QUALIFIED",
            "created_at": definition.created_at.astimezone(timezone.utc).isoformat(),
            "invariants": ["Missing evidence is never evidence of no effect.",
                           "A compensation never erases a commit that happened.",
                           "Facts from an observer that is not QUALIFIED are never evidence."]}


def effect_summary(definition, observations):
    """What a set of facts establishes about one attempted effect. Conservative by construction."""
    payload = definition.payload
    facts = sorted(({"effect": o["effect"], "observed_at": o["observed_at"], "qualified": o.get("qualified", False),
                     "note": o.get("note", "")} for o in observations), key=lambda f: f["observed_at"])
    qualified = [f for f in facts if f["qualified"]]
    present = {f["effect"] for f in qualified}
    covers_commit = "COMMITTED" in payload["observed_effects"]
    absence_is_denial = payload["failure_semantics"]["on_missing_record"] == "DENIED"
    limitations = list(payload["coverage_limits"])
    if not qualified:
        effect, committed = "UNKNOWN", None
        reason = ("Facts exist for this attempt but none came from a qualified observer, so nothing is "
                  "established. That is not evidence that no effect committed." if facts else
                  "No observation exists for this attempt. That is not evidence that no effect committed.")
    elif "COMMITTED" in present and "COMPENSATED" in present:
        effect, committed = "COMMITTED_THEN_COMPENSATED", True
        reason = "The effect committed and was later reversed. The commit still happened."
    elif "COMMITTED" in present:
        effect, committed = "COMMITTED", True
        reason = "The system of record durably holds this effect."
    elif "COMPENSATED" in present:
        effect, committed = "UNKNOWN", None
        reason = "A reversal was observed without the commit it reverses; the original effect is not established."
    elif "DENIED" in present:
        effect, committed = "DENIED", False
        reason = "A control refused the attempt before any effect could commit."
    elif present <= {"ATTEMPTED", "AUTHORIZED", "DISPATCHED", "UNKNOWN"}:
        if absence_is_denial and covers_commit and "UNKNOWN" not in present:
            effect, committed = "NO_EFFECT_OBSERVED", False
            reason = ("This observer covers commits for this resource and found none inside its observation "
                      "window, so no effect committed.")
        else:
            effect, committed = "UNKNOWN", None
            reason = ("Only pre-commit facts exist. Without commit coverage, absence cannot establish that no "
                      "effect committed.")
    else:
        effect, committed = "UNKNOWN", None
        reason = "The facts do not combine into an established outcome."
    return {"schema_version": PROFILE, "effect": effect, "committed": committed,
            "compensated": "COMPENSATED" in present, "reason": reason,
            "facts": facts, "qualified_facts": len(qualified), "unqualified_facts": len(facts) - len(qualified),
            "observation_window_seconds": payload["observation_window_seconds"],
            "coverage_limits": limitations,
            "principle": "Missing evidence is not evidence of no effect; a compensation does not erase a commit."}


def run_harness(observe, *, harness_version="observer-harness/v1"):
    """Every scenario an observer must answer correctly before it can produce evidence.

    `observe(scenario)` is the observer under test. It must return one fact from the
    observer vocabulary for each scenario name.
    """
    results, failures = {}, []
    for name, description, required in SCENARIOS:
        try:
            answer = observe(name)
        except Exception as error:  # noqa: BLE001 - an observer that raises has failed that scenario
            answer, error_note = "ERROR", type(error).__name__
            failures.append({"scenario": name, "expected": required, "actual": answer, "error": error_note})
            results[name] = answer
            continue
        results[name] = answer
        if answer != required:
            failures.append({"scenario": name, "expected": required, "actual": answer,
                             "description": description})
    return {"harness_version": harness_version, "results": results, "failures": failures,
            "outcome": "PASSED" if not failures else "FAILED"}


@router.post("/v1/systems/{system_id}/observer-definitions", status_code=201)
def create_definition(system_id: UUID, body: ObserverDefinitionInput, a: Actor = Depends(actor)):
    """Declare a business-effect observer contract. It starts UNQUALIFIED."""
    require(a, SECURITY)
    from .change_assurance import scoped
    from .release_integrity import lock_system

    with transaction(a.user_id, a.org_id) as session:
        get_record(session, a.org_id, system_id, "system")
        scoped(session, a.org_id, body.environment_id, "environment", system_id)
        lock_system(session, a.org_id, system_id)
        payload = {**body.model_dump(mode="json"), "schema_version": PROFILE, "system_id": str(system_id),
                   "environment_id": str(body.environment_id), "declared_by": str(a.user_id),
                   "establishes_evidence": False}
        payload["contract_digest"] = contract_digest(payload)
        row = add_record(session, a.org_id, "observer_definition", payload,
                         {"system": system_id, "environment": body.environment_id})
        audit(session, a.org_id, a.user_id, "observer.defined", row.id)
        return definition_view(session, a.org_id, row)


@router.get("/v1/systems/{system_id}/observer-definitions")
def list_definitions(system_id: UUID, a: Actor = Depends(actor)):
    with transaction(a.user_id, a.org_id) as session:
        get_record(session, a.org_id, system_id, "system")
        rows = history(session, a.org_id, "observer_definition", system_id)[:50]
        return {"items": [definition_view(session, a.org_id, row) for row in rows],
                "states": STATE_MEANING, "effects": FACT_MEANING,
                "scenarios": [{"scenario": n, "description": d, "required_answer": r} for n, d, r in SCENARIOS]}


@router.get("/v1/observer-definitions/{definition_id}")
def get_definition(definition_id: UUID, a: Actor = Depends(actor)):
    with transaction(a.user_id, a.org_id) as session:
        return definition_view(session, a.org_id,
                               get_record(session, a.org_id, definition_id, "observer_definition"))


@router.post("/v1/observer-definitions/{definition_id}/qualification", status_code=201)
def record_qualification(definition_id: UUID, body: QualificationInput, a: Actor = Depends(actor)):
    """Record a harness run and a person's review. Passing every scenario is the only way to QUALIFIED."""
    require(a, SECURITY)
    from .release_integrity import lock_system

    with transaction(a.user_id, a.org_id) as session:
        definition = get_record(session, a.org_id, definition_id, "observer_definition")
        lock_system(session, a.org_id, definition.payload["system_id"])
        if body.contract_digest != definition.payload["contract_digest"]:
            raise HTTPException(409, "This qualification was produced for a different observer contract")
        failures = sorted(name for name, answer in body.results.items() if answer != REQUIRED_ANSWER[name])
        outcome = "PASSED" if not failures else "FAILED"
        row = add_record(session, a.org_id, "observer_qualification", {
            "schema_version": PROFILE, "system_id": definition.payload["system_id"],
            "environment_id": definition.payload["environment_id"], "definition_id": str(definition.id),
            "contract_digest": body.contract_digest, "harness_version": body.harness_version,
            "results": body.results, "failed_scenarios": failures, "outcome": outcome,
            "evidence_reference": body.evidence_reference, "review_note": body.review_note,
            "reviewed_by": str(a.user_id)}, {"observer_definition": definition.id})
        audit(session, a.org_id, a.user_id, f"observer.qualification_{outcome.lower()}", row.id)
        return {"id": str(row.id), "outcome": outcome, "failed_scenarios": failures,
                "qualification": qualification_state(session, a.org_id, definition)}


class RevokeInput(Strict):
    reason: str = Field(min_length=10, max_length=2000)


@router.post("/v1/observer-definitions/{definition_id}/revoke", status_code=201)
def revoke_definition(definition_id: UUID, body: RevokeInput, a: Actor = Depends(actor)):
    """Withdraw qualification. Historical facts remain; new facts are no longer evidence."""
    require(a, SECURITY)
    reason = body.reason
    with transaction(a.user_id, a.org_id) as session:
        definition = get_record(session, a.org_id, definition_id, "observer_definition")
        row = add_record(session, a.org_id, "observer_revocation", {
            "schema_version": PROFILE, "system_id": definition.payload["system_id"],
            "definition_id": str(definition.id), "family_id": str(definition.id),
            "revoked_by": str(a.user_id), "reason": str(reason)[:2000]}, {"observer_definition": definition.id})
        audit(session, a.org_id, a.user_id, "observer.revoked", row.id)
        return {"id": str(row.id), "qualification": qualification_state(session, a.org_id, definition)}


@router.post("/v1/observer-definitions/{definition_id}/observations", status_code=201)
def record_observation(definition_id: UUID, body: ObservationInput, a: Actor = Depends(actor)):
    """Record one observed fact. Its qualification is stamped from the contract's state now."""
    require(a)
    with transaction(a.user_id, a.org_id) as session:
        definition = get_record(session, a.org_id, definition_id, "observer_definition")
        qualification = qualification_state(session, a.org_id, definition)
        if qualification["state"] == "REVOKED":
            raise HTTPException(409, "This observer's qualification was revoked")
        if body.effect not in definition.payload["observed_effects"] and body.effect != "UNKNOWN":
            raise HTTPException(422, "This observer's contract does not cover that effect")
        identifier = uuid5(a.org_id, f"observer-fact:{definition.id}:{body.idempotency_key}")
        existing = session.get(Record, identifier)
        if existing is not None:
            return {**existing.payload, "id": str(identifier), "duplicate": True}
        payload = {
            "schema_version": PROFILE, "system_id": definition.payload["system_id"],
            "environment_id": definition.payload["environment_id"], "definition_id": str(definition.id),
            "correlation_value": body.correlation_value, "effect": body.effect, "meaning": FACT_MEANING[body.effect],
            "action": body.action, "resource_reference": body.resource_reference,
            "observed_at": body.observed_at.astimezone(timezone.utc).isoformat(),
            "record_digest": body.record_digest, "compensates": body.compensates, "note": body.note,
            "qualification_state": qualification["state"], "qualified": qualification["state"] == "QUALIFIED",
            "recorded_by": str(a.user_id), "idempotency_key": body.idempotency_key,
        }
        row = add_record(session, a.org_id, "business_effect_observation", payload,
                         {"observer_definition": definition.id})
        return {**payload, "id": str(row.id)}


@router.get("/v1/observer-definitions/{definition_id}/effects")
def observed_effect(definition_id: UUID, correlation_value: str, a: Actor = Depends(actor)):
    """What this observer establishes about one attempted effect."""
    if len(correlation_value) > 200:
        raise HTTPException(422, "Correlation value exceeds bounds")
    with transaction(a.user_id, a.org_id) as session:
        definition = get_record(session, a.org_id, definition_id, "observer_definition")
        rows = [r.payload for r in history(session, a.org_id, "business_effect_observation",
                                          definition.payload["system_id"])
                if r.payload.get("definition_id") == str(definition.id)
                and r.payload.get("correlation_value") == correlation_value]
        return {**effect_summary(definition, rows), "definition_id": str(definition.id),
                "correlation_value": correlation_value,
                "qualification": qualification_state(session, a.org_id, definition)}
