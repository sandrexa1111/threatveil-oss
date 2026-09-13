"""Bounded AI seams: proposals only, off by default.

No ThreatVeil conclusion depends on a model. A provider may only produce a proposal a
person must approve; it is given the minimum context the task needs (names, not
payloads, evidence or secrets), and what it returns must cite the exact inputs it was
shown. Every call is recorded as ai_usage with provider, model, feature, tokens,
estimated cost, latency and the result, so AI cost is visible per organization and
per feature, and a paid provider cannot run without a configured budget.

Invariants, structural here and asserted by tests:
  * no model output changes an assurance status, a clearance, evidence or authority;
  * UNKNOWN never becomes CURRENT, STALE never becomes VALID, FAIL never becomes PASS;
  * with the feature flag off, no provider is constructed and no call is made.
"""

import time
from datetime import timedelta
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import Field
from sqlalchemy import select

from .auth import SECURITY, Actor, actor, require
from .config import settings
from .db import Record, add_record, get_record, now, transaction
from .schemas import Input

router = APIRouter(tags=["ai-assistance"])
PROFILE = "ai-usage/v1"
FEATURES = ("dependency_mapping", "claim_authoring")
INVARIANTS = [
    "A model proposes; a person approves. No model output changes an assurance status.",
    "No model can turn UNKNOWN into CURRENT, STALE into VALID, or FAIL into PASS.",
    "A proposal carries the inputs it was shown, so a reviewer can check it against the records.",
]
MAX_SUBJECTS = 20
MAX_CANDIDATES = 40


class AiUnavailable(HTTPException):
    def __init__(self, detail):
        super().__init__(409, detail)


Strict = Input


class MappingProposal(Strict):
    subject: str = Field(max_length=500)
    maps_to: list[str] = Field(min_length=1, max_length=5)
    rationale: str = Field(max_length=300)
    cited_inputs: list[str] = Field(min_length=1, max_length=10)


class MappingProposals(Strict):
    proposals: list[MappingProposal] = Field(max_length=MAX_SUBJECTS)


class ClaimDraft(Strict):
    claim: str = Field(max_length=300)
    permitted_outcome: str = Field(max_length=1000)
    forbidden_outcome: str = Field(max_length=1000)
    legitimate_task: str = Field(max_length=1000)
    ground_truth_source: str = Field(max_length=300)
    declared_dependencies: list[str] = Field(default_factory=list, max_length=10)
    rationale: str = Field(max_length=300)
    cited_inputs: list[str] = Field(min_length=1, max_length=10)


class Usage(Strict):
    input_tokens: int = 0
    output_tokens: int = 0
    latency_ms: int = 0


def enabled(feature):
    config = settings()
    if feature not in FEATURES:
        raise AiUnavailable("Unknown AI feature")
    flag = {"dependency_mapping": config.ai_mapping_enabled, "claim_authoring": config.ai_claims_enabled}[feature]
    return bool(flag) and config.ai_provider != "disabled"


class MockProvider:
    """A deterministic stand-in. No network, no model, used by tests and local demos."""

    name, model = "mock", "deterministic-mock/v1"

    def propose_mappings(self, payload):
        from .dependency_mapping import tokens

        proposals = []
        for subject in payload["subjects"]:
            names = [subject["subject"], *subject.get("names", [])]
            for candidate in payload["candidates"]:
                overlap = {t for name in names for t in tokens(name)} & set(tokens(candidate))
                if overlap:
                    proposals.append(MappingProposal(
                        subject=subject["subject"], maps_to=[candidate],
                        rationale=f"Shared name tokens: {', '.join(sorted(overlap))}.",
                        cited_inputs=[subject["subject"], candidate]))
                    break
        return MappingProposals(proposals=proposals[:MAX_SUBJECTS]), Usage(input_tokens=0, output_tokens=0)

    def draft_claim(self, payload):
        resource = payload["resource"]
        return ClaimDraft(
            claim=f"The agent never commits a change to {resource} without a recorded approval"[:300],
            permitted_outcome=f"The agent changes {resource} after an approval is recorded",
            forbidden_outcome=f"A change to {resource} is committed with no recorded approval",
            legitimate_task=payload.get("intent", "The agent completes its routine task")[:1000],
            ground_truth_source=f"The system of record for {resource}",
            declared_dependencies=payload.get("dependencies", [])[:10],
            rationale="Derived from the declared resource and the reviewed approval pattern.",
            cited_inputs=[resource]), Usage()


class OpenAiProvider:
    """The existing bounded provider pattern: a strict schema, one call, no tools."""

    def __init__(self):
        config = settings()
        if not config.openai_api_key:
            raise AiUnavailable("No provider credential is configured")
        self.name, self.model = "openai", config.ai_model

    def _parse(self, instructions, payload, schema):
        from openai import OpenAI

        started = time.monotonic()
        client = OpenAI(api_key=settings().openai_api_key, timeout=30, max_retries=0)
        response = client.responses.parse(
            model=self.model, instructions=instructions,
            input=[{"role": "user", "content": str(payload)[:20000]}], text_format=schema)
        usage = getattr(response, "usage", None)
        return response.output_parsed, Usage(
            input_tokens=int(getattr(usage, "input_tokens", 0) or 0),
            output_tokens=int(getattr(usage, "output_tokens", 0) or 0),
            latency_ms=int((time.monotonic() - started) * 1000))

    def propose_mappings(self, payload):
        return self._parse(
            "Propose which reviewed claim dependency each named source fact corresponds to. Use only the names "
            "given. Cite the exact inputs you used. If you are unsure, omit the subject. You are proposing for "
            "human review; you are not deciding anything.", payload, MappingProposals)

    def draft_claim(self, payload):
        return self._parse(
            "Draft one security claim in plain business language from the given resource and intent. State the "
            "forbidden outcome precisely. Cite the exact inputs you used. A person will review and edit this.",
            payload, ClaimDraft)


def provider(feature):
    if not enabled(feature):
        raise AiUnavailable(f"AI assistance for {feature} is disabled in this deployment")
    config = settings()
    if config.ai_provider == "mock":
        return MockProvider()
    return OpenAiProvider()


def _month_start():
    stamp = now()
    return stamp.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def estimated_cost(usage: Usage):
    config = settings()
    return round(usage.input_tokens / 1_000_000 * config.ai_price_per_million_input
                 + usage.output_tokens / 1_000_000 * config.ai_price_per_million_output, 6)


def spent_this_month(session, org):
    total = 0.0
    for payload in session.scalars(select(Record.payload).where(
            Record.organization_id == org, Record.kind == "ai_usage", Record.created_at >= _month_start())):
        total += float(payload.get("estimated_cost_usd") or 0)
    return round(total, 6)


def check_budget(session, org, provider_name):
    """A paid provider needs a configured budget, and may not exceed it."""
    if provider_name == "mock":
        return 0.0
    budget = float(settings().ai_monthly_usd_budget or 0)
    if budget <= 0:
        raise AiUnavailable("No AI budget is configured for this deployment; paid AI assistance is disabled")
    spent = spent_this_month(session, org)
    if spent >= budget:
        raise HTTPException(429, "This month's AI assistance budget is exhausted")
    return budget


def record_usage(session, org, *, feature, provider_name, model, usage: Usage, system_id=None, result=None,
                 outcome="PROPOSED", references=None):
    payload = {"schema_version": PROFILE, "feature": feature, "provider": provider_name, "model": model,
               "system_id": str(system_id) if system_id else None,
               "input_tokens": usage.input_tokens, "output_tokens": usage.output_tokens,
               "latency_ms": usage.latency_ms, "estimated_cost_usd": estimated_cost(usage),
               "result_count": len(result or []), "approval_outcome": outcome,
               "changed_assurance": False, "invariants": INVARIANTS}
    return add_record(session, org, "ai_usage", payload, references or {})


class MappingAssistInput(Strict):
    installation_id: UUID
    environment_id: UUID | None = None
    subjects: list[str] = Field(default_factory=list, max_length=MAX_SUBJECTS)


class ClaimAssistInput(Strict):
    resource: str = Field(min_length=2, max_length=120)
    intent: str = Field(min_length=10, max_length=500)
    dependencies: list[str] = Field(default_factory=list, max_length=10)


@router.post("/v1/systems/{system_id}/ai/mapping-proposals", status_code=201)
def ai_mapping_proposals(system_id: UUID, body: MappingAssistInput, a: Actor = Depends(actor)):
    """Ask the configured provider to propose mappings. They are inert until reviewed."""
    require(a, SECURITY)
    from .assurance_intelligence import load
    from .dependency_mapping import PROFILE as MAPPING_PROFILE
    from .dependency_mapping import REASONS, proposal_view, suggest

    with transaction(a.user_id, a.org_id) as session:
        # Tenancy first: a caller learns nothing about this deployment's configuration
        # for a system they cannot see.
        get_record(session, a.org_id, system_id, "system")
        installation = get_record(session, a.org_id, body.installation_id, "connector_installation")
        if installation.payload["system_id"] != str(system_id):
            raise HTTPException(404, "Source not found for this system")
        engine = provider("dependency_mapping")
        check_budget(session, a.org_id, engine.name)
        ctx = load(session, a.org_id, system_id, body.environment_id or installation.payload["environment_id"])
        deterministic = suggest(ctx, installation.id)
        wanted = set(body.subjects or [])
        items = [item for item in deterministic["items"] if not wanted or item["subject"] in wanted]
        # Minimal context: names only. No payloads, no evidence, no secrets, no customer data.
        from .dependency_mapping import candidates as claim_dependencies

        payload = {"subjects": [{"subject": item["subject"], "names": item["names"][:5]}
                                for item in items[:MAX_SUBJECTS]],
                   "candidates": sorted(claim_dependencies(ctx))[:MAX_CANDIDATES]}
        result, usage = engine.propose_mappings(payload)
        known = {item["subject"] for item in items}
        created = []
        for proposal in result.proposals:
            if proposal.subject not in known:
                continue  # a model may not invent a subject this source never reported
            row = add_record(session, a.org_id, "dependency_mapping_proposal", {
                "schema_version": MAPPING_PROFILE, "system_id": str(system_id),
                "environment_id": str(ctx.environment.id), "installation_id": str(installation.id),
                "subject": proposal.subject, "maps_to": proposal.maps_to[:20],
                "reason": "CUSTOMER_JUDGEMENT", "reason_text": REASONS.get("CONFIG_KEY_MATCH"),
                "confidence": "STATED", "origin": "AI_PROPOSED", "provider": engine.name, "model": engine.model,
                "evidence": f"Model rationale: {proposal.rationale}"[:1000],
                "note": "Cited inputs: " + ", ".join(proposal.cited_inputs[:10]),
                "proposed_by": str(a.user_id), "affects_scoping": False, "status": "PROPOSED",
            }, {"system": system_id, "installation": installation.id})
            created.append(row)
        record = record_usage(session, a.org_id, feature="dependency_mapping", provider_name=engine.name,
                              model=engine.model, usage=usage, system_id=system_id, result=created,
                              references={"system": system_id})
        return {"items": [proposal_view(row) for row in created], "ai_usage_id": str(record.id),
                "provider": engine.name, "model": engine.model, "affects_scoping": False,
                "invariants": INVARIANTS,
                "note": "Every proposal requires human approval before it narrows anything."}


@router.post("/v1/systems/{system_id}/ai/claim-draft")
def ai_claim_draft(system_id: UUID, body: ClaimAssistInput, a: Actor = Depends(actor)):
    """Ask the configured provider for a claim draft. Nothing is recorded as a claim."""
    require(a)
    with transaction(a.user_id, a.org_id) as session:
        get_record(session, a.org_id, system_id, "system")
        engine = provider("claim_authoring")
        check_budget(session, a.org_id, engine.name)
        result, usage = engine.draft_claim(body.model_dump(mode="json"))
        record = record_usage(session, a.org_id, feature="claim_authoring", provider_name=engine.name,
                              model=engine.model, usage=usage, system_id=system_id, result=[result],
                              references={"system": system_id})
        return {"draft": result.model_dump(mode="json"), "ai_usage_id": str(record.id), "recorded_as_claim": False,
                "provider": engine.name, "model": engine.model, "status": "DRAFT / NOT VERIFIED FOR YOUR SYSTEM",
                "invariants": INVARIANTS}


@router.get("/v1/measurements/ai-usage")
def ai_usage(a: Actor = Depends(actor)):
    """What AI assistance cost this tenant, per feature. Zero is the normal answer."""
    with transaction(a.user_id, a.org_id) as session:
        rows = list(session.scalars(select(Record).where(
            Record.organization_id == a.org_id, Record.kind == "ai_usage").order_by(Record.created_at.desc())
            .limit(2000)))
        features = {}
        for row in rows:
            payload = row.payload
            entry = features.setdefault(payload["feature"], {
                "feature": payload["feature"], "calls": 0, "input_tokens": 0, "output_tokens": 0,
                "estimated_cost_usd": 0.0, "providers": []})
            entry["calls"] += 1
            entry["input_tokens"] += payload.get("input_tokens", 0)
            entry["output_tokens"] += payload.get("output_tokens", 0)
            entry["estimated_cost_usd"] = round(entry["estimated_cost_usd"]
                                                + float(payload.get("estimated_cost_usd") or 0), 6)
            if payload["provider"] not in entry["providers"]:
                entry["providers"].append(payload["provider"])
        config = settings()
        return {"schema_version": PROFILE, "as_of": now().isoformat(),
                "enabled": {feature: enabled(feature) for feature in FEATURES},
                "provider": config.ai_provider, "model": config.ai_model,
                "monthly_budget_usd": float(config.ai_monthly_usd_budget or 0),
                "spent_this_month_usd": spent_this_month(session, a.org_id),
                "features": sorted(features.values(), key=lambda item: item["feature"]),
                "period_start": _month_start().isoformat(),
                "retention": "Usage records are tenant records; prompts and model output are not retained here.",
                "invariants": INVARIANTS}


def window_note():
    """Used by documentation tests to show the recording window is a calendar month."""
    return {"period": "calendar month", "since": _month_start().isoformat(),
            "next_reset": (_month_start() + timedelta(days=31)).replace(day=1).isoformat()}
