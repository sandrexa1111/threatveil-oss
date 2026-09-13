"""Portable tenant memory without authentication material or provider credentials."""

import json
from sqlalchemy import select, tuple_
from sqlalchemy.orm import aliased

from .db import Record, Edge, transaction, now

# Deliberately never exported: a credential record names a secret-manager version, which is a
# deployment secret rather than portable customer memory. Organization erasure still removes it.
NEVER_EXPORTED = frozenset({"credential"})

EXPORT_KINDS = frozenset(
    {
        "adoption",
        "ai_usage",
        "assurance_case",
        "assurance_passport",
        "assurance_receipt",
        "audit",
        "authorization_decision",
        "auto_reproof_execution",
        "auto_reproof_policy",
        "baseline",
        "billing_event",
        "billing_receipt",
        "binding",
        "business_effect_observation",
        "canary",
        "change",
        "change_event",
        "change_impact",
        "change_set",
        "claim_definition",
        "commercial_interest",
        "commercial_subscription",
        "compiler_proposal",
        "connector_configuration",
        "connector_installation",
        "consequence_feedback",
        "consumer_acceptance",
        "data_policy",
        "deletion_cancelled",
        "dependency_mapping",
        "dependency_mapping_proposal",
        "dependency_mapping_review",
        "enforcement_acknowledgement",
        "enforcement_request",
        "entitlement",
        "environment",
        "environment_target_binding",
        "evidence_record",
        "exception_approval",
        "exception_revocation",
        "finance_assessment",
        "finance_assessment_dispatched",
        "finance_assessment_prepared",
        "finance_change",
        "finance_setup",
        "finding",
        "fingerprint_review",
        "fix",
        "gauntlet",
        "github_app_installation",
        "github_app_revocation",
        "github_binding_review",
        "github_change_event",
        "github_check_publication",
        "impact",
        "integration_intake",
        "launch_event",
        "launch_time",
        "measurement_consent",
        "observer",
        "observer_definition",
        "observer_qualification",
        "observer_revocation",
        "organization_deletion",
        "passport_revocation",
        "passport_share",
        "passport_share_revocation",
        "permission_envelope",
        "pilot_agreement",
        "product_metric",
        "proof_execution",
        "proof_plan",
        "proof_scope",
        "property",
        "proposal",
        "proposed_change_assessment",
        "regression",
        "relationship_assertion",
        "release",
        "release_authorization",
        "release_authorization_revocation",
        "release_authorization_use",
        "release_decision",
        "release_exception",
        "release_policy",
        "result",
        "run",
        "schedule_execution",
        "schedule_skipped",
        "selection_audit",
        "service_metric",
        "source_assertion",
        "source_batch",
        "source_change",
        "source_health",
        "status_event",
        "system",
        "system_state",
        "target",
        "tool_contract",
        "trial_capture",
        "worker_completion",
    }
)


def export_memory(user_id, org_id):
    cutoff = now()

    def line(value):
        return json.dumps(value, separators=(",", ":"), default=str) + "\n"

    yield line(
        {
            "type": "manifest",
            "schema": "threatveil-memory/v1",
            "organization_id": str(org_id),
            "snapshot_at": cutoff.isoformat(),
            "raw_evidence": "Fetch scoped capture endpoints before their recorded expiry; raw objects are not embedded.",
            "excluded": [
                "credentials",
                "authentication",
                "billing provider secrets",
                "pending outbound messages",
            ],
        }
    )
    cursor = None
    while True:
        with transaction(user_id, org_id) as session:
            query = select(Record).where(
                Record.organization_id == org_id,
                Record.kind.in_(EXPORT_KINDS),
                Record.created_at <= cutoff,
            )
            if cursor:
                query = query.where(tuple_(Record.created_at, Record.id) > cursor)
            rows = list(session.scalars(query.order_by(Record.created_at, Record.id).limit(25)))
            batch = [
                {
                    "type": "record",
                    "id": str(r.id),
                    "kind": r.kind,
                    "created_at": r.created_at,
                    "payload": r.payload,
                }
                for r in rows
            ]
            if rows:
                cursor = (rows[-1].created_at, rows[-1].id)
        for record in batch:
            yield line(record)
        if len(rows) < 25:
            break
    cursor = None
    while True:
        with transaction(user_id, org_id) as session:
            source, target = aliased(Record), aliased(Record)
            query = (
                select(Edge)
                .join(
                    source,
                    (source.id == Edge.source_id)
                    & (source.organization_id == Edge.organization_id),
                )
                .join(
                    target,
                    (target.id == Edge.target_id)
                    & (target.organization_id == Edge.organization_id),
                )
                .where(
                    Edge.organization_id == org_id,
                    source.kind.in_(EXPORT_KINDS),
                    target.kind.in_(EXPORT_KINDS),
                    source.created_at <= cutoff,
                    target.created_at <= cutoff,
                )
            )
            if cursor:
                query = query.where(tuple_(Edge.source_id, Edge.target_id, Edge.relation) > cursor)
            rows = list(
                session.scalars(
                    query.order_by(Edge.source_id, Edge.target_id, Edge.relation).limit(250)
                )
            )
            batch = [
                {
                    "type": "edge",
                    "source_id": str(r.source_id),
                    "target_id": str(r.target_id),
                    "relation": r.relation,
                }
                for r in rows
            ]
            if rows:
                cursor = (rows[-1].source_id, rows[-1].target_id, rows[-1].relation)
        for edge in batch:
            yield line(edge)
        if len(rows) < 250:
            break
    yield line({"type": "complete", "snapshot_at": cutoff.isoformat()})
