"""Tenant-owned integration drafts and explicit security review of fingerprint facts."""

from typing import Any
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import Field
from sqlalchemy import select

from .assurance import ExactCandidate
from .auth import Actor, SECURITY, actor, require
from .core.contracts import SystemFingerprint, digest
from .core.validity import canonical_fingerprint, change_set, configuration_digest
from .db import Account, Record, add_record, audit, get_record, serialize, transaction
from .integrations.intake import FORMATS, IntakeContext, normalize_integration
from .schemas import Input
from .workspace_reads import page

router = APIRouter(prefix="/v1/integrations/intake", tags=["integration-intake"])


class IntakeRequest(Input):
    system_id: UUID
    payload: dict[str, Any]
    context: IntakeContext | None = None
    idempotency_key: str = Field(min_length=8, max_length=120)


class FingerprintReview(Input):
    source_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate: ExactCandidate
    fingerprint: SystemFingerprint
    previous_fingerprint: SystemFingerprint
    review_reason: str = Field(min_length=10, max_length=2000)
    idempotency_key: str = Field(min_length=8, max_length=120)


def _existing(session, org_id, kind, key, request_digest):
    record = session.scalar(
        select(Record).where(
            Record.organization_id == org_id,
            Record.kind == kind,
            Record.payload["idempotency_key"].astext == key,
        )
    )
    if record and record.payload["request_digest"] != request_digest:
        raise HTTPException(409, "Idempotency key was already used for a different request")
    return record


@router.get("")
def list_intakes(
    system_id: UUID | None = None,
    limit: int = Query(default=25, ge=1, le=200),
    cursor: str | None = Query(default=None, max_length=512),
    a: Actor = Depends(actor),
):
    with transaction(a.user_id, a.org_id) as session:
        if system_id:
            get_record(session, a.org_id, system_id, "system")
        rows, pagination = page(
            session, a.org_id, "integration_intake", limit, cursor, system_id=system_id
        )
        # Large normalized results are available by explicit item reads.
        return {
            "items": [
                {k: v for k, v in serialize(row).items() if k not in {"normalized", "context"}}
                for row in rows
            ],
            "pagination": pagination,
            "formats": list(FORMATS),
        }


@router.get("/{intake_id}")
def get_intake(intake_id: UUID, a: Actor = Depends(actor)):
    with transaction(a.user_id, a.org_id) as session:
        return serialize(get_record(session, a.org_id, intake_id, "integration_intake"))


@router.post("/{kind}", status_code=201)
def create_intake(kind: str, body: IntakeRequest, a: Actor = Depends(actor)):
    require(a)
    if kind not in FORMATS:
        raise HTTPException(422, "Unsupported integration format")
    ctx = body.context or IntakeContext(source_id=kind)
    context_identity = ctx.model_dump(mode="json", exclude={"received_at"})
    if body.context and "received_at" in body.context.model_fields_set:
        context_identity["received_at"] = body.context.received_at.isoformat()
    try:
        request_digest = digest(
            {
                "kind": kind,
                "system_id": str(body.system_id),
                "payload": body.payload,
                "context": context_identity,
            }
        )
    except (ValueError, TypeError, RecursionError):
        raise HTTPException(422, "Integration input is not bounded finite JSON") from None
    with transaction(a.user_id, a.org_id) as session:
        # Verify ownership before parsing private source details or returning a replay.
        get_record(session, a.org_id, body.system_id, "system")
        session.get(Account, a.org_id, with_for_update=True)
        previous = _existing(
            session, a.org_id, "integration_intake", body.idempotency_key, request_digest
        )
        if previous:
            return serialize(previous)
        try:
            normalized = normalize_integration(kind, body.payload, context=ctx)
        except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
            # Do not return validation objects containing customer payloads/secrets.
            raise HTTPException(
                422, "Malformed or unsupported integration input; no records were created"
            ) from None
        intake_id = uuid4()
        finding_ids = [uuid4() for _ in normalized.findings]
        record = add_record(
            session,
            a.org_id,
            "integration_intake",
            {
                "system_id": str(body.system_id),
                "format": kind,
                "status": "DRAFT",
                "data_class": "PRIVATE_CUSTOMER_DATA",
                "cross_customer_use": False,
                "source_digest": normalized.source_digest,
                "context": ctx.model_dump(mode="json"),
                "normalizer_version": normalized.normalizer_version,
                "normalized": normalized.model_dump(mode="json"),
                "fingerprint_digest": configuration_digest(normalized.fingerprint),
                "observation_count": len(normalized.observations),
                "finding_count": len(finding_ids),
                "finding_ids": [str(identifier) for identifier in finding_ids],
                "idempotency_key": body.idempotency_key,
                "request_digest": request_digest,
                "imported_by": str(a.user_id),
                "review_required": True,
                "limitations": list(normalized.limitations),
            },
            {"system": body.system_id},
            record_id=intake_id,
        )
        for identifier, finding in zip(finding_ids, normalized.findings, strict=True):
            add_record(
                session,
                a.org_id,
                "finding",
                {
                    **finding.model_dump(mode="json"),
                    "system_id": str(body.system_id),
                    "intake_id": str(intake_id),
                    "data_class": "PRIVATE_CUSTOMER_DATA",
                    "provenance": {
                        "format": kind,
                        "source_id": ctx.source_id,
                        "source_digest": normalized.source_digest,
                        "result_digest": finding.result_digest,
                        "scanner": finding.scanner,
                        "scanner_version": finding.scanner_version,
                    },
                },
                {"system": body.system_id, "integration_intake": intake_id},
                record_id=identifier,
            )
        audit(session, a.org_id, a.user_id, "integration.intake_created", intake_id)
        return serialize(record)


@router.post("/{intake_id}/approve-fingerprint", status_code=201)
def approve_fingerprint(intake_id: UUID, body: FingerprintReview, a: Actor = Depends(actor)):
    require(a, SECURITY)
    if not body.review_reason.strip():
        raise HTTPException(422, "A substantive fingerprint review reason is required")
    request_digest = digest({"intake_id": str(intake_id), **body.model_dump(mode="json")})
    with transaction(a.user_id, a.org_id) as session:
        intake = get_record(session, a.org_id, intake_id, "integration_intake")
        session.get(Account, a.org_id, with_for_update=True)
        previous = _existing(
            session, a.org_id, "fingerprint_review", body.idempotency_key, request_digest
        )
        if previous:
            return serialize(previous)
        if body.source_digest != intake.payload["source_digest"]:
            raise HTTPException(409, "Review does not identify the imported source digest")
        imported = SystemFingerprint.model_validate(intake.payload["normalized"]["fingerprint"])
        if not imported.components:
            raise HTTPException(422, "This intake contains no candidate fingerprint facts")
        supplied = {(c.type, c.id): c for c in body.fingerprint.components}
        for component in imported.components:
            candidate = supplied.get((component.type, component.id))
            if candidate is None or digest(component.model_dump(exclude={"provenance"})) != digest(
                candidate.model_dump(exclude={"provenance"})
            ):
                raise HTTPException(
                    422,
                    "Reviewed fingerprint must retain every imported component without changing its content",
                )
            if component.provenance == "UNKNOWN" and candidate.provenance != "UNKNOWN":
                raise HTTPException(
                    422, "Review cannot convert missing imported facts into known evidence"
                )
        if not any(
            c.digest == body.candidate.digest and c.version == body.candidate.version
            for c in body.fingerprint.components
        ):
            raise HTTPException(
                422, "Full fingerprint must bind the exact release candidate content and version"
            )
        # Human review approves declared bindings, not the trustworthiness of source
        # instrumentation or the presence of this candidate in a deployed target.
        fingerprint = canonical_fingerprint(body.fingerprint)
        for component in fingerprint["components"]:
            if component["provenance"] == "OBSERVED":
                component["provenance"] = "DECLARED"
        system_id = intake.payload["system_id"]
        delta = add_record(
            session,
            a.org_id,
            "change_set",
            {
                "system_id": system_id,
                "source": "reviewed_integration_intake",
                "intake_id": str(intake.id),
                "source_digest": intake.payload["source_digest"],
                "candidate_identity": body.candidate.model_dump(mode="json"),
                "previous": canonical_fingerprint(body.previous_fingerprint),
                "candidate": fingerprint,
                **change_set(body.previous_fingerprint, fingerprint),
            },
            {"system": system_id, "integration_intake": intake.id},
        )
        review = add_record(
            session,
            a.org_id,
            "fingerprint_review",
            {
                "system_id": system_id,
                "intake_id": str(intake.id),
                "change_set_id": str(delta.id),
                "candidate": body.candidate.model_dump(mode="json"),
                "fingerprint": fingerprint,
                "fingerprint_digest": configuration_digest(fingerprint),
                "reviewed_by": str(a.user_id),
                "review_reason": body.review_reason,
                "source_digest": body.source_digest,
                "status": "REVIEWED_DECLARATION",
                "idempotency_key": body.idempotency_key,
                "request_digest": request_digest,
                "limitations": intake.payload["limitations"]
                + [
                    "Fingerprint review grants no execution authority, witness qualification or security verdict.",
                    "This reviewed declaration can be used in a proof plan; required evidence must still be established.",
                ],
            },
            {"system": system_id, "integration_intake": intake.id, "change_set": delta.id},
        )
        audit(session, a.org_id, a.user_id, "integration.fingerprint_reviewed", review.id)
        return serialize(review)
