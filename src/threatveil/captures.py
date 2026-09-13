"""Durable per-trial evidence prevents later execution errors from erasing known failures."""

from fastapi import HTTPException
from sqlalchemy import select
from datetime import datetime
import json

from .core.contracts import Observation, digest, trial_correlation
from .core.evaluation import evaluate_trace
from .db import Record, add_record, now
from .observers import bound_source
from .evidence_storage import store_observation, load_observation

MAX_CAPTURE_BYTES = 2 * 1024 * 1024
MAX_RUN_CAPTURE_BYTES = 16 * 1024 * 1024


def require_capture_capacity(session, org_id, run_id):
    used = sum(r.payload["capture_bytes"] for r in captured_trials(session, org_id, run_id))
    if used + MAX_CAPTURE_BYTES > MAX_RUN_CAPTURE_BYTES:
        raise HTTPException(
            413, "Run evidence budget exhausted; reduce trial count or observation size"
        )


def captured_trials(session, org_id, run_id):
    return list(
        session.scalars(
            select(Record)
            .where(
                Record.organization_id == org_id,
                Record.kind == "trial_capture",
                Record.payload["run_id"].astext == str(run_id),
            )
            .order_by(Record.created_at)
        )
    )


def evaluate_persisted(session, org_id, run):
    from .execution import evaluate_acquisition

    records = captured_trials(session, org_id, run.id)
    observations = [
        {
            "variant_id": r.payload["variant_id"],
            "index": r.payload["index"],
            "observation": load_observation(org_id, run.id, r.payload["raw_evidence"]),
        }
        for r in records
    ]
    evaluated_at = {
        (r.payload["variant_id"], r.payload["index"]): datetime.fromisoformat(
            r.payload["evaluated_at"]
        )
        for r in records
    }
    expected = run.payload["trials"] * run.payload["variant_count"]
    if len(records) != expected:
        raise ValueError("Incomplete durable observations")
    result = evaluate_acquisition(run.payload, observations, trusted_evaluation_times=evaluated_at)
    by_slot = {(r.payload["variant_id"], r.payload["index"]): str(r.id) for r in records}
    for trial in result["trials"]:
        trial.pop("observation", None)
        trial["capture_id"] = by_slot[(trial["variant_id"], trial["index"])]
    result["evidence"].pop("observations", None)
    result["evidence"]["capture_ids"] = [str(r.id) for r in records]
    return result


def persist_capture(session, org_id, run, item):
    from .adverse_memory import capture_provenance, lock_artifact_scope

    lock_artifact_scope(session, org_id, run.payload)
    try:
        observation = Observation.model_validate(item["observation"])
        variant, index = item["variant_id"], item["index"]
        if (
            variant not in {f"explicit-{n}" for n in range(run.payload["variant_count"])}
            or type(index) is not int
            or not 0 <= index < run.payload["trials"]
            or observation.correlation_id != trial_correlation(run.id, variant, index)
        ):
            raise ValueError()
    except (ValueError, KeyError, TypeError):
        raise HTTPException(422, "Observation is not assigned to this run") from None
    for existing in captured_trials(session, org_id, run.id):
        if (existing.payload["variant_id"], existing.payload["index"]) == (variant, index):
            if existing.payload["observation_digest"] != digest(observation):
                raise HTTPException(409, "Assigned trial already has different immutable evidence")
            return existing
    encoded_bytes = len(
        json.dumps(observation.model_dump(mode="json"), separators=(",", ":")).encode()
    )
    if encoded_bytes > MAX_CAPTURE_BYTES:
        raise HTTPException(413, "Observation exceeds evidence limit")
    require_capture_capacity(session, org_id, run.id)
    evaluated_at = now()
    result = evaluate_trace(
        run.payload["property_definition"],
        observation,
        qualified_witnesses=bound_source(run.payload, observation),
        now=evaluated_at,
    )
    from .security_memory import security_facts
    from .governance import current_policy

    return add_record(
        session,
        org_id,
        "trial_capture",
        {
            "run_id": str(run.id),
            "purpose": "OBSERVER_QUALIFICATION"
            if run.payload.get("qualification_case")
            else "ASSURANCE",
            "security_facts": security_facts(org_id, observation, result),
            "provenance": capture_provenance(run.payload, observation),
            "observed_fingerprint": observation.fingerprint.model_dump(mode="json")
            if observation.fingerprint
            else None,
            "variant_id": variant,
            "index": index,
            "observation_digest": digest(observation),
            "raw_evidence": store_observation(org_id, run.id, observation.model_dump(mode="json"),
                retention_days=current_policy(session, org_id)["raw_retention_days"]),
            "evaluation": result,
            "evaluated_at": evaluated_at.isoformat(),
            "capture_bytes": encoded_bytes,
        },
        {"run": run.id},
    )
