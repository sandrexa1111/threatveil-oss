"""A useful retry cannot erase a confirmed failure of the same observed artifact.

Only immutable control-plane records are read here. Worker-supplied provenance or
aggregate verdicts must never be accepted as inputs to this history index.
"""

from sqlalchemy import select, text

from .core.contracts import Observation, SystemFingerprint, digest
from .db import Record, RunState
from .observers import bound_source, observation_binding_digest


def fingerprint_digest(value):
    """Configuration identity excludes ordering and provenance-label changes."""
    fingerprint = SystemFingerprint.model_validate(value or {})
    if not fingerprint.components:
        return None
    return digest(
        sorted(
            [
                {
                    "type": c.type,
                    "id": c.id,
                    "version": None if c.digest else c.version,
                    "digest": c.digest,
                    "dependencies": sorted(set(c.dependencies)),
                }
                for c in fingerprint.components
            ],
            key=lambda c: (c["type"], c["id"]),
        )
    )


def exact_observed_candidate(plan, fingerprint):
    """The reviewed component and its signed content identity must match."""
    fingerprint = SystemFingerprint.model_validate(fingerprint or {})
    binding, candidate = plan.get("observation_binding") or {}, plan.get("candidate") or {}
    candidate_type = candidate.get("type")
    if candidate_type not in {"application_version", "model_version", "git_commit"}:
        return False
    component_type = (
        "application" if candidate_type == "git_commit" else candidate_type.removesuffix("_version")
    )
    matching = [
        c
        for c in fingerprint.components
        if c.type == component_type and c.id == binding.get("candidate_component_id")
    ]
    if len(matching) != 1:
        return False
    component = matching[0]
    if not (
        component.provenance == "OBSERVED"
        and component.version == plan.get("version") == candidate.get("version")
    ):
        return False
    if candidate_type == "git_commit":
        github = plan.get("github") or {}
        return bool(
            github.get("verified_workflow") is True
            and candidate.get("digest") == github.get("sha") == component.version
        )
    return bool(candidate.get("digest") and component.digest == candidate["digest"])


def _provenance(plan, fingerprint, qualified):
    binding = plan.get("observation_binding") or {}
    qualified = bool(qualified and binding.get("approved") and not plan.get("qualification_case"))
    return {
        "version": 2,
        "qualified": qualified,
        "candidate_observed": bool(qualified and exact_observed_candidate(plan, fingerprint)),
        "fingerprint_digest": fingerprint_digest(fingerprint),
        "binding_digest": observation_binding_digest(binding) if binding else None,
    }


def capture_provenance(plan, observation):
    """Persist with the server's evaluated capture, including interrupted runs."""
    observation = Observation.model_validate(observation)
    return _provenance(plan, observation.fingerprint, bool(bound_source(plan, observation)))


def _capture_profile(plan, capture):
    stored = capture.payload
    if stored.get("provenance", {}).get("version") == 2:
        return stored["provenance"]
    # Older captures already persist the fingerprint that was covered by both
    # signatures. A server-evaluated FAIL could only use the bound, verified source.
    # This does not re-trust expired raw evidence or a customer's claimed verdict.
    if stored.get("observed_fingerprint"):
        return _provenance(plan, stored["observed_fingerprint"], True)
    if stored.get("observation"):
        return capture_provenance(plan, stored["observation"])
    return None


def adverse_memory(session, org_id, run, result):
    """Read all known failures in the same scoped observed configuration.

    No date or latest-N cutoff clears a failure. Candidate.id is deliberately not
    a history key: it is a caller label, not a signed content identity. A complete
    PASS remains a sample PASS; callers must block release/fix eligibility instead
    of rewriting its observed sample verdict to FAIL.
    """
    response = {"blocked": False, "run_ids": [], "capture_ids": [], "uncertain_run_ids": []}
    plan = run.payload
    current = _provenance(
        plan,
        result.get("fingerprint"),
        result.get("qualification", {}).get("qualified") is True
        and result.get("candidate_observed") is True,
    )
    if not current["qualified"] or not current["candidate_observed"]:
        return response
    candidate = plan.get("candidate") or {}
    query = select(Record).where(
        Record.organization_id == org_id,
        Record.kind == "run",
        Record.id != run.id,
        *[
            Record.payload[field].astext == plan[field]
            for field in ("system_id", "property_id", "target_id")
        ],
        *[
            Record.payload["candidate"][field].astext == candidate.get(field)
            for field in ("type", "digest")
        ],
    )
    for previous in session.scalars(query):
        old_plan = previous.payload
        if old_plan.get("qualification_case") or not (
            old_plan.get("observation_binding") or {}
        ).get("approved"):
            continue
        if observation_binding_digest(old_plan["observation_binding"]) != current["binding_digest"]:
            continue
        failures = list(
            session.scalars(
                select(Record).where(
                    Record.organization_id == org_id,
                    Record.kind == "trial_capture",
                    Record.payload["run_id"].astext == str(previous.id),
                    Record.payload["evaluation"]["security_verdict"].astext == "FAIL",
                )
            )
        )
        for capture in failures:
            profile = _capture_profile(old_plan, capture)
            if profile is None:
                response["uncertain_run_ids"].append(str(previous.id))
            elif (
                profile["qualified"]
                and profile["candidate_observed"]
                and profile["binding_digest"] == current["binding_digest"]
                and profile["fingerprint_digest"] == current["fingerprint_digest"]
            ):
                response["run_ids"].append(str(previous.id))
                response["capture_ids"].append(str(capture.id))
        # Retain support for pre-capture completed results. New active external
        # executions always have captures, including failures interrupted later.
        if not failures:
            state = session.get(RunState, (org_id, previous.id))
            old_result = session.get(Record, state.result_id) if state and state.result_id else None
            if old_result and old_result.payload.get("security_verdict") == "FAIL":
                old = old_result.payload
                profile = _provenance(
                    old_plan,
                    old.get("fingerprint"),
                    old.get("qualification", {}).get("qualified") is True
                    and old.get("candidate_observed") is True,
                )
                if (
                    profile["candidate_observed"]
                    and profile["fingerprint_digest"] == current["fingerprint_digest"]
                ):
                    response["run_ids"].append(str(previous.id))
                elif not old.get("fingerprint", {}).get("components"):
                    response["uncertain_run_ids"].append(str(previous.id))
    for key in ("run_ids", "capture_ids", "uncertain_run_ids"):
        response[key] = sorted(set(response[key]))
    response["blocked"] = bool(response["run_ids"] or response["uncertain_run_ids"])
    return response


def lock_artifact_scope(session, org_id, plan):
    """Serialize evidence capture/finalization for one scoped artifact, never lock other tenants."""
    from .release_integrity import lock_system

    lock_system(session, org_id, plan.get("system_id"))
    candidate = plan.get("candidate") or {}
    identity = {
        "organization_id": str(org_id),
        **{key: plan.get(key) for key in ("system_id", "property_id", "target_id")},
        "candidate": {key: candidate.get(key) for key in ("type", "digest")},
    }
    key = int(digest(identity)[:16], 16) & ((1 << 63) - 1)
    session.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": key})
