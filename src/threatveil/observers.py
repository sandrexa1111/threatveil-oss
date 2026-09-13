"""Public-key bound observation sources and separately signed ground-truth digests.

Signature possession is not certification of collector correctness. Qualification
also requires active assigned controls, independent deployment review and approval.
"""

import base64
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from fastapi import HTTPException
from sqlalchemy import select
from pydantic import Field, model_validator

from .core.contracts import Observation, PropertyDefinition, digest
from .db import Record, get_record
from .schemas import Input


class ObserverInput(Input):
    system_id: UUID
    property_id: UUID
    target_id: UUID
    source_id: str = Field(min_length=1, max_length=150)
    source_version: str = Field(min_length=1, max_length=150)
    candidate_component_id: str = Field(min_length=1, max_length=200)
    public_key: str = Field(min_length=40, max_length=100)
    ground_truth_public_key: str = Field(min_length=40, max_length=100)
    initial_state_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    fixture_reference: str = Field(min_length=1, max_length=300)
    independence_review: str = Field(min_length=40, max_length=4000)

    @model_validator(mode="after")
    def keys(self):
        decoded = [base64.b64decode(value, validate=True)
                   for value in (self.public_key, self.ground_truth_public_key)]
        for key in decoded:
            Ed25519PublicKey.from_public_bytes(key)
        if decoded[0] == decoded[1]:
            raise ValueError("Observer and ground-truth collectors require distinct signing keys")
        self.public_key, self.ground_truth_public_key = (
            base64.b64encode(key).decode() for key in decoded
        )
        return self


class ObserverApproval(Input):
    permitted_run_id: UUID
    prohibited_run_id: UUID
    missing_run_id: UUID
    review_note: str = Field(min_length=20, max_length=4000)


def signing_message(observation: Observation, role: str):
    payload = observation.model_dump(mode="json", exclude={"attestations"})
    return ("threatveil-observation-v1:" + role + ":" + digest(payload)).encode()


def attestations_valid(observation, binding):
    obs = Observation.model_validate(observation)
    if obs.initial_state_digest != binding.get("initial_state_digest"):
        return False
    try:
        if base64.b64decode(binding["public_key"], validate=True) == base64.b64decode(
                binding["ground_truth_public_key"], validate=True):
            return False
    except (ValueError, KeyError, TypeError):
        return False
    for role, key_field in (
        ("observer", "public_key"),
        ("ground_truth", "ground_truth_public_key"),
    ):
        try:
            key = Ed25519PublicKey.from_public_bytes(
                base64.b64decode(binding[key_field], validate=True)
            )
            key.verify(
                base64.b64decode(obs.attestations[role], validate=True), signing_message(obs, role)
            )
        except (ValueError, KeyError, TypeError, InvalidSignature):
            return False
    sources = [w for w in obs.witnesses if w.id == binding["source_id"]]
    return not sources or all(w.source_version == binding["source_version"] for w in sources)


def bound_source(plan, observation):
    binding = plan.get("observation_binding")
    if not binding or not attestations_valid(observation, binding):
        return ()
    prop = PropertyDefinition.model_validate(plan["property_definition"])
    if binding["source_id"] not in prop.observation_contract.required_witnesses:
        return ()
    if not binding.get("approved") and not plan.get("qualification_case"):
        return ()
    return {binding["source_id"]: binding["source_version"]}


def observation_binding_digest(binding):
    """Historical compatibility follows the reviewed source and its exact scope."""
    fields = ("system_id", "property_id", "target_id", "source_id", "source_version",
              "candidate_component_id", "public_key", "ground_truth_public_key",
              "initial_state_digest", "fixture_reference")
    return digest({field: binding.get(field) for field in fields})


def active_observer(session, org_id, observer_id):
    observer = get_record(session, org_id, observer_id, "observer")
    family = observer.payload.get("supersedes_id", str(observer.id))
    revoked = session.scalar(
        select(Record.id).where(
            Record.organization_id == org_id,
            Record.kind == "observer_revocation",
            Record.payload["family_id"].astext == family,
        )
    )
    if revoked:
        raise HTTPException(403, "Observation source has been revoked")
    return observer
