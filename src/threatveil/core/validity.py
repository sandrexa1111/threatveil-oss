"""Versioned proof dependencies and deterministic, conservative evidence validity.

This module reasons about applicability, never establishes a security PASS. An
unchanged dependency graph is meaningful only within an explicitly reviewed scope.
"""

from datetime import datetime
from typing import Literal

from pydantic import Field, model_validator

from .contracts import Contract, SystemFingerprint, digest

ALGORITHM = "proof-scope-v1"


def canonical_fingerprint(value: dict | SystemFingerprint) -> dict:
    fingerprint = SystemFingerprint.model_validate(value)
    return {
        "schema_version": fingerprint.schema_version,
        "components": sorted(
            [
                {**c.model_dump(mode="json"), "dependencies": sorted(set(c.dependencies))}
                for c in fingerprint.components
            ],
            key=lambda c: (c["type"], c["id"]),
        ),
    }


def configuration_digest(value: dict | SystemFingerprint) -> str:
    """Content identity is independent of ordering and provenance relabeling."""
    value = canonical_fingerprint(value)
    return digest([{k: v for k, v in c.items() if k != "provenance"} for c in value["components"]])


def component_map(value):
    return {f'{c["type"]}:{c["id"]}': c for c in canonical_fingerprint(value)["components"]}


def known(component):
    return bool(
        component
        and component["provenance"] in {"OBSERVED", "DECLARED"}
        and (component.get("digest") or component.get("version"))
    )


def content(component):
    return {k: v for k, v in component.items() if k != "provenance"} if component else None


def change_set(previous, candidate):
    old, new = component_map(previous), component_map(candidate)
    changes, unknowns = [], []
    if not old or not new:
        unknowns.append("A complete previous and candidate fingerprint has not been supplied")
    for key in sorted(old.keys() | new.keys()):
        before, after = old.get(key), new.get(key)
        if before is not None and not known(before) or after is not None and not known(after):
            unknowns.append(f"Unknown or inferred component identity: {key}")
        if content(before) != content(after):
            changes.append({
                "component": key,
                "change_type": "ADDED" if before is None else "REMOVED" if after is None else "MODIFIED",
                "before": before,
                "after": after,
            })
    return {
        "algorithm_version": ALGORITHM,
        "previous_digest": configuration_digest(previous),
        "candidate_digest": configuration_digest(candidate),
        "changes": changes,
        "unknowns": sorted(set(unknowns)),
    }


class ScopeBinding(Contract):
    component: str = Field(min_length=3, max_length=301, pattern=r"^[^:]+:.+$")
    relationship: Literal["EXACT", "FAMILY", "SEMANTIC"] = "EXACT"
    compatible_digests: tuple[str, ...] = Field(default=(), max_length=50)
    rationale: str = Field(default="", max_length=2000)

    @model_validator(mode="after")
    def explicit_compatibility(self):
        if self.relationship != "EXACT" and not self.rationale.strip():
            raise ValueError("Family or semantic bindings require a reviewable rationale")
        if self.relationship == "EXACT" and self.compatible_digests:
            raise ValueError("Exact bindings cannot carry compatibility exceptions")
        if any(len(v) != 64 or any(c not in "0123456789abcdef" for c in v) for v in self.compatible_digests):
            raise ValueError("Compatibility must enumerate exact SHA-256 component digests")
        return self


class ProofScope(Contract):
    bindings: tuple[ScopeBinding, ...] = Field(default=(), max_length=500)
    coverage: Literal["FULL_FINGERPRINT", "REVIEWED_DEPENDENCIES", "UNKNOWN"] = "FULL_FINGERPRINT"
    authority: Literal["SYSTEM", "HUMAN_REVIEWED", "PROPOSED"] = "SYSTEM"
    review_reason: str = Field(default="", max_length=4000)
    max_age_seconds: int = Field(default=86400, ge=1, le=86400)
    limitations: tuple[str, ...] = ()

    @model_validator(mode="after")
    def reviewed_scope(self):
        keys = [b.component for b in self.bindings]
        if len(keys) != len(set(keys)):
            raise ValueError("Duplicate proof dependency")
        if self.coverage == "REVIEWED_DEPENDENCIES" and (
            self.authority != "HUMAN_REVIEWED" or not self.review_reason.strip() or not keys
        ):
            raise ValueError("Selective proof reuse requires nonempty security-reviewed bindings")
        return self


def invalidate(scope, established, candidate, *, created_at: datetime, evaluated_at: datetime):
    scope = ProofScope.model_validate(scope)
    old, new = component_map(established), component_map(candidate)
    delta = change_set(established, candidate)
    changed = {v["component"] for v in delta["changes"]}
    reasons, unknowns, affected = [], [], set()
    if not old or not new:
        unknowns.append("Evidence or candidate fingerprint is empty")
    if scope.coverage == "UNKNOWN" or scope.authority == "PROPOSED":
        unknowns.append("Proof dependency coverage has not been established")
    age = (evaluated_at - created_at).total_seconds()
    if age < 0 or age > scope.max_age_seconds:
        unknowns.append("Evidence is outside its declared validity window")
    bindings = {b.component: b for b in scope.bindings}
    roots = set(old) | set(new) | set(bindings) if scope.coverage == "FULL_FINGERPRINT" else set(bindings)
    # Follow both graphs so removed edges cannot hide an old dependency. Cycles
    # terminate; a dangling edge remains UNKNOWN even when its parent is unchanged.
    reachable, pending = set(), sorted(roots)
    while pending:
        key = pending.pop()
        if key in reachable:
            continue
        reachable.add(key)
        for mapping in (old, new):
            if key not in mapping:
                if key not in changed:
                    unknowns.append(f"Unresolved proof dependency: {key}")
                continue
            pending.extend(set(mapping[key]["dependencies"]) - reachable)
    # Any unknown candidate dimension widens the decision. It cannot prove that
    # an unobserved component is outside a reviewed dependency surface.
    for key in sorted(old.keys() | new.keys()):
        if key in old and not known(old[key]) or key in new and not known(new[key]):
            unknowns.append(f"Unknown identity or authority: {key}")
    if scope.coverage == "REVIEWED_DEPENDENCIES":
        added = set(new) - set(old)
        if added - reachable:
            unknowns.append("New components fall outside the reviewed dependency coverage")
    for key in sorted(changed & reachable):
        binding = bindings.get(key)
        after = new.get(key)
        compatible = bool(
            binding
            and binding.relationship != "EXACT"
            and scope.authority == "HUMAN_REVIEWED"
            and after and after.get("digest") in binding.compatible_digests
            and old.get(key)
            and old[key]["dependencies"] == after["dependencies"]
        )
        if compatible:
            reasons.append(f"Explicit reviewed {binding.relationship.lower()} compatibility: {key}")
        else:
            affected.add(key)
            reasons.append(f"Changed dependency invalidates this evidence: {key}")
    status = "VOID" if affected else "UNKNOWN" if unknowns else "STILL_VALID"
    if not reasons and status == "STILL_VALID":
        reasons.append("All dependencies and reviewed compatibility assumptions remain unchanged")
    return {
        "status": status,
        "reasons": sorted(set(reasons + unknowns)),
        "changed_dimensions": sorted(affected),
        "dependency_closure": sorted(reachable),
        "unknowns": sorted(set(unknowns)),
        "algorithm_version": ALGORITHM,
        "rule_provenance": "Deterministic exact content comparison and transitive dependency closure",
    }


def proof_obligation(property_id, definition, reasons, *, trials=5, variants=1):
    return {
        "property_id": property_id,
        "reasons": sorted(set(reasons)),
        "required_observers": list(definition.get("observation_contract", {}).get("required_witnesses", [])),
        "required_operations": list(definition.get("observation_contract", {}).get("required_operations", [])),
        "trials_per_variant": trials,
        "variant_count": variants,
        "legitimate_task": definition.get("legitimate_task", ""),
        "legitimate_control": definition.get("legitimate_control"),
        "fixture_requirement": "Reuse an authorized starting fixture and qualified observation boundary",
    }
