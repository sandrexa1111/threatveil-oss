"""Extensible evidence-applicability rules. Unknowns broaden, never narrow, replay."""

from dataclasses import dataclass

from .contracts import SystemFingerprint, digest


@dataclass(frozen=True)
class ImpactRule:
    component_type: str
    tags: frozenset[str]
    all_properties: bool = False


RULES = {
    rule.component_type: rule
    for rule in (
        ImpactRule("model", frozenset(), True),
        ImpactRule("application", frozenset(), True),
        ImpactRule(
            "prompt", frozenset(("instructions", "untrusted_content", "tools", "data_boundary"))
        ),
        ImpactRule("tool", frozenset(("tools", "authorization"))),
        ImpactRule("mcp", frozenset(("mcp", "tools", "authorization"))),
        ImpactRule("permissions", frozenset(("authorization", "tenant", "approval", "payments"))),
        ImpactRule("rag", frozenset(("retrieval", "untrusted_content", "data_boundary"))),
        ImpactRule(
            "memory", frozenset(("memory", "persistence", "delegation", "untrusted_content"))
        ),
    )
}


def analyze_change(previous: dict, candidate: dict, properties: list[dict]) -> dict:
    before, after = (
        SystemFingerprint.model_validate(previous),
        SystemFingerprint.model_validate(candidate),
    )
    old = {(c.type, c.id): c for c in before.components}
    new = {(c.type, c.id): c for c in after.components}
    changed = [
        key
        for key in sorted(set(old) | set(new))
        if key not in old or key not in new or digest(old[key]) != digest(new[key])
    ]
    unknowns = []
    if not before.components:
        unknowns.append("Previous fingerprint has no components; evidence applicability is unknown")
    for component in before.components:
        if component.provenance == "UNKNOWN" or not (component.digest or component.version):
            unknowns.append(f"Previous component state is unknown: {component.type}:{component.id}")
    for component in after.components:
        if component.provenance == "UNKNOWN" or not (component.digest or component.version):
            unknowns.append(f"Unknown component state: {component.type}:{component.id}")
    if not after.components:
        unknowns.append("Candidate fingerprint has no components")
    for kind, key in changed:
        if kind not in RULES:
            unknowns.append(f"Unregistered impact mapping: {kind}:{key}")
    selected, excluded = [], []
    for prop in properties:
        definition = prop.get("definition", prop)
        identity = prop.get("id", definition.get("id"))
        tags = set(definition.get("tags", []))
        dependencies = set(definition.get("dependencies", []))
        reasons = list(unknowns)
        if changed and not dependencies:
            reasons.append("Dependency coverage missing; conservatively replay")
        for kind, key in changed:
            rule = RULES.get(kind)
            if rule and (
                rule.all_properties or f"{kind}:{key}" in dependencies or tags & rule.tags
            ):
                reasons.append(f"Changed {kind}:{key} affects this property's assumptions")
        entry = {"property_id": identity, "reasons": sorted(set(reasons))}
        if reasons:
            selected.append({**entry, "applicability": "UNKNOWN" if unknowns else "STALE"})
        else:
            excluded.append(
                {
                    **entry,
                    "applicability": "CURRENT",
                    "reasons": ["No changed declared dependency or applicable rule"],
                }
            )
    return {
        "algorithm_version": "declared-impact-v1",
        "previous_digest": digest(before),
        "candidate_digest": digest(after),
        "changed_components": [{"type": kind, "id": key} for kind, key in changed],
        "selected": selected,
        "excluded": excluded,
        "unknowns": unknowns,
        "selected_property_ids": [item["property_id"] for item in selected],
        "limitations": [
            "Declared dependency analysis; full-suite audits must validate selection.",
            "Selection does not execute tests or transfer historical verdicts.",
        ],
    }
