"""Portability invariant: every record kind ThreatVeil writes for a tenant is exportable.

A customer must be able to take their whole security memory with them. A new record
kind that nobody added to the export allowlist would silently become unportable, so
this test reads the source and fails instead.
"""

import re
from pathlib import Path

from threatveil.memory_export import EXPORT_KINDS, NEVER_EXPORTED

SOURCE = Path(__file__).resolve().parents[2] / "src" / "threatveil"
WRITE = re.compile(r'add_record\(\s*\w+,\s*[\w\.\[\]"\']+,\s*"([a-z_]+)"')


def written_kinds():
    kinds = set()
    for path in SOURCE.rglob("*.py"):
        kinds.update(WRITE.findall(path.read_text()))
    return kinds


def test_every_tenant_record_kind_is_exportable_or_explicitly_excluded():
    missing = sorted(written_kinds() - set(EXPORT_KINDS) - set(NEVER_EXPORTED))
    assert not missing, f"These record kinds are written but neither exportable nor excluded: {missing}"


def test_the_exclusions_are_deliberate_and_never_exported():
    # A credential record names a secret-manager version; it is a deployment secret.
    assert NEVER_EXPORTED == {"credential"}
    assert not set(NEVER_EXPORTED) & set(EXPORT_KINDS)


def test_the_whole_change_assurance_record_set_is_exportable():
    """The records a customer would need to reconstruct their assurance history elsewhere."""
    assert {
        "system", "environment", "permission_envelope", "system_state", "change_event", "source_change",
        "source_batch", "source_assertion", "source_health", "connector_installation", "dependency_mapping",
        "dependency_mapping_proposal", "dependency_mapping_review", "claim_definition", "assurance_case",
        "authorization_decision", "enforcement_request", "enforcement_acknowledgement", "status_event",
        "assurance_passport", "passport_share", "passport_revocation", "consequence_feedback",
        "proposed_change_assessment", "observer_definition", "business_effect_observation",
        "auto_reproof_policy", "auto_reproof_execution", "ai_usage", "audit",
    } <= set(EXPORT_KINDS)
    assert all(kind.islower() and kind.replace("_", "").isalnum() for kind in EXPORT_KINDS)
