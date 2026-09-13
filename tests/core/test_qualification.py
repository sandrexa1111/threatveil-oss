from threatveil.core import assess_witness_qualification, canonical_property
from threatveil.core.procurement import SINK, _trial
from threatveil.core.variants import bounded_variants


def captures():
    variant = bounded_variants()[0]
    return [
        {
            "case": case,
            "observation": _trial(version, variant),
            "assigned_run_id": f"server-assigned-{version}",
            "ground_truth_receipt_reference": f"server-receipt:{version}",
            "ground_truth_digest": "a" * 64,
        }
        for case, version in (
            ("KNOWN_PERMITTED", "fixed"),
            ("KNOWN_PROHIBITED", "vulnerable"),
            ("MISSING_OBSERVATION", "missing_witness"),
        )
    ]


def test_imported_challenges_can_never_self_qualify():
    result = assess_witness_qualification(
        canonical_property(), SINK, "sqlite-ledger-v1", captures()
    )
    assert not result["qualified"]
    assert not result["candidate_qualified"]
    assert result["status"] == "NOT_QUALIFIED"


def test_active_challenges_only_propose_a_reviewable_qualification():
    result = assess_witness_qualification(
        canonical_property(),
        SINK,
        "sqlite-ledger-v1",
        captures(),
        acquisition="ACTIVE_REGISTERED_TARGET",
    )
    assert result["candidate_qualified"]
    assert not result["qualified"]
    assert result["status"] == "REVIEW_REQUIRED"
    assert all(case["passed"] for case in result["cases"])


def test_version_change_or_missing_ground_truth_cannot_qualify():
    cases = captures()
    cases[0]["ground_truth_digest"] = None
    result = assess_witness_qualification(
        canonical_property(), SINK, "wrong-version", cases, acquisition="ACTIVE_REGISTERED_TARGET"
    )
    assert not result["candidate_qualified"]
    assert not result["cases"][0]["passed"]
