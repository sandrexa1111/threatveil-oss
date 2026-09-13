"""Current Assurance Passport: issuance, sharing and current-status checks.

A passport is a portable representation of one bounded current assurance case. It
is not a certification, a trust score or a statement that a system is safe. It says
which claims evidence currently supports for one system, environment and exact
state, which are stale, failed or unknown, what authority they govern, and where to
check whether that is still true.

Authenticity (offline, signed) and current status (online, recomputed) are separate
by design. A shared link carries an HMAC capability bound to one organization,
passport and share; it reveals the passport and its recomputed status, nothing else.
"""

import base64
import hmac
import re
import time
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from uuid import UUID, uuid4, uuid5

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fastapi import HTTPException
from sqlalchemy.exc import IntegrityError

from .change_assurance import history, projection
from .change_assurance_api import _support_digest, clearance_status
from .config import settings
from .db import Organization, Record, add_record, get_record, now, transaction

PROFILE = "threatveil-assurance-passport/v1"
SHARE_PROFILE = b"threatveil-passport-share/v1\n"
DEFAULT_DAYS = 30
MAX_DAYS = 90
PUBLIC_CHECKS_PER_MINUTE = 30
STATUS_TEXT = {
    "CURRENT": "This passport still describes the system as it is now.",
    "SUPERSEDED": "The system changed after this passport was issued. It remains an authentic historical "
                  "record, but it no longer describes the current system.",
    "REASSESS": "The evidence behind this passport moved; it must be re-established before it speaks for "
                "the current system.",
    "EXPIRED": "This passport has passed its validity window.",
    "REVOKED": "The issuer withdrew this passport.",
    "UNKNOWN": "ThreatVeil cannot currently establish this passport's status.",
}
LIMITATIONS = [
    "Covers only the listed claims for the named system, environment and exact state.",
    "Evidence comes from bounded, qualified verification; it does not describe behavior outside these claims.",
    "Authority listed here is the reviewed boundary; this document grants no permission.",
    "Offline verification proves authenticity at issue time only; current status requires the status check.",
]
DISCLOSURE = {
    "STANDARD": "Claims, authority labels, clearance and evidence status. Internal identifiers, resource names "
                "and interface names are withheld, so this passport can be shared outside the organization.",
    "INTERNAL": "Everything in STANDARD plus internal identifiers, resource names and interface names. Only for "
                "recipients already inside the organization's trust boundary.",
}
WITHHELD_IN_STANDARD = ["organization.id", "system.id", "environment.id", "state.id", "clearance.decision_id",
                        "authority.consequential_actions[].resources", "authority.interfaces_outside_boundary"]
NOT_CLAIMS = [
    "Not a certification, attestation of compliance or audit opinion.",
    "Not a trust score or a statement that the system is safe.",
    "Not evidence about any system, environment or state other than the one named.",
    "Not proof that an external control enforced this decision.",
]


def build_document(ctx, passport_id, organization_name, audience, days, stamp, *, disclosure="STANDARD"):
    """The signed document.

    Redaction happens here, at issuance, because a signature covers exactly what it
    signs: a share can never reveal less than the document it carries. STANDARD
    therefore withholds internal identifiers, resource names and interface names,
    and carries a stable pseudonymous system reference so an external recipient can
    still correlate successive passports for the same system.
    """
    from .assurance_intelligence import action_label, authority_map, clearance, evidence_currency

    view = clearance(ctx)
    currency = evidence_currency(ctx)
    authority = authority_map(ctx)
    groups = {"supported": [], "needs_fresh_evidence": [], "failed": [], "unknown": []}
    for claim in currency["claims"]:
        target = {"SUPPORTED": "supported", "NEEDS_FRESH_EVIDENCE": "needs_fresh_evidence",
                  "FAILED": "failed"}.get(claim["status"], "unknown")
        groups[target].append({
            "title": claim["title"], "statement": claim.get("statement"),
            "governs": [g["label"] for g in claim["governs"]], "legitimate_task": claim.get("legitimate_task"),
            "evidence": {"status": claim["applicability"], "meaning": claim["currency"],
                         "produced_at": (claim.get("evidence") or {}).get("produced_at"),
                         "security": claim["security"], "legitimate_task": claim["legitimate_task_outcome"]},
            "executable": claim["property_id"] is not None,
        })
    rows = (ctx.current or {}).get("properties", [])
    decision = view.get("decision") or {}
    envelope = ctx.envelope.payload if ctx.envelope else {}
    internal = disclosure == "INTERNAL"
    # Pseudonymous and stable: correlates this system's passports without revealing its identifier.
    reference = sha256(f"{ctx.org}:{ctx.system.id}".encode()).hexdigest()
    undeclared = authority["undeclared_interfaces"]
    return {
        "schema_version": PROFILE, "passport_id": str(passport_id), "issuer": settings().trust_issuer,
        "signature_profile": "dsse-in-toto-ed25519/v1", "algorithm": "Ed25519",
        "issued_at": stamp.isoformat(), "expires_at": (stamp + timedelta(days=days)).isoformat(),
        "audience": audience, "disclosure": disclosure, "disclosure_meaning": DISCLOSURE[disclosure],
        "withheld": [] if internal else list(WITHHELD_IN_STANDARD),
        "organization": {"name": organization_name, **({"id": str(ctx.org)} if internal else {})},
        "system": {"name": ctx.system.payload.get("name"), "reference": reference,
                   "description": ctx.system.payload.get("description"), "synthetic": ctx.synthetic,
                   **({"id": str(ctx.system.id)} if internal else {})},
        "environment": {"name": ctx.environment.payload["name"], "purpose": ctx.environment.payload["purpose"],
                        **({"id": str(ctx.environment.id)} if internal else {})},
        "state": {"digest": ctx.state.payload["state_digest"], "provenance": ctx.state.payload["provenance"],
                  "envelope_digest": ctx.state.payload["envelope_digest"],
                  **({"id": str(ctx.state.id)} if internal else {})},
        "authority": {"policy_epoch": envelope.get("policy_epoch"), "reviewed_until": envelope.get("expires_at"),
                      "grants_permissions": False,
                      "consequential_actions": [
                          {"action": a["action"], "label": a["label"], "assurance": a["assurance"],
                           **({"resources": a["resources"]} if internal else {"resource_count": len(a["resources"])})}
                          for a in authority["authorities"]],
                      "interfaces_outside_boundary": [i["label"] for i in undeclared] if internal else [],
                      "interfaces_outside_boundary_count": len(undeclared)},
        "clearance": {"state": view["state"], "label": view["label"], "meaning": view["meaning"],
                      "decision_action": decision.get("action"), "decision_status": view.get("decision_status"),
                      "last_current_clearance_at": view.get("last_current_clearance_at"),
                      **({"decision_id": decision.get("id")} if internal else {})},
        "claims": groups,
        "evidence_summary": {key: sum(1 for r in rows if r["applicability"] == key)
                             for key in ("CURRENT", "STALE", "INVALID", "UNKNOWN")},
        "support_digest": _support_digest(ctx.current) if ctx.current else None,
        "status_check": {
            "semantics": "Current status is recomputed on request: CURRENT, SUPERSEDED, REASSESS, EXPIRED or REVOKED.",
            "shared_link": "Use the status link shared with this passport. Offline verification never establishes current status.",
            "authenticated_path": f"/v1/passports/{passport_id}",
        },
        "verification": {"trust_directory": "/v1/trust/keys", "predicate_type": "https://threatveil.com/attestation/assurance-passport/v1",
                         "authenticity": "Verify the DSSE signature with a key resolved from the published trust directory.",
                         "tools": "threatveil verify-passport, or threatveil.sdk.passports.verify_passport_with_directory"},
        "powers_summary": [action_label(a["action"]) for a in authority["authorities"]],
        "limitations": LIMITATIONS + ([] if not ctx.synthetic else
                                      ["This passport describes a labelled synthetic demonstration system."]),
        "not_claims": NOT_CLAIMS,
    }


def issue(session, org, user_id, system_id, *, environment_id=None, audience, days=DEFAULT_DAYS,
          disclosure="STANDARD"):
    from .assurance_intelligence import clearance, load
    from .release_integrity import lock_system
    from .release_signing import signing_key
    from .sdk.passports import sign_passport

    if not 1 <= days <= MAX_DAYS:
        raise HTTPException(422, f"A passport is valid for between 1 and {MAX_DAYS} days")
    lock_system(session, org, system_id)
    ctx = load(session, org, system_id, environment_id)
    if ctx.state is None or ctx.current is None:
        raise HTTPException(409, "Establish a baseline before issuing a passport")
    organization = session.get(Organization, org)
    passport_id = uuid4()
    document = build_document(ctx, passport_id, organization.name if organization else "Organization",
                              audience, days, now(), disclosure=disclosure)
    envelope = sign_passport(document, signing_key())
    view = clearance(ctx)
    decision_id = (view.get("decision") or {}).get("id")
    references = {"system": system_id, "environment": ctx.environment.id, "state": ctx.state.id}
    if decision_id:
        references["decision"] = decision_id
    # Internal references live in the record, never in a document that may be shared.
    return add_record(session, org, "assurance_passport", {
        "schema_version": PROFILE, "system_id": str(system_id), "environment_id": str(ctx.environment.id),
        "state_id": str(ctx.state.id), "decision_id": decision_id, "decision_status": view.get("decision_status"),
        "disclosure": disclosure, "passport": document, "envelope": envelope, "issued_by": str(user_id),
        "audience": audience,
    }, references, record_id=passport_id)


def current_status(session, org, row):
    """Recompute whether a passport still describes the system. History is unchanged."""
    value = row.payload
    document = value["passport"]
    # Identifiers come from the record; a STANDARD document withholds them by design.
    state_id = value.get("state_id") or document["state"].get("id")
    decision_id = value.get("decision_id") or document["clearance"].get("decision_id")
    decision_status = value.get("decision_status") or document["clearance"].get("decision_status")
    stamp = now()
    result = {"passport_id": str(row.id), "checked_at": stamp.isoformat(), "issued_at": document["issued_at"],
              "state_digest_at_issue": document["state"]["digest"], "authentic_record_unchanged": True}
    revoked = [r for r in history(session, org, "passport_revocation", value["system_id"])
               if r.payload.get("passport_id") == str(row.id)]
    states = history(session, org, "system_state", value["system_id"], value["environment_id"])
    latest = states[0] if states else None
    result["current_state_digest"] = latest.payload["state_digest"] if latest else None
    if revoked:
        status = "REVOKED"
    elif datetime.fromisoformat(document["expires_at"]) <= stamp:
        status = "EXPIRED"
    elif latest is None:
        status = "UNKNOWN"
    elif (str(latest.id) != state_id if state_id else latest.payload["state_digest"] != document["state"]["digest"]):
        status = "SUPERSEDED"
    else:
        # A passport speaks for what it described at issue. If that included a current
        # clearance, the clearance must still hold; otherwise its described support must.
        current = projection(session, org, latest)
        if decision_id and decision_status == "CURRENT":
            decision = get_record(session, org, decision_id, "authorization_decision")
            reuse = current if decision.payload["state_id"] == str(latest.id) else None
            status = clearance_status(session, org, decision, current=reuse)
        elif _support_digest(current) == document.get("support_digest"):
            status = "CURRENT"
        elif any(datetime.fromisoformat(e["recorded_at"]) > row.created_at
                 for p in current["properties"] for e in p.get("affected_by", [])):
            status = "SUPERSEDED"
        else:
            status = "REASSESS"
    return {**result, "status": status, "text": STATUS_TEXT[status],
            "current_state_matches": bool(latest and latest.payload["state_digest"] == document["state"]["digest"])}


def list_item(session, org, row, *, with_status=True):
    document = row.payload["passport"]
    item = {"id": str(row.id), "issued_at": document["issued_at"], "expires_at": document["expires_at"],
            "audience": document["audience"], "clearance": document["clearance"]["label"],
            "environment": document["environment"]["name"], "state_digest": document["state"]["digest"],
            "disclosure": document.get("disclosure", "INTERNAL")}
    if with_status:
        item["current_status"] = current_status(session, org, row)
    return item


def detail(session, org, row):
    shares = [r for r in history(session, org, "passport_share", row.payload["system_id"])
              if r.payload.get("passport_id") == str(row.id)]
    revoked_shares = {r.payload["share_id"] for r in history(session, org, "passport_share_revocation", row.payload["system_id"])}
    return {"id": str(row.id), "passport": row.payload["passport"], "envelope": row.payload["envelope"],
            "current_status": current_status(session, org, row),
            "shares": [{"id": str(s.id), "label": s.payload["label"], "expires_at": s.payload["expires_at"],
                        "created_at": s.created_at.isoformat(), "revoked": str(s.id) in revoked_shares}
                       for s in shares]}


def disclosure_preview(session, org, row):
    """Exactly what an external recipient would see, before any link exists."""
    document = row.payload["passport"]
    profile = document.get("disclosure", "INTERNAL")
    actions = document["authority"]["consequential_actions"]
    return {
        "passport_id": str(row.id), "disclosure": profile,
        "meaning": document.get("disclosure_meaning", DISCLOSURE.get(profile)),
        "withheld": document.get("withheld", []),
        "discloses": {
            "organization_name": document["organization"]["name"],
            "system_name": document["system"].get("name"),
            "system_description": document["system"].get("description"),
            "environment": f"{document['environment']['name']} ({document['environment']['purpose']})",
            "clearance": document["clearance"]["label"],
            "claim_titles": [c["title"] for group in document["claims"].values() for c in group],
            "authority_labels": [a["label"] for a in actions],
            "resource_names": sorted({r for a in actions for r in a.get("resources", [])}),
            "interface_names": list(document["authority"].get("interfaces_outside_boundary") or []),
            "internal_identifiers": sorted(
                name for name, present in (
                    ("organization.id", "id" in document["organization"]), ("system.id", "id" in document["system"]),
                    ("environment.id", "id" in document["environment"]), ("state.id", "id" in document["state"]),
                    ("clearance.decision_id", "decision_id" in document["clearance"])) if present),
            "state_digest": document["state"]["digest"],
            "system_reference": document["system"].get("reference"),
        },
        "current_status": current_status(session, org, row), "passport": document,
        "note": "A shared link reveals exactly this document and a freshly recomputed status. Nothing else in "
                "your workspace is reachable through it.",
    }


def _share_key():
    from .release_signing import signing_key

    raw = signing_key().private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                      serialization.NoEncryption())
    # Domain-separated derivation: the attestation key never signs a capability token.
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"threatveil-passport-share-v1",
                info=b"passport share capability").derive(raw)


def make_token(org, passport_id, share_id, expires_at):
    body = (UUID(str(org)).bytes + UUID(str(passport_id)).bytes + UUID(str(share_id)).bytes
            + int(expires_at.timestamp()).to_bytes(8, "big"))
    mac = hmac.new(_share_key(), SHARE_PROFILE + body, sha256).digest()
    return base64.urlsafe_b64encode(body + mac).decode().rstrip("=")


def read_token(token):
    if not isinstance(token, str) or len(token) != 118 or not re.fullmatch(r"[A-Za-z0-9_-]+", token):
        raise HTTPException(404, "Shared passport not found")
    try:
        raw = base64.urlsafe_b64decode(token + "==")
    except ValueError:
        raise HTTPException(404, "Shared passport not found") from None
    body, mac = raw[:56], raw[56:]
    if len(raw) != 88 or not hmac.compare_digest(mac, hmac.new(_share_key(), SHARE_PROFILE + body, sha256).digest()):
        raise HTTPException(404, "Shared passport not found")
    expires = datetime.fromtimestamp(int.from_bytes(body[48:56], "big"), tz=timezone.utc)
    if expires <= now():
        raise HTTPException(410, "This shared passport link has expired")
    return UUID(bytes=body[:16]), UUID(bytes=body[16:32]), UUID(bytes=body[32:48]), expires


def share(session, org, user_id, row, *, label, days):
    if not 1 <= days <= MAX_DAYS:
        raise HTTPException(422, f"A share link is valid for between 1 and {MAX_DAYS} days")
    document = row.payload["passport"]
    expires = min(now() + timedelta(days=days), datetime.fromisoformat(document["expires_at"]))
    if expires <= now():
        raise HTTPException(409, "This passport has expired; issue a new one before sharing")
    if any(r.payload.get("passport_id") == str(row.id)
           for r in history(session, org, "passport_revocation", row.payload["system_id"])):
        raise HTTPException(409, "A revoked passport cannot be shared")
    share_id = uuid4()
    token = make_token(org, row.id, share_id, expires)
    record = add_record(session, org, "passport_share", {
        "schema_version": PROFILE, "system_id": row.payload["system_id"],
        "environment_id": row.payload["environment_id"], "passport_id": str(row.id), "label": label,
        "expires_at": expires.isoformat(), "token_digest": sha256(token.encode()).hexdigest(),
        "shared_by": str(user_id), "contacted_recipient": False,
    }, {"passport": row.id}, record_id=share_id)
    return record, token


def revoke(session, org, user_id, row, reason):
    return add_record(session, org, "passport_revocation", {
        "schema_version": PROFILE, "system_id": row.payload["system_id"], "passport_id": str(row.id),
        "reason": reason, "revoked_by": str(user_id)}, {"passport": row.id})


def revoke_share(session, org, user_id, share_row, reason):
    return add_record(session, org, "passport_share_revocation", {
        "schema_version": PROFILE, "system_id": share_row.payload["system_id"], "share_id": str(share_row.id),
        "passport_id": share_row.payload["passport_id"], "reason": reason, "revoked_by": str(user_id)},
        {"share": share_row.id})


def record_check(session, org, name, *, bucket_seconds=3600, **dimensions):
    """At most one minimized service record per dimension set and time bucket."""
    bucket = int(time.time() // bucket_seconds)
    key = ":".join(f"{k}={dimensions[k]}" for k in sorted(dimensions))
    identifier = uuid5(UUID(str(org)), f"{name}:{key}:{bucket}")
    if session.get(Record, identifier) is not None:
        return
    try:
        with session.begin_nested():
            add_record(session, org, "service_metric", {
                "schema_version": "service-metric-v1", "name": name, "bucket": bucket,
                "bucket_seconds": bucket_seconds, **{k: str(v) for k, v in dimensions.items()},
                "source": "SERVER_OBSERVED", "data_class": "SERVICE_OPERATION"}, record_id=identifier)
    except IntegrityError:
        pass


def _limit(session, share_id):
    from sqlalchemy.dialects.postgresql import insert
    from .db import RateBucket

    key = sha256(f"passport-share|{share_id}".encode()).hexdigest()
    statement = insert(RateBucket).values(key=key, window=int(time.time() // 60), count=1)
    count = session.execute(statement.on_conflict_do_update(
        index_elements=["key", "window"], set_={"count": RateBucket.count + 1}).returning(RateBucket.count)).scalar_one()
    if count > PUBLIC_CHECKS_PER_MINUTE:
        raise HTTPException(429, "Status check rate limit reached; try again shortly")


def public_view(token):
    """What an external party sees through a shared link: the passport, verification
    material pointers and a freshly recomputed status. Nothing else is reachable."""
    org, passport_id, share_id, expires = read_token(token)
    with transaction(org_id=org) as session:
        try:
            row = get_record(session, org, passport_id, "assurance_passport")
            share_row = get_record(session, org, share_id, "passport_share")
        except HTTPException:
            raise HTTPException(404, "Shared passport not found") from None
        if share_row.payload["passport_id"] != str(passport_id) or not hmac.compare_digest(
                share_row.payload["token_digest"], sha256(token.encode()).hexdigest()):
            raise HTTPException(404, "Shared passport not found")
        if any(r.payload.get("share_id") == str(share_id)
               for r in history(session, org, "passport_share_revocation", row.payload["system_id"])):
            raise HTTPException(410, "The issuer withdrew this shared link")
        _limit(session, share_id)
        status = current_status(session, org, row)
        record_check(session, org, "passport.status_checked", share=share_id, passport=passport_id)
        return {"schema_version": "threatveil-shared-passport/v1", "passport": row.payload["passport"],
                "envelope": row.payload["envelope"], "current_status": status,
                "share": {"label": share_row.payload["label"], "expires_at": expires.isoformat()},
                "verification": {"trust_directory": "/v1/trust/keys",
                                 "authenticity_and_status_are_separate": True,
                                 "note": "Verify the signature to establish authenticity at issue time. "
                                         "The status above is recomputed now and is not part of the signed record."}}
