"""Offline passport verification, the Python gate client and its fail-closed helper."""

import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from typer.testing import CliRunner

from threatveil.cli import app
from threatveil.sdk.client import ThreatVeilClient
from threatveil.sdk.passports import sign_passport
from threatveil.sdk.trust_directory import key_id, serialize_directory

STAMP = datetime(2026, 9, 11, 12, 0, tzinfo=timezone.utc)


def passport(system="00000000-0000-4000-8000-00000000000a"):
    return {"schema_version": "threatveil-assurance-passport/v1", "passport_id": "p-1", "issuer": "threatveil",
            "signature_profile": "dsse-in-toto-ed25519/v1", "algorithm": "Ed25519",
            "issued_at": STAMP.isoformat(), "expires_at": (STAMP + timedelta(days=30)).isoformat(),
            "organization": {"id": "org", "name": "Vendor"}, "system": {"id": system, "name": "Finance Agent"},
            "state": {"id": "s", "digest": "a" * 64}, "clearance": {"label": "Cleared"}}


def pem(key):
    return key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def test_cli_verifies_a_passport_with_a_key_or_directory_and_rejects_tampering(tmp_path):
    key = Ed25519PrivateKey.generate()
    envelope = sign_passport(passport(), key)
    (tmp_path / "passport.json").write_text(json.dumps({"envelope": envelope}))
    (tmp_path / "key.pem").write_bytes(pem(key))
    directory = serialize_directory("threatveil", [{
        "keyid": key_id(key.public_key()), "algorithm": "Ed25519", "signature_profile": "dsse-in-toto-ed25519/v1",
        "status": "ACTIVE", "valid_from": "2026-01-01T00:00:00+00:00", "valid_until": "2031-01-01T00:00:00+00:00",
        "revoked_at": None, "public_key_pem": pem(key).decode(), "supersedes": None}])
    (tmp_path / "directory.json").write_text(json.dumps(directory))
    runner = CliRunner()
    by_key = runner.invoke(app, ["verify-passport", str(tmp_path / "passport.json"), "--public-key", str(tmp_path / "key.pem")])
    assert by_key.exit_code == 0, by_key.output
    assert json.loads(by_key.output)["authenticity_only"] is True
    by_directory = runner.invoke(app, ["verify-passport", str(tmp_path / "passport.json"),
                                       "--directory", str(tmp_path / "directory.json"), "--passport-id", "p-1"])
    assert by_directory.exit_code == 0, by_directory.output
    assert "Not established offline" in json.loads(by_directory.output)["current_status"]
    tampered = dict(envelope, payload=sign_passport(passport("00000000-0000-4000-8000-00000000000b"), key)["payload"])
    (tmp_path / "tampered.json").write_text(json.dumps(tampered))
    assert runner.invoke(app, ["verify-passport", str(tmp_path / "tampered.json"), "--public-key", str(tmp_path / "key.pem")]).exit_code == 1
    other = Ed25519PrivateKey.generate()
    (tmp_path / "other.pem").write_bytes(pem(other))
    assert runner.invoke(app, ["verify-passport", str(tmp_path / "passport.json"), "--public-key", str(tmp_path / "other.pem")]).exit_code == 1
    assert runner.invoke(app, ["verify-passport", str(tmp_path / "passport.json")]).exit_code != 0


def test_python_gate_client_is_scoped_read_only_and_fails_closed():
    seen = []

    def handler(request):
        seen.append(request)
        future = (datetime.now(timezone.utc) + timedelta(seconds=60)).isoformat()
        return httpx.Response(200, json={"status": "CURRENT", "action": "ALLOW", "cleared": True,
                                         "authorizes": False, "freshness": {"valid_until": future}})

    client = ThreatVeilClient("https://control.example", "tvk_synthetic", http_client=httpx.Client(transport=httpx.MockTransport(handler)))
    system = "00000000-0000-4000-8000-00000000000a"
    answer = client.current_assurance(system, action="invoice.update", expected_state_digest="b" * 64, consumer="ci-gate")
    assert seen[0].method == "GET" and seen[0].url.path == f"/v1/systems/{system}/assurance/current"
    assert seen[0].url.params["action"] == "invoice.update" and seen[0].headers["x-threatveil-consumer"] == "ci-gate"
    assert ThreatVeilClient.is_cleared(answer)
    assert not ThreatVeilClient.is_cleared({**answer, "status": "UNKNOWN", "cleared": False})
    assert not ThreatVeilClient.is_cleared({**answer, "action": "REQUIRE_APPROVAL"})
    assert not ThreatVeilClient.is_cleared({**answer, "freshness": {"valid_until": "2000-01-01T00:00:00+00:00"}})
    assert not ThreatVeilClient.is_cleared({"cleared": True})
    with pytest.raises(ValueError):
        client.current_assurance("../billing")
    with pytest.raises(ValueError):
        client.current_assurance(system, consumer="Bad Label")
    assert len(seen) == 1
