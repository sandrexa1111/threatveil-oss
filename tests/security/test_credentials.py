from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException

from threatveil import credentials

from test_tokens import account as account


def test_production_reference_requires_exact_organization_project_and_numeric_version(monkeypatch):
    org = uuid4()
    cfg = SimpleNamespace(is_local=False, secret_project="approved-project")  # noqa: S106 - project ID, not a secret
    monkeypatch.setattr(credentials, "settings", lambda: cfg)
    credentials.validate_reference(f"projects/approved-project/secrets/tv-org-{org}-provider/versions/3", org)
    invalid = [f"projects/approved-project/secrets/tv-org-{uuid4()}-provider/versions/3",
               f"projects/other-project/secrets/tv-org-{org}-provider/versions/3",
               f"projects/approved-project/secrets/tv-org-{org}-provider/versions/latest",
               f"projects/approved-project/secrets/tv-org-{org}-provider/versions/0",
               f"projects/approved-project/secrets/tv-org-{org}-../versions/3", "local:test:key"]
    for value in invalid:
        with pytest.raises(HTTPException) as exc:
            credentials.validate_reference(value, org)
        assert exc.value.status_code == 422


def test_credential_api_rejects_raw_secret_fields_and_lists_only_references(account):
    owner, _, _ = account
    response = owner.post("/v1/credentials", json={"name": "Test provider", "secret_version": "local:test:provider"})
    assert response.status_code == 201
    assert "value" not in response.json()
    invalid = owner.post("/v1/credentials", json={"name": "Raw secret", "secret_version": "local:test:provider",
                                                  "value": "synthetic-do-not-store-secret"})
    assert invalid.status_code == 422
    listing = owner.get("/v1/credentials")
    assert listing.status_code == 200
    assert "synthetic-do-not-store-secret" not in listing.text
