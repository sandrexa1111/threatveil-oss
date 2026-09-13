from copy import deepcopy
from datetime import timedelta
from types import SimpleNamespace
from uuid import uuid4
import os

import pytest
from fastapi import HTTPException

from threatveil import evidence_storage as storage
from threatveil.db import now


@pytest.fixture
def local_store(tmp_path, monkeypatch):
    monkeypatch.setattr(
        storage, "settings", lambda: SimpleNamespace(is_local=True, evidence_dir=tmp_path)
    )
    return tmp_path


def test_local_object_is_immutable_private_and_tenant_bound(local_store):
    org, run = uuid4(), uuid4()
    content = {"receipts": [{"value": "<script>untrusted payload</script>"}]}
    ref = storage.store_observation(org, run, content)
    assert storage.load_observation(org, run, ref) == content
    assert storage.store_observation(org, run, content)["sha256"] == ref["sha256"]
    assert (local_store / ref["key"]).stat().st_mode & 0o777 == 0o600
    with pytest.raises(RuntimeError, match="scope"):
        storage.load_observation(uuid4(), run, ref)
    with pytest.raises(ValueError):
        storage.object_key(org, run, "../secret")
    (local_store / ref["key"]).write_bytes(b"tampered")
    with pytest.raises(RuntimeError, match="integrity"):
        storage.load_observation(org, run, ref)
    with pytest.raises(RuntimeError, match="integrity"):
        storage.store_observation(org, run, content)


def test_expired_raw_evidence_never_silently_substitutes(local_store):
    org, run = uuid4(), uuid4()
    ref = storage.store_observation(org, run, {"sample": True})
    expired = {**ref, "expires_at": (now() - timedelta(seconds=1)).isoformat()}
    with pytest.raises(HTTPException) as error:
        storage.load_observation(org, run, expired)
    assert error.value.status_code == 410
    (local_store / ref["key"]).unlink()
    with pytest.raises(HTTPException) as error:
        storage.load_observation(org, run, ref)
    assert error.value.status_code == 410


def test_retention_removes_only_expired_raw_namespace(local_store):
    org, run = uuid4(), uuid4()
    old = storage.store_observation(org, run, {"old": True})
    fresh = storage.store_observation(org, run, {"fresh": True})
    path = local_store / old["key"]
    elapsed = (now() - timedelta(days=31)).timestamp()
    os.utime(path, (elapsed, elapsed))
    keep = local_store / "customer-note.json"
    keep.write_text("keep")
    os.utime(keep, (elapsed, elapsed))
    assert storage.purge_local_expired() == 1
    assert keep.exists() and (local_store / fresh["key"]).exists()


def test_gcs_uses_exact_generation_and_bounded_read(monkeypatch):
    from google.cloud import storage as gcs
    from google.api_core.exceptions import PreconditionFailed

    org, run, objects = uuid4(), uuid4(), {}

    class Blob:
        def __init__(self, key, generation=None):
            self.key, self.generation = key, generation

        def upload_from_string(self, data, **kwargs):
            assert kwargs["if_generation_match"] == 0
            if self.key in objects:
                raise PreconditionFailed("existing")
            objects[self.key] = data
            self.generation = 7

        def reload(self, **kwargs):
            self.generation, self.size = 7, len(objects[self.key])

        def download_as_bytes(self, **kwargs):
            assert kwargs["if_generation_match"] == 7
            if "start" in kwargs:
                assert kwargs["start"] == 0 and kwargs["end"] == storage.MAX_OBJECT_BYTES
            return objects[self.key]

    class Bucket:
        def blob(self, key, generation=None):
            return Blob(key, generation)

    class Client:
        def bucket(self, name):
            assert name == "configured-evidence"
            return Bucket()

    monkeypatch.setattr(gcs, "Client", Client)
    monkeypatch.setattr(
        storage,
        "settings",
        lambda: SimpleNamespace(is_local=False, evidence_bucket="configured-evidence"),
    )
    ref = storage.store_observation(org, run, {"sample": True})
    assert ref["generation"] == "7"
    assert storage.store_observation(org, run, {"sample": True})["sha256"] == ref["sha256"]
    assert storage.load_observation(org, run, ref) == {"sample": True}
    corrupt = deepcopy(ref)
    corrupt["bytes"] += 1
    with pytest.raises(RuntimeError, match="integrity"):
        storage.load_observation(org, run, corrupt)
