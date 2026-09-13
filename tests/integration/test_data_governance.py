"""Real tenant storage and migration-role erasure of newly created test organizations."""

from uuid import UUID, uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from threatveil import erasure
from threatveil.config import settings
from threatveil.db import Record, TargetState, add_record, transaction
from threatveil.evidence_storage import store_observation

from test_product import customer as customer, setup


def request_erasure(client):
    response = client.post('/v1/governance/deletion-requests', json={
        'organization_name': 'Isolated acceptance', 'reason': 'Synthetic acceptance cleanup',
        'export_acknowledged': True})
    assert response.status_code == 201, response.text
    return response.json()


def test_consent_is_explicit_and_never_enables_training(customer):
    value = customer.get('/v1/governance/policy').json()
    assert not value['abstract_features_opt_in'] and not value['model_training_enabled']
    body = {'reason': 'Reviewed customer data policy', 'model_training_opt_in': True}
    assert customer.post('/v1/governance/policy', json=body).status_code == 422
    body.update(contract_reference='SYNTHETIC-CONTRACT', raw_retention_days=1)
    assert customer.post('/v1/governance/policy', json=body).status_code == 201
    value = customer.get('/v1/governance/policy').json()
    assert value['model_training_opt_in'] and not value['model_training_enabled']
    assert not value['cross_customer_processing_enabled'] and value['raw_retention_days'] == 1


def test_deletion_freezes_writes_cancel_does_not_restore_target(customer):
    demo = setup(customer)
    request = request_erasure(customer)
    assert customer.post('/v1/demo/setup', json={}).status_code == 423
    assert customer.get('/v1/governance/policy').status_code == 200
    assert customer.post(f"/v1/governance/deletion-requests/{request['id']}/cancel").status_code == 201
    with transaction(org_id=UUID(demo['system']['organization_id'])) as session:
        assert session.get(TargetState, (UUID(demo['system']['organization_id']), UUID(demo['target']['id']))).revoked_at
    assert customer.get('/v1/governance/policy').json()['deletion_request_id'] is None


def test_runtime_cannot_enable_append_only_erasure(customer):
    demo = setup(customer)
    org = UUID(demo['system']['organization_id'])
    with pytest.raises(DBAPIError, match='append-only'):
        with transaction(org_id=org) as session:
            session.execute(text("SELECT set_config('tv.erase_org', :org, true)"), {'org': str(org)})
            session.execute(text('DELETE FROM records WHERE id=:id'), {'id': UUID(demo['system']['id'])})


@pytest.mark.parametrize('interrupt_cleanup', [False, True])
def test_scoped_local_erasure_and_authenticated_crash_recovery(customer, monkeypatch, tmp_path, interrupt_cleanup):
    demo = setup(customer)
    org = UUID(demo['system']['organization_id'])
    cfg = settings()
    monkeypatch.setattr(cfg, 'evidence_dir', tmp_path / 'evidence')
    run_id = uuid4()
    own = store_observation(org, run_id, {'synthetic': True})
    other = store_observation(uuid4(), uuid4(), {'other_tenant': 'preserve'})
    with transaction(org_id=org) as session:
        add_record(session, org, 'trial_capture', {'run_id': str(run_id), 'raw_evidence': own})
    requested = request_erasure(customer)
    monkeypatch.chdir(tmp_path)
    with pytest.raises(ValueError, match='exact organization'):
        erasure.erase_local_organization(org, requested['id'], str(uuid4()))
    cleanup = erasure._cleanup
    if interrupt_cleanup:
        def crash(*args):
            raise RuntimeError('injected crash after database commit')
        monkeypatch.setattr(erasure, '_cleanup', crash)
        with pytest.raises(RuntimeError, match='injected crash'):
            erasure.erase_local_organization(org, requested['id'], str(org))
        monkeypatch.setattr(erasure, '_cleanup', cleanup)
    result = erasure.erase_local_organization(org, requested['id'], str(org))
    assert result['status'] == 'CORE_ERASED'
    assert not (cfg.evidence_dir / own['key']).exists()
    assert (cfg.evidence_dir / other['key']).exists()
    with transaction(org_id=org) as session:
        assert session.get(Record, UUID(demo['system']['id'])) is None
    assert erasure.erase_local_organization(org, requested['id'], str(org))['status'] == 'CORE_ERASED'


def test_local_storage_rejects_symlinked_namespace(customer, monkeypatch, tmp_path):
    cfg = settings()
    monkeypatch.setattr(cfg, 'evidence_dir', tmp_path / 'evidence')
    cfg.evidence_dir.mkdir()
    outside = tmp_path / 'outside'
    outside.mkdir()
    (cfg.evidence_dir / 'raw').symlink_to(outside, target_is_directory=True)
    with pytest.raises(OSError):
        store_observation(uuid4(), uuid4(), {'secret': 'synthetic'})
    assert not list(outside.iterdir())
