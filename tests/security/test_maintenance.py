from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import timedelta
from uuid import UUID, uuid4

from sqlalchemy import select

from threatveil import api, maintenance
from threatveil.auth import digest
from threatveil.core import run_procurement
from threatveil.db import Account, Lease, Membership, Outbox, Record, RunState, Schedule, now, transaction

from test_broker import claimed, queued_run as queued_run, signed


def scope_routes(monkeypatch, org_id):
    """Test the real reconciler without touching unrelated local development accounts."""
    @contextmanager
    def scoped_transaction(*args, **kwargs):
        with transaction(*args, **kwargs) as session:
            if args or kwargs:
                yield session
            else:
                class RouteSession:
                    def scalars(self, statement):
                        return session.scalars(statement.where(Outbox.organization_id == org_id))
                yield RouteSession()
    monkeypatch.setattr(maintenance, "transaction", scoped_transaction)


def test_unclaimed_dispatch_can_retry_but_claimed_expiry_never_reexecutes(queued_run, monkeypatch):
    h = queued_run
    scope_routes(monkeypatch, h["org_id"])
    with transaction(org_id=h["org_id"]) as session:
        lease = session.scalar(select(Lease).where(Lease.token_hash == digest(h["dispatch"]["bootstrap_token"])))
        lease.bootstrap_expires = now()-timedelta(seconds=1)
    result = maintenance.reconcile_runs()
    assert str(h["run_id"]) in result["retried_unclaimed"]
    with transaction(org_id=h["org_id"]) as session:
        state = session.get(RunState, (h["org_id"], h["run_id"]))
        assert state.status == "QUEUED" and not state.settled
    from threatveil.broker import prepare_dispatch
    h["dispatch"] = prepare_dispatch(h["org_id"], h["run_id"])
    lease, _, _ = claimed(h)
    with transaction(org_id=h["org_id"]) as session:
        session.get(Lease, UUID(lease["lease_id"])).lease_expires = now()-timedelta(seconds=1)
    result = maintenance.reconcile_runs()
    assert str(h["run_id"]) in result["timed_out"]
    assert not result["retried_unclaimed"]
    with transaction(org_id=h["org_id"]) as session:
        state = session.get(RunState, (h["org_id"], h["run_id"]))
        assert state.status == "TIMEOUT" and state.settled
        account = session.get(Account, h["org_id"])
        assert account.reserved == 0 and account.consumed == 4


def test_old_unclaimed_dispatch_cannot_requeue_past_absolute_run_deadline(queued_run, monkeypatch):
    h = queued_run
    scope_routes(monkeypatch, h["org_id"])
    future = now()+timedelta(minutes=21)
    monkeypatch.setattr(maintenance, "now", lambda: future)
    result = maintenance.reconcile_runs()
    assert str(h["run_id"]) in result["timed_out"]
    assert str(h["run_id"]) not in result["retried_unclaimed"]
    with transaction(org_id=h["org_id"]) as session:
        account = session.get(Account, h["org_id"])
        assert account.reserved == 0 and account.consumed == 0
        state = session.get(RunState, (h["org_id"], h["run_id"]))
        result_record = session.get(Record, state.result_id)
        assert result_record.payload["usage"]["units"] == 0


def test_completion_is_recovered_exactly_once_after_finalizer_crash(queued_run, monkeypatch):
    h = queued_run
    scope_routes(monkeypatch, h["org_id"])
    lease, key, _ = claimed(h)
    original = api.finish_run
    monkeypatch.setattr(api, "finish_run", lambda *_: None)
    result = run_procurement("fixed", trials=2, execution_id=str(h["run_id"]))
    response = h["worker"].post("/v1/complete", json=signed(lease, key, "complete", {"result": result}))
    assert response.status_code == 200
    with transaction(org_id=h["org_id"]) as session:
        assert not session.get(RunState, (h["org_id"], h["run_id"])).settled
    monkeypatch.setattr(api, "finish_run", original)
    assert str(h["run_id"]) in maintenance.reconcile_runs()["recovered"]
    assert not maintenance.reconcile_runs()["recovered"]
    with transaction(org_id=h["org_id"]) as session:
        results = list(session.scalars(select(Record).where(Record.kind == "result")))
        assert len(results) == 1
        account = session.get(Account, h["org_id"])
        assert account.reserved == 0 and account.consumed == 4


def due_schedule(h):
    assert h["owner"].post("/v1/commercial/subscription", json={"action": "upgrade", "plan": "pro",
        "idempotency_key": str(uuid4())}).status_code == 200
    demo = h["demo"]
    response = h["owner"].post("/v1/schedules", json={"name": "Test cadence", "interval_hours": 1,
        "run_template": {"system_id": demo["system"]["id"], "property_id": demo["property"]["id"],
                         "target_id": demo["target"]["id"], "version": "fixed", "trials": 1}})
    assert response.status_code == 201, response.text
    schedule_id = UUID(response.json()["id"])
    with transaction(org_id=h["org_id"]) as session:
        session.get(Schedule, schedule_id).next_at = now()-timedelta(days=7)
    return schedule_id


def test_due_schedule_coalesces_missed_periods_and_concurrent_ticks(queued_run, monkeypatch):
    h = queued_run
    scope_routes(monkeypatch, h["org_id"])
    schedule_id = due_schedule(h)
    with ThreadPoolExecutor(max_workers=2) as pool:
        runs = list(pool.map(lambda _: maintenance.tick_schedules(), range(2)))
    assert sum(len(group) for group in runs) == 1
    assert not maintenance.tick_schedules()
    with transaction(org_id=h["org_id"]) as session:
        assert session.get(Schedule, schedule_id).next_at > now()


def test_schedule_rechecks_current_creator_authority(queued_run, monkeypatch):
    h = queued_run
    scope_routes(monkeypatch, h["org_id"])
    schedule_id = due_schedule(h)
    user_id = UUID(h["owner"].get("/v1/auth/me").json()["user"]["id"])
    with transaction(user_id=user_id, org_id=h["org_id"]) as session:
        session.get(Membership, (h["org_id"], user_id)).role = "viewer"
    assert not maintenance.tick_schedules()
    with transaction(org_id=h["org_id"]) as session:
        assert not session.get(Schedule, schedule_id).enabled
        assert session.scalar(select(Record).where(Record.kind == "schedule_skipped")) is not None


def test_schedule_rechecks_current_commercial_entitlement(queued_run, monkeypatch):
    from threatveil import commercial

    h = queued_run
    scope_routes(monkeypatch, h["org_id"])
    schedule_id = due_schedule(h)
    response = h["owner"].post("/v1/commercial/subscription", json={"action": "cancel",
        "idempotency_key": str(uuid4())})
    assert response.status_code == 200
    boundary = commercial._stamp(response.json()["subscription"]["period_end"])
    monkeypatch.setattr(commercial, "now", lambda: boundary + timedelta(seconds=1))
    assert not maintenance.tick_schedules()
    with transaction(org_id=h["org_id"]) as session:
        assert session.get(Schedule, schedule_id).enabled
        skipped = session.scalar(select(Record).where(Record.kind == "schedule_skipped"))
        assert skipped.payload["status_code"] == 402
        assert skipped.payload["reason"]["resource"] == "release.automation"
