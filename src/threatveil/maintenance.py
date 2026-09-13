"""Idempotent recovery and scheduled verification; no automatic replay of claimed runs."""

from datetime import timedelta
from uuid import UUID

from fastapi import BackgroundTasks, HTTPException
from sqlalchemy import select

from .auth import Actor, SECURITY
from .config import settings
from .db import (
    Lease,
    Membership,
    Outbox,
    Record,
    RunState,
    Schedule,
    User,
    add_record,
    context,
    get_record,
    now,
    transaction,
)
from .schemas import RunInput


def tick_schedules():
    from .api import create_run, execute_run

    # Global routes contain scheduling identifiers, never execution specifications.
    with transaction() as session:
        routes = [
            (r.id, r.organization_id, r.payload["schedule_id"])
            for r in session.scalars(
                select(Outbox)
                .where(Outbox.topic == "schedule.tick", Outbox.status == "active")
                .order_by(Outbox.created_at)
                .limit(1000)
            )
        ]
    launched = []
    for route_id, org_id, schedule_id in routes:
        run_id = None
        with transaction(org_id=org_id) as session:
            schedule = session.scalar(
                select(Schedule)
                .where(Schedule.id == UUID(schedule_id))
                .with_for_update(skip_locked=True)
            )
            if schedule is None:
                continue
            if not schedule.enabled:
                session.get(Outbox, route_id).status = "disabled"
                continue
            if schedule.next_at > now():
                continue
            context(session, schedule.user_id, org_id)
            membership = session.get(Membership, (org_id, schedule.user_id))
            user = session.get(User, schedule.user_id)
            try:
                if not membership or membership.role not in SECURITY:
                    raise HTTPException(403, "Schedule creator no longer has security authority")
                actor = Actor(
                    user.id, org_id, membership.role, user.email, user.name, "", "schedule"
                )
                plan = RunInput.model_validate(
                    {
                        **schedule.run_template,
                        "idempotency_key": f"schedule:{schedule.id}:{int(schedule.next_at.timestamp())}",
                    }
                )
                result = create_run(plan, BackgroundTasks(), actor)
                run_id = UUID(result["id"])
                add_record(
                    session,
                    org_id,
                    "schedule_execution",
                    {
                        "schedule_id": str(schedule.id),
                        "run_id": str(run_id),
                        "due_at": schedule.next_at.isoformat(),
                    },
                    {"run": run_id},
                )
            except HTTPException as error:
                add_record(
                    session,
                    org_id,
                    "schedule_skipped",
                    {
                        "schedule_id": str(schedule.id),
                        "reason": error.detail,
                        "status_code": error.status_code,
                    },
                )
                if error.status_code in (401, 403, 404, 422):
                    schedule.enabled = False
            # Missed periods are coalesced. No catch-up execution storm.
            schedule.next_at = now() + timedelta(hours=schedule.interval_hours)
        if run_id:
            if settings().is_local:
                execute_run(org_id, run_id)
            launched.append(str(run_id))
    return launched


def reconcile_runs():
    from .api import finish_run

    with transaction() as session:
        routes = [
            (r.id, r.organization_id, UUID(r.payload["run_id"]))
            for r in session.scalars(
                select(Outbox)
                .where(Outbox.topic == "run.dispatch", Outbox.status != "settled")
                .order_by(Outbox.created_at)
                .limit(1000)
            )
        ]
    recovered, timed_out, retried = [], [], []
    for route_id, org_id, run_id in routes:
        result = None
        with transaction(org_id=org_id) as session:
            state = session.scalar(
                select(RunState)
                .where(RunState.organization_id == org_id, RunState.run_id == run_id)
                .with_for_update(skip_locked=True)
            )
            if state is None:
                continue
            route = session.get(Outbox, route_id)
            if state.settled:
                route.status = "settled"
                continue
            completion = session.scalar(
                select(Record).where(
                    Record.organization_id == org_id,
                    Record.kind == "worker_completion",
                    Record.payload["run_id"].astext == str(run_id),
                )
            )
            if completion:
                result = completion.payload["result"]
                recovered.append(str(run_id))
            else:
                leases = list(
                    session.scalars(
                        select(Lease)
                        .where(Lease.organization_id == org_id, Lease.run_id == run_id)
                        .order_by(Lease.fence.desc())
                    )
                )
                latest = leases[0] if leases else None
                expired = latest and (
                    (latest.claimed_at and latest.lease_expires <= now())
                    or (not latest.claimed_at and latest.bootstrap_expires <= now())
                )
                run = get_record(session, org_id, run_id, "run")
                absolute_deadline_reached = run.created_at + timedelta(minutes=20) <= now()
                if (
                    latest
                    and expired
                    and not latest.claimed_at
                    and len(leases) < 3
                    and not absolute_deadline_reached
                ):
                    latest.revoked = True
                    state.status, route.status = "QUEUED", "pending"
                    retried.append(str(run_id))
                    continue
                if expired or absolute_deadline_reached:
                    for lease in leases:
                        lease.revoked = True
                    result = {
                        "security_verdict": "INCONCLUSIVE",
                        "task_outcome": "UNKNOWN",
                        "execution_status": "TIMEOUT",
                        "limitations": [
                            "Execution expired without complete evidence. Claimed work is never automatically replayed."
                        ],
                    }
                    timed_out.append(str(run_id))
        if result is not None:
            finish_run(org_id, run_id, result)
    return {"recovered": recovered, "timed_out": timed_out, "retried_unclaimed": retried}


def reconcile():
    from .evidence_storage import purge_local_expired
    from .integrations.revenue_delivery import deliver_pending
    from .integrations.github_release import reconcile_github_checks

    return {
        **reconcile_runs(),
        "scheduled": tick_schedules(),
        "raw_objects_expired": purge_local_expired(),
        "deliveries": deliver_pending(limit=10),
        "github_checks": reconcile_github_checks(),
    }
