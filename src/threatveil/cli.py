"""Local assurance and hosted workflow client. No implicit target execution."""

import json
import os
from pathlib import Path
from uuid import UUID, uuid4

import typer

app = typer.Typer(no_args_is_help=True, help="Prove. Remember. Re-prove.")
operator = typer.Typer(
    no_args_is_help=True, help="Operator commands require local deployment access."
)
app.add_typer(operator, name="operator")


def emit(value, output: Path | None = None):
    text = json.dumps(value, indent=2, ensure_ascii=False)
    if output:
        with output.open("x") as stream:
            stream.write(text + "\n")
    else:
        typer.echo(text)


def client():
    from .sdk.client import ThreatVeilClient

    token = os.environ.get("TV_API_TOKEN")
    if not token:
        raise typer.BadParameter(
            "Set TV_API_TOKEN to a scoped API token issued in workspace settings"
        )
    return ThreatVeilClient(os.environ.get("TV_API_URL", "http://127.0.0.1:8000"), token)


@app.command()
def demo(output: Path | None = typer.Option(None, help="Write a new JSON evidence file")):
    """Run the five synthetic consequential cases locally; no customer/provider connection."""
    from .core import run_procurement, compare_runs

    cases = {
        v: run_procurement(v)
        for v in ("vulnerable", "fixed", "regressed", "missing_witness", "bad_fix")
    }
    cases["regressed"]["comparison"] = compare_runs(cases["fixed"], cases["regressed"])
    emit(
        {"scope": "Local synthetic procurement; not a live agent evaluation", "cases": cases},
        output,
    )


@app.command()
def templates(output: Path | None = None):
    """Print the reviewed property library without executing it."""
    from .core import templates as library

    emit({"items": library()}, output)


@app.command("run")
def run_command(
    system: UUID = typer.Option(...),
    property: UUID = typer.Option(...),
    target: UUID = typer.Option(...),
    candidate_version: str = typer.Option(...),
    trials: int = typer.Option(5, min=1, max=100),
    variants: int = typer.Option(1, min=1, max=5),
    baseline: UUID | None = None,
    observer: UUID | None = None,
    stimulus: Path | None = None,
    observation: Path | None = None,
    candidate: Path | None = None,
    output: Path | None = None,
    timeout: int = typer.Option(300, min=1, max=600),
):
    """Execute an approved scoped property and exit nonzero unless the release decision allows it."""
    payload = {
        "system_id": str(system),
        "property_id": str(property),
        "target_id": str(target),
        "version": candidate_version,
        "trials": trials,
        "variant_count": variants,
        "idempotency_key": str(uuid4()),
        "baseline_id": str(baseline) if baseline else None,
        "observer_id": str(observer) if observer else None,
    }
    for field, path in (
        ("stimulus", stimulus),
        ("observation", observation),
        ("candidate", candidate),
    ):
        if path:
            if path.stat().st_size > 1_000_000:
                raise typer.BadParameter("Input file exceeds 1 MB")
            payload[field] = json.loads(path.read_text())
    with client() as api:
        started = api._request("POST", "/v1/runs", payload)
        result = api.wait_run(started["id"], timeout_seconds=timeout)
    emit(result, output)
    if result.get("release_action") != "ALLOW":
        raise typer.Exit(1)


@app.command()
def evidence(run_id: UUID, output: Path | None = None):
    """Export scoped evidence with no execution side effect."""
    with client() as api:
        emit(api.get_evidence(str(run_id)), output)


def read_json_input(path: Path, maximum: int = 1_000_000) -> dict:
    from .sdk.receipts import read_receipt

    try:
        if path.stat().st_size > maximum:
            raise ValueError("Input exceeds bounds")
        return read_receipt(path.read_bytes())
    except (OSError, ValueError):
        raise typer.BadParameter(
            "Input must be an existing, bounded, unambiguous JSON object"
        ) from None


@app.command("normalize")
def normalize_command(format: str, source: Path, output: Path | None = None):
    """Normalize an integration file locally; writes no hosted history or security verdict."""
    from .integrations.intake import normalize_integration

    try:
        normalized = normalize_integration(format, read_json_input(source))
    except (ValueError, TypeError):
        raise typer.BadParameter("Malformed or unsupported integration input") from None
    emit(normalized.model_dump(mode="json"), output)


@app.command("intake")
def intake_command(
    format: str,
    source: Path,
    system: UUID = typer.Option(...),
    idempotency_key: str = typer.Option(..., min=8),
    output: Path | None = None,
):
    """Import a private integration draft into an owned hosted system."""
    with client() as api:
        result = api.import_integration(
            format,
            system_id=str(system),
            payload=read_json_input(source),
            idempotency_key=idempotency_key,
        )
    emit(result, output)


@app.command("release")
def release_command(release_id: UUID, output: Path | None = None):
    """Read an exact-candidate release and its current applicability."""
    with client() as api:
        emit(api.get_release(str(release_id)), output)


@app.command("proof-plan")
def proof_plan_command(plan_id: UUID, output: Path | None = None):
    """Read re-proof obligations without starting execution."""
    with client() as api:
        emit(api.get_proof_plan(str(plan_id)), output)


@app.command("plan-release")
def plan_release_command(source: Path, output: Path | None = None):
    """Create a hosted proof plan from reviewed candidate JSON; does not execute it."""
    with client() as api:
        emit(api.create_proof_plan(**read_json_input(source)), output)


@app.command("decide-release")
def decide_release_command(
    plan: UUID = typer.Option(...), mode: str = typer.Option("WARN"), output: Path | None = None
):
    """Record a release decision under the chosen OBSERVE/WARN/BLOCK policy."""
    if mode not in {"OBSERVE", "WARN", "BLOCK"}:
        raise typer.BadParameter("Mode must be OBSERVE, WARN or BLOCK")
    with client() as api:
        emit(api.create_release(str(plan), policy={"mode": mode}), output)


@app.command("decide-authorized-release")
def decide_authorized_release_command(source: Path, output: Path | None = None):
    """Consume TV_RELEASE_TOKEN for the exact security-approved binding in source."""
    from .sdk.client import ThreatVeilClient

    token = os.environ.get("TV_RELEASE_TOKEN", "")
    if not token.startswith("tvrel_"):
        raise typer.BadParameter("Set TV_RELEASE_TOKEN to a short-lived exact release authorization")
    with ThreatVeilClient(os.environ.get("TV_API_URL", "http://127.0.0.1:8000"), token) as api:
        decision = api.decide_authorized_release(read_json_input(source))
        emit(decision, output)
        if decision["release_action"] != "ALLOW":
            raise typer.Exit(2)


@app.command("verify-receipt")
def verify_receipt_command(
    receipt: Path,
    public_key: Path = typer.Option(...),
    candidate_fingerprint: str = typer.Option(...),
    organization: UUID = typer.Option(...),
    system: UUID | None = None,
    require_action: str | None = None,
    output: Path | None = None,
):
    """Verify a historical receipt offline with a separately trusted public key and scope."""
    from .sdk.receipts import verify_release_receipt

    if require_action not in (None, "ALLOW", "WARN", "BLOCK"):
        raise typer.BadParameter("Required action must be ALLOW, WARN or BLOCK")
    value = read_json_input(receipt)
    try:
        if public_key.stat().st_size > 16000:
            raise ValueError("Key exceeds bounds")
        result = verify_release_receipt(
            value.get("envelope", value),
            public_key.read_bytes(),
            expected_candidate_fingerprint_digest=candidate_fingerprint,
            expected_organization_id=str(organization),
            expected_system_id=str(system) if system else None,
        )
        if require_action and result["predicate"]["release_action"] != require_action:
            raise ValueError("Signed action does not satisfy the requested action")
    except (OSError, ValueError):
        typer.echo(
            "Receipt verification failed for the configured trusted key and expected scope",
            err=True,
        )
        raise typer.Exit(1) from None
    emit({"verified": True, "historical_only": True, "statement": result}, output)


@app.command("assurance-current")
def assurance_current_command(
    system: UUID,
    environment: UUID | None = None,
    action: str | None = None,
    expected_state_digest: str | None = None,
    require_cleared: bool = typer.Option(False, "--require-cleared",
                                         help="Exit 2 unless the answer is fresh, CURRENT and ALLOW"),
    output: Path | None = None,
):
    """Ask the Assurance Gate whether a system is still cleared to act. Never an authorization."""
    from .sdk.client import ThreatVeilClient

    with client() as tv:
        result = tv.current_assurance(str(system), environment_id=str(environment) if environment else None,
                                      action=action, expected_state_digest=expected_state_digest,
                                      consumer="threatveil-cli")
    emit(result, output)
    if require_cleared and not ThreatVeilClient.is_cleared(result):
        raise typer.Exit(2)


@app.command("verify-passport")
def verify_passport_command(
    passport: Path,
    directory: Path | None = typer.Option(None, help="Trust directory JSON obtained independently"),
    public_key: Path | None = typer.Option(None, help="Independently trusted Ed25519 public key (PEM)"),
    passport_id: str | None = None,
    output: Path | None = None,
):
    """Verify a Current Assurance Passport offline. Establishes authenticity at issue time only."""
    from .sdk.passports import verify_passport, verify_passport_with_directory
    from .sdk.trust_directory import TrustError, load_directory

    if (directory is None) == (public_key is None):
        raise typer.BadParameter("Provide exactly one of --directory or --public-key")
    value = read_json_input(passport)
    envelope = value.get("envelope", value)
    try:
        if directory is not None:
            statement = verify_passport_with_directory(
                envelope, load_directory(read_json_input(directory)), passport_id=passport_id)
        else:
            if public_key.stat().st_size > 16000:
                raise ValueError("Key exceeds bounds")
            statement = verify_passport(envelope, public_key.read_bytes(), passport_id=passport_id)
    except (OSError, ValueError, TrustError):
        typer.echo("Passport verification failed for the trusted key material and expected scope", err=True)
        raise typer.Exit(1) from None
    predicate = statement["predicate"]
    emit({"verified": True, "authenticity_only": True, "passport_id": predicate["passport_id"],
          "system": predicate["system"]["name"], "issued_at": predicate["issued_at"],
          "clearance_at_issue": predicate["clearance"]["label"],
          "current_status": "Not established offline. Use the status link shared with this passport.",
          "statement": statement}, output)


def _definition_payload(path: Path, fmt: str | None):
    """A proposed configuration: an agent definition when the format is known, else a JSON document."""
    from .agent_definitions import infer_format

    if path.stat().st_size > 262_144:
        raise typer.BadParameter("A proposed configuration must be at most 256 KiB")
    raw = path.read_text()
    chosen = fmt or infer_format(path)
    if chosen:
        document = json.loads(raw) if path.suffix == ".json" else raw
        return {"format": chosen, "document": document}
    return json.loads(raw)


@app.command("propose-change")
def propose_change_command(
    system: UUID,
    installation: UUID = typer.Option(..., help="The source this configuration belongs to"),
    file: Path = typer.Option(..., exists=True, dir_okay=False, readable=True),
    fmt: str | None = typer.Option(None, "--format", help="Agent-definition format; inferred from the path otherwise"),
    reference_type: str = typer.Option("MANUAL", help="PULL_REQUEST, COMMIT, BRANCH or MANUAL"),
    reference: str | None = typer.Option(None, help="Pull request number, branch or label"),
    url: str | None = typer.Option(None, help="https link to the change, for people"),
    revision: str | None = typer.Option(None, help="Commit revision, if known"),
    output: Path | None = typer.Option(None),
):
    """What would this change break? A dry run that never touches current clearance."""
    try:
        payload = _definition_payload(file, fmt)
    except (OSError, ValueError) as error:
        raise typer.BadParameter(f"Could not read a bounded configuration: {error}") from None
    result = client().propose_change(str(system), installation_id=str(installation), payload=payload,
                                     reference={"type": reference_type.upper(), "id": reference, "url": url,
                                                "revision": revision})
    summary = result.get("summary", {})
    emit({"label": result.get("label"), "effect": summary.get("effect"), "headline": summary.get("headline"),
          "claims_affected": summary.get("claims_affected"),
          "declared_claims_affected": summary.get("declared_claims_affected"),
          "clearance": result.get("clearance"), "check": result.get("check"),
          "explanation": result.get("explanation"), "id": result.get("id")}, output)


def _git_revisions(path: Path, limit: int):
    """The last revisions of one tracked file, read from the local repository only."""
    import subprocess

    target = str(path)
    if target.startswith("-"):
        raise typer.BadParameter("Invalid path")
    try:
        log = subprocess.run(["git", "log", f"-n{limit}", "--format=%H%x09%cI", "--", target],  # noqa: S603,S607
                             capture_output=True, text=True, check=True, timeout=30).stdout
    except (OSError, subprocess.SubprocessError) as error:
        raise typer.BadParameter(f"Could not read local git history: {error}") from None
    revisions = []
    for line in reversed([line for line in log.splitlines() if line.strip()]):
        sha, _, stamp = line.partition("\t")
        content = subprocess.run(["git", "show", f"{sha}:{target}"],  # noqa: S603,S607
                                 capture_output=True, text=True, timeout=30)
        if content.returncode != 0 or len(content.stdout) > 262_144:
            continue
        revisions.append({"revision": sha[:40], "committed_at": stamp, "content": content.stdout})
    return revisions


@app.command("replay-config-history")
def replay_history_command(
    system: UUID,
    installation: UUID = typer.Option(..., help="The source this configuration belongs to"),
    path: Path = typer.Option(..., help="Tracked configuration file, relative to the repository"),
    limit: int = typer.Option(5, min=2, max=20),
    fmt: str | None = typer.Option(None, "--format", help="Agent-definition format; inferred from the path otherwise"),
    output: Path | None = typer.Option(None),
):
    """Replay real configuration history and show what each change would have meant today."""
    from .agent_definitions import infer_format

    chosen = fmt or infer_format(path)
    revisions = []
    for item in _git_revisions(path, limit):
        document = json.loads(item["content"]) if str(path).endswith(".json") else item["content"]
        payload = {"format": chosen, "document": document} if chosen else document
        revisions.append({"revision": item["revision"], "committed_at": item["committed_at"], "payload": payload})
    if len(revisions) < 2:
        raise typer.BadParameter("At least two readable revisions of that file are required")
    result = client().replay_configuration_history(str(system), installation_id=str(installation),
                                                  revisions=revisions)
    emit({"mode": result.get("mode"), "note": result.get("note"),
          "items": [{"revision": item.get("reference", {}).get("revision"),
                     "effect": item.get("summary", {}).get("effect"),
                     "headline": item.get("summary", {}).get("headline")} for item in result.get("items", [])]}, output)


@app.command("mcp-serve")
def mcp_serve_command():
    """Serve read-only MCP over stdio; hosted tenant history requires TV_API_TOKEN."""
    from .sdk.mcp_server import main

    main()


@operator.command("reconcile")
def reconcile():
    """Run one maintenance pass. Use deployment identity, never a customer runner identity."""
    from .maintenance import reconcile as tick

    emit(tick())


@operator.command("pilot")
def pilot(
    organization: UUID,
    trial_limit: int = typer.Option(..., min=0, max=100000),
    systems: int = typer.Option(1, min=1, max=100),
    reason: str = typer.Option(...),
):
    """Assign an explicitly audited unpaid pilot from the trusted deployment shell."""
    from .db import Account, add_record, transaction

    if len(reason) < 20:
        raise typer.BadParameter("An explicit pilot agreement reason is required")
    with transaction(org_id=organization) as session:
        account = session.get(Account, organization, with_for_update=True)
        if not account:
            raise typer.BadParameter("Organization unavailable")
        if account.paid or account.status == "active":
            raise typer.BadParameter("Use billing reconciliation for an existing paid subscription")
        account.status, account.plan = "manual_pilot", "manual_pilot"
        account.trial_limit, account.max_systems = trial_limit, systems
        add_record(
            session,
            organization,
            "pilot_agreement",
            {
                "reason": reason,
                "trial_limit": trial_limit,
                "max_systems": systems,
                "paid": False,
                "actor": "deployment_operator",
            },
        )
    emit({"organization_id": str(organization), "status": "manual_pilot", "paid": False})


def _operator_name(value):
    return value or os.environ.get("TV_OPERATOR", "deployment_operator")


def _operator_record(model, values, kind, operator_name):
    """Validate and append one internal operator record. Never visible to a customer."""
    from pydantic import ValidationError

    from .operator_store import OperatorError, record

    try:
        emit(record(model(**{k: v for k, v in values.items() if v is not None}), kind,
                    operator=_operator_name(operator_name)))
    except (ValidationError, OperatorError) as error:
        raise typer.BadParameter(str(error)) from None


def _today():
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).date().isoformat()


@operator.command("time")
def staff_time(
    organization: UUID,
    minutes: int = typer.Option(..., min=1, max=720),
    category: str = typer.Option(..., help="SYSTEM_MODELING, CLAIM_AUTHORING, OBSERVER_SETUP, DEPENDENCY_MAPPING, "
                                           "BASELINE, DEBUGGING, SUPPORT, CUSTOM_INTEGRATION or OTHER"),
    stage: str = typer.Option(..., help="QUALIFICATION, KICKOFF, MODELING, OBSERVATION, BASELINE, WATCH, "
                                        "REESTABLISH, CONVERSION, SUPPORT or OTHER"),
    work_date: str | None = typer.Option(None, help="YYYY-MM-DD (default: today, UTC)"),
    system: UUID | None = typer.Option(None),
    observer: str | None = typer.Option(None),
    support_event: str | None = typer.Option(None),
    note: str = typer.Option(""),
    operator_name: str | None = typer.Option(None, "--operator"),
):
    """Log internal staff time for an organization, system, observer, stage or support event."""
    from .operator_store import StaffTime

    _operator_record(StaffTime, {"organization_id": organization, "work_date": work_date or _today(),
                                 "minutes": minutes, "category": category.upper(), "stage": stage.upper(),
                                 "system_id": system, "observer": observer, "support_event": support_event,
                                 "note": note}, "staff_time", operator_name)


@operator.command("classify")
def classify(organization: UUID, classification: str = typer.Option(..., help="CUSTOMER, DESIGN_PARTNER, INTERNAL or TEST"),
             reason: str = typer.Option(...), operator_name: str | None = typer.Option(None, "--operator")):
    """Classify an organization. INTERNAL and TEST organizations are excluded from every business metric."""
    from .operator_store import Classification

    _operator_record(Classification, {"organization_id": organization, "classification": classification.upper(),
                                      "reason": reason}, "org_classification", operator_name)


@operator.command("prospect")
def prospect(handle: str, archetype: str = typer.Option(...), source: str = typer.Option("FOUNDER_NETWORK"),
             note: str = typer.Option(""), operator_name: str | None = typer.Option(None, "--operator")):
    """Record a prospect under a pseudonymous handle. Never a name, email or phone number."""
    from .operator_store import Prospect

    _operator_record(Prospect, {"prospect": handle, "archetype": archetype, "source": source.upper(), "note": note},
                     "prospect", operator_name)


@operator.command("proof")
def commercial_proof(
    handle: str,
    event: str = typer.Option(..., help="QUALIFIED, DISQUALIFIED, PAIN_CONFIRMED, OFFER_MADE, OFFER_ACCEPTED, "
                                        "OFFER_REJECTED, CONTRACT_SIGNED, KICKOFF, GATE_INSTALLED, "
                                        "PASSPORT_CHECKED, CONVERTED or CHURNED"),
    occurred_on: str | None = typer.Option(None, help="YYYY-MM-DD (default: today, UTC)"),
    organization: UUID | None = typer.Option(None),
    offer: str | None = typer.Option(None),
    price_usd: int | None = typer.Option(None),
    price_variant: str | None = typer.Option(None),
    contract_value_usd: int | None = typer.Option(None),
    reason: str = typer.Option(""),
    operator_name: str | None = typer.Option(None, "--operator"),
):
    """Record one commercial proof fact (offers and pricing experiments included). Nothing is sent."""
    from .operator_store import ProofEvent

    _operator_record(ProofEvent, {"prospect": handle, "event": event.upper(), "occurred_on": occurred_on or _today(),
                                  "organization_id": organization, "offer": offer.upper() if offer else None,
                                  "price_usd": price_usd, "price_variant": price_variant,
                                  "contract_value_usd": contract_value_usd, "reason": reason},
                     "commercial_proof", operator_name)


@operator.command("business-report")
def business_report(weeks: int = typer.Option(12, min=1, max=52),
                    output: Path | None = typer.Option(None, help="Write a new JSON file"),
                    operator_name: str | None = typer.Option(None, "--operator")):
    """Founder business dashboard: RPS, confirmed activation, precision, staff time, commercial proof."""
    from .operator_store import OperatorError, founder_report

    try:
        emit(founder_report(operator=_operator_name(operator_name), weeks=weeks), output)
    except OperatorError as error:
        raise typer.BadParameter(str(error)) from None


@operator.command("investor-export")
def investor_metrics(fmt: str = typer.Option("csv", "--format", help="csv or json"),
                     output: Path | None = typer.Option(None),
                     operator_name: str | None = typer.Option(None, "--operator")):
    """Founder metrics with definitions, numerators and denominators. Zero is a valid value."""
    from .operator_store import OperatorError, founder_report, investor_export

    if fmt not in {"csv", "json"}:
        raise typer.BadParameter("Format must be csv or json")
    try:
        result = investor_export(founder_report(operator=_operator_name(operator_name)), fmt=fmt)
    except OperatorError as error:
        raise typer.BadParameter(str(error)) from None
    if fmt == "json":
        emit(result, output)
    elif output:
        with output.open("x") as stream:
            stream.write(result)
    else:
        typer.echo(result)


@operator.command("github-bind")
def github_bind(
    organization: UUID,
    security_owner: UUID,
    repository_id: str,
    repository: str,
    owner_id: str,
    workflow_ref: str,
    allowed_ref: str,
    plan: Path,
):
    """Install a founder-verified repository binding after reviewing repository ownership."""
    import re
    from .db import GitHubBinding, Membership, add_record, transaction
    from .api import authorized_target
    from .schemas import RunInput
    from .auth import SECURITY

    if (
        not repository_id.isdigit()
        or not owner_id.isdigit()
        or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository)
    ):
        raise typer.BadParameter("Numeric repository/owner IDs and owner/repository name required")
    if (
        not allowed_ref.startswith("refs/heads/")
        or not workflow_ref.startswith(repository + "/.github/workflows/")
        or not workflow_ref.endswith("@" + allowed_ref)
    ):
        raise typer.BadParameter("Pin the exact trusted workflow and branch")
    template = RunInput.model_validate(
        {**json.loads(plan.read_text()), "idempotency_key": "github-binding-validation"}
    )
    with transaction(security_owner, organization) as session:
        member = session.get(Membership, (organization, security_owner))
        if not member or member.role not in SECURITY:
            raise typer.BadParameter("An active security-owner membership is required")
        target = authorized_target(session, organization, template.target_id)
        if target.payload["adapter"] not in {"http", "mcp"} or not template.observer_id:
            raise typer.BadParameter(
                "Bind an active HTTP/MCP target with a qualified observation source"
            )
        if session.get(GitHubBinding, repository_id):
            raise typer.BadParameter(
                "Repository already bound; review revocation before replacement"
            )
        session.add(
            GitHubBinding(
                repository_id=repository_id,
                repository=repository,
                organization_id=organization,
                user_id=security_owner,
                owner_id=owner_id,
                workflow_ref=workflow_ref,
                allowed_ref=allowed_ref,
                run_template=template.model_dump(mode="json"),
            )
        )
        add_record(
            session,
            organization,
            "github_binding_review",
            {
                "repository_id": repository_id,
                "repository": repository,
                "workflow_ref": workflow_ref,
                "operator_verified": True,
            },
        )
    emit({"repository": repository, "status": "bound", "live_workflow_verified": False})


if __name__ == "__main__":
    app()
