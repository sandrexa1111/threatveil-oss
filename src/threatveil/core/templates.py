"""Curated property intents. Installation requires system-specific witness binding."""

from .contracts import ActionPhase, ObservationContract, Predicate, PropertyDefinition


# id, title, predicate, operation, resource tags, action tags, required observer
_TEMPLATES = (
    (
        "cross-tenant-disclosure",
        "Cross-tenant disclosure",
        "cross_tenant",
        "resource.read",
        ("customer_data", "database", "crm"),
        ("read",),
        "resource-audit",
    ),
    (
        "unauthorized-tool",
        "Unauthorized tool invocation",
        "unauthorized_action",
        "tool.invoke",
        ("mcp", "internal_apis"),
        ("execute", "write"),
        "tool-dispatch",
    ),
    (
        "external-transmission",
        "Unauthorized external transmission",
        "unauthorized_action",
        "external.send",
        ("email", "browser"),
        ("send", "publish"),
        "external-sink",
    ),
    (
        "approval-bypass",
        "Approval bypass",
        "missing_approval",
        "action.execute",
        ("payments", "cloud"),
        ("approve", "transfer"),
        "approval-ledger",
    ),
    (
        "privilege-escalation",
        "Privilege escalation",
        "unauthorized_action",
        "permissions.modify",
        ("cloud", "internal_apis"),
        ("modify_permissions",),
        "identity-audit",
    ),
    (
        "secret-disclosure",
        "Secret disclosure",
        "forbidden_value",
        "data.output",
        ("files", "code", "cloud"),
        ("read", "send"),
        "output-witness",
    ),
    (
        "system-prompt-disclosure",
        "Confidential system prompt disclosure",
        "forbidden_value",
        "data.output",
        ("files",),
        ("read",),
        "output-witness",
    ),
    (
        "sensitive-disclosure",
        "Sensitive data disclosure",
        "forbidden_value",
        "data.output",
        ("customer_data", "crm", "database"),
        ("read", "send"),
        "output-witness",
    ),
    (
        "state-mutation",
        "Unauthorized state mutation",
        "unauthorized_action",
        "state.write",
        ("database", "files", "crm"),
        ("write", "delete"),
        "state-ledger",
    ),
    (
        "payment-authorization",
        "Payment authorization boundary",
        "missing_approval",
        "beneficiary.update",
        ("payments",),
        ("transfer", "write", "approve"),
        "payment-ledger",
    ),
    (
        "untrusted-side-effect",
        "Untrusted content cannot authorize a side effect",
        "untrusted_action",
        "state.write",
        ("files", "email", "browser"),
        ("write", "send"),
        "state-ledger",
    ),
    (
        "mcp-privilege",
        "MCP privilege boundary",
        "unauthorized_action",
        "tool.invoke",
        ("mcp",),
        ("execute", "write"),
        "mcp-audit",
    ),
    (
        "rag-tool-escalation",
        "RAG-to-tool escalation",
        "untrusted_action",
        "tool.invoke",
        ("files", "database", "mcp"),
        ("execute",),
        "tool-dispatch",
    ),
    (
        "indirect-injection",
        "Indirect instruction injection",
        "untrusted_action",
        "external.send",
        ("browser", "email", "files"),
        ("send", "execute"),
        "external-sink",
    ),
    (
        "memory-poisoning",
        "Memory poisoning persistence",
        "untrusted_action",
        "memory.write",
        ("database", "files"),
        ("write",),
        "memory-state",
    ),
    (
        "cross-agent-escalation",
        "Cross-agent privilege escalation",
        "unauthorized_action",
        "authority.delegate",
        ("internal_apis", "mcp"),
        ("execute", "approve"),
        "delegation-audit",
    ),
    (
        "external-confirmation",
        "External action requires confirmation",
        "missing_approval",
        "external.send",
        ("email", "browser"),
        ("send", "publish"),
        "external-sink",
    ),
    (
        "code-execution",
        "Code execution boundary",
        "unauthorized_action",
        "code.execute",
        ("code",),
        ("execute",),
        "execution-sink",
    ),
    (
        "cloud-privilege",
        "Cloud privilege boundary",
        "unauthorized_action",
        "cloud.modify",
        ("cloud",),
        ("write", "delete", "modify_permissions"),
        "cloud-audit",
    ),
    (
        "customer-egress",
        "Customer data egress",
        "unauthorized_action",
        "customer.export",
        ("customer_data", "crm", "database"),
        ("send", "publish"),
        "export-sink",
    ),
)


def templates() -> list[dict]:
    result = []
    for key, title, kind, operation, access, actions, witness in _TEMPLATES:
        phases = (
            (ActionPhase.DISPATCHED, ActionPhase.COMMITTED)
            if operation
            in (
                "tool.invoke",
                "external.send",
                "action.execute",
                "code.execute",
                "cloud.modify",
                "customer.export",
            )
            else (ActionPhase.COMMITTED,)
        )
        if operation == "authority.delegate":
            phases = (ActionPhase.AUTHORIZED, ActionPhase.DISPATCHED, ActionPhase.COMMITTED)
        definition = PropertyDefinition(
            id=key,
            title=title,
            description=f"System-specific assurance of {title.lower()}.",
            predicates=(
                Predicate(
                    kind=kind,
                    operations=(operation,),
                    phases=phases,
                    values=("SYNTHETIC-PROTECTED-MARKER",) if kind == "forbidden_value" else (),
                ),
            ),
            observation_contract=ObservationContract(
                boundary=key, required_witnesses=(witness,), required_operations=(operation,)
            ),
            tags=tuple(dict.fromkeys(access + actions)),
            legitimate_task="Bind an approved positive business-task fixture before fix verification",
        ).model_dump(mode="json")
        result.append(
            {
                "id": key,
                "title": title,
                "description": definition["description"],
                "definition": definition,
                "access": list(access),
                "actions": list(actions),
                "required_witnesses": [witness],
                "status": "REQUIRES_SYSTEM_BINDING",
                "binding_requirements": [
                    "Map concrete actor, resource, and operation",
                    "Qualify an authoritative observer",
                    "Provide vulnerable, fixed, and missing-observation fixtures",
                    "Bind a legitimate-task positive control",
                ],
                "release_policy": "WARN",
            }
        )
    return result


def suggest_templates(access: list[str], actions: list[str]) -> dict:
    access_set = {value.lower().replace(" ", "_") for value in access}
    actions_set = {value.lower().replace(" ", "_") for value in actions}
    recommendations = []
    for template in templates():
        matches = sorted(access_set.intersection(template["access"]))
        action_matches = sorted(actions_set.intersection(template["actions"]))
        if matches and action_matches:
            recommendations.append(
                {
                    **template,
                    "reasons": [
                        f"Access: {', '.join(matches)}",
                        f"Actions: {', '.join(action_matches)}",
                    ],
                    "score": len(matches) + len(action_matches),
                }
            )
    recommendations.sort(key=lambda item: (-item["score"], item["id"]))
    return {
        "recommendations": recommendations,
        "limitations": [
            "Recommendations are proposed intent, not installed or verified assurance."
        ],
    }
