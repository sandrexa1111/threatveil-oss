"""Tenant-scoped installation of reviewed, still-unapproved tool contracts."""

from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends

from .auth import Actor, actor, require
from .core.tool_contracts import (
    TEMPLATE_ID,
    ToolContractBinding,
    compile_tool_contract,
    tool_contract_templates,
)
from .db import add_record, audit, get_record, serialize, transaction
from .schemas import Input

router = APIRouter(prefix="/v1/tool-contracts", tags=["tool-contracts"])


class InstallToolContract(Input):
    system_id: UUID
    template_id: Literal["consequential-tool-v1"] = TEMPLATE_ID
    binding: ToolContractBinding
    reviewed: Literal[True]


@router.get("")
def templates(a: Actor = Depends(actor)):
    return {"items": tool_contract_templates()}


@router.post("/install", status_code=201)
def install(body: InstallToolContract, a: Actor = Depends(actor)):
    require(a)
    bundle = compile_tool_contract(body.binding)
    with transaction(a.user_id, a.org_id) as session:
        get_record(session, a.org_id, body.system_id, "system")
        saved = add_record(
            session,
            a.org_id,
            "tool_contract",
            {
                "system_id": str(body.system_id),
                **bundle,
                "reviewed_by": str(a.user_id),
            },
            {"system": body.system_id},
            record_id=UUID(bundle["bundle_id"]),
        )
        items = []
        for entry in bundle["properties"]:
            prop = add_record(
                session,
                a.org_id,
                "property",
                {
                    "system_id": str(body.system_id),
                    "title": entry["definition"]["title"],
                    "description": entry["definition"]["description"],
                    "template_id": TEMPLATE_ID,
                    "definition": entry["definition"],
                    "approved": False,
                    "version": 1,
                    "tool_contract_id": str(saved.id),
                    "tool_contract_axis": entry["axis"],
                    "tool_contract_binding": bundle["binding"],
                    "binding_digest": bundle["binding_digest"],
                    "test_requirements": entry["test_requirements"],
                },
                {"system": body.system_id, "tool_contract": saved.id},
            )
            items.append(serialize(prop))
        audit(session, a.org_id, a.user_id, "tool_contract.installed_draft", saved.id)
        return {
            "bundle_id": str(saved.id),
            "status": "DRAFT",
            "items": items,
            "binding_digest": bundle["binding_digest"],
            "observation_boundary": bundle["observation_boundary"],
            "limitations": bundle["limitations"],
        }
