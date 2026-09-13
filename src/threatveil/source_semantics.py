"""Deterministic source semantics: what exactly changed, which way authority moved,
and which reviewed claim dependencies a change touches.

Nothing here infers authority. Structured authority facts come only from a source's
own declared authorization block, and direction is classified only for a small,
versioned vocabulary of restriction and scope conditions; everything else remains
UNKNOWN_IMPACT. A reviewed dependency mapping is an explicit, append-only customer
(or labelled synthetic-package) statement that a named source subject corresponds
to a reviewed claim dependency. Without one, a source change keeps its conservative
meaning: every claim it could reach needs review.
"""

from .core.contracts import digest

SEMANTICS = "authority-semantics/v1"
EXPANDED = "AUTHORITY_EXPANDED"
CONTRACTED = "AUTHORITY_CONTRACTED"
EQUIVALENT = "AUTHORITY_EQUIVALENT"
UNKNOWN = "UNKNOWN_IMPACT"
CLASSES = (EXPANDED, CONTRACTED, EQUIVALENT, UNKNOWN)

# A restriction narrows authority while it holds; relaxing one expands authority.
RESTRICTIONS = frozenset({
    "approval_required", "approval", "human_approval", "human_in_loop", "requires_confirmation",
    "tenant_bound", "read_only", "dual_control", "mfa_required", "sandboxed",
})
# A scope list grants authority per item; adding an item expands authority.
SCOPES = frozenset({"scopes", "permissions", "allowed_actions", "actions", "resources", "roles", "tenants",
                    "tools", "allow", "allowed_tools", "servers", "enabled_servers", "mcp_servers",
                    "additional_directories", "delegates_to"})
# A denial list withholds authority per item; removing an item expands authority.
DENIALS = frozenset({"deny", "denied_tools", "disallowed_tools", "ask", "disabled_servers"})
# A grant flag confers authority while it holds; enabling one expands authority.
GRANTS = frozenset({"allow_delegation", "allow_code_execution", "enable_all_project_servers"})
# Ordered modes, least to most authority. Values outside the list are never guessed.
ORDERED = {"default_mode": ("plan", "default", "acceptEdits", "bypassPermissions")}
RESTRICTED = frozenset({"true", "required", "enabled", "enforced", "yes", "on"})
UNRESTRICTED = frozenset({"false", "not_required", "disabled", "optional", "no", "off", "none"})
# Component types whose change concerns authority even when only a digest is retained.
AUTHORITY_TYPES = frozenset({"permissions", "identity", "iam", "role", "policy", "credential_scope"})
CONSERVATIVE_KINDS = frozenset({"SOURCE_GAP", "CONNECTOR_CONFIGURATION"})
MCP_PARTS = ("protocol_version", "server_info", "capabilities", "catalog_metadata")
MAX_LEAVES = 200
MAX_DEPTH = 6
MAX_TEXT = 200


def _segment(value):
    return str(value).replace("~", "~0").replace("/", "~1")


def pointer(*parts):
    """JSON-pointer style path; tool names containing dots stay unambiguous."""
    return "/".join(_segment(part) for part in parts)


def split_pointer(value):
    return [part.replace("~1", "/").replace("~0", "~") for part in str(value).split("/")]


def _leaf(value):
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return value if len(value) <= MAX_TEXT else "sha256:" + digest(value)
    if (isinstance(value, list) and len(value) <= 100
            and all(item is None or isinstance(item, (bool, int, float, str)) for item in value)):
        return sorted({str(item) if len(str(item)) <= MAX_TEXT else "sha256:" + digest(str(item))
                       for item in value})
    return "sha256:" + digest(value)


def bounded_authorization(value):
    """Flatten a declared authorization block into bounded path -> scalar facts.

    Returns None when no authorization was captured, so absence is never mistaken
    for an empty, unrestricted configuration. Long or structured values are kept as
    digests: they remain comparable but are never interpreted.
    """
    if value is None:
        return None
    leaves, bounded = {}, False

    def walk(node, parts):
        nonlocal bounded
        if len(leaves) >= MAX_LEAVES:
            bounded = True
            return
        if isinstance(node, dict) and node and len(parts) < MAX_DEPTH:
            for key in sorted(node):
                walk(node[key], [*parts, key])
        else:
            leaves[pointer("authorization", *parts)] = _leaf(node)

    walk(value, [])
    if bounded:
        leaves[pointer("authorization", "__bounded__")] = True
    return leaves


def _restriction(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        text = value.strip().lower()
        if text in RESTRICTED:
            return True
        if text in UNRESTRICTED:
            return False
    return None


def classify_condition(path, before, after, *, present_before=True, present_after=True):
    """Direction of one authorization fact. Unrecognized fields are never guessed."""
    name = split_pointer(path)[-1].lower()
    if present_before and present_after and digest(before) == digest(after):
        return EQUIVALENT, "Unchanged."
    if name == "__bounded__":
        return UNKNOWN, "The authorization block exceeded ThreatVeil's comparison bound."
    if name in RESTRICTIONS:
        old = _restriction(before) if present_before else None
        new = _restriction(after) if present_after else None
        if old is True and (new is False or not present_after):
            return EXPANDED, ("A declared restriction was relaxed." if present_after
                              else "A declared restriction was removed.")
        if new is True and (old is False or not present_before):
            return CONTRACTED, "A declared restriction was added or tightened."
        return UNKNOWN, "The restriction value is not one ThreatVeil can compare."
    if name in SCOPES:
        if (present_before and not isinstance(before, list)) or (present_after and not isinstance(after, list)):
            return UNKNOWN, "The scope is not a comparable list."
        old, new = set(before or []), set(after or [])
        added, removed = sorted(new - old), sorted(old - new)
        if added:
            note = "Scope added: " + ", ".join(added[:5]) + "."
            return EXPANDED, note + (" Scope also removed: " + ", ".join(removed[:5]) + "." if removed else "")
        if removed:
            return CONTRACTED, "Scope removed: " + ", ".join(removed[:5]) + "."
        return EQUIVALENT, "Unchanged."
    if name in DENIALS:
        if (present_before and not isinstance(before, list)) or (present_after and not isinstance(after, list)):
            return UNKNOWN, "The denial list is not a comparable list."
        old, new = set(before or []), set(after or [])
        added, removed = sorted(new - old), sorted(old - new)
        if removed:
            note = "Denial or confirmation removed: " + ", ".join(removed[:5]) + "."
            return EXPANDED, note + (" Also added: " + ", ".join(added[:5]) + "." if added else "")
        if added:
            return CONTRACTED, "Denial or confirmation added: " + ", ".join(added[:5]) + "."
        return EQUIVALENT, "Unchanged."
    if name in GRANTS:
        old = _restriction(before) if present_before else None
        new = _restriction(after) if present_after else None
        if new is True and old is False:
            return EXPANDED, "A declared grant was enabled."
        if new is False and old is True:
            return CONTRACTED, "A declared grant was disabled."
        return UNKNOWN, "The grant's default is not declared on both sides."
    if name in ORDERED:
        order = ORDERED[name]
        if present_before and present_after and before in order and after in order:
            return (EXPANDED, f"Mode widened from {before} to {after}.") if order.index(after) > order.index(before) \
                else (CONTRACTED, f"Mode narrowed from {before} to {after}.")
        return UNKNOWN, "The mode is not one ThreatVeil can compare."
    return UNKNOWN, "ThreatVeil has no reviewed semantics for this authorization field."


def combine(directions):
    """The new boundary is EXPANDED unless it is provably contained in the old one."""
    values = set(directions)
    if EXPANDED in values:
        return EXPANDED
    if UNKNOWN in values:
        return UNKNOWN
    if CONTRACTED in values:
        return CONTRACTED
    return EQUIVALENT


def _conditions(flat, parent):
    prefix = parent + "/"
    return {path[len(prefix):]: value for path, value in (flat or {}).items()
            if path.startswith(prefix) and "/" not in path[len(prefix):]}


def authorization_diff(before, after, *, introduced=frozenset(), withdrawn=frozenset()):
    """Compare two flattened declared authorization blocks.

    Conditions declared for a newly exposed interface qualify that new authority;
    they never count as reducing existing authority. The same holds in reverse for
    conditions withdrawn together with their interface.
    """
    if before is None and after is None:
        return None
    if before is None or after is None:
        return {"classification": UNKNOWN, "subjects": [], "dimensions": [{
            "kind": "AUTHORIZATION", "subject": "authorization", "subject_path": "authorization",
            "condition": "authorization", "path": "authorization",
            "before": None if before is None else "captured", "after": None if after is None else "captured",
            "direction": UNKNOWN,
            "reason": "Authorization configuration was captured on only one side of this change.",
        }]}
    dimensions, parents = [], []
    for path in sorted(before.keys() | after.keys()):
        present_before, present_after = path in before, path in after
        if present_before and present_after and digest(before[path]) == digest(after[path]):
            continue
        parts = split_pointer(path)
        parent = pointer(*parts[:-1])
        subject = parts[-2] if len(parts) > 2 else "authorization"
        if subject in introduced and not present_before:
            direction, reason = EQUIVALENT, ("Declared for a newly exposed interface; it qualifies that new "
                                             "authority and does not reduce existing authority.")
        elif subject in withdrawn and not present_after:
            direction, reason = EQUIVALENT, "Withdrawn together with its interface."
        else:
            direction, reason = classify_condition(
                path, before.get(path), after.get(path),
                present_before=present_before, present_after=present_after,
            )
        if parent not in parents:
            parents.append(parent)
        dimensions.append({
            "kind": "AUTHORIZATION", "subject": subject,
            "subject_path": parent, "condition": parts[-1], "path": path,
            "before": before.get(path), "after": after.get(path),
            "present_before": present_before, "present_after": present_after,
            "direction": direction, "reason": reason,
        })
    subjects = []
    for parent in parents:
        name = split_pointer(parent)[-1] if parent != "authorization" else "authorization"
        direction = (EXPANDED if name in introduced else CONTRACTED if name in withdrawn else
                     combine(d["direction"] for d in dimensions if d["subject_path"] == parent))
        subjects.append({"subject_path": parent, "subject": name, "before": _conditions(before, parent),
                         "after": _conditions(after, parent), "direction": direction})
    return {"classification": combine(d["direction"] for d in dimensions) if dimensions else EQUIVALENT,
            "subjects": subjects, "dimensions": dimensions}


def interface_diff(before, after):
    """Tool-level changes in a declared catalog.

    A newly exposed tool expands what the system can invoke. A changed contract is
    UNKNOWN: ThreatVeil does not interpret tool schema semantics. An incomplete
    catalog cannot establish a removal.
    """
    old = ((before or {}).get("facts") or {}).get("tool_components") or {}
    new = ((after or {}).get("facts") or {}).get("tool_components") or {}
    old_components = (before or {}).get("components") or {}
    new_components = (after or {}).get("components") or {}
    dimensions = []
    for key in sorted(old.keys() | new.keys()):
        name = new.get(key) or old.get(key)
        base = {"kind": "INTERFACE", "subject": name, "subject_path": key, "condition": "interface", "path": key}
        if key not in old:
            dimensions.append({**base, "before": None, "after": "exposed", "direction": EXPANDED,
                               "reason": "A new callable interface was exposed to the system."})
        elif key not in new:
            if (after or {}).get("complete"):
                dimensions.append({**base, "before": "exposed", "after": None, "direction": CONTRACTED,
                                   "reason": "An interface is no longer exposed."})
        elif (old_components.get(key) or {}).get("digest") != (new_components.get(key) or {}).get("digest"):
            dimensions.append({**base, "before": "contract", "after": "changed contract", "direction": UNKNOWN,
                               "reason": "The interface contract changed; ThreatVeil does not interpret tool schema semantics."})
    return dimensions


def _structured(batch):
    facts = (batch or {}).get("facts") or {}
    return bool(batch) and ("catalog_parts" in facts or "definition_parts" in facts)


def explain_source_change(event, before, after):
    """Name the subjects a recorded source change touched, deterministically.

    `event`, `before` and `after` are record payloads (source_change and the two
    source_batch snapshots). Subjects are mappable names; `unexplained` parts can
    never be scoped, so the change stays conservative.
    """
    changed = sorted(event.get("changed_components", []))
    result = {"semantics": SEMANTICS, "changed_components": changed, "subjects": [],
              "unexplained": [], "conservative": False, "initial": before is None,
              "change_kind": event.get("change_kind"), "authority": None}
    if event.get("change_kind") in CONSERVATIVE_KINDS or not changed or after is None:
        result["conservative"] = True
        result["unexplained"] = changed or [str(event.get("change_kind") or "UNKNOWN")]
        result["authority"] = {"classification": UNKNOWN, "subjects": [], "dimensions": [],
                               "reason": "A source gap or connector reconfiguration cannot be scoped to named facts."}
        return result
    identity = event.get("source_identity") or after.get("source_identity")
    comparable = _structured(before) and _structured(after)
    interfaces = interface_diff(before, after) if comparable else []
    authz = authorization_diff(
        (before.get("facts") or {}).get("authorization"), (after.get("facts") or {}).get("authorization"),
        introduced=frozenset(d["subject"] for d in interfaces if d["direction"] == EXPANDED),
        withdrawn=frozenset(d["subject"] for d in interfaces if d["direction"] == CONTRACTED),
    ) if comparable else None
    subjects, unexplained = [], []
    for key in changed:
        kind = key.partition(":")[0]
        if comparable and key == f"permissions:{identity}":
            paths = [d["path"] for d in (authz or {}).get("dimensions", [])]
            if paths and all(path != "authorization" for path in paths):
                subjects.extend(paths)
            else:
                unexplained.append(key)
            continue
        if comparable and kind == "mcp":
            before_parts = (before["facts"].get("catalog_parts") or {})
            after_parts = (after["facts"].get("catalog_parts") or {})
            moved = [part for part in MCP_PARTS if before_parts.get(part) != after_parts.get(part)]
            if moved:
                subjects.extend(pointer("mcp", part) for part in moved)
            elif not ((authz or {}).get("dimensions") or any(k.startswith("tool:") for k in changed)):
                unexplained.append(key)
            continue
        subjects.append(key)
    result["subjects"] = sorted(set(subjects))
    result["unexplained"] = sorted(set(unexplained))
    if before is None:
        result["authority"] = {"classification": UNKNOWN, "subjects": [], "dimensions": [],
                               "reason": "First observation from this source; there is no earlier authority to compare."}
    elif comparable:
        dimensions = [*(authz or {}).get("dimensions", []), *interfaces]
        if authz is None and not interfaces:
            reason = "The source declared no authorization configuration; ThreatVeil cannot establish that authority is unchanged."
            result["authority"] = {"classification": UNKNOWN, "subjects": [], "dimensions": [], "reason": reason}
        else:
            result["authority"] = {
                "classification": combine(d["direction"] for d in dimensions) if dimensions else EQUIVALENT,
                "subjects": (authz or {}).get("subjects", []), "dimensions": dimensions,
                "reason": "Compared the declared authorization and interface catalog before and after this change.",
            }
    else:
        touched = [key for key in changed if key.partition(":")[0] in AUTHORITY_TYPES]
        result["authority"] = {
            "classification": UNKNOWN, "subjects": [],
            "dimensions": [{"kind": "DIGEST", "subject": key, "subject_path": key, "condition": "configuration",
                            "path": key, "before": "digest", "after": "changed digest", "direction": UNKNOWN,
                            "reason": "Permission or identity configuration changed; only a digest is retained, "
                                      "so its direction cannot be established."} for key in touched],
            "reason": ("Authority-bearing configuration changed without structured facts."
                       if touched else "This source reports no structured authority facts; ThreatVeil cannot "
                                       "establish whether authority changed."),
        }
    return result


def mapping_index(rows, installation_id):
    """Latest reviewed mapping per subject for one source installation."""
    index = {}
    for row in rows:  # history() order: newest first
        value = row.payload
        if value.get("installation_id") != str(installation_id):
            continue
        index.setdefault(value["subject"], {"id": str(row.id), "maps_to": list(value.get("maps_to", [])),
                                            "authority_basis": value.get("authority_basis")})
    return index


def scope_change(explanation, index):
    """Translate named subjects into reviewed claim dependencies, or refuse to.

    Every subject must carry a reviewed mapping. One unmapped subject leaves the
    whole change conservative, because an unnamed fact can reach any claim.
    """
    if explanation["conservative"] or explanation["unexplained"] or not explanation["subjects"]:
        return {"fully_mapped": False, "dependencies": [], "mapping_ids": [],
                "unmapped": explanation["unexplained"] or explanation["subjects"]}
    dependencies, used, unmapped = set(), [], []
    for subject in explanation["subjects"]:
        mapping = index.get(subject)
        if not mapping or not mapping["maps_to"]:
            unmapped.append(subject)
            continue
        dependencies.update(mapping["maps_to"])
        used.append(mapping["id"])
    return {"fully_mapped": not unmapped, "dependencies": sorted(dependencies) if not unmapped else [],
            "mapping_ids": used, "unmapped": unmapped}
