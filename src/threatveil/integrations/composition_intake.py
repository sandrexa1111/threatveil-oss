"""CycloneDX composition and SARIF finding imports, without external resolution."""

import re
from typing import Any

from threatveil.core.contracts import FingerprintComponent, SystemFingerprint, digest

from .intake import (
    MAX_ITEMS,
    ImportedFinding,
    IntakeContext,
    NormalizedIntake,
    array_value,
    component_id,
    object_value,
    text_value,
)


def _bom_component(value: dict) -> dict:
    result = dict(value)
    for field in ("components", "services"):
        if field in value:
            result[field] = sorted((_bom_component(v) for v in value[field]), key=digest)
    if "hashes" in value:
        result["hashes"] = sorted(array_value(value["hashes"], "CycloneDX hashes"), key=digest)
    return result


def _bom_canonical(value: dict) -> dict:
    """Normalize known BOM collections; never reorder similarly named extensions."""
    result = _bom_component(value)
    if "dependencies" in value:
        dependencies = []
        for raw in value["dependencies"]:
            entry = dict(raw)
            for field in ("dependsOn", "provides"):
                if field in entry:
                    entry[field] = sorted(
                        array_value(entry[field], f"CycloneDX {field}"), key=digest
                    )
            dependencies.append(entry)
        result["dependencies"] = sorted(dependencies, key=digest)
    metadata = value.get("metadata", {})
    if "component" in metadata:
        result["metadata"] = {**metadata, "component": _bom_component(metadata["component"])}
    return result


def normalize_cyclonedx(payload: dict, ctx: IntakeContext) -> NormalizedIntake:
    if payload.get("bomFormat") != "CycloneDX":
        raise ValueError("Expected a CycloneDX JSON document")
    if payload.get("specVersion") not in {"1.4", "1.5", "1.6", "1.7"}:
        raise ValueError("Supported CycloneDX JSON versions are 1.4 through 1.7")
    objects: dict[str, tuple[str, dict]] = {}
    parent_edges: dict[str, list[str]] = {}
    limitations = {
        "Composition is a declared inventory; it does not prove deployed state or behavior.",
        "No BOM signature, external reference, license or vulnerability assertion is independently verified.",
    }

    def collect(raw: Any, service: bool = False, parent: str | None = None):
        item = object_value(raw, "CycloneDX service" if service else "CycloneDX component")
        name = text_value(item.get("name"), "CycloneDX component name")
        kind = "service" if service else text_value(item.get("type"), "CycloneDX component type")
        ref = item.get("bom-ref") or item.get("purl") or f"{item.get('group', '')}/{name}"
        ref = text_value(ref, "CycloneDX component reference", limit=4096)
        if ref in objects:
            raise ValueError("Duplicate or ambiguous CycloneDX component identity")
        if len(objects) >= MAX_ITEMS:
            raise ValueError("CycloneDX import exceeds 5000 components")
        mapped = (
            "model"
            if kind == "machine-learning-model"
            else "application"
            if kind == "application"
            else "service"
            if service
            else "dependency"
        )
        objects[ref] = (mapped, item)
        if parent:
            parent_edges.setdefault(parent, []).append(ref)
        for child in array_value(item.get("components", []), "Nested CycloneDX components"):
            collect(child, parent=ref)
        for child in array_value(item.get("services", []), "Nested CycloneDX services"):
            collect(child, service=True, parent=ref)

    metadata = object_value(payload.get("metadata", {}), "CycloneDX metadata")
    if "component" in metadata:
        collect(metadata["component"])
    for item in array_value(payload.get("components", []), "CycloneDX components"):
        collect(item)
    for item in array_value(payload.get("services", []), "CycloneDX services"):
        collect(item, service=True)
    graph: dict[str, list[str]] = {}
    for raw in array_value(payload.get("dependencies", []), "CycloneDX dependencies"):
        entry = object_value(raw, "CycloneDX dependency")
        ref = text_value(entry.get("ref"), "CycloneDX dependency reference", limit=4096)
        if ref in graph:
            raise ValueError("Duplicate CycloneDX dependency graph entry")
        refs = array_value(entry.get("dependsOn", []), "CycloneDX dependsOn")
        refs = [text_value(r, "CycloneDX dependency reference", limit=4096) for r in refs]
        if len(refs) != len(set(refs)):
            raise ValueError("Duplicate CycloneDX dependency edge")
        graph[ref] = refs
    unresolved = (set(graph) | {ref for refs in graph.values() for ref in refs}) - objects.keys()
    missing_graph = set(objects) - graph.keys()
    if unresolved:
        limitations.add("Some dependencies refer to unresolved components or external BOMs.")
    if missing_graph:
        limitations.add(
            "Components omitted from the dependency graph have UNKNOWN dependency coverage."
        )
    components = []
    for ref, (kind, item) in objects.items():
        version = item.get("version")
        if version is not None:
            version = text_value(version, "CycloneDX component version", limit=1000)
        refs = set(graph.get(ref, [])) | set(parent_edges.get(ref, []))
        dependencies = [
            f"{objects[r][0] if r in objects else 'dependency'}:{component_id(r)}"
            for r in sorted(refs)
        ]
        if ref in missing_graph:
            dependencies.append(f"dependency_graph:{component_id(ref)}")
        components.append(
            FingerprintComponent(
                type=kind,
                id=component_id(ref),
                version=version,
                digest=digest(_bom_component(item)),
                provenance="DECLARED",
                dependencies=tuple(dependencies),
            )
        )
    for ref in sorted(unresolved):
        components.append(
            FingerprintComponent(type="dependency", id=component_id(ref), provenance="UNKNOWN")
        )
    for ref in sorted(missing_graph):
        components.append(
            FingerprintComponent(
                type="dependency_graph", id=component_id(ref), provenance="UNKNOWN"
            )
        )
    compositions = array_value(payload.get("compositions", []), "CycloneDX compositions")
    complete_composition = bool(compositions)
    for raw in compositions:
        composition = object_value(raw, "CycloneDX composition")
        if (
            composition.get("aggregate") != "complete"
            or composition.get("assemblies")
            or composition.get("dependencies")
        ):
            complete_composition = False
            limitations.add("The BOM declares an incomplete or unknown composition.")
    if not complete_composition or unresolved or missing_graph:
        components.append(
            FingerprintComponent(
                type="composition_coverage", id=ctx.source_id, provenance="UNKNOWN"
            )
        )
    # Keep every root/extension field in the aggregate identity. An unsupported
    # semantic field can cause conservative invalidation, never silent equality.
    components.append(
        FingerprintComponent(
            type="composition",
            id=ctx.source_id,
            version=payload["specVersion"],
            digest=digest(_bom_canonical(payload)),
            provenance="DECLARED",
        )
    )
    components.sort(key=lambda c: (c.type, c.id))
    return NormalizedIntake(
        format="cyclonedx",
        source_digest=digest(payload),
        fingerprint=SystemFingerprint(components=tuple(components)),
        details={
            "spec_version": payload["specVersion"],
            "component_count": len(objects),
            "unresolved_references": sorted(unresolved),
            "missing_dependency_graph": sorted(missing_graph),
        },
        limitations=tuple(sorted(limitations)),
    )


def _sarif_message(message: Any, rule: dict, driver: dict) -> str:
    message = object_value(message, "SARIF message")
    content = message.get("text") or message.get("markdown")
    if content is None and message.get("id"):
        message_id = text_value(message["id"], "SARIF message id")
        strings = object_value(rule.get("messageStrings", {}), "SARIF rule messageStrings")
        value = strings.get(message_id)
        if value is None:
            strings = object_value(
                driver.get("globalMessageStrings", {}), "SARIF globalMessageStrings"
            )
            value = strings.get(message_id)
        if value is not None:
            rendered = object_value(value, "SARIF message string")
            content = rendered.get("text") or rendered.get("markdown")
    content = text_value(content, "SARIF result message", limit=20000)
    arguments = array_value(message.get("arguments", []), "SARIF message arguments", limit=100)
    if any(not isinstance(argument, str) for argument in arguments):
        raise ValueError("SARIF message arguments must be strings")

    def replacement(match):
        index = int(match.group(1))
        if index >= len(arguments):
            raise ValueError("SARIF message argument is missing")
        return arguments[index]

    return text_value(
        re.sub(r"(?<!\{)\{([0-9]+)\}(?!\})", replacement, content),
        "SARIF expanded message",
        limit=20000,
    )


def normalize_sarif(payload: dict, ctx: IntakeContext) -> NormalizedIntake:
    if payload.get("version") != "2.1.0":
        raise ValueError("Supported SARIF version is 2.1.0")
    findings = []
    limitations = {"SARIF results are unverified findings; no property is activated by import."}
    source_digest = digest(payload)
    for run_index, raw in enumerate(array_value(payload.get("runs"), "SARIF runs", limit=100)):
        run = object_value(raw, "SARIF run")
        tool = object_value(run.get("tool"), "SARIF tool")
        driver = object_value(tool.get("driver"), "SARIF driver")
        text_value(driver.get("name"), "SARIF scanner name")
        extensions = array_value(tool.get("extensions", []), "SARIF tool extensions", limit=100)
        artifacts = array_value(run.get("artifacts", []), "SARIF artifacts")
        for result_index, raw_result in enumerate(
            array_value(run.get("results", []), "SARIF results")
        ):
            if len(findings) >= MAX_ITEMS:
                raise ValueError("SARIF import exceeds 5000 results")
            result = object_value(raw_result, "SARIF result")
            rule_ref = object_value(result.get("rule", {}), "SARIF reporting descriptor reference")
            component_ref = object_value(
                rule_ref.get("toolComponent", {}), "SARIF tool component reference"
            )
            selected_driver = driver
            if component_ref:
                index = component_ref.get("index")
                if (
                    isinstance(index, int)
                    and not isinstance(index, bool)
                    and 0 <= index < len(extensions)
                ):
                    selected_driver = object_value(extensions[index], "SARIF tool extension")
                    if component_ref.get("name") not in (None, selected_driver.get("name")):
                        raise ValueError("SARIF extension name and index disagree")
                else:
                    matches = [
                        item
                        for item in extensions
                        if isinstance(item, dict)
                        and (
                            component_ref.get("guid")
                            and item.get("guid") == component_ref["guid"]
                            or component_ref.get("name")
                            and item.get("name") == component_ref["name"]
                        )
                    ]
                    if len(matches) != 1:
                        raise ValueError("SARIF tool component reference is unresolved")
                    selected_driver = matches[0]
            rules = array_value(selected_driver.get("rules", []), "SARIF rules")
            rule_id = result.get("ruleId", rule_ref.get("id"))
            rule_index = result.get("ruleIndex", rule_ref.get("index"))
            rule = {}
            if rule_index is not None:
                if (
                    not isinstance(rule_index, int)
                    or isinstance(rule_index, bool)
                    or not 0 <= rule_index < len(rules)
                ):
                    raise ValueError("SARIF ruleIndex is outside the rule table")
                rule = object_value(rules[rule_index], "SARIF rule")
                if rule_id is not None and rule_id != rule.get("id"):
                    raise ValueError("SARIF rule identity and index disagree")
                rule_id = rule.get("id")
            elif rule_id is not None:
                matches = [r for r in rules if isinstance(r, dict) and r.get("id") == rule_id]
                if len(matches) > 1:
                    raise ValueError("Duplicate SARIF rule identity")
                rule = matches[0] if matches else {}
            if rule_id is not None:
                rule_id = text_value(rule_id, "SARIF rule id")
            scanner = text_value(selected_driver.get("name"), "SARIF scanner")
            description = _sarif_message(result.get("message"), rule, selected_driver)
            level = result.get(
                "level",
                object_value(rule.get("defaultConfiguration", {}), "SARIF rule defaults").get(
                    "level", "warning"
                ),
            )
            if level not in {"none", "note", "warning", "error"}:
                raise ValueError("Invalid SARIF result level")
            locations = []
            for location in array_value(result.get("locations", []), "SARIF locations", limit=100):
                location = object_value(location, "SARIF location")
                physical = object_value(
                    location.get("physicalLocation", {}), "SARIF physicalLocation"
                )
                artifact = object_value(
                    physical.get("artifactLocation", {}), "SARIF artifactLocation"
                )
                if "index" in artifact:
                    index = artifact["index"]
                    if (
                        not isinstance(index, int)
                        or isinstance(index, bool)
                        or not 0 <= index < len(artifacts)
                    ):
                        raise ValueError("SARIF artifact index is outside the artifact table")
                    resolved = object_value(
                        object_value(artifacts[index], "SARIF artifact").get("location", {}),
                        "SARIF artifact location",
                    )
                    if (
                        artifact.get("uri")
                        and resolved.get("uri")
                        and artifact["uri"] != resolved["uri"]
                    ):
                        raise ValueError("SARIF artifact URI and index disagree")
                    artifact = {**resolved, **artifact}
                    location = {
                        **location,
                        "physicalLocation": {**physical, "artifactLocation": artifact},
                    }
                locations.append(location)
            partial = object_value(
                result.get("partialFingerprints", {}), "SARIF partialFingerprints"
            )
            if any(not isinstance(v, str) for v in partial.values()):
                raise ValueError("SARIF partial fingerprints must be strings")
            suppressions = tuple(
                object_value(v, "SARIF suppression")
                for v in array_value(
                    result.get("suppressions", []), "SARIF suppressions", limit=100
                )
            )
            if suppressions:
                limitations.add(
                    "Suppressed scanner results are retained; suppression does not erase adverse evidence."
                )
            if "externalPropertyFileReferences" in run:
                limitations.add(
                    "External SARIF property files were not fetched; this import may be incomplete."
                )
            title = rule.get("name") or rule_id or f"{scanner} finding"
            if len(title) > 200:
                title = f"{scanner[:120]} finding {digest(title)[:16]}"
            findings.append(
                ImportedFinding(
                    title=title,
                    description=description,
                    scanner=scanner,
                    scanner_version=selected_driver.get(
                        "semanticVersion", selected_driver.get("version")
                    ),
                    rule_id=rule_id,
                    level=level,
                    locations=tuple(locations),
                    partial_fingerprints=partial,
                    source_digest=source_digest,
                    result_digest=digest(result),
                    external_id=digest(
                        {
                            "scanner": scanner,
                            "run": run_index,
                            "result": result_index,
                            "source": source_digest,
                        }
                    ),
                    baseline_state=result.get("baselineState"),
                    result_kind=result.get("kind", "fail"),
                    suppressions=suppressions,
                )
            )
    return NormalizedIntake(
        format="sarif",
        source_digest=source_digest,
        findings=tuple(findings),
        limitations=tuple(sorted(limitations)),
    )
