'use client';

/**
 * Ecosystem identity, and the small set of glyphs that belong to ThreatVeil alone.
 *
 * Truth rule: an identity only ever appears beside a relationship label, and the label
 * says exactly what the relationship is. "Claude Code · Import" means ThreatVeil reads a
 * file you supply; it never means a live Anthropic integration, a partnership or an
 * endorsement. Third-party marks are shown as neutral monogram tiles with the product's
 * name in text: no official asset files were available to this build, and several
 * vendors' mark-usage terms were unclear, so no proprietary logo is reproduced here.
 * `SourceMark` is the single place an approved asset would later be substituted.
 */

import styles from './signature.module.css';

export type EcosystemId =
  | 'github' | 'claude_code' | 'claude_agent_sdk' | 'openai_agents' | 'mcp' | 'langgraph' | 'crewai'
  | 'cloud_run' | 'opentelemetry' | 'sarif' | 'cyclonedx' | 'manifest' | 'definition' | 'gate' | 'github_checks' | 'observer';

export const ECOSYSTEM: Record<EcosystemId, {name: string; monogram: string}> = {
  github: {name: 'GitHub', monogram: 'GH'},
  github_checks: {name: 'GitHub Checks', monogram: 'GH'},
  claude_code: {name: 'Claude Code', monogram: 'CC'},
  claude_agent_sdk: {name: 'Claude Agent SDK', monogram: 'AS'},
  openai_agents: {name: 'OpenAI Agents SDK', monogram: 'OA'},
  mcp: {name: 'MCP', monogram: 'MCP'},
  langgraph: {name: 'LangGraph', monogram: 'LG'},
  crewai: {name: 'CrewAI', monogram: 'CA'},
  cloud_run: {name: 'Cloud Run', monogram: 'CR'},
  opentelemetry: {name: 'OpenTelemetry', monogram: 'OT'},
  sarif: {name: 'SARIF', monogram: 'SF'},
  cyclonedx: {name: 'CycloneDX', monogram: 'CDX'},
  manifest: {name: 'ThreatVeil manifest', monogram: 'TV'},
  definition: {name: 'Agent definition', monogram: '{ }'},
  gate: {name: 'Assurance Gate', monogram: ''},
  observer: {name: 'Qualified observer', monogram: 'QO'},
};

/** Connector ids the platform implements, to the identity a customer recognises. */
export const CONNECTOR_ECOSYSTEM: Record<string, EcosystemId> = {
  github: 'github', mcp: 'mcp', gcp_cloud_run: 'cloud_run', otel: 'opentelemetry', openai_agents: 'openai_agents',
  anthropic_hooks: 'claude_agent_sdk', cyclonedx: 'cyclonedx', sarif: 'sarif', agent_definition: 'definition',
};

/** Definition formats the deterministic adapters read, and the identity each format establishes. */
export const FORMATS: {id: string; label: string; ecosystem: EcosystemId; file: string}[] = [
  {id: 'claude_settings', label: 'Claude Code settings', ecosystem: 'claude_code', file: 'settings.json'},
  {id: 'claude_subagent', label: 'Claude subagent', ecosystem: 'claude_code', file: 'agents/*.md'},
  {id: 'mcp_json', label: 'MCP server configuration', ecosystem: 'mcp', file: '.mcp.json'},
  {id: 'mcp_tools', label: 'MCP tool catalog', ecosystem: 'mcp', file: 'tools/list snapshot'},
  {id: 'langgraph', label: 'LangGraph configuration', ecosystem: 'langgraph', file: 'langgraph.json'},
  {id: 'crewai', label: 'CrewAI agents', ecosystem: 'crewai', file: 'agents.yaml'},
  {id: 'manifest', label: 'ThreatVeil agent manifest', ecosystem: 'manifest', file: 'threatveil.yaml'},
];
export const formatInfo = (id: unknown) => FORMATS.find(format => format.id === id);

/** The exact relationship an identity has with ThreatVeil. A logo never implies more. */
export const RELATIONSHIP: Record<string, string> = {
  LIVE_SOURCE: 'Live source', PROTOCOL_SOURCE: 'Protocol source', IMPORT: 'Import', IMPORTED: 'Imported snapshot',
  TRACE_IMPORT: 'Trace import', DEFINITION: 'Supported definition', DECLARED: 'Declared in definition',
  EVIDENCE_SOURCE: 'Evidence source', INSTRUMENTED: 'Sends observations', CONSUMER: 'Consumer',
  SECURITY_IMPORT: 'Advanced security import',
};

export function SourceMark({id, size = 'sm', name = false, relationship}: {
  id: EcosystemId | string | undefined; size?: 'sm' | 'md' | 'lg'; name?: boolean; relationship?: string;
}) {
  const known = ECOSYSTEM[(id || 'definition') as EcosystemId] || ECOSYSTEM.definition;
  const label = RELATIONSHIP[relationship || ''] || relationship;
  return <span className={styles.source} data-size={size}>
    <span className={styles.mark} data-eco={id} data-size={size} aria-hidden="true"
      data-long={known.monogram.length > 2 ? 'true' : undefined}>
      {id === 'gate' ? <GateGlyph size={size === 'lg' ? 16 : 12}/> : known.monogram}
    </span>
    {name && <span className={styles.sourceName}>{known.name}</span>}
    {!name && <span className="sr-only">{known.name}</span>}
    {label && <span className={styles.relationship}>{label}</span>}
  </span>;
}

/* ---------------------------------------------------------------------------------
   ThreatVeil glyphs. Five, and only for concepts unique to the product. Standard UI
   actions keep ordinary icons. Monochrome, 16px grid, currentColor.
   --------------------------------------------------------------------------------- */

type GlyphProps = {size?: number; className?: string};
const svg = (size: number, className: string | undefined, children: React.ReactNode) =>
  <svg width={size} height={size} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth={1.5}
    strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" className={className}>{children}</svg>;

/** Assurance: a chain of established links ending in the current answer. */
export function AssuranceGlyph({size = 16, className}: GlyphProps) {
  return svg(size, className, <>
    <circle cx="8" cy="2.8" r="1.6"/><circle cx="8" cy="8" r="1.6"/>
    <circle cx="8" cy="13.2" r="1.9" fill="currentColor"/>
    <path d="M8 4.4v2M8 9.6v1.7"/>
  </>);
}

/** Authority: what a system can do, crossing its declared boundary. */
export function AuthorityGlyph({size = 16, className}: GlyphProps) {
  return svg(size, className, <>
    <path d="M10 3.2H3.6a1 1 0 0 0-1 1v7.6a1 1 0 0 0 1 1H10"/>
    <path d="M6.5 8h7M11 5.5 13.5 8 11 10.5"/>
  </>);
}

/** Evidence continuity: observations that still describe the system as it runs now. */
export function EvidenceGlyph({size = 16, className}: GlyphProps) {
  return svg(size, className, <>
    <path d="M2 11.5h12"/>
    <circle cx="4" cy="11.5" r="1.3"/><circle cx="8" cy="11.5" r="1.3"/>
    <circle cx="12" cy="11.5" r="1.5" fill="currentColor"/>
    <path d="M4 8.6V4.5M8 8.6V3M12 8.4V6"/>
  </>);
}

/** Assurance Gate: a read-only answer between two posts. No lock, no shield: it grants nothing. */
export function GateGlyph({size = 16, className}: GlyphProps) {
  return svg(size, className, <>
    <path d="M3 2.5v11M13 2.5v11"/>
    <path d="M3 6h10" strokeDasharray="1.6 1.6"/>
    <circle cx="8" cy="10" r="1.7" fill="currentColor"/>
  </>);
}

/** Passport: a portable signed statement, and a separate ring for its current status. */
export function PassportGlyph({size = 16, className}: GlyphProps) {
  return svg(size, className, <>
    <path d="M9.5 14H4a1.2 1.2 0 0 1-1.2-1.2V3.2A1.2 1.2 0 0 1 4 2h6a1.2 1.2 0 0 1 1.2 1.2V7"/>
    <path d="M5.2 5h3.6M5.2 7.4h2.4"/>
    <path d="M14.2 11.6a2.6 2.6 0 1 1-1.1-2.1"/>
    <path d="m11 11.4 1 1 2.2-2.4"/>
  </>);
}
