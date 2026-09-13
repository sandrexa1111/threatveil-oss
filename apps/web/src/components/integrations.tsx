'use client';

/**
 * Integrations: an operating surface, not a catalogue.
 *
 * Every row states its relationship type (live source, import, protocol source, evidence
 * source, consumer, security import), its real state, what it does in one sentence, and
 * one action that actually exists. Only connectors the platform implements appear, an
 * import is never shown as a live connection, and a logo means exactly what its label says.
 */

import Link from 'next/link';
import { useSearchParams } from 'next/navigation';
import { useCallback, useEffect, useMemo, useState, type FormEvent } from 'react';
import { ArrowRight, Copy, KeyRound } from 'lucide-react';
import { api, items, obj, str, type RecordData } from '@/lib/api';
import { Drawer, EmptyState, Skeleton, StatusPill, ago, arr, list, num, plural, type Fields } from './product';
import { GateGlyph, RELATIONSHIP, SourceMark, type EcosystemId } from './ecosystem';
import { DetectionBar, DropZone, FoundFacts, documentOf, useDefinition } from './definition-input';
import { JsonDetails, type WorkspaceContext } from './workspace-parts';
import styles from './product.module.css';
import sig from './signature.module.css';
import c from './completion.module.css';

type Kind = 'LIVE_SOURCE' | 'IMPORT' | 'PROTOCOL_SOURCE' | 'EVIDENCE_SOURCE' | 'TRACE_IMPORT' | 'SECURITY_IMPORT';
type Mode = 'POLL' | 'PUSH' | 'IMPORT';
type Entry = {
  key: string; eco: EcosystemId; name: string; kind: Kind; connector: string; group: string;
  what: string; action: string; modes: Mode[]; formats?: string[];
};

const ENTRIES: Entry[] = [
  {key: 'github', eco: 'github', name: 'GitHub', kind: 'LIVE_SOURCE', connector: 'github', group: 'code', modes: ['POLL'],
    what: 'Watch a repository’s configured branch revision with a read credential. File contents are not read.', action: 'Connect GitHub'},
  {key: 'claude_code', eco: 'claude_code', name: 'Claude Code', kind: 'IMPORT', connector: 'agent_definition', group: 'code', modes: ['IMPORT'],
    formats: ['claude_settings', 'claude_subagent', 'mcp_json'],
    what: 'Import settings.json permissions and MCP servers, .mcp.json, and subagent definitions.', action: 'Import configuration'},
  {key: 'manifest', eco: 'manifest', name: 'ThreatVeil manifest', kind: 'IMPORT', connector: 'agent_definition', group: 'code', modes: ['IMPORT'],
    formats: ['manifest'], what: 'Describe agents, tools, approvals and MCP servers when a framework defines them in code.', action: 'Import manifest'},
  {key: 'mcp', eco: 'mcp', name: 'MCP', kind: 'PROTOCOL_SOURCE', connector: 'mcp', group: 'protocols', modes: ['IMPORT', 'POLL'],
    formats: ['mcp_tools', 'mcp_json'],
    what: 'Read a verified MCP server’s tool catalog, or import a tools/list snapshot or .mcp.json.', action: 'Connect or import'},
  {key: 'langgraph', eco: 'langgraph', name: 'LangGraph', kind: 'IMPORT', connector: 'agent_definition', group: 'platforms', modes: ['IMPORT'],
    formats: ['langgraph'], what: 'Import langgraph.json graph entry points. Tools defined in code stay unknown.', action: 'Import configuration'},
  {key: 'crewai', eco: 'crewai', name: 'CrewAI', kind: 'IMPORT', connector: 'agent_definition', group: 'platforms', modes: ['IMPORT'],
    formats: ['crewai'], what: 'Import agents.yaml: each agent’s tools, delegation and code-execution flags.', action: 'Import configuration'},
  {key: 'openai_agents', eco: 'openai_agents', name: 'OpenAI Agents SDK', kind: 'TRACE_IMPORT', connector: 'openai_agents', group: 'platforms',
    modes: ['IMPORT'], what: 'Import Span.export() records as recorded invocations. Agent definitions are code and are not read.', action: 'Import traces'},
  {key: 'anthropic_hooks', eco: 'claude_agent_sdk', name: 'Claude Agent SDK hooks', kind: 'TRACE_IMPORT', connector: 'anthropic_hooks',
    group: 'platforms', modes: ['IMPORT'], what: 'Import hook events — tool use, subagent start and stop — as recorded invocations.', action: 'Import events'},
  {key: 'cloud_run', eco: 'cloud_run', name: 'Cloud Run', kind: 'LIVE_SOURCE', connector: 'gcp_cloud_run', group: 'infrastructure',
    modes: ['POLL', 'IMPORT'], what: 'Read one service’s desired configuration and IAM policy. Never a running-code attestation.', action: 'Connect Cloud Run'},
  {key: 'otel', eco: 'opentelemetry', name: 'OpenTelemetry', kind: 'EVIDENCE_SOURCE', connector: 'otel', group: 'evidence', modes: ['PUSH', 'IMPORT'],
    what: 'Receive OTLP JSON GenAI spans as observations of what the system did.', action: 'Set up'},
  {key: 'sarif', eco: 'sarif', name: 'SARIF', kind: 'SECURITY_IMPORT', connector: 'sarif', group: 'evidence', modes: ['IMPORT'],
    what: 'Import scanner findings. They remain unreviewed and carry no behavioral verdict.', action: 'Import'},
  {key: 'cyclonedx', eco: 'cyclonedx', name: 'CycloneDX', kind: 'SECURITY_IMPORT', connector: 'cyclonedx', group: 'evidence', modes: ['IMPORT'],
    what: 'Import a declared software composition and its dependencies.', action: 'Import'},
];

const GROUPS: [string, string, string][] = [
  ['code', 'Code & configuration', 'What your agent is declared to be.'],
  ['protocols', 'Agent protocols', 'The tools an agent can actually reach.'],
  ['platforms', 'Agent platforms', 'Frameworks and SDKs your agents are built with.'],
  ['infrastructure', 'Infrastructure', 'Where the system is deployed and what it may do there.'],
  ['evidence', 'Evidence & observability', 'Observations of what the system did, and specialised security imports.'],
];

type State = {label: string; tone: 'ok' | 'attention' | 'neutral' | 'import'};
const connectorOf = (item: Fields) => str(obj(item.payload).connector_id, str(item.connector_id));
const modeOf = (item: Fields) => str(obj(item.payload).mode, str(item.mode));

function stateOf(entry: Entry, installs: Fields[], info: {systems: number; credentials: RecordData[] | null; restricted: boolean; mcpTargets: number}): State {
  if (!info.systems) return {label: 'Needs system', tone: 'neutral'};
  const live = installs.filter(item => modeOf(item) !== 'IMPORT');
  const connected = live.map(item => obj(item.health)).filter(health => health.connected);
  if (connected.length) return {label: `Connected · last seen ${ago(connected[0].last_recorded_at)}`, tone: 'ok'};
  if (live.some(item => !['CURRENT', 'DECLARED'].includes(str(obj(item.health).status))))
    return {label: 'Needs attention', tone: 'attention'};
  if (live.length) return {label: entry.connector === 'otel' ? 'Waiting for observations' : 'Not yet read', tone: 'neutral'};
  const imports = installs.filter(item => modeOf(item) === 'IMPORT');
  if (imports.length && entry.connector !== 'agent_definition') return {label: `Imported · ${plural(imports.length, 'snapshot')}`, tone: 'import'};
  if (entry.kind === 'LIVE_SOURCE' && entry.modes[0] === 'POLL' && info.credentials !== null && !info.restricted && !info.credentials.length)
    return {label: 'Configuration required', tone: 'attention'};
  if (entry.kind === 'LIVE_SOURCE') return {label: 'Not connected', tone: 'neutral'};
  if (entry.connector === 'otel') return {label: 'Not configured', tone: 'neutral'};
  return {label: 'Import available', tone: 'import'};
}

export function Integrations({ctx}: {ctx: WorkspaceContext}) {
  const params = useSearchParams();
  const [catalog, setCatalog] = useState<Fields[] | null>(null);
  const [installed, setInstalled] = useState<Fields[]>([]);
  const [credentials, setCredentials] = useState<RecordData[] | null>(null);
  const [restricted, setRestricted] = useState(false);
  const [error, setError] = useState('');
  const [open, setOpen] = useState<Entry | null>(null);
  const systems = items(ctx.dashboard?.systems);
  const [systemId, setSystemId] = useState(params.get('system') || '');
  useEffect(() => {
    if (!systemId && systems[0]) setSystemId(systems[0].id);
  }, [systems, systemId]);

  const load = useCallback(async () => {
    try {
      const [available, current] = await Promise.all([api<Fields>('/connectors/catalog'), api<Fields>('/connectors?limit=200')]);
      setCatalog(arr(available.items)); setInstalled(arr(current.items)); setError('');
    } catch (e) { setCatalog([]); setError(e instanceof Error ? e.message : 'Unable to load integrations.'); }
  }, []);
  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    api('/credentials').then(r => setCredentials(items(r))).catch(() => { setRestricted(true); setCredentials([]); });
  }, []);

  const implemented = useMemo(() => new Set((catalog || []).map(item => str(item.id, str(item.connector_id)))), [catalog]);
  const mcpTargets = ctx.targets.filter(target => target.adapter === 'mcp').length;
  const info = {systems: systems.length, credentials, restricted, mcpTargets};
  const installsFor = (entry: Entry) => installed.filter(item => connectorOf(item) === entry.connector);
  const live = installed.filter(item => modeOf(item) !== 'IMPORT' && obj(item.health).connected).length;
  const imports = installed.filter(item => modeOf(item) === 'IMPORT').length;
  const attention = installed.filter(item => modeOf(item) !== 'IMPORT'
    && !['CURRENT', 'DECLARED'].includes(str(obj(item.health).status))).length;
  const definitions = installed.filter(item => connectorOf(item) === 'agent_definition').length;

  if (!catalog) return <Skeleton label="Loading integrations" rows={5} header/>;
  const visible = ENTRIES.filter(entry => implemented.has(entry.connector));
  const action = (entry: Entry) => systems.length
    ? <button type="button" className="button outline small" onClick={() => setOpen(entry)}>{entry.action}</button>
    : <Link href="/app/systems/new" className="button outline small">Connect a system first</Link>;

  return <div className={styles.root}>
    <div className={styles.sectionHead}>
      <div>
        <h2>Integrations</h2>
        <p>Where your agents live, exactly how ThreatVeil relates to each, and what reads ThreatVeil’s answer.</p>
      </div>
      {systems.length > 1 && <label style={{minWidth: 220}}>Actions apply to
        <select value={systemId} onChange={e => setSystemId(e.target.value)}>
          {systems.map(system => <option key={system.id} value={system.id}>{str(system.name, system.id)}</option>)}
        </select>
      </label>}
    </div>
    {error && <div className="notice error" role="alert">{error}</div>}

    <section className={styles.attentionSummary} data-tone={attention ? 'attention' : 'ok'} aria-label="Integration summary">
      <strong>{live ? `${plural(live, 'live source')} connected` : 'No live source connected'}</strong>
      <span>{plural(imports, 'imported snapshot')}</span>
      {attention > 0 && <span>{plural(attention, 'source')} need attention</span>}
      <span>{visible.length} implemented integrations</span>
    </section>

    {!systems.length && <EmptyState title="Connect a system first."
      body="Every source and import belongs to one protected system and its environment."
      action={<Link href="/app/systems/new" className="button dark small">Connect a system <ArrowRight size={14}/></Link>}/>}

    <section aria-labelledby="recommended" className={styles.block}>
      <div className={c.groupHead}><h2 id="recommended">Recommended</h2><p>The fastest way to a real answer about your own system.</p></div>
      <div className={c.recommended}>
        {visible.filter(entry => ['github', 'mcp', 'claude_code'].includes(entry.key)).map(entry => {
          const state = stateOf(entry, installsFor(entry), info);
          return <article key={entry.key} className={c.method} style={{cursor: 'default'}}>
            <span className={c.methodTop}>
              {entry.key === 'claude_code'
                ? <SourceMark id="definition" size="lg" name/>
                : <SourceMark id={entry.eco} size="lg" name/>}
              <span className={c.methodKind}>{entry.key === 'claude_code' ? 'Supported definitions' : RELATIONSHIP[entry.kind]}</span>
            </span>
            <p>{entry.key === 'claude_code' ? 'Upload any supported definition — Claude Code, MCP, LangGraph, CrewAI or a manifest — and the format is detected.' : entry.what}</p>
            <span style={{display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap'}}>
              <span className={c.state} data-tone={state.tone}>{state.label}</span>
              {entry.key === 'claude_code' && !systems.length
                ? <Link href="/app/systems/new" className="button outline small">Upload configuration</Link> : action(entry)}
            </span>
          </article>;
        })}
      </div>
    </section>

    {GROUPS.map(([group, title, description]) => {
      const rows = visible.filter(entry => entry.group === group);
      if (!rows.length) return null;
      return <section key={group} aria-labelledby={`group-${group}`} className={styles.block}>
        <div className={c.groupHead}>
          <h2 id={`group-${group}`}>{title}</h2><p>{description}</p>
          {group === 'code' && !!definitions && <p>{plural(definitions, 'agent definition import')} across your systems.</p>}
        </div>
        <ul className={c.integrationRows}>
          {rows.map(entry => {
            const state = stateOf(entry, installsFor(entry), info);
            const manifest = (catalog || []).find(item => str(item.id) === entry.connector);
            return <li key={entry.key} className={c.integrationRow}>
              <SourceMark id={entry.eco} size="md"/>
              <div className={c.integrationName}>
                <strong>{entry.name}</strong>
                <span className={c.methodKind}>{RELATIONSHIP[entry.kind]}</span>
              </div>
              <div className={c.integrationWhat}>{entry.what}</div>
              <div className={c.integrationSide}>
                <span className={c.state} data-tone={state.tone}>{state.label}</span>
                {action(entry)}
              </div>
              <details>
                <summary>Coverage and limitations</summary>
                <ul>{list(manifest?.limitations).map(line => <li key={line}>{line}</li>)}
                  <li>Modes: {entry.modes.map(mode => mode === 'POLL' ? 'ThreatVeil reads it' : mode === 'PUSH' ? 'you send observations' : 'you upload a snapshot').join(' · ')}</li>
                </ul>
              </details>
            </li>;
          })}
          {group === 'evidence' && <li className={c.integrationRow}>
            <SourceMark id="observer" size="md"/>
            <div className={c.integrationName}><strong>Qualified observers</strong><span className={c.methodKind}>Evidence source</span></div>
            <div className={c.integrationWhat}>A reviewed observer that can witness a committed business effect — the only basis for positive assurance.</div>
            <div className={c.integrationSide}>
              <Link href="/app/settings/developer#observers" className="button outline small">Manage observers</Link>
            </div>
          </li>}
        </ul>
      </section>;
    })}

    <Consumers systems={systems} systemId={systemId}/>

    {open && <ConnectDrawer entry={open} ctx={ctx} systems={systems} systemId={systemId} setSystemId={setSystemId}
      credentials={credentials} restricted={restricted} manifest={(catalog || []).find(item => str(item.id) === open.connector)}
      onClose={() => setOpen(null)} onDone={load}/>}
  </div>;
}

/** Who reads ThreatVeil's answer: the Assurance Gate, and GitHub Checks on an exact commit. */
function Consumers({systems, systemId}: {systems: RecordData[]; systemId: string}) {
  const [github, setGithub] = useState<Fields | null>(null);
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    api<Fields>('/integrations').then(value => setGithub(arr(value.items).find(item => item.id === 'github') || null)).catch(() => undefined);
  }, []);
  const system = systems.find(item => item.id === systemId) || systems[0];
  const origin = typeof window === 'undefined' ? 'https://your-threatveil-host' : window.location.origin;
  const command = system
    ? `curl -s \\\n  -H "Authorization: Bearer $THREATVEIL_TOKEN" \\\n  -H "X-ThreatVeil-Consumer: ci-gate" \\\n  ${origin}/api/backend/v1/systems/${system.id}/assurance/current`
    : 'Connect a system to see the exact gate URL for it.';
  const bound = num(github?.active_bindings);
  return <section aria-labelledby="consumers" className={styles.block} id="assurance-gate">
    <div className={c.groupHead}>
      <h2 id="consumers">Use ThreatVeil’s answer</h2>
      <p>Consumers read assurance. Your policy decides what happens next.</p>
    </div>
    <div className={c.consumers}>
      <article className={sig.primitive} data-kind="gate" aria-label="Assurance Gate consumer">
        <div className={sig.primitiveHead}>
          <span className={sig.primitiveGlyph}><GateGlyph size={15}/></span>
          <div><h3>Assurance Gate</h3><span>Consumer · a read-only answer for one system</span></div>
          <span className={c.state} data-tone={system ? 'ok' : 'neutral'}>{system ? 'Ready' : 'Needs system'}</span>
        </div>
        <p className={sig.primitiveNote}>
          {system ? `Answers for ${str(system.name)}. ` : ''}UNKNOWN never means authorization, and no response grants permission.
        </p>
        <div className={styles.code}>{command}</div>
        <div className={sig.primitiveActions}>
          <button className="button outline small" disabled={!system}
            onClick={() => { navigator.clipboard?.writeText(command.replaceAll('\\\n  ', '')); setCopied(true); }}>
            <Copy size={14}/>{copied ? 'Copied' : 'Copy command'}
          </button>
          <Link href="/app/settings/developer" className="text-button"><KeyRound size={13}/>Issue a read-only token <ArrowRight size={13}/></Link>
        </div>
      </article>
      <article className={sig.primitive} aria-label="GitHub Checks consumer">
        <div className={sig.primitiveHead}>
          <SourceMark id="github_checks" size="lg"/>
          <div><h3>GitHub Checks</h3><span>Consumer · proposed-change checks on an exact commit</span></div>
          <span className={c.state} data-tone={bound ? 'ok' : 'attention'}>{bound ? `Connected · ${plural(bound, 'binding')}` : 'Configuration required'}</span>
        </div>
        <p className={sig.primitiveNote}>Publishes a non-blocking check against an exact candidate revision. A binding is configuration, not a verified external GitHub execution.</p>
        <div className={sig.primitiveActions}>
          <Link href="/app/settings/security" className="button outline small">Workflow bindings <ArrowRight size={13}/></Link>
          <Link href="/docs" className="text-button">Setup guidance <ArrowRight size={13}/></Link>
        </div>
        {!!github && <JsonDetails data={github} label="Configured binding status"/>}
      </article>
    </div>
  </section>;
}

/**
 * Connect or import one integration for one system, using only the connector API that
 * already exists: create the installation, then collect (live), accept pushes, or import.
 */
function ConnectDrawer({entry, ctx, systems, systemId, setSystemId, credentials, restricted, manifest, onClose, onDone}: {
  entry: Entry; ctx: WorkspaceContext; systems: RecordData[]; systemId: string; setSystemId: (id: string) => void;
  credentials: RecordData[] | null; restricted: boolean; manifest?: Fields; onClose: () => void; onDone: () => Promise<void>;
}) {
  const [environmentId, setEnvironmentId] = useState<string | null>(null);
  const [mode, setMode] = useState<Mode>(entry.modes[0]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState('');
  const [file, setFile] = useState<{name: string; text: string} | null>(null);
  const definition = useDefinition(ctx);
  const system = systems.find(item => item.id === systemId);
  const targets = ctx.targets.filter(target => target.system_id === systemId && target.adapter === 'mcp');
  const usesDefinition = mode === 'IMPORT' && !!entry.formats;

  useEffect(() => {
    setEnvironmentId(null);
    if (!systemId) return;
    api<Fields>(`/systems/${systemId}/summary`).then(summary => setEnvironmentId(str(obj(summary.environment).id, '')))
      .catch(() => setEnvironmentId(''));
  }, [systemId]);

  const roles = (mode === 'IMPORT' && entry.connector === 'mcp') ? ['DISCOVER', 'CHANGE']
    : list(manifest?.installation_roles).length ? list(manifest?.installation_roles) : ['DISCOVER', 'CHANGE'];
  const expires = (days: number) => new Date(Date.now() + days * 86400000).toISOString();

  async function install(connector: string, installMode: Mode, name: string, configuration: Fields = {}, credential?: string, installRoles = roles) {
    return ctx.mutate('/connectors', {system_id: systemId, environment_id: environmentId, connector_id: connector,
      mode: installMode, roles: installRoles, name, configuration, credential_id: credential || null,
      expires_at: expires(installMode === 'IMPORT' ? 30 : 7)});
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const name = str(form.get('name'), `${entry.name} for ${str(system?.name, 'system')}`);
    setBusy(true); setError(''); setResult('');
    try {
      if (mode === 'POLL') {
        const configuration = entry.connector === 'github'
          ? {repository: form.get('repository'), repository_id: form.get('repository_id'), ref: form.get('ref')}
          : entry.connector === 'gcp_cloud_run' ? {service: form.get('service')}
          : {target_id: form.get('target_id'), path: form.get('path')};
        const installation = await install(entry.connector, 'POLL', name, configuration, String(form.get('credential_id') || ''));
        const collected = await ctx.mutate(`/connectors/${installation.id}/collect`, {event_id: crypto.randomUUID()});
        setResult(str(collected.status) === 'RECORDED' ? 'Connected. The first read was recorded.'
          : `Saved. The first read returned ${str(collected.status).replaceAll('_', ' ').toLowerCase()}; nothing was recorded as observed.`);
      } else if (mode === 'PUSH') {
        const installation = await install(entry.connector, 'PUSH', name, {}, undefined, ['OBSERVE']);
        setResult(`Ready to receive. Send OTLP JSON batches to /api/backend/v1/connectors/${installation.id}/telemetry with a workspace API token.`);
      } else if (usesDefinition) {
        const format = definition.format;
        if (!format) throw new Error('Choose a file ThreatVeil can read first.');
        if (entry.formats && !entry.formats.includes(format) && entry.connector !== 'agent_definition' && format !== 'mcp_json')
          throw new Error('This integration cannot read that format.');
        const catalog = format === 'mcp_tools';
        const installation = await install(catalog ? 'mcp' : 'agent_definition', 'IMPORT',
          name, {}, undefined, ['DISCOVER', 'CHANGE']);
        await ctx.mutate(`/connectors/${installation.id}/import`, {event_id: crypto.randomUUID(), valid_at: new Date().toISOString(),
          payload: catalog ? documentOf(definition.text, format) : {format, document: documentOf(definition.text, format)}});
        setResult('Imported. ThreatVeil compares the next import of this source against it.');
      } else {
        if (!file) throw new Error('Choose the export file to import.');
        let payload: unknown;
        try { payload = JSON.parse(file.text); } catch { throw new Error('That file is not valid JSON.'); }
        const installation = await install(entry.connector, 'IMPORT', name);
        await ctx.mutate(`/connectors/${installation.id}/import`, {event_id: crypto.randomUUID(), valid_at: new Date().toISOString(), payload});
        setResult('Imported as an unreviewed snapshot. It is never presented as a live connection.');
      }
      await onDone();
    } catch (e) { setError(e instanceof Error ? e.message : 'That could not be completed.'); }
    finally { setBusy(false); }
  }

  const credentialMissing = credentials !== null && !restricted && !credentials.length;
  const liveBlocked = mode === 'POLL' && ((entry.connector !== 'mcp' && credentialMissing) || (entry.connector === 'mcp' && !targets.length));
  return <Drawer open title={`${entry.action} · ${entry.name}`} onClose={onClose}
    subtitle={<SourceMark id={entry.eco} name relationship={entry.kind}/>}>
    <form onSubmit={submit} style={{display: 'grid', gap: 12}}>
      <label>Protected system
        <select value={systemId} onChange={e => setSystemId(e.target.value)}>
          {systems.map(item => <option key={item.id} value={item.id}>{str(item.name, item.id)}</option>)}
        </select>
      </label>
      {environmentId === null ? <Skeleton label="Loading the system environment" rows={1}/>
        : !environmentId ? <div className={c.config}><strong>Needs an environment</strong>
          <p>Every source belongs to one environment. <Link href={`/app/systems/${systemId}/setup`}>Set one up</Link> first.</p></div>
        : <>
          {entry.modes.length > 1 && <div className={c.filters} role="group" aria-label="Connection mode">
            {entry.modes.map(item => <button key={item} type="button" aria-pressed={mode === item} onClick={() => setMode(item)}>
              {item === 'POLL' ? 'Live source' : item === 'PUSH' ? 'Send observations' : 'Import a file'}
            </button>)}
          </div>}
          <label>Connection name<input name="name" maxLength={120} defaultValue={`${entry.name} for ${str(system?.name, 'system')}`}/></label>

          {mode === 'POLL' && liveBlocked && <div className={c.config}>
            <strong>Configuration required</strong>
            <p>{entry.connector === 'mcp'
              ? 'A live MCP source reads only a verified MCP target registered for this system. Register and verify one under Developer → Authorized targets.'
              : 'No read credential reference is registered for this organization. An owner registers one before ThreatVeil can read this source.'}</p>
            <Link href={entry.connector === 'mcp' ? '/app/targets' : '/app/settings/security'} className="text-button">
              {entry.connector === 'mcp' ? 'Authorized targets' : 'Settings → Security'} <ArrowRight size={13}/></Link>
          </div>}
          {mode === 'POLL' && !liveBlocked && <>
            {entry.connector === 'github' && <>
              <label>Repository<input name="repository" required placeholder="organization/repository"/></label>
              <label>Numeric repository ID<input name="repository_id" required inputMode="numeric"/></label>
              <label>Branch reference<input name="ref" required defaultValue="refs/heads/main"/></label>
            </>}
            {entry.connector === 'gcp_cloud_run' && <label>Cloud Run resource
              <input name="service" required placeholder="projects/project/locations/region/services/service"/></label>}
            {entry.connector === 'mcp' && <>
              <label>Verified MCP target<select name="target_id" required>
                {targets.map(target => <option key={target.id} value={target.id}>{str(target.name, target.id)}</option>)}
              </select></label>
              <label>Authorized MCP path<input name="path" required defaultValue="/mcp"/></label>
            </>}
            {entry.connector !== 'mcp' && <label>Read credential reference
              {restricted ? <input name="credential_id" required placeholder="Reference ID from an owner"/>
                : <select name="credential_id" required>{(credentials || []).map(item =>
                    <option key={item.id} value={item.id}>{str(item.name || item.label, item.id)}</option>)}</select>}
            </label>}
            <p className={styles.muted}>Use a narrowly scoped credential. A connection does not qualify business effects or identify every running component.</p>
          </>}

          {mode === 'PUSH' && <p className={styles.muted}>ThreatVeil creates an intake for this system. An authenticated uploader is not an independent witness, and sampling stays unknown.</p>}

          {usesDefinition && <>
            <DropZone onFile={definition.pick} hint={entry.connector === 'mcp'
              ? 'A tools/list catalog snapshot or a .mcp.json.' : 'The format is detected automatically.'}/>
            <DetectionBar definition={definition}/>
            {!!definition.format && definition.result && <FoundFacts result={definition.result}/>}
          </>}
          {mode === 'IMPORT' && !entry.formats && <>
            <DropZone accept=".json,application/json" hint={`A ${entry.name} JSON export. It is imported as an unreviewed snapshot.`}
              onFile={async picked => setFile({name: picked.name, text: await picked.text()})}/>
            {file && <span className={c.fileName} role="status">{file.name}</span>}
          </>}

          {error && <div className="notice error" role="alert">{error}</div>}
          {result && <div className="notice success" role="status">{result}</div>}
          <div style={{display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap'}}>
            <button className="button dark small" disabled={busy || liveBlocked || (usesDefinition && !definition.format)}>
              {busy ? 'Working…' : mode === 'POLL' ? 'Connect and read' : mode === 'PUSH' ? 'Create intake' : 'Import'}
            </button>
            <button type="button" className="text-button" onClick={onClose}>Close</button>
          </div>
          <StatusPill label={RELATIONSHIP[mode === 'POLL' ? 'LIVE_SOURCE' : mode === 'PUSH' ? 'INSTRUMENTED' : 'IMPORTED']} tone="neutral"/>
        </>}
    </form>
  </Drawer>;
}
