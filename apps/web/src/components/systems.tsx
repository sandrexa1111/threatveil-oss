'use client';

/**
 * Systems: a clean inventory of protected systems, and the flow that connects one.
 * Nothing here is a template gallery once real systems exist.
 */

import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { ArrowRight, Boxes, FlaskConical, Upload } from 'lucide-react';
import { api, items, obj, str, date, type RecordData } from '@/lib/api';
import {
  EmptyState, NEXT_ACTION, PrimaryAction, Skeleton, SourceLine, StatusPill, arr, clearanceView, list, num,
  useListKeys, type Fields,
} from './product';
import { FORMATS, SourceMark, formatInfo } from './ecosystem';
import { SetupProgress, type Stage } from './signature';
import { DetectionBar, DropZone, FoundFacts, documentOf, useDefinition } from './definition-input';
import type { WorkspaceContext } from './workspace-parts';
import styles from './product.module.css';
import c from './completion.module.css';

export function SystemsInventory({ctx}: {ctx: WorkspaceContext}) {
  const [data, setData] = useState<Fields | null>(null);
  const [error, setError] = useState('');
  const keys = useListKeys<HTMLDivElement>();
  const load = useCallback(async () => {
    try { setData(await api<Fields>('/home')); setError(''); }
    catch (e) { setError(e instanceof Error ? e.message : 'Unable to load your systems.'); }
  }, []);
  useEffect(() => { load(); }, [load, ctx.dashboard]);
  const systems = arr(data?.systems);
  return <div className={styles.root}>
    <div className={styles.sectionHead}>
      <div>
        <h2>Protected systems</h2>
        <p>Each system, whether it is current, and what changed most recently. ↑↓ moves between systems.</p>
      </div>
      <PrimaryAction href="/app/systems/new">Connect system</PrimaryAction>
    </div>
    {error && <div className="notice error" role="alert">{error}</div>}
    {!data ? <Skeleton label="Loading your systems" rows={3}/>
      : !systems.length ? <EmptyState icon={Boxes}
        title="No systems connected."
        body="A protected system is one consequential workflow: its environment, what it is allowed to do, and the security claims that must stay true."
        action={<PrimaryAction href="/app/systems/new">Connect your first system</PrimaryAction>}/>
      : <div className={styles.inventory} ref={keys.ref} onKeyDown={keys.onKeyDown}>
          {systems.map(row => <SystemRow key={str(row.id)} row={row}/>)}
        </div>}
    {!!data?.truncated && <p className={styles.muted}>Older systems remain available through the API and exports.</p>}
  </div>;
}

function SystemRow({row}: {row: Fields}) {
  const id = str(row.id);
  const clearance = clearanceView(obj(row.clearance));
  const claims = obj(row.claims);
  const outstanding = num(claims.needs_fresh_evidence) + num(claims.failed);
  const latest = obj(row.latest_change);
  const action = NEXT_ACTION[str(row.next_action)];
  return <article className={styles.inventoryRow}>
    <div className={styles.inventoryName}>
      <Link href={`/app/systems/${id}`} data-row-link>{str(row.name)}</Link>
      <div className={styles.inventoryMeta}>
        <span>{str(obj(row.environment).name, 'No environment yet')}</span>
        {!!obj(row.environment).purpose && <span className="tag">{str(obj(row.environment).purpose).toLowerCase()}</span>}
        {!!row.synthetic && <span className="tag">Synthetic example</span>}
      </div>
    </div>
    <div className={styles.inventoryFacts}>
      <span>{num(claims.supported)} current claim{num(claims.supported) === 1 ? '' : 's'}
        {outstanding ? ` · ${outstanding} need${outstanding === 1 ? 's' : ''} fresh evidence` : ''}</span>
      {latest.headline
        ? <Link href={`/app/systems?change=${str(latest.id)}&system=${id}`} scroll={false} className={styles.muted} title={str(latest.headline)}>
            {str(latest.headline).slice(0, 64)}{str(latest.headline).length > 64 ? '…' : ''} · {date(latest.recorded_at)}
          </Link>
        : <span className={styles.muted}>No change observed yet</span>}
      <SourceLine sources={obj(row.sources)}/>
    </div>
    <div className={styles.inventoryAction}>
      <StatusPill label={clearance.label} tone={clearance.tone} canonical={clearance.state}/>
      <Link href={action ? action.path(id) : `/app/systems/${id}`} className="button outline small">
        {action ? action.label : 'Open'} <ArrowRight size={14}/>
      </Link>
    </div>
  </article>;
}

type Method = 'upload' | 'paste' | 'github' | 'mcp' | 'manual';
const METHODS: Method[] = ['upload', 'paste', 'github', 'mcp', 'manual'];
const DEFINITION_HINT = 'Claude Code settings.json or subagent, .mcp.json, langgraph.json, CrewAI agents.yaml or a ThreatVeil manifest. The format is detected for you.';

/**
 * Connect a system.
 *
 * The customer picks how the system is connected; ThreatVeil reads whatever it can
 * establish first — the format, tools, MCP servers, models, permissions — and then asks
 * only for what no file can declare. A live GitHub source needs a registered read
 * credential; without one this flow says CONFIGURATION REQUIRED rather than pretending.
 */
export function ConnectSystem({ctx}: {ctx: WorkspaceContext}) {
  const router = useRouter();
  const params = useSearchParams();
  const definition = useDefinition(ctx);
  const requested = params.get('method') as Method;
  const [method, setMethod] = useState<Method>(METHODS.includes(requested) ? requested : 'upload');
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');
  const [confirmed, setConfirmed] = useState(false);
  const [credentials, setCredentials] = useState<RecordData[] | null>(null);
  const [restricted, setRestricted] = useState(false);
  const [github, setGithub] = useState({repository: '', repository_id: '', ref: 'refs/heads/main', credential_id: ''});
  const wantsExample = params.get('example') === 'finance';

  useEffect(() => {
    if (method !== 'github' || credentials) return;
    api('/credentials').then(r => setCredentials(items(r))).catch(() => { setRestricted(true); setCredentials([]); });
  }, [method, credentials]);

  const detected = definition.result?.format ? definition.result : null;
  const githubReady = method === 'github' && !!github.repository && !!github.repository_id && !!github.ref && !!github.credential_id;
  const ready = !!detected || method === 'manual' || githubReady;
  const choose = (next: Method) => { setMethod(next); setError(''); if (next === 'manual') definition.reset(); };

  const stages: Stage[] = [
    {key: 'understood', label: 'System understood', done: !!detected || githubReady,
      detail: detected ? (list(detected.ecosystem).map(id => str(id)).length ? `${formatInfo(detected.format)?.label} read` : 'Definition read')
        : 'Connect or import below'},
    {key: 'claims', label: 'Security claim defined', done: false, detail: 'Right after connecting'},
    {key: 'proposed', label: 'Proposed change checked', done: false},
    {key: 'evidence', label: 'Verified evidence', done: false},
    {key: 'live', label: 'Live monitoring', done: false},
    {key: 'reliance', label: 'Machine or external reliance', done: false},
  ];

  async function create(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setBusy('Connecting your system'); setError('');
    try {
      const split = (key: string) => String(form.get(key) || '').split(',').map(v => v.trim()).filter(Boolean);
      const system = await ctx.mutate('/systems', {
        name: form.get('name'), description: form.get('purpose'), access: split('access'), actions: split('actions')});
      const environment = await ctx.mutate('/change-assurance/environments', {
        system_id: system.id, name: form.get('environment'), purpose: form.get('purpose_kind'),
        boundary: form.get('boundary'), owner: str(ctx.identity?.user.name, 'Workspace owner')});
      const notes: string[] = [];
      if (detected) {
        setBusy('Importing what ThreatVeil read');
        const catalog = detected.format === 'mcp_tools';
        const installation = await ctx.mutate('/connectors', {
          system_id: system.id, environment_id: environment.id, connector_id: catalog ? 'mcp' : 'agent_definition',
          mode: 'IMPORT', roles: ['DISCOVER', 'CHANGE'],
          name: catalog ? 'MCP tool catalog' : str(formatInfo(detected.format)?.label, 'Agent definition'),
          configuration: {}, expires_at: new Date(Date.now() + 30 * 86400000).toISOString()});
        await ctx.mutate(`/connectors/${installation.id}/import`, {
          event_id: crypto.randomUUID(), valid_at: new Date().toISOString(),
          payload: catalog ? documentOf(definition.text, 'mcp_tools') as Record<string, unknown>
            : {format: detected.format, document: documentOf(definition.text, str(detected.format))}});
      }
      if (githubReady) {
        setBusy('Connecting the GitHub repository');
        const installation = await ctx.mutate('/connectors', {
          system_id: system.id, environment_id: environment.id, connector_id: 'github', mode: 'POLL',
          roles: ['DISCOVER', 'CHANGE'], name: github.repository,
          configuration: {repository: github.repository, repository_id: github.repository_id, ref: github.ref},
          credential_id: github.credential_id, expires_at: new Date(Date.now() + 7 * 86400000).toISOString()});
        const collected = await ctx.mutate(`/connectors/${installation.id}/collect`, {event_id: crypto.randomUUID()});
        notes.push(str(collected.status) === 'RECORDED' ? 'GitHub revision read.'
          : `GitHub source saved; the first read returned ${str(collected.status).replaceAll('_', ' ').toLowerCase()}.`);
      }
      await ctx.refresh();
      ctx.notify(`System connected. ${notes.join(' ')} Now define one security claim: what must stay true?`.replace(/\s+/g, ' '));
      router.push(`/app/systems/${system.id}/claims`);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not connect this system.');
    } finally { setBusy(''); }
  }

  async function finance() {
    setBusy('Preparing the synthetic example'); setError('');
    try {
      const value = await ctx.mutate('/change-assurance/finance/setup', {
        owner: str(ctx.identity?.user.name, 'Workspace owner'), confirm_synthetic_scope: true});
      await ctx.refresh();
      ctx.notify('The synthetic example is ready. Establish its baseline to see a cleared system.');
      router.push(`/app/systems/${str(value.system_id)}/setup`);
    } catch (e) { setError(e instanceof Error ? e.message : 'Could not prepare the example.'); }
    finally { setBusy(''); }
  }

  const credentialsMissing = credentials !== null && !restricted && credentials.length === 0;
  return <div className={styles.root}>
    <div className={styles.sectionHead}>
      <div>
        <h2>Connect a system</h2>
        <p>ThreatVeil reads what it can establish on its own, then asks you only for what no file can declare.</p>
      </div>
    </div>
    {error && <div className="notice error" role="alert">{error}</div>}
    {(busy || definition.busy) && <p role="status" className={styles.muted}>{busy || 'Reading your definition'}…</p>}

    <SetupProgress stages={stages} title="From connection to current assurance" level={3} action={false}/>

    <section className={styles.step} data-done={ready && method !== 'manual'} aria-labelledby="connect-method">
      <div className={styles.stepHead}>
        <span className={styles.stepNum} data-done={!!detected}>1</span>
        <h3 id="connect-method">How do you want to connect your AI system?</h3>
      </div>
      <div className={styles.stepBody}>
        <div className={c.methods}>
          <button type="button" className={c.method} aria-pressed={method === 'github'} onClick={() => choose('github')}>
            <span className={c.methodTop}><SourceMark id="github" size="lg" name/><span className={c.methodKind}>Live source</span></span>
            <strong>Watch a repository</strong>
            <p>Reads the repository identity and its branch revision with a read credential. File contents are not read.</p>
          </button>
          <button type="button" className={c.method} aria-pressed={method === 'mcp'} onClick={() => choose('mcp')}>
            <span className={c.methodTop}><SourceMark id="mcp" size="lg" name/><span className={c.methodKind}>Agent protocol</span></span>
            <strong>Import MCP configuration</strong>
            <p>A .mcp.json or a tools/list catalog snapshot now; a live server connects once the system exists.</p>
          </button>
          <button type="button" className={c.method} aria-pressed={method === 'upload'} onClick={() => choose('upload')}>
            <span className={c.methodTop}>
              <span style={{display: 'inline-flex', width: 30, height: 30, alignItems: 'center', justifyContent: 'center',
                borderRadius: 7, border: '1px solid var(--line-strong)'}}><Upload size={15} aria-hidden="true"/></span>
              <span className={c.methodKind}>Supported definitions</span>
            </span>
            <strong>Upload configuration</strong>
            <p>Claude Code, MCP, LangGraph, CrewAI or a ThreatVeil manifest. The format is detected automatically.</p>
          </button>
        </div>
        <div className={c.methodSecondary}>
          <button type="button" className="text-button" aria-pressed={method === 'paste'} onClick={() => choose('paste')}>Paste definition</button>
          <button type="button" className="text-button" aria-pressed={method === 'manual'} onClick={() => choose('manual')}>Advanced manual setup</button>
        </div>

        {method === 'upload' && <>
          <DropZone onFile={definition.pick} hint={DEFINITION_HINT}/>
          <ul className={c.formats} aria-label="Supported definition formats">
            {FORMATS.filter(format => format.id !== 'mcp_tools').map(format => <li key={format.id}>
              <SourceMark id={format.ecosystem}/><span>{format.label}</span><code>{format.file}</code>
            </li>)}
          </ul>
          <p className={styles.muted}>
            OpenAI Agents SDK definitions are code, which ThreatVeil never runs or parses: describe them with a ThreatVeil
            manifest. Their trace exports can be imported as evidence from Integrations once the system exists.
          </p>
        </>}

        {method === 'paste' && <>
          <label>Paste a definition
            <textarea className="code-input" rows={7} value={definition.text} spellCheck={false}
              onChange={e => definition.setText(e.target.value)}
              placeholder={'{"permissions": {"allow": ["Bash(git:*)"], "deny": []}, "mcpServers": {}}'}/>
          </label>
          <div className={styles.stepActions}>
            <button type="button" className="button dark small" disabled={!definition.text.trim() || definition.busy}
              onClick={() => definition.read(definition.text, '')}>
              <Upload size={14}/>Read this definition
            </button>
          </div>
        </>}

        {method === 'mcp' && <>
          <DropZone onFile={definition.pick} accept=".json,application/json"
            hint="A project .mcp.json, or a tools/list catalog snapshot exported from your MCP server."/>
          <div className={c.config}>
            <strong>Live MCP: configuration required</strong>
            <p>ThreatVeil reads a live server only through a verified MCP target registered for a system. Import a
              snapshot now, then connect the live server from Integrations.</p>
          </div>
        </>}

        {method === 'github' && <>
          {credentials === null ? <Skeleton label="Checking credential references" rows={1}/>
            : credentialsMissing ? <div className={c.config}>
              <strong>Configuration required</strong>
              <p>No read credential reference is registered for this organization, so ThreatVeil cannot read a
                repository yet. An owner registers one (Settings → Security). You can still connect by uploading the
                agent definition from the repository below.</p>
            </div>
            : <div className="two-grid">
              <label>Repository<input value={github.repository} placeholder="organization/repository"
                onChange={e => setGithub({...github, repository: e.target.value})}/></label>
              <label>Numeric repository ID<input value={github.repository_id} inputMode="numeric"
                onChange={e => setGithub({...github, repository_id: e.target.value})}/></label>
              <label>Branch reference<input value={github.ref} onChange={e => setGithub({...github, ref: e.target.value})}/></label>
              <label>Read credential reference
                {restricted
                  ? <input value={github.credential_id} placeholder="Reference ID from an owner"
                      onChange={e => setGithub({...github, credential_id: e.target.value})}/>
                  : <select value={github.credential_id} onChange={e => setGithub({...github, credential_id: e.target.value})}>
                      <option value="">Choose a reference</option>
                      {credentials.map(item => <option key={item.id} value={item.id}>{str(item.name || item.label, item.id)}</option>)}
                    </select>}
              </label>
            </div>}
          <p className={styles.muted}>A repository revision is not a deployed state. To let ThreatVeil understand the agent itself, add its definition file:</p>
          <DropZone onFile={definition.pick} label="Upload the definition from this repository" hint={DEFINITION_HINT}/>
        </>}

        <DetectionBar definition={definition}/>
        <p className={styles.muted}>
          Secret values are never retained: only names and digests. A definition file is declared configuration, never
          proof of what is running.
        </p>
      </div>
    </section>

    {detected && <section className={styles.step} data-done="true" aria-labelledby="found">
      <div className={styles.stepHead}>
        <span className={styles.stepNum} data-done="true">2</span>
        <h3 id="found">ThreatVeil found</h3>
      </div>
      <div className={styles.stepBody}><FoundFacts result={detected}/></div>
    </section>}

    {ready && <form onSubmit={create}>
      <section className={styles.step} aria-labelledby="confirm">
        <div className={styles.stepHead}>
          <span className={styles.stepNum}>{detected ? 3 : 2}</span>
          <h3 id="confirm">Confirm what ThreatVeil cannot know</h3>
        </div>
        <div className={styles.stepBody}>
          <div className="two-grid">
            <label>System name
              <input name="name" required maxLength={120} placeholder="Customer support agent"
                defaultValue={detected ? list(detected.agents)[0] || '' : ''}/>
            </label>
            <label>Environment
              <input name="environment" required defaultValue="Staging" maxLength={120}/>
            </label>
          </div>
          <label>Operating environment
            <select name="purpose_kind" defaultValue="STAGING">
              <option value="STAGING">Staging</option>
              <option value="SANDBOX">Sandbox</option>
              <option value="PRODUCTION">Production — observation acceptance required</option>
            </select>
          </label>
          <label>What useful work does it do?
            <textarea name="purpose" required maxLength={4000} rows={2}
              placeholder="Answers support tickets and issues refunds against the payments ledger."/>
          </label>
          <label>Operating boundary
            <textarea name="boundary" required minLength={10} rows={2}
              placeholder="Which resources are in scope, and where does this system operate?"/>
          </label>
          {method === 'manual' && <div className="two-grid">
            <label>What can it access?
              <input name="access" placeholder="payments, customer data, MCP"/>
              <small className="field-help">Comma separated. Used to suggest relevant claims.</small>
            </label>
            <label>What can it do?
              <input name="actions" placeholder="read, write, approve"/>
              <small className="field-help">Comma separated: read, write, delete, send, execute, approve.</small>
            </label>
          </div>}
          <div className={styles.stepActions}>
            <button className="button dark small" disabled={!!busy}>Connect system <ArrowRight size={14}/></button>
            <Link href="/app/systems" className="text-button">Cancel</Link>
          </div>
        </div>
      </section>
    </form>}

    <details className={styles.quiet} open={wantsExample}>
      <summary><FlaskConical size={13} aria-hidden="true"/>Use the synthetic example instead</summary>
      <div className={styles.quietBody}>
        <p className={styles.lead}>
          A synthetic finance agent: three claims, real commits to isolated synthetic rows, a forbidden beneficiary change
          and a useful invoice task. Synthetic data only; it never counts as customer activity.
        </p>
        <label className="checkbox-label" style={{display: 'flex', gap: 9, alignItems: 'center'}}>
          <input type="checkbox" style={{width: 'auto'}} checked={confirmed || wantsExample}
            onChange={e => setConfirmed(e.target.checked)}/>
          I approve these synthetic checks and the legitimate invoice fixture.
        </label>
        <div>
          <button className="button outline small" disabled={!!busy || !(confirmed || wantsExample)} onClick={finance}>
            {busy ? 'Preparing…' : 'Prepare finance example'} <ArrowRight size={14}/>
          </button>
        </div>
      </div>
    </details>
  </div>;
}
