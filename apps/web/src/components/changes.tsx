'use client';

/**
 * Changes: detected changes across every protected system, and the proposed-change check
 * that answers "can I ship this?".
 *
 * A proposed check is read-only with respect to current assurance. That is stated on the
 * result, because it is the property a customer most needs to trust. ThreatVeil never
 * fetches a pull request: it reads the candidate file the customer supplies, and a pull
 * request number and link only label the result with an exact reference.
 */

import Link from 'next/link';
import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { ArrowRight, GitPullRequest, Upload } from 'lucide-react';
import { api, date, items, obj, str } from '@/lib/api';
import {
  AUTHORITY_MOVE, CHANGE_EFFECT, CLAIM_STATE, EmptyState, PrimaryAction, Skeleton, StatusPill,
  arr, clearanceView, list, num, plural, useListKeys, type Fields, type Tone,
} from './product';
import { CONNECTOR_ECOSYSTEM, SourceMark } from './ecosystem';
import { ChangeImpact } from './signature';
import { ChangePreview } from './change-preview';
import { DetectionBar, DropZone, documentOf, useDefinition } from './definition-input';
import { JsonDetails, type WorkspaceContext } from './workspace-parts';
import styles from './product.module.css';
import c from './completion.module.css';

type Tab = 'detected' | 'proposed';

export function Changes({ctx, tab}: {ctx: WorkspaceContext; tab: Tab}) {
  return <div className={styles.root}>
    <div className={styles.sectionHead}>
      <div>
        <h2>Changes</h2>
        <p>What moved in your systems, and what a change you are about to ship would affect.</p>
      </div>
      <PrimaryAction href="/app/changes/propose">Check a proposed change</PrimaryAction>
    </div>
    <nav className={styles.segmented} aria-label="Change views">
      <Link href="/app/changes" aria-current={tab === 'detected' ? 'page' : undefined}>Detected</Link>
      <Link href="/app/changes/propose" aria-current={tab === 'proposed' ? 'page' : undefined}>Proposed checks</Link>
    </nav>
    {tab === 'detected' ? <Detected/> : <ProposedChecks ctx={ctx}/>}
    <ChangePreview/>
  </div>;
}

function tone(effect: string): Tone {
  if (effect === 'OPEN') return 'attention';
  if (effect === 'NO_CLAIM_AFFECTED' || effect === 'COVERED_BY_LATER_VERIFICATION') return 'ok';
  return 'neutral';
}

/** Observed changes across the organization, newest first, each with where it came from. */
function Detected() {
  const [data, setData] = useState<Fields | null>(null);
  const [error, setError] = useState('');
  const [all, setAll] = useState(false);
  const keys = useListKeys<HTMLDivElement>();
  useEffect(() => {
    api<Fields>('/home').then(setData).catch(e => setError(e instanceof Error ? e.message : 'Unable to load changes.'));
  }, []);
  if (error) return <div className="notice error" role="alert">{error}</div>;
  if (!data) return <Skeleton label="Loading changes" rows={3}/>;
  const detected = arr(data.systems).flatMap(row => {
    const source = all && obj(row.latest_change).id ? [obj(row.latest_change), ...arr(row.open_changes)] : arr(row.open_changes);
    const seen = new Set<string>();
    return source.filter(change => {
      const id = str(change.id);
      if (!id || seen.has(id)) return false;
      seen.add(id); return true;
    }).map(change => ({...change, system_id: row.id, system: row.name} as Fields));
  }).sort((a, b) => str(b.recorded_at).localeCompare(str(a.recorded_at)));

  const filter = <label className={styles.muted} style={{display: 'flex', gap: 8, alignItems: 'center'}}>
    <input type="checkbox" style={{width: 'auto'}} checked={all} onChange={e => setAll(e.target.checked)}/>
    Include changes already covered by later verification
  </label>;
  if (!detected.length) return <>
    {filter}
    <EmptyState
      title="No changes detected yet."
      body="ThreatVeil records a change when a connected source reports that a system moved. Until then, you can still ask what a change you are about to ship would break."
      action={<PrimaryAction href="/app/changes/propose">Check a proposed change</PrimaryAction>}/>
  </>;

  return <>
    {filter}
    <div className={styles.attentionList} ref={keys.ref} onKeyDown={keys.onKeyDown}>{detected.map(change => {
      const effect = str(change.effect);
      const move = AUTHORITY_MOVE[str(change.classification)];
      const connector = str(change.connector, '');
      return <article key={`${str(change.system_id)}-${str(change.id)}`} className={styles.changeRow} data-tone={tone(effect)}>
        <div className={styles.changeHeadline}>
          <Link href={`/app/changes?change=${str(change.id)}&system=${str(change.system_id)}`} scroll={false} data-row-link>
            <strong>{str(change.headline)}</strong>
          </Link>
          <span className={styles.muted}>
            {connector ? <SourceMark id={CONNECTOR_ECOSYSTEM[connector]} name/> : <span>Declared boundary</span>}
            · <Link href={`/app/systems/${str(change.system_id)}`} className="text-button">{str(change.system)}</Link>
            · {date(change.recorded_at)}
          </span>
        </div>
        <div className={styles.changeFacts}>
          {move && <StatusPill label={move.label} tone={move.tone} canonical={str(change.classification)}/>}
          <StatusPill label={CHANGE_EFFECT[effect] || effect} tone={tone(effect)} canonical={effect}/>
          {num(change.claims_affected) > 0 && <span className={styles.muted}>
            {plural(num(change.claims_affected), 'claim')} affected · {num(change.still_holds)} still hold
          </span>}
        </div>
        <Link href={`/app/systems/${str(change.system_id)}/activity`} className="button outline small">
          Review change <ArrowRight size={14}/>
        </Link>
      </article>;
    })}</div>
  </>;
}

type Input = 'github' | 'upload' | 'paste';

/**
 * Check a change. The candidate comes from a file (or pasted text) the customer supplies;
 * ThreatVeil detects its format, diffs it against the source's last observation and
 * answers at claim level without touching current assurance.
 */
function ProposedChecks({ctx}: {ctx: WorkspaceContext}) {
  const systems = items(ctx.dashboard?.systems);
  const [systemId, setSystemId] = useState(str(systems[0]?.id, ''));
  const [sources, setSources] = useState<Fields[] | null>(null);
  const [source, setSource] = useState('');
  const [input, setInput] = useState<Input>('upload');
  const [result, setResult] = useState<Fields | null>(null);
  const [history, setHistory] = useState<Fields[]>([]);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const candidate = useDefinition(ctx);

  const refresh = useCallback(async () => {
    if (!systemId) { setSources([]); setHistory([]); return; }
    const [overview, listed] = await Promise.all([
      api<Fields>(`/systems/${systemId}/mappings-overview`), api<Fields>(`/systems/${systemId}/proposed-changes`)]);
    setSources(arr(overview.sources)); setHistory(arr(listed.items));
  }, [systemId]);
  useEffect(() => { refresh().catch(e => setError(e instanceof Error ? e.message : 'Unable to load sources.')); }, [refresh]);
  useEffect(() => { if (!systemId && systems[0]?.id) setSystemId(str(systems[0].id)); }, [systems, systemId]);
  const evaluable = (sources || []).filter(item => ['agent_definition', 'mcp'].includes(str(item.connector_id)));
  useEffect(() => {
    if (evaluable[0] && !evaluable.some(item => str(item.installation_id) === source)) setSource(str(evaluable[0].installation_id));
  }, [evaluable, source]);
  const selected = evaluable.find(item => str(item.installation_id) === source);
  const connector = str(selected?.connector_id, '');
  const allowed = connector === 'mcp' ? ['mcp_tools'] : ['claude_settings', 'claude_subagent', 'mcp_json', 'langgraph', 'crewai', 'manifest'];

  async function run(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setError(''); setResult(null);
    const format = candidate.format;
    if (!candidate.text.trim()) { setError('Add the candidate configuration first.'); return; }
    if (!format) {
      // Pasted text is read the same way an upload is; nothing is sent until the format is known.
      await candidate.read(candidate.text, candidate.fileName);
      return;
    }
    if (!allowed.includes(format)) { setError('This source cannot read that format. Choose the source the candidate belongs to.'); return; }
    setBusy(true);
    try {
      const payload = connector === 'agent_definition'
        ? {format, document: documentOf(candidate.text, format)} : documentOf(candidate.text, format);
      const github = input === 'github';
      const created = await ctx.mutate(`/systems/${systemId}/proposed-changes`, {
        installation_id: source, payload, idempotency_key: crypto.randomUUID(),
        reference: {
          type: github ? 'PULL_REQUEST' : str(form.get('type'), 'MANUAL'),
          id: String(form.get('reference') || '') || null,
          url: String(form.get('url') || '') || null,
          revision: String(form.get('revision') || '') || null,
        }});
      setResult({...created, connector_id: connector, source_name: selected?.name}); await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not evaluate that change.');
    } finally { setBusy(false); }
  }

  if (!systems.length) return <EmptyState
    title="Connect a system first."
    body="A proposed check compares a configuration you are about to ship against the claims of one protected system."
    action={<PrimaryAction href="/app/systems/new">Connect a system</PrimaryAction>}/>;

  const sourceOf = (item: Fields) => (sources || []).find(s => str(s.installation_id) === str(item.installation_id));
  return <>
    <details className={result ? styles.quiet : styles.formOpen} open={!result}>
      <summary><GitPullRequest size={13} aria-hidden="true"/>{result ? 'Check another change' : 'Check a change'}</summary>
      <div className={styles.quietBody}>
        {!result && <p className={styles.lead}>
          Give ThreatVeil the configuration you are about to ship. It detects the format, compares it with what the source
          last reported, and answers against your current security claims. It reads only.
        </p>}
        {error && <div className="notice error" role="alert">{error}</div>}
        {sources === null ? <Skeleton label="Loading sources" rows={2}/>
          : !evaluable.length ? <p>
            This system has no source ThreatVeil can compare a candidate against. Import an agent definition or an MCP tool
            catalog first. <Link href={`/app/integrations?system=${systemId}`} className="text-button">Integrations <ArrowRight size={14}/></Link>
          </p>
          : <form onSubmit={run} style={{display: 'grid', gap: 14, maxWidth: 760}}>
            <div className="two-grid">
              <label>Protected system
                <select value={systemId} onChange={e => { setSystemId(e.target.value); setResult(null); candidate.reset(); }}>
                  {systems.map(s => <option key={s.id} value={s.id}>{str(s.name, s.id)}</option>)}
                </select>
              </label>
              <label>Compared against
                <select value={source} onChange={e => { setSource(e.target.value); candidate.reset(); }}>
                  {evaluable.map(s => <option key={str(s.installation_id)} value={str(s.installation_id)}>
                    {str(s.name)} · {str(s.connector_id) === 'mcp' ? 'MCP' : 'agent definition'}</option>)}
                </select>
              </label>
            </div>
            <div className={c.filters} role="group" aria-label="Where the candidate comes from">
              <button type="button" aria-pressed={input === 'github'} onClick={() => setInput('github')}>
                <SourceMark id="github"/>GitHub pull request</button>
              <button type="button" aria-pressed={input === 'upload'} onClick={() => setInput('upload')}>
                <Upload size={12} aria-hidden="true"/>Upload candidate config</button>
              <button type="button" aria-pressed={input === 'paste'} onClick={() => setInput('paste')}>Paste candidate definition</button>
            </div>

            {input === 'github' && <>
              <div className="two-grid">
                <label>Pull request<input name="reference" maxLength={120} placeholder="#482" required/></label>
                <label>Commit (optional)<input name="revision" maxLength={64} pattern="[0-9a-f]{7,64}" placeholder="exact candidate SHA"/></label>
              </div>
              <label>Link (https, optional)<input name="url" maxLength={500} placeholder="https://github.com/organization/agent/pull/482"/></label>
              <p className={styles.muted}>
                ThreatVeil does not fetch pull requests. Upload the candidate file from the pull request; the number, commit and link
                label the result exactly. To check every pull request automatically, publish from CI with GitHub Checks.
              </p>
            </>}
            {input !== 'paste'
              ? <DropZone onFile={candidate.pick} label="Upload candidate configuration"
                  hint={connector === 'mcp' ? 'The candidate tools/list catalog snapshot.' : 'The candidate definition file. Its format is detected.'}/>
              : <label>Candidate definition
                  <textarea name="payload" rows={8} className="code-input" value={candidate.text} spellCheck={false}
                    onChange={e => { candidate.setText(e.target.value); }}
                    placeholder={connector === 'agent_definition' ? '{"permissions": {"allow": [], "deny": []}}'
                      : '{"protocol_version": "2026-07-28", "tools": [], "authorization": {"tools": {}}}'}/>
                </label>}
            <DetectionBar definition={candidate} allowed={allowed}/>
            {input !== 'github' && <details>
              <summary className={styles.muted} style={{cursor: 'pointer'}}>Add a reference (optional)</summary>
              <div className="two-grid" style={{marginTop: 8}}>
                <label>Reference type
                  <select name="type" defaultValue="MANUAL">
                    {['PULL_REQUEST', 'COMMIT', 'BRANCH', 'MANUAL'].map(value =>
                      <option key={value} value={value}>{value.replaceAll('_', ' ').toLowerCase()}</option>)}
                  </select>
                </label>
                <label>Reference<input name="reference" maxLength={120} placeholder="#42"/></label>
              </div>
            </details>}
            <div>
              <button className="button dark small" disabled={busy || candidate.busy || !source || !candidate.text.trim()}>
                {busy ? 'Evaluating…' : candidate.format ? 'Check this change' : 'Read and check this change'} <ArrowRight size={15}/>
              </button>
            </div>
          </form>}
      </div>
    </details>

    {result && <ProposedResult result={result}/>}

    {!!history.length && <section aria-labelledby="earlier-checks">
      <div className={styles.sectionHead}>
        <h2 id="earlier-checks">Earlier checks</h2>
        <p>{plural(history.length, 'evaluation')} recorded. None of them is current state.</p>
      </div>
      <div className={styles.attentionList}>{history.slice(0, 20).map(item => {
        const summary = obj(item.summary);
        const effect = str(summary.effect);
        const origin = sourceOf(item);
        return <article key={str(item.id)} className={styles.changeRow} data-tone={effect === 'WOULD_REQUIRE_REPROOF' ? 'attention' : 'ok'}>
          <div className={styles.changeHeadline}>
            <strong>{str(summary.headline)}</strong>
            <span className={styles.muted}>
              {origin && <SourceMark id={CONNECTOR_ECOSYSTEM[str(origin.connector_id)]}/>}
              {str(obj(item.reference).type).replaceAll('_', ' ').toLowerCase()}
              {obj(item.reference).id ? ` ${str(obj(item.reference).id)}` : ''} · {date(item.created_at)}
            </span>
          </div>
          <div className={styles.changeFacts}>
            <StatusPill label={str(item.mode).toLowerCase()} tone="neutral" canonical={str(item.status)}/>
            <span className={styles.muted} title={`Canonical effect: ${effect}`}>{PROPOSED_EFFECT[effect] || effect.replaceAll('_', ' ').toLowerCase()}</span>
          </div>
          <button className="button outline small"
            onClick={() => setResult({...item, connector_id: origin?.connector_id, source_name: origin?.name})}>
            Open result <ArrowRight size={14}/>
          </button>
        </article>;
      })}</div>
    </section>}
  </>;
}

/** A proposed check's effect in customer words. The canonical value stays in the title. */
const PROPOSED_EFFECT: Record<string, string> = {
  WOULD_REQUIRE_REPROOF: 'claims would need fresh evidence', NO_CLAIM_AFFECTED: 'no claim affected',
  NO_CHANGE: 'no change', NO_BASELINE: 'nothing to compare against yet', NO_CLAIMS: 'no claims defined',
  DECLARED_CLAIMS_AFFECTED: 'declared claims affected', NO_DECLARED_CLAIM_AFFECTED: 'no declared claim affected',
};

/** The reference exactly as supplied. A GitHub identity appears only for a github.com link, labelled as not fetched. */
function referenceSource(reference: Fields) {
  let github = false;
  try { github = new URL(str(reference.url, '')).hostname === 'github.com'; } catch { github = false; }
  const label = reference.id ? `${str(reference.type).replaceAll('_', ' ').toLowerCase()} ${str(reference.id)}` : '';
  return {github, label: [label, reference.revision ? str(reference.revision).slice(0, 12) : ''].filter(Boolean).join(' · ')};
}

export function ProposedResult({result}: {result: Fields}) {
  const summary = obj(result.summary);
  const check = obj(result.check);
  const clearance = obj(result.clearance);
  const reference = obj(result.reference);
  const authority = obj(result.authority);
  const claims = arr(result.claims);
  const affected = claims.filter(claim => claim.reached);
  const unaffected = claims.filter(claim => !claim.reached);
  const declared = arr(summary.declared_claims_affected).length ? arr(summary.declared_claims_affected) : arr(result.declared_claims);
  const current = clearanceView({state: str(clearance.current)});
  const after = clearanceView({state: str(clearance.if_applied, str(clearance.current))});
  const ref = referenceSource(reference);
  const [copied, setCopied] = useState(false);

  return <div className={styles.review}>
    <header className={styles.reviewHead}>
      <div className={styles.reviewRef}>
        <StatusPill label="Proposed" tone="neutral" canonical={str(result.status, 'PROPOSED')}/>
        {ref.github && <span style={{display: 'inline-flex', gap: 6, alignItems: 'center'}}>
          <SourceMark id="github" name/><span className={styles.muted}>reference · not fetched</span></span>}
        <span className={styles.muted}>checked {date(result.created_at)}</span>
      </div>
      <h2>{affected.length ? `${plural(affected.length, 'security claim')} would need fresh evidence`
        : 'No approved security claim would be affected'}</h2>
      <p className={styles.muted}>This check reads only. It has not changed current assurance.</p>
    </header>

    <ChangeImpact
      source={{connector: str(result.connector_id, ''), name: str(result.source_name, ''),
        relationship: 'IMPORTED', reference: ref.label || undefined, url: str(reference.url, '') || undefined}}
      headline={str(summary.headline)} when={result.created_at} whenLabel="checked"
      dimensions={arr(authority.dimensions)} classification={str(summary.classification, '')}
      affected={affected.map(claim => ({key: str(claim.property_id), title: str(claim.title),
        note: `${CLAIM_STATE[str(claim.current_status)]?.label.toLowerCase() || str(claim.current_status).replaceAll('_', ' ').toLowerCase()} → would need fresh evidence`}))}
      holds={unaffected.map(claim => str(claim.title))}
      declared={declared.map(claim => ({key: str(claim.definition_id), title: str(claim.claim)}))}
      before={{caption: 'Current system', label: current.label, state: current.state, tone: current.tone, note: 'Unchanged by this check.'}}
      after={{caption: 'If shipped', label: after.label, state: after.state, tone: after.tone,
        note: str(clearance.if_applied) === str(clearance.current) ? 'No change to clearance.' : 'If nothing else changed.'}}
      open={affected.length > 0}/>

    <details className={styles.quiet}>
      <summary>Reasoning, limits and the body a CI step would publish</summary>
      <div className={styles.quietBody}>
        <ol className={styles.reasoning}>{list(result.explanation).map(line => <li key={line}>{line}</li>)}</ol>
        <ul className={styles.limits}>{list(result.limitations).map(line => <li key={line}>{line}</li>)}</ul>
        <div className={styles.machineLine}>
          <span className={styles.muted}>check {str(check.conclusion)} · {str(check.mode)} · not blocking</span>
          <button className="button outline small" onClick={() => {
            navigator.clipboard?.writeText(JSON.stringify(result, null, 2)); setCopied(true);
          }}>{copied ? 'Copied' : 'Copy result'}</button>
        </div>
        <JsonDetails label="Check body that a CI step would publish" data={check}/>
      </div>
    </details>
  </div>;
}
