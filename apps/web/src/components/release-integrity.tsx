'use client';

import Link from 'next/link';
import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react';
import { ArrowRight, Download, GitBranch, RefreshCw, ShieldCheck, X } from 'lucide-react';
import { api, date, items, obj, str, title, type PageWindow, type RecordData } from '@/lib/api';
import { Badge, DetailGrid, Empty, JsonDetails, RecordTable, type WorkspaceContext } from './workspace-parts';

type Collection = 'releases' | 'evidence-ledger' | 'change-sets' | 'proof-plans';
type Mode = 'timeline' | 'releases' | 'evidence' | 'changes';
type LedgerPage = { items: RecordData[]; pagination: PageWindow };
const collectionTitles: Record<Collection, string> = { releases: 'release decisions', 'evidence-ledger': 'evidence records', 'change-sets': 'change sets', 'proof-plans': 're-proof plans' };
const strings = (value: unknown) => Array.isArray(value) ? value.map(v => str(v)).join('; ') : str(value);
const fingerprint = (record: RecordData) => { const c = obj(record.candidate); return str(c.version || c.id, 'Unspecified candidate'); };
const candidateDigest = (record: RecordData) => str(obj(record.candidate).digest, 'Unknown digest');

function useLedger(collection: Collection, systemId: string, revision: number, limit: number, enabled = true) {
  const [records, setRecords] = useState<RecordData[]>([]);
  const [pagination, setPagination] = useState<PageWindow | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const generation = useRef(0);
  const query = `/${collection}?limit=${limit}${systemId ? `&system_id=${encodeURIComponent(systemId)}` : ''}`;
  useEffect(() => {
    const controller = new AbortController();
    generation.current += 1;
    setRecords([]); setPagination(null); setError(''); setBusy(enabled);
    if (enabled) api<LedgerPage>(query, { signal: controller.signal }).then(data => {
      if (!controller.signal.aborted) { setRecords(items(data)); setPagination(data.pagination); }
    }).catch(e => { if (!controller.signal.aborted) setError(e instanceof Error ? e.message : 'Records are unavailable.'); })
      .finally(() => { if (!controller.signal.aborted) setBusy(false); });
    return () => { controller.abort(); generation.current += 1; };
  }, [query, revision, enabled]);
  async function more() {
    if (!pagination?.next_cursor || busy) return;
    const current = generation.current;
    setBusy(true); setError('');
    try {
      const data = await api<LedgerPage>(`${query}&cursor=${encodeURIComponent(pagination.next_cursor)}`);
      if (current !== generation.current) return;
      setRecords(existing => [...existing, ...items(data).filter(row => !existing.some(r => r.id === row.id))]);
      setPagination(data.pagination);
    } catch (e) { if (current === generation.current) setError(e instanceof Error ? e.message : 'Older records are unavailable.'); }
    finally { if (current === generation.current) setBusy(false); }
  }
  return { records, pagination, error, busy, more };
}
type LedgerState = ReturnType<typeof useLedger>;
function LedgerWindow({ state, collection }: { state: LedgerState; collection: Collection }) {
  return <>{state.error && <p className="notice error" role="alert">Could not load {collectionTitles[collection]}: {state.error}</p>}
    {state.busy && !state.records.length && <p className="operation-intro" role="status">Loading {collectionTitles[collection]}…</p>}
    {state.pagination && <div className="window-control"><span>{state.records.length} of {state.pagination.total} {collectionTitles[collection]} loaded · newest first</span>{state.pagination.next_cursor && <button className="button outline small" onClick={state.more} disabled={state.busy}>Load older {collectionTitles[collection]} <ArrowRight size={14} /></button>}</div>}</>;
}

export function ReleaseIntegrity({ ctx, mode }: { ctx: WorkspaceContext; mode: Mode }) {
  const compact = mode === 'timeline';
  const [systemId, setSystemId] = useState('');
  const [revision, setRevision] = useState(0);
  const [selected, setSelected] = useState<{ collection: Collection; record: RecordData } | null>(null);
  const [detailError, setDetailError] = useState('');
  const selectedRequest = useRef(0);
  const refresh = useCallback(() => setRevision(n => n + 1), []);
  const releases = useLedger('releases', systemId, revision, compact ? 5 : 25, compact || mode === 'releases');
  const evidence = useLedger('evidence-ledger', systemId, revision, 25, mode === 'evidence');
  const changes = useLedger('change-sets', systemId, revision, 25, mode === 'changes');
  const plans = useLedger('proof-plans', systemId, revision, 25, mode === 'changes' || mode === 'releases');
  const systems = items(ctx.dashboard?.systems);
  const properties = items(ctx.dashboard?.properties);
  const propertyName = (id: unknown) => str(properties.find(p => p.id === id)?.title, str(id));
  const systemName = (id: unknown) => str(systems.find(s => s.id === id)?.name, str(id));
  function clearSelected() { selectedRequest.current += 1; setSelected(null); setDetailError(''); }
  useEffect(() => { clearSelected(); }, [systemId, mode]);
  useEffect(() => () => { selectedRequest.current += 1; }, []);
  useEffect(() => {
    if (mode !== 'releases') return;
    const identifier = new URLSearchParams(window.location.search).get('release');
    if (!identifier || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(identifier)) return;
    const requestId = ++selectedRequest.current;
    api(`/releases/${identifier}`).then(record => {
      if (requestId === selectedRequest.current) setSelected({ collection: 'releases', record });
    }).catch(error => {
      if (requestId === selectedRequest.current) setDetailError(error instanceof Error ? error.message : 'Release details unavailable.');
    });
  }, [mode]);
  async function inspect(collection: Collection, record: RecordData) {
    const requestId = ++selectedRequest.current;
    setSelected({ collection, record }); setDetailError('');
    if (collection === 'releases' || collection === 'evidence-ledger') {
      try { const detail = await api(`/${collection}/${encodeURIComponent(record.id)}`); if (requestId === selectedRequest.current) setSelected({ collection, record: detail }); }
      catch (e) { if (requestId === selectedRequest.current) setDetailError(e instanceof Error ? e.message : 'Release details unavailable.'); }
    }
  }
  const record = selected?.record;
  return <div className={`release-integrity ${compact ? 'compact' : ''}`}>
    {!compact && <div className="release-toolbar"><label>Release system<select value={systemId} onChange={e => setSystemId(e.target.value)}><option value="">All systems</option>{systems.map(s => <option key={s.id} value={s.id}>{title(s)}</option>)}</select></label><button className="button outline small" onClick={refresh}><RefreshCw size={14} />Refresh records</button></div>}
    {(compact || mode === 'releases') && <section className="card release-history" aria-label="Release timeline"><div className="card-heading"><div><div className="eyebrow">EXACT CANDIDATE · HISTORICAL DECISION</div><h2>Release timeline</h2><p>What changed, what was re-proven, and why this candidate could ship.</p></div>{compact && <Link href="/app/releases" className="text-button">All releases <ArrowRight size={14} /></Link>}</div><LedgerWindow state={releases} collection="releases" />
      {releases.records.length ? <div className="release-timeline">{releases.records.map(release => <button key={release.id} className={`release-event release-${str(release.release_action, 'unknown').toLowerCase()}`} onClick={() => inspect('releases', release)}><div className="release-event-head"><span>{systemName(release.system_id)}</span><Badge value={release.release_action} /></div><h3>{fingerprint(release)}</h3><code title={candidateDigest(release)}>{candidateDigest(release)}</code><div className="release-event-details"><span>{items(release.properties).length} evaluated properties</span><span>{str(obj(release.policy).mode, 'Unknown policy')} mode</span><span>{date(release.evaluated_at || release.created_at)}</span></div><span className="text-button">Inspect decision <ArrowRight size={13} /></span></button>)}</div> : !releases.busy && !releases.error && <Empty icon={ShieldCheck} title="No release decision has been recorded." description="Establish scoped evidence, create a re-proof plan, and evaluate the exact candidate. A completed run alone is not a historical release decision." action={<Link className="button outline small" href="/app/impact">Explore a candidate change <ArrowRight size={14} /></Link>} />}
    </section>}

    {mode === 'evidence' && <section className="card" aria-label="Evidence ledger"><div className="card-heading"><div><div className="eyebrow">PERSISTED PROOF, WITH ITS LIMITS</div><h2>Evidence ledger</h2><p>The security result when recorded is separate from applicability to a later candidate. Inspect its re-proof plan to see STILL VALID, VOID, or UNKNOWN.</p></div></div><LedgerWindow state={evidence} collection="evidence-ledger" /><RecordTable records={evidence.records} columns={[
      { label: 'Property / system', render: r => <><strong>{propertyName(r.property_id)}</strong><small>{systemName(r.system_id)}</small></> },
      { label: 'Candidate', render: r => <><strong>{fingerprint(r)}</strong><small className="mono">{candidateDigest(r)}</small></> },
      { label: 'Recorded security', render: r => <Badge value={r.security_verdict} /> },
      { label: 'Legitimate task', render: r => <Badge value={r.task_outcome} /> },
      { label: 'Scope / expiry', render: r => <><small className="mono">{str(r.proof_scope_id, 'Scope not recorded')}</small><small>{r.expires_at ? date(r.expires_at) : 'No expiry recorded'}</small></> },
      { label: '', render: r => <button className="text-button" onClick={() => inspect('evidence-ledger', r)}>Inspect evidence <ArrowRight size={13} /></button> },
    ]} empty="No scoped evidence has been recorded. Run observations and historical proof records remain distinct." /></section>}

    {mode === 'changes' && <><section className="card" aria-label="Candidate changes"><div className="card-heading"><div><div className="eyebrow">CHANGE → AFFECTED PROOF</div><h2>Recorded candidate changes</h2><p>Each change set retains the compared fingerprints and explicit unknowns.</p></div></div><LedgerWindow state={changes} collection="change-sets" /><RecordTable records={changes.records} columns={[
      { label: 'System', render: r => <strong>{systemName(r.system_id)}</strong> },
      { label: 'Changed components', render: r => String(items(r.changes).length) },
      { label: 'Unknowns', render: r => strings(r.unknowns) === '' ? 'None recorded' : strings(r.unknowns) },
      { label: 'Recorded', render: r => date(r.created_at) },
      { label: '', render: r => <button className="text-button" onClick={() => inspect('change-sets', r)}>Inspect change <ArrowRight size={13} /></button> },
    ]} empty="No candidate comparison has been recorded. Declare the exact candidate and its fingerprint below." /></section><PlanCreator ctx={ctx} systemId={systemId} onCreated={plan => { refresh(); inspect('proof-plans', plan); }} /></>}

    {(mode === 'changes' || mode === 'releases') && <section className="card" aria-label="Re-proof plans"><div className="card-heading"><div><div className="eyebrow">WHAT MUST BE RE-PROVEN?</div><h2>Re-proof plans</h2><p>Required properties, invalidated evidence, and the observations needed before a release decision.</p></div></div><LedgerWindow state={plans} collection="proof-plans" /><RecordTable records={plans.records} columns={[
      { label: 'System / candidate', render: r => <><strong>{systemName(r.system_id)}</strong><small>{fingerprint(r)}</small></> },
      { label: 'Re-proof obligations', render: r => String(items(r.obligations).length) },
      { label: 'Reusable evidence', render: r => Array.isArray(r.reused_evidence_ids) ? r.reused_evidence_ids.length : 'Unknown' },
      { label: 'Recorded', render: r => date(r.created_at) },
      { label: '', render: r => <button className="text-button" onClick={() => inspect('proof-plans', r)}>Inspect plan <ArrowRight size={13} /></button> },
    ]} empty="A re-proof plan is created from the candidate fingerprint and previous scoped evidence." /></section>}

    {selected && record && <section className="card release-detail" aria-label="Selected integrity record"><div className="card-heading"><div><div className="eyebrow">PERSISTED RECORD</div><h2>{selected.collection === 'releases' ? 'Why this release decision happened' : selected.collection === 'proof-plans' ? 'Evidence applicability and re-proof' : selected.collection === 'change-sets' ? 'Exact candidate changes' : 'What established this property'}</h2></div><button className="icon-button" aria-label="Close integrity record" onClick={clearSelected}><X size={19} /></button></div>{detailError && <p className="notice error" role="alert">{detailError}</p>}
      <DetailGrid data={{ 'Record': record.id, 'System': systemName(record.system_id), ...(record.candidate ? { 'Candidate': fingerprint(record), 'Candidate digest': candidateDigest(record) } : {}), 'Recorded': date(record.evaluated_at || record.created_at) }} />
      {selected.collection === 'releases' && <><div className="release-outcome"><Badge value={record.release_action} /><span>Underlying evidence decision: <strong>{str(record.underlying_action)}</strong> · {str(obj(record.policy).mode)} mode</span></div>{record.current ? <div className={obj(record.current).current === true ? 'notice' : 'notice error'}><span><strong>Current applicability: {str(obj(record.current).release_action)}</strong> · checked {date(obj(record.current).checked_at)}. {obj(record.current).current === true ? 'The recorded decision remains applicable in the currently checked scope.' : 'The current evidence or authorization differs from this historical decision.'} {Array.isArray(obj(record.current).reasons) ? strings(obj(record.current).reasons) : ''}</span></div> : null}<RecordTable records={items(record.properties).map((r, i) => ({ ...r, id: str(r.property_id, String(i)) }))} columns={[
        { label: 'Property', render: r => <strong>{propertyName(r.property_id)}</strong> }, { label: 'Applicability', render: r => <Badge value={r.validity} /> }, { label: 'Security', render: r => <Badge value={r.security_verdict} /> }, { label: 'Task', render: r => <Badge value={r.task_outcome} /> }, { label: 'Reason', render: r => <small>{strings(r.reasons)}</small> },
      ]} empty="No property rows were returned. Inspect the recorded limitations." />{Array.isArray(record.exceptions) && record.exceptions.length > 0 && <div className="notice">An explicit exception is part of this decision. It does not turn the underlying evidence into PASS.</div>}<JsonDetails data={record.exceptions || []} label="Recorded exceptions" />{record.receipt ? <><JsonDetails data={record.receipt} label="Signed assurance receipt" /><p className="field-help">{str(obj(obj(record.receipt).trust).limitation, 'Verify with an independently trusted signing key. A key bundled with the receipt does not establish signer trust.')}</p><button className="button outline small" onClick={() => downloadJson(record.receipt, `threatveil-receipt-${record.id}.json`)}><Download size={14} />Export receipt</button></> : <p className="field-help">{record.receipt_id ? `Receipt reference: ${str(record.receipt_id)}. Receipt payload is not included in this response.` : 'No signed receipt is included in this record.'}</p>}</>}
      {selected.collection === 'proof-plans' && <><RecordTable records={items(record.invalidations).map((r, i) => ({ ...r, id: str(r.evidence_id, String(i)) }))} columns={[
        { label: 'Property', render: r => <strong>{propertyName(r.property_id)}</strong> }, { label: 'Applicability', render: r => <Badge value={r.status} /> }, { label: 'Changed dimensions', render: r => <small>{strings(r.changed_dimensions)}</small> }, { label: 'Reason', render: r => <small>{strings(r.reasons)}</small> },
      ]} empty="No previous evidence was assessed; inspect the obligations and unknowns." /><h3 className="integrity-subheading">Required re-proof</h3>{items(record.obligations).map((o, i) => <article className="proof-obligation" key={str(o.property_id, String(i))}><h4>{propertyName(o.property_id)}</h4><p>{strings(o.reasons)}</p><DetailGrid data={{ 'Required observers': strings(o.required_observers), 'Trials per variant': o.trials_per_variant, 'Variants': o.variant_count, 'Legitimate task': o.legitimate_task }} /><button className="button outline small" onClick={() => ctx.openForm('run', { id: 'planned-run', system_id: record.system_id, property_id: o.property_id, candidate: record.candidate, fingerprint: record.fingerprint, version: obj(record.candidate).version, trials: o.trials_per_variant, variant_count: o.variant_count })}>Configure re-proof run <ArrowRight size={13} /></button></article>)}<ReleaseEvaluator ctx={ctx} plan={record} onCreated={release => { refresh(); inspect('releases', release); }} /></>}
      {selected.collection === 'change-sets' && <RecordTable records={items(record.changes).map((r, i) => ({ ...r, id: String(i) }))} columns={[
        { label: 'Component', render: r => <strong>{str(r.component)}</strong> }, { label: 'Change', render: r => str(r.change_type) }, { label: 'Before', render: r => <small className="mono">{str(r.before)}</small> }, { label: 'After', render: r => <small className="mono">{str(r.after)}</small> },
      ]} empty="No concrete component changes were recorded. Inspect unknown dimensions before drawing a conclusion." />}
      {selected.collection === 'evidence-ledger' && <><div className="release-outcome"><Badge value={record.security_verdict} /><Badge value={record.task_outcome} /><span>Recorded result; current applicability requires a candidate comparison.</span></div><DetailGrid data={{ 'Qualified observation': record.qualified === true ? 'Qualified in recorded scope' : 'Qualification not established', 'Proof scope': record.proof_scope_id, 'Expiry': date(record.expires_at) }} />{record.proof_scope ? <JsonDetails data={record.proof_scope} label="Proof scope, dependency bindings, and provenance" open /> : null}{record.run_id ? <Link className="button outline small" href={`/app/runs/${encodeURIComponent(str(record.run_id))}`}>Inspect authoritative observations <ArrowRight size={13} /></Link> : null}</>}
      {Array.isArray(record.limitations) && record.limitations.length > 0 && <p className="notice">{strings(record.limitations)}</p>}<JsonDetails data={record} label="Complete immutable record and provenance" />
    </section>}
  </div>;
}

function PlanCreator({ ctx, systemId, onCreated }: { ctx: WorkspaceContext; systemId: string; onCreated: (record: RecordData) => void }) {
  const systems = items(ctx.dashboard?.systems);
  const [system, setSystem] = useState(systemId || systems[0]?.id || '');
  const [candidate, setCandidate] = useState('{"type":"application_version","id":"","version":"","digest":""}');
  const [candidateFingerprint, setFingerprint] = useState('{"components":[]}');
  const [previous, setPrevious] = useState('{"components":[]}');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  useEffect(() => { if (systemId) setSystem(systemId); }, [systemId]);
  useEffect(() => { const fp = JSON.stringify(systems.find(s => s.id === system)?.fingerprint || { components: [] }, null, 2); setFingerprint(fp); setPrevious(fp); }, [system]);
  async function submit(e: FormEvent) {
    e.preventDefault(); setBusy(true); setError('');
    try { const result = await ctx.mutate('/proof-plans', { system_id: system, candidate: JSON.parse(candidate), fingerprint: JSON.parse(candidateFingerprint), previous_fingerprint: JSON.parse(previous) }); onCreated(result); ctx.notify('Re-proof plan recorded. Evidence applicability and required observations remain explicit.'); }
    catch (e) { setError(e instanceof SyntaxError ? 'Enter valid JSON for both fingerprints and the candidate identity.' : e instanceof Error ? e.message : 'Plan creation failed.'); }
    finally { setBusy(false); }
  }
  return <details className="card plan-creator"><summary><span><GitBranch size={18} />Plan re-proof for an exact candidate</span><ArrowRight size={16} /></summary><form onSubmit={submit}><p className="operation-intro">Record the candidate and all known security-relevant components. The planner uses approved properties and historical evidence. Missing dependencies remain unknown.</p><label>Plan system<select value={system} required onChange={e => setSystem(e.target.value)}><option value="">Choose a system</option>{systems.map(s => <option key={s.id} value={s.id}>{title(s)}</option>)}</select></label><label>Plan candidate identity<textarea className="code-input" aria-label="Plan candidate identity" value={candidate} onChange={e => setCandidate(e.target.value)} required rows={4} /></label><div className="two-grid"><label>Previous proof fingerprint<textarea className="code-input" aria-label="Previous proof fingerprint" value={previous} onChange={e => setPrevious(e.target.value)} required rows={8} /></label><label>Candidate proof fingerprint<textarea className="code-input" aria-label="Candidate proof fingerprint" value={candidateFingerprint} onChange={e => setFingerprint(e.target.value)} required rows={8} /></label></div>{error && <p className="notice error" role="alert">{error}</p>}<button className="button dark small" disabled={busy || !system}>{busy ? 'Planning…' : 'Create re-proof plan'}<ArrowRight size={14} /></button></form></details>;
}
function ReleaseEvaluator({ ctx, plan, onCreated }: { ctx: WorkspaceContext; plan: RecordData; onCreated: (record: RecordData) => void }) {
  const [mode, setMode] = useState('WARN');
  const [propertyModes, setPropertyModes] = useState('{}');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  async function submit(e: FormEvent) {
    e.preventDefault(); setBusy(true); setError('');
    try { const result = await ctx.mutate('/releases', { plan_id: plan.id, policy: { mode, property_modes: JSON.parse(propertyModes) }, exception_ids: [] }); onCreated(result); ctx.notify('Exact-candidate release decision recorded. Inspect the underlying evidence and configured enforcement mode.'); }
    catch (e) { setError(e instanceof SyntaxError ? 'Enter a JSON object mapping property IDs to OBSERVE, WARN, or BLOCK.' : e instanceof Error ? e.message : 'Release evaluation failed.'); }
    finally { setBusy(false); }
  }
  return <form className="release-evaluator" onSubmit={submit}><h3>Evaluate this release candidate</h3><p className="operation-intro">The server checks current evidence for all approved properties. Creating this decision does not itself deploy the candidate or configure a GitHub required check.</p><div className="two-grid"><label>Release policy mode<select value={mode} onChange={e => setMode(e.target.value)}><option value="OBSERVE">OBSERVE — record underlying results</option><option value="WARN">WARN — surface unresolved evidence</option><option value="BLOCK">BLOCK — enforce the property decision</option></select></label><label>Property-specific policy (JSON)<textarea className="code-input" rows={3} value={propertyModes} onChange={e => setPropertyModes(e.target.value)} /></label></div>{error && <p className="notice error" role="alert">{error}</p>}<button className="button dark small" disabled={busy}>{busy ? 'Evaluating…' : 'Record release decision'}<ShieldCheck size={14} /></button></form>;
}
function downloadJson(data: unknown, name: string) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }));
  const anchor = document.createElement('a'); anchor.href = url; anchor.download = name; anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
