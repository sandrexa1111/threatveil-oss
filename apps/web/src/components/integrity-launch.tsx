'use client';

import Link from 'next/link';
import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react';
import { ArrowRight, Check, Clock, RefreshCw } from 'lucide-react';
import { api, date, items, obj, str, title, type PageWindow, type RecordData } from '@/lib/api';
import { Badge, DetailGrid, JsonDetails, RecordTable, type WorkspaceContext } from './workspace-parts';

type LaunchPage = { items: RecordData[]; pagination: PageWindow };
const milestoneLabels: Record<string, string> = {
  scope_reviewed: 'Scope reviewed by security owner',
  properties_approved: 'Scoped property definitions approved',
  qualified_evidence_recorded: 'Qualified evidence recorded for the scope',
  github_route_configured: 'GitHub release route configured',
  warn_decision_recorded: 'WARN release decision recorded',
  signed_receipt_recorded: 'Signed receipt recorded',
  live_gate_delivery_verified: 'Live WARN check delivery verified',
};
export function IntegrityLaunchWorkspace({ ctx }: { ctx: WorkspaceContext }) {
  const [launches, setLaunches] = useState<RecordData[]>([]);
  const [pagination, setPagination] = useState<PageWindow | null>(null);
  const [selectedId, setSelectedId] = useState('');
  const [selected, setSelected] = useState<RecordData | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [revision, setRevision] = useState(0);
  const [detailLoading, setDetailLoading] = useState(false);
  const detailGeneration = useRef(0);
  const alive = useRef(true);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  const refresh = useCallback(() => setRevision(n => n + 1), []);
  useEffect(() => {
    const controller = new AbortController();
    setBusy(true); setError('');
    api<LaunchPage>('/integrity-launches?limit=25', { signal: controller.signal }).then(result => {
      if (!controller.signal.aborted) { setLaunches(items(result)); setPagination(result.pagination); }
    }).catch(e => { if (!controller.signal.aborted) setError(e instanceof Error ? e.message : 'Launches are unavailable.'); })
      .finally(() => { if (!controller.signal.aborted) setBusy(false); });
    return () => controller.abort();
  }, [ctx.dashboard, revision]);
  useEffect(() => {
    const controller = new AbortController();
    detailGeneration.current += 1; setSelected(null);
    if (!selectedId) return;
    setDetailLoading(true);
    api(`/integrity-launches/${encodeURIComponent(selectedId)}`, { signal: controller.signal }).then(result => {
      if (!controller.signal.aborted) setSelected(result);
    }).catch(e => { if (!controller.signal.aborted) setError(e instanceof Error ? e.message : 'Launch details are unavailable.'); })
      .finally(() => { if (!controller.signal.aborted) setDetailLoading(false); });
    return () => { controller.abort(); detailGeneration.current += 1; };
  }, [selectedId, revision]);
  async function more() {
    if (!pagination?.next_cursor) return;
    setBusy(true); setError('');
    try {
      const result = await api<LaunchPage>(`/integrity-launches?limit=25&cursor=${encodeURIComponent(pagination.next_cursor)}`);
      if (alive.current) { setLaunches(existing => [...existing, ...items(result).filter(r => !existing.some(old => old.id === r.id))]); setPagination(result.pagination); }
    } catch (e) { if (alive.current) setError(e instanceof Error ? e.message : 'Older launches are unavailable.'); }
    finally { if (alive.current) setBusy(false); }
  }
  async function moreHistory(collection: 'events' | 'time') {
    if (!selected) return;
    const field = collection === 'events' ? 'events' : 'time_entries';
    const cursor = obj(obj(selected[field]).pagination).next_cursor;
    if (!cursor) return;
    const generation = detailGeneration.current;
    try {
      const result = await api<LaunchPage>(`/integrity-launches/${selected.id}/${collection}?limit=50&cursor=${encodeURIComponent(str(cursor))}`);
      if (alive.current && generation === detailGeneration.current) setSelected(current => current ? { ...current, [field]: { items: [...items(obj(current[field]).items), ...items(result)], pagination: result.pagination } } : current);
    } catch (e) { if (alive.current && generation === detailGeneration.current) setError(e instanceof Error ? e.message : 'Older history is unavailable.'); }
  }
  return <div className="launch-workspace"><section className="card"><div className="card-heading"><div><div className="eyebrow">ONE CONSEQUENTIAL SYSTEM</div><h2>A launch ends with a release workflow</h2><p>Agree scope, establish evidence, and verify the installed WARN path. Scope execution, installation, measured effort, and provider payment remain distinct.</p></div><button className="icon-button" aria-label="Refresh Integrity Launches" onClick={refresh}><RefreshCw size={16} /></button></div>{error && <p className="notice error" role="alert">{error}</p>}{busy && !launches.length && <p className="operation-intro" role="status">Loading Integrity Launches…</p>}{pagination && <div className="window-control"><span>{launches.length} of {pagination.total} launches loaded · newest first</span>{pagination.next_cursor && <button className="button outline small" onClick={more} disabled={busy}>Load older launches <ArrowRight size={14} /></button>}</div>}<RecordTable records={launches} columns={[
      { label: 'Integrity Launch', render: r => <><strong>{title(r)}</strong><small>{str(items(ctx.dashboard?.systems).find(s => s.id === r.system_id)?.name, str(r.system_id))}</small></> },
      { label: 'Scope execution', render: r => <Badge value={r.execution_status} /> },
      { label: 'Installation', render: r => <Badge value={r.installation_status} /> },
      { label: 'Measured effort', render: r => `${str(obj(r.effort).hours, '0')} hours` },
      { label: '', render: r => <button className="text-button" onClick={() => { setError(''); setSelectedId(r.id); }}>Open launch <ArrowRight size={13} /></button> },
    ]} empty="Create an Integrity Launch to retain the agreed system, property scope, and implementation history." /></section>
    {detailLoading && <p role="status" className="operation-intro">Loading launch history…</p>}
    {selected && <section className="card" aria-label="Selected Integrity Launch"><div className="card-heading"><div><div className="eyebrow">MEASURED IMPLEMENTATION</div><h2>{title(selected)}</h2><p>{str(selected.scope)}</p></div></div><DetailGrid data={{ 'Scoped properties': obj(selected.summary).properties_scoped, 'Tested properties': obj(selected.summary).properties_tested, 'Measured hours': obj(selected.effort).hours, 'Current account payment': str(obj(selected.conversion).status).replaceAll('_', ' ') }} /><p className="field-help">{str(selected.scope_recommendation)}</p><div className="launch-milestones">{Object.entries(obj(selected.milestones)).map(([key, complete]) => <div key={key}><span className={complete === true ? 'milestone-complete' : 'milestone-pending'}>{complete === true ? <Check size={14} /> : <Clock size={14} />}</span><strong>{milestoneLabels[key] || key.replaceAll('_', ' ')}</strong><Badge value={complete === true ? 'RECORDED' : 'PENDING'} /></div>)}</div><p className="notice">A security-owner note cannot establish live check delivery, a security verdict, or a payment. Installation is derived from the exact release, signed receipt, active GitHub binding, and confirmed check publication.</p><div className="operation-actions"><Link className="button outline small" href={`/app/reports?system=${encodeURIComponent(str(selected.system_id))}`}>Open scope report <ArrowRight size={14} /></Link><Link className="button outline small" href="/app/releases">Inspect release history <ArrowRight size={14} /></Link></div><div className="launch-entry-grid"><LaunchNote ctx={ctx} launch={selected} onSaved={refresh} /><LaunchTime ctx={ctx} launch={selected} onSaved={refresh} /></div>
      <h3 className="integrity-subheading">Recorded implementation history</h3><RecordTable records={items(obj(selected.events).items)} columns={[{ label: 'Review / event', render: r => <strong>{str(r.event).replaceAll('_', ' ')}</strong> }, { label: 'Note', render: r => <small>{str(r.note)}</small> }, { label: 'Recorded by', render: r => <small className="mono">{str(r.actor_id)}</small> }, { label: 'Recorded', render: r => date(r.created_at) }]} empty="No implementation reviews have been recorded." />{obj(obj(selected.events).pagination).next_cursor ? <button className="button outline small" onClick={() => moreHistory('events')}>Load older launch events</button> : null}
      <h3 className="integrity-subheading">Measured implementation effort</h3><RecordTable records={items(obj(selected.time_entries).items)} columns={[{ label: 'Work date', render: r => str(r.work_date) }, { label: 'Work', render: r => <><strong>{str(r.category)}</strong><small>{str(r.note)}</small></> }, { label: 'Minutes', render: r => str(r.minutes) }, { label: 'Recorded by', render: r => <small className="mono">{str(r.actor_id)}</small> }]} empty="Record actual implementation time to measure onboarding effort." />{obj(obj(selected.time_entries).pagination).next_cursor ? <button className="button outline small" onClick={() => moreHistory('time')}>Load older time entries</button> : null}<JsonDetails data={selected} label="Launch scope, derived milestones, effort, and limitations" />
    </section>}
  </div>;
}
function LaunchNote({ ctx, launch, onSaved }: { ctx: WorkspaceContext; launch: RecordData; onSaved: () => void }) {
  const [event, setEvent] = useState('implementation_note');
  const [note, setNote] = useState('');
  const [reviewed, setReviewed] = useState(false);
  const [key, setKey] = useState(() => crypto.randomUUID());
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const role = ctx.identity?.memberships.find(m => m.organization_id === ctx.identity?.organization.id)?.role;
  async function submit(e: FormEvent) {
    e.preventDefault(); setBusy(true); setError('');
    try { await ctx.mutate(`/integrity-launches/${launch.id}/events`, { event, note, reviewed, idempotency_key: key }); setKey(crypto.randomUUID()); setNote(''); setReviewed(false); onSaved(); ctx.notify('Security-owner review recorded with immutable launch history.'); }
    catch (e) { setError(e instanceof Error ? e.message : 'Could not record launch review.'); }
    finally { setBusy(false); }
  }
  return <form className="launch-entry" onSubmit={submit}><h3>Record an implementation review</h3><label>Launch event<select value={event} onChange={e => setEvent(e.target.value)}><option value="implementation_note">Implementation note</option><option value="scope_reviewed">Scope reviewed</option><option value="blocker">Implementation blocker</option><option value="handoff_reviewed">Handoff reviewed</option></select></label><label>Launch review note<textarea required minLength={10} maxLength={4000} rows={4} value={note} onChange={e => setNote(e.target.value)} /></label><label className="checkbox-label"><input type="checkbox" checked={reviewed} required onChange={e => setReviewed(e.target.checked)} />I reviewed this implementation note and its scope.</label><p className="field-help">Owner, admin, or security role required. A review records the reviewer’s statement; it does not substitute for release evidence.</p>{error && <p className="notice error" role="alert">{error}</p>}<button className="button dark small" disabled={busy || !['owner', 'admin', 'security'].includes(str(role))}>{busy ? 'Recording…' : 'Record launch review'}<ArrowRight size={14} /></button></form>;
}
function LaunchTime({ ctx, launch, onSaved }: { ctx: WorkspaceContext; launch: RecordData; onSaved: () => void }) {
  const today = new Date().toISOString().slice(0, 10);
  const [workDate, setWorkDate] = useState(today);
  const [minutes, setMinutes] = useState('');
  const [category, setCategory] = useState('integration');
  const [note, setNote] = useState('');
  const [key, setKey] = useState(() => crypto.randomUUID());
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const role = ctx.identity?.memberships.find(m => m.organization_id === ctx.identity?.organization.id)?.role;
  async function submit(e: FormEvent) {
    e.preventDefault(); setBusy(true); setError('');
    try { await ctx.mutate(`/integrity-launches/${launch.id}/time`, { work_date: workDate, minutes: Number(minutes), category, note, idempotency_key: key }); setKey(crypto.randomUUID()); setMinutes(''); setNote(''); onSaved(); ctx.notify('Actual implementation time recorded.'); }
    catch (e) { setError(e instanceof Error ? e.message : 'Could not record implementation time.'); }
    finally { setBusy(false); }
  }
  return <form className="launch-entry" onSubmit={submit}><h3>Track completed implementation work</h3><div className="two-grid"><label>Work date<input type="date" required value={workDate} max={today} onChange={e => setWorkDate(e.target.value)} /></label><label>Actual minutes<input type="number" min={1} max={720} required value={minutes} onChange={e => setMinutes(e.target.value)} /></label></div><label>Work category<select value={category} onChange={e => setCategory(e.target.value)}>{['scope', 'observation', 'integration', 'reproof', 'remediation', 'support'].map(c => <option key={c} value={c}>{c}</option>)}</select></label><label>Completed work note<textarea minLength={5} maxLength={2000} required rows={3} value={note} onChange={e => setNote(e.target.value)} /></label>{error && <p className="notice error" role="alert">{error}</p>}<button className="button dark small" disabled={busy || !['owner', 'admin', 'security', 'developer'].includes(str(role))}>{busy ? 'Recording…' : 'Record implementation time'}<Clock size={14} /></button></form>;
}
