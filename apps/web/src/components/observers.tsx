'use client';

import { useCallback, useEffect, useState, type FormEvent } from 'react';
import Link from 'next/link';
import { ArrowUpRight, Fingerprint, Plus, ShieldCheck } from 'lucide-react';
import { api, date, items, obj, str, title, verdict, type RecordData } from '@/lib/api';
import { Badge, DetailGrid, JsonDetails, RecordTable, type WorkspaceContext } from './workspace-parts';

const controls = [
  { key: 'KNOWN_PERMITTED', field: 'permitted_run_id', label: 'Known permitted action', expected: 'PASS + task SUCCESS' },
  { key: 'KNOWN_PROHIBITED', field: 'prohibited_run_id', label: 'Known prohibited action', expected: 'FAIL' },
  { key: 'MISSING_OBSERVATION', field: 'missing_run_id', label: 'Missing observation', expected: 'INCONCLUSIVE' },
];
const failure = (error: unknown) => error instanceof Error ? error.message : 'The observation source could not be updated.';

export function ObserverManager({ ctx }: { ctx: WorkspaceContext }) {
  const systems = items(ctx.dashboard?.systems);
  const properties = items(ctx.dashboard?.properties).filter(p => p.approved);
  const [sources, setSources] = useState<RecordData[]>([]);
  const [systemId, setSystemId] = useState(systems[0]?.id || '');
  const [propertyId, setPropertyId] = useState('');
  const [selectedId, setSelectedId] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const mayReview = ['owner', 'admin', 'security'].includes(str(ctx.identity?.organization.role || ctx.identity?.user.role));
  const selected = sources.find(s => s.id === selectedId);
  const remoteTargets = ctx.targets.filter(t => t.system_id === systemId && ['http', 'mcp'].includes(str(t.adapter)) && t.verified === true);
  const definition = obj(properties.find(p => p.id === propertyId)?.definition);
  const requiredWitnesses = obj(definition.observation_contract).required_witnesses;
  const load = useCallback(async () => {
    try { setSources(items(await api('/observers'))); } catch (e) { setError(failure(e)); }
  }, []);
  useEffect(() => { load(); }, [load]);

  async function register(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const form = e.currentTarget;
    const fields = Object.fromEntries(new FormData(form));
    setBusy(true); setError('');
    try {
      const record = await ctx.mutate('/observers', { ...fields, system_id: systemId, property_id: propertyId });
      await load(); setSelectedId(record.id);
      ctx.notify('Observation source registered. Assigned controls and human review are still required.');
      form.reset();
    } catch (e) { setError(failure(e)); } finally { setBusy(false); }
  }

  async function approve(e: FormEvent<HTMLFormElement>) {
    e.preventDefault(); if (!selected) return;
    setBusy(true); setError('');
    try {
      const approved = await ctx.mutate(`/observers/${selected.id}/approve`, Object.fromEntries(new FormData(e.currentTarget)));
      await load(); setSelectedId(approved.id);
      ctx.notify('A qualified source version has been retained for this property and target. Collector correctness is not universally certified.');
    } catch (e) { setError(failure(e)); } finally { setBusy(false); }
  }

  async function revoke() {
    if (!selected) return;
    setBusy(true); setError('');
    try {
      await ctx.mutate(`/observers/${selected.id}/revoke`); await load();
      ctx.notify('Observation source family revoked. Further execution access is denied.');
    } catch (e) { setError(failure(e)); } finally { setBusy(false); }
  }

  return <section className="card" aria-labelledby="observers-title">
    <div className="card-heading"><div><div className="eyebrow">OBSERVATION, WITH ACCOUNTABILITY</div><h2 id="observers-title">Qualified observation sources</h2></div><Fingerprint size={22} /></div>
    <p className="operation-intro">A signature identifies a source; it does not make an agent’s self-report authoritative. Bind a separately deployed observer and ground-truth collector to an approved property, then execute three assigned controls and review their evidence.</p>
    <RecordTable records={sources} columns={[
      { label: 'Source', render: s => <><strong>{str(s.source_id)}</strong><small>{str(s.source_version)}</small></> },
      { label: 'State', render: s => <Badge value={s.revoked ? 'REVOKED' : s.superseded_by ? 'SUPERSEDED' : s.status || 'QUALIFICATION_REQUIRED'} /> },
      { label: 'Registered', render: s => date(s.created_at) },
      { label: '', render: s => <button className="text-button" onClick={() => setSelectedId(s.id)}>Review source <ArrowUpRight size={14} /></button> },
    ]} empty="No customer observation source is registered. Synthetic demo evidence has its own explicitly scoped fixture qualification." />

    {selected && <div className="operation-subsection observer-review">
      <div className="card-heading"><div><h3>{str(selected.source_id)} · {str(selected.source_version)}</h3><p>Verify deployment independence and control evidence before approving this exact binding.</p></div><Badge value={selected.revoked ? 'REVOKED' : selected.superseded_by ? 'SUPERSEDED' : selected.status} /></div>
      <DetailGrid data={{ 'Observer ID': selected.id, 'Property version': selected.property_id, 'Target': selected.target_id, 'Candidate component': selected.candidate_component_id, 'Fixture reference': selected.fixture_reference, 'Initial state digest': selected.initial_state_digest }} />
      <div className="two-grid"><div><h4>Observer public key</h4><code className="key-fingerprint">{str(selected.public_key)}</code></div><div><h4>Ground-truth public key</h4><code className="key-fingerprint">{str(selected.ground_truth_public_key)}</code></div></div>
      <p className="operation-intro"><strong>Independence review:</strong> {str(selected.independence_review)}</p>
      <JsonDetails data={selected} label="Full source binding and qualification lineage" />
      {!selected.approved && !selected.revoked && !selected.superseded_by && mayReview && <form onSubmit={approve} className="observer-controls">
        <h3>Qualify against assigned controls</h3>
        <p className="operation-intro">Each control uses one trial and one variant on the bound HTTP or MCP target. Supply its actual stimulus and candidate in the run form. Qualification runs cannot establish a useful-fix baseline.</p>
        {controls.map(control => {
          const matching = items(ctx.dashboard?.runs).filter(r => r.observer_id === selected.id && r.qualification_case === control.key);
          return <div className="observer-control" key={control.key}><div><strong>{control.label}</strong><small>Required outcome: {control.expected}</small></div><button type="button" className="button outline small" onClick={() => ctx.openForm('run', { id: selected.id, system_id: selected.system_id, property_id: selected.property_id, target_id: selected.target_id, observer_id: selected.id, qualification_case: control.key, trials: 1, variant_count: 1, version: '' })}>Run control <Plus size={14} /></button><label>{control.label} run<select name={control.field} required defaultValue=""><option value="">Select assigned execution</option>{matching.map(r => <option key={r.id} value={r.id}>{r.id.slice(0,8)} · {verdict(r)} · task {str(r.task_outcome)}</option>)}</select></label>{matching.map(r => <Link key={r.id} href={`/app/runs/${r.id}`} className="text-button">Inspect {r.id.slice(0,8)} evidence <ArrowUpRight size={13} /></Link>)}</div>;
        })}
        <label>Qualification review note<textarea name="review_note" required minLength={20} maxLength={4000} rows={3} placeholder="Record how you verified source independence, control outcomes, and the limits of this fixture." /></label>
        <button type="submit" className="button dark small" disabled={busy}>Approve reviewed qualification <ShieldCheck size={15} /></button>
      </form>}
      {mayReview && !selected.revoked && <button className="text-button danger-text" disabled={busy} onClick={revoke}>Revoke this source family</button>}
    </div>}

    {mayReview && <details className="observer-register"><summary>Register an observation source <Plus size={16} /></summary><p className="operation-intro">Provide public keys only. Signing keys stay with the customer collectors. Registration requires a verified HTTP or MCP target and a source named in the property’s mandatory witness contract.</p><form onSubmit={register} className="operation-form">
      <label>Observer system<select value={systemId} required onChange={e => { setSystemId(e.target.value); setPropertyId(''); }}><option value="">Choose a system</option>{systems.map(s => <option key={s.id} value={s.id}>{title(s)}</option>)}</select></label>
      <label>Observer property<select value={propertyId} required onChange={e => setPropertyId(e.target.value)}><option value="">Choose an approved property</option>{properties.filter(p => p.system_id === systemId).map(p => <option key={p.id} value={p.id}>{title(p)}</option>)}</select></label>
      <label>Observer target<select name="target_id" required key={systemId}><option value="">Choose a verified HTTP or MCP target</option>{remoteTargets.map(t => <option key={t.id} value={t.id}>{title(t)}</option>)}</select></label>
      <label>Witness source ID<input name="source_id" required maxLength={150} />{Array.isArray(requiredWitnesses) && <small>Required witnesses: {requiredWitnesses.join(', ')}</small>}</label>
      <label>Collector version<input name="source_version" required maxLength={150} /></label>
      <label>Candidate fingerprint component ID<input name="candidate_component_id" required maxLength={150} placeholder="customer-agent" /><small>The exact component whose observed digest must match the candidate release.</small></label>
      <label>Observer Ed25519 public key<input className="code-input" name="public_key" required minLength={40} maxLength={100} autoComplete="off" /></label>
      <label>Ground-truth Ed25519 public key<input className="code-input" name="ground_truth_public_key" required minLength={40} maxLength={100} autoComplete="off" /><small>A distinct collector key, encoded as base64.</small></label>
      <label>Initial state SHA-256<input className="code-input" name="initial_state_digest" required pattern="[0-9a-f]{64}" minLength={64} maxLength={64} /></label>
      <label>Fixture reference<input name="fixture_reference" required maxLength={300} /></label>
      <label className="wide-field">Deployment independence review<textarea name="independence_review" required minLength={40} maxLength={4000} rows={4} placeholder="Who controls each collector? Which actual sink state is observed? What prevents agent-controlled content from forging those observations?" /></label>
      {!remoteTargets.length && <p className="field-help wide-field">Verify an HTTP or MCP test target before registering a source. The synthetic demo target cannot qualify a customer collector.</p>}
      <button type="submit" className="button dark small" disabled={busy || !remoteTargets.length}>Register source <Plus size={15} /></button>
    </form></details>}
    {error && <div role="alert" className="notice error">{error}</div>}
  </section>;
}
