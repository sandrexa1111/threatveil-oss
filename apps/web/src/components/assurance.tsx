'use client';

import { useEffect, useState, type FormEvent } from 'react';
import { ArrowRight, Plus, RefreshCw, X } from 'lucide-react';
import { api, date, items, obj, str, verdict, type RecordData } from '@/lib/api';
import { Badge, DetailGrid, JsonDetails, RecordTable, type WorkspaceContext } from './workspace-parts';

type Pair = { baseline_id: string; candidate_run_id: string };
type AssessmentKind = 'canaries' | 'selection-audits';
export function AssurancePanels({ ctx, systemId, impactId }: { ctx: WorkspaceContext; systemId: string; impactId?: string }) {
  const baselines = items(ctx.dashboard?.baselines).filter(b => b.system_id === systemId);
  const runs = items(ctx.dashboard?.runs).filter(r => r.system_id === systemId);
  const [candidate, setCandidate] = useState('{"type":"application_version","id":"","version":"","digest":""}');
  const [pairs, setPairs] = useState<Pair[]>([{ baseline_id: '', candidate_run_id: '' }]);
  const [impact, setImpact] = useState(impactId || '');
  const [runIds, setRunIds] = useState<string[]>([]);
  const [history, setHistory] = useState<RecordData[]>([]);
  const [assessment, setAssessment] = useState<RecordData | null>(null);
  const [selectedKind, setSelectedKind] = useState<AssessmentKind>('canaries');
  const [reference, setReference] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  useEffect(() => { setImpact(impactId || ''); }, [impactId]);
  useEffect(() => { setPairs([{ baseline_id: '', candidate_run_id: '' }]); setRunIds([]); setAssessment(null); }, [systemId]);
  async function loadHistory() {
    if (!systemId) return;
    try {
      const result = await Promise.all((['canaries', 'selection-audits'] as AssessmentKind[]).map(async kind => {
        const data = await api(`/${kind}?system_id=${encodeURIComponent(systemId)}&limit=50`);
        return items(data).map(record => ({ ...record, collection: kind } as RecordData));
      }));
      setHistory(result.flat().sort((a, b) => String(b.created_at).localeCompare(String(a.created_at))));
    } catch (e) { setError(e instanceof Error ? e.message : 'Assurance history is unavailable.'); }
  }
  useEffect(() => { loadHistory(); }, [systemId]);
  async function evaluate(kind: AssessmentKind, e: FormEvent) {
    e.preventDefault(); setBusy(true); setError('');
    try {
      const identity = JSON.parse(candidate);
      const payload = kind === 'canaries'
        ? { system_id: systemId, candidate: identity, pairs: pairs.map(pair => ({ baseline_id: pair.baseline_id, ...(pair.candidate_run_id ? { candidate_run_id: pair.candidate_run_id } : {}) })) }
        : { impact_id: impact, candidate: identity, candidate_run_ids: runIds };
      const result = await ctx.mutate(`/${kind}`, payload);
      setAssessment(result); setSelectedKind(kind); setReference(result.id); await loadHistory();
      ctx.notify('Assurance snapshot retained. Its decision applies only to the declared candidate and assessed scope.');
    } catch (e) { setError(e instanceof SyntaxError ? 'Enter valid JSON for the expected candidate identity.' : e instanceof Error ? e.message : 'Assurance evaluation is unavailable.'); }
    finally { setBusy(false); }
  }
  async function inspect(kind: AssessmentKind, id: string) {
    setBusy(true); setError('');
    try { setAssessment(await api(`/${kind}/${encodeURIComponent(id)}`)); setSelectedKind(kind); setReference(id); }
    catch (e) { setError(e instanceof Error ? e.message : 'The saved assurance record is unavailable.'); }
    finally { setBusy(false); }
  }
  const current = obj(assessment?.current);
  return <>
    <section className="card assurance-intro"><div className="card-heading"><div><div className="eyebrow">EXISTING EVIDENCE, BEFORE RELEASE</div><h2>Candidate security assurance</h2></div></div><p className="operation-intro">Compare completed evidence against historical memory. These assessments do not execute tools or deploy a candidate. Missing, stale, or incompatible evidence remains explicit.</p><label>Expected candidate identity<textarea className="code-input" aria-label="Expected candidate identity" rows={5} value={candidate} onChange={e => setCandidate(e.target.value)} /><small className="field-help">Provide type, identity, exact version, and expected digest. A model or application version label alone is insufficient.</small></label></section>

    <form className="card" onSubmit={e => evaluate('canaries', e)}><div className="card-heading"><div><div className="eyebrow">SECURITY CANARY</div><h2>What holds on this candidate?</h2></div></div><p className="operation-intro">Select up to 25 distinct property baselines and their candidate runs. An absent candidate run is recorded as unknown. The current assessment rechecks authorization, source qualification, and evidence freshness.</p>
      {pairs.map((pair, index) => {
        const baseline = baselines.find(b => b.id === pair.baseline_id);
        return <div className="canary-pair" key={index}><label>Verified baseline {index + 1}<select required value={pair.baseline_id} onChange={e => setPairs(existing => existing.map((p, i) => i === index ? { baseline_id: e.target.value, candidate_run_id: '' } : p))}><option value="">Choose a verified baseline</option>{baselines.map(b => <option key={b.id} value={b.id}>{str(items(ctx.dashboard?.properties).find(p => p.id === b.property_id)?.title, 'Property')} · {b.id.slice(0, 8)}</option>)}</select></label><label>Candidate run {index + 1}<select value={pair.candidate_run_id} onChange={e => setPairs(existing => existing.map((p, i) => i === index ? { ...p, candidate_run_id: e.target.value } : p))}><option value="">No evidence yet → UNKNOWN</option>{runs.filter(r => !baseline || r.property_id === baseline.property_id).map(r => <option key={r.id} value={r.id}>{str(r.version)} · {verdict(r)} · {r.id.slice(0, 8)}</option>)}</select></label>{pairs.length > 1 && <button type="button" className="icon-button" aria-label={`Remove pair ${index + 1}`} onClick={() => setPairs(existing => existing.filter((_, i) => i !== index))}><X size={17} /></button>}</div>;
      })}<div className="operation-actions"><button type="button" className="button outline small" disabled={pairs.length >= 25 || busy} onClick={() => setPairs(existing => [...existing, { baseline_id: '', candidate_run_id: '' }])}>Add property pair <Plus size={14} /></button><button type="submit" className="button dark small" disabled={busy || !systemId || !baselines.length}>Evaluate security canary <ArrowRight size={14} /></button></div>{!baselines.length && <p className="field-help">Verify a useful fix to retain a baseline, or load older baselines above.</p>}</form>

    <form className="card" onSubmit={e => evaluate('selection-audits', e)}><div className="card-heading"><div><div className="eyebrow">CHANGE SELECTION AUDIT</div><h2>Did the selected suite miss anything?</h2></div></div><p className="operation-intro">Compare the impact analysis’s selected and excluded properties with existing candidate evidence. A confirmed failure in an excluded property is a missed failure. Unobserved or incompatible properties make the audit incomplete.</p><label>Impact analysis record ID<input name="impact_id" required value={impact} onChange={e => setImpact(e.target.value)} placeholder="Run change analysis above or enter its saved ID" /></label><fieldset className="audit-run-options"><legend>Candidate runs for the full property scope</legend><p className="field-help">Choose one run per property. Selecting another run replaces the previous selection for that property.</p>{runs.length ? runs.map(run => <label className="checkbox-label" key={run.id}><input type="checkbox" checked={runIds.includes(run.id)} onChange={e => setRunIds(ids => e.target.checked ? [...ids.filter(id => runs.find(r => r.id === id)?.property_id !== run.property_id), run.id] : ids.filter(id => id !== run.id))} />{str(items(ctx.dashboard?.properties).find(p=>p.id===run.property_id)?.title, str(run.property_id))} · {str(run.version)} · {verdict(run)} · {run.id.slice(0, 8)}</label>) : <p className="field-help">There are no loaded runs for this system. Missing evidence cannot establish full-suite assurance.</p>}</fieldset><button type="submit" className="button dark small" disabled={busy || !impact || !systemId}>Audit test selection <ArrowRight size={14} /></button></form>

    {error && <div className="notice error" role="alert">{error}</div>}
    {assessment && <section className="card assurance-result" aria-label="Current assurance assessment"><div className="card-heading"><div><div className="eyebrow">CURRENT ASSESSMENT</div><h2>{selectedKind === 'canaries' ? 'Candidate security canary' : 'Test selection audit'}</h2></div><Badge value={current.release_action || 'UNKNOWN'} /></div><DetailGrid data={{ 'Record': assessment.id, 'Complete scope': current.complete === true ? 'Yes' : 'No', 'Checked': current.checked_at, 'Evidence age limit': current.max_evidence_age_hours ? `${current.max_evidence_age_hours} hours` : 'See scope' }} /><RecordTable records={items(current.rows).map((row, index) => ({ ...row, id: str(row.property_id, String(index)) }))} columns={[{ label: 'Property', render: row => <strong>{str(items(ctx.dashboard?.properties).find(p => p.id === row.property_id)?.title, str(row.property_id))}</strong> }, { label: 'Classification', render: row => <Badge value={row.classification} /> }, { label: 'Selection', render: row => str(row.selection, 'Requested pair') }, { label: 'Reason', render: row => <small>{Array.isArray(row.reasons) ? row.reasons.join('; ') : str(row.reasons)}</small> }]} empty="No assessed rows were returned." /><JsonDetails data={current} label="Current evidence, scope, and limitations" open /><JsonDetails data={assessment.snapshot} label="Immutable assessment when saved" /><button className="button outline small" disabled={busy} onClick={() => inspect(selectedKind, assessment.id)}>Recheck current applicability <RefreshCw size={14} /></button></section>}

    <section className="card"><div className="card-heading"><div><h2>Saved assurance snapshots</h2><p>Latest 50 per assessment type for this system. Saved decisions may differ from current applicability.</p></div></div><RecordTable records={history} columns={[{ label: 'Assessment', render: row => <strong>{row.collection === 'canaries' ? 'Security canary' : 'Selection audit'} · {row.id.slice(0, 8)}</strong> }, { label: 'Saved decision', render: row => <Badge value={obj(row.snapshot).release_action || 'UNKNOWN'} /> }, { label: 'Saved', render: row => date(row.created_at) }, { label: '', render: row => <button className="text-button" disabled={busy} onClick={() => inspect(row.collection as AssessmentKind, row.id)}>Inspect current scope <ArrowRight size={13} /></button> }]} empty="No assurance snapshot has been saved for this system." /><form className="inline-form" onSubmit={e => { e.preventDefault(); inspect(selectedKind, reference); }}><label>Assessment type<select value={selectedKind} onChange={e => setSelectedKind(e.target.value as AssessmentKind)}><option value="canaries">Security canary</option><option value="selection-audits">Selection audit</option></select></label><label>Saved assessment ID<input value={reference} required onChange={e => setReference(e.target.value)} /></label><button type="submit" className="button outline small" disabled={busy}>Open saved assessment</button></form></section>
  </>;
}
