'use client';

import { useEffect, useRef, useState } from 'react';
import { Download, FileText, X } from 'lucide-react';
import { api, ApiError, items, obj, str, verdict, type RecordData } from '@/lib/api';
import { Badge, DetailGrid, JsonDetails } from './workspace-parts';

export function CapturedTrials({ runId, trials, captureIds }: { runId: string; trials: RecordData[]; captureIds: string[] }) {
  const [selected, setSelected] = useState('');
  const [capture, setCapture] = useState<RecordData | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const request = useRef<AbortController | null>(null);
  useEffect(() => () => request.current?.abort(), []);
  async function inspect(id: string) {
    request.current?.abort();
    const controller = new AbortController(); request.current = controller;
    setSelected(id); setCapture(null); setError(''); setLoading(true);
    try {
      const record = await api(`/runs/${encodeURIComponent(runId)}/captures/${encodeURIComponent(id)}`, { signal: controller.signal });
      if (!controller.signal.aborted) setCapture(record);
    } catch (e) {
      if (!controller.signal.aborted) setError(e instanceof ApiError && e.status === 410
        ? 'This detailed capture has expired under its retention policy. The recorded verdict and evidence digest remain historical records; missing detail does not create a new PASS.'
        : e instanceof Error ? e.message : 'Capture evidence is unavailable.');
    } finally { if (!controller.signal.aborted) setLoading(false); }
  }
  const ids = [...new Set([...trials.map(t => str(t.capture_id, '')).filter(Boolean), ...captureIds])];
  const observation = obj(capture?.observation);
  const receipts = items(observation.receipts);
  return <div className="captured-trials">
    <p className="operation-intro">Detailed external observations are retained separately. Load one assigned capture at a time to inspect its receipts, source qualification, and state. Capture access is scoped to this organization and run.</p>
    <div className="capture-list">{ids.map((id, index) => {
      const trial = trials.find(t => t.capture_id === id);
      return <article key={id} className={`capture-summary ${selected === id ? 'selected' : ''}`}><div><strong>{trial ? `Trial ${Number(trial.index) + 1} · ${str(trial.variant_id)}` : `Retained capture ${index + 1}`}</strong><small className="mono">{id.slice(0, 12)}</small></div>{trial && <Badge value={verdict(trial)} />}<button type="button" className="button outline small" onClick={() => inspect(id)} disabled={loading && selected === id}><FileText size={14} />{loading && selected === id ? 'Loading…' : 'Inspect capture'}</button></article>;
    })}</div>
    {selected && <section className="capture-detail" aria-label="Selected capture evidence" aria-busy={loading}>
      <div className="card-heading"><div><div className="eyebrow">ASSIGNED DURABLE OBSERVATION</div><h3>Capture {selected.slice(0, 12)}</h3></div><button type="button" className="icon-button" aria-label="Close capture" onClick={() => { request.current?.abort(); setSelected(''); setCapture(null); setLoading(false); }}><X size={18} /></button></div>
      {error && <div role="alert" className="notice error">{error}</div>}
      {loading && <p role="status">Retrieving retained evidence…</p>}
      {capture && <><DetailGrid data={{ 'Run': capture.run_id, 'Variant': capture.variant_id, 'Trial index': capture.index, 'Observed evaluation': obj(capture.evaluation).security_verdict, 'Evaluated at': capture.evaluated_at, 'Initial state digest': observation.initial_state_digest }} />
        {receipts.map((receipt, index) => <div className="observation" key={receipt.id || index}><div className="observation-index">{String(index + 1).padStart(2, '0')}</div><div><div className="observation-title"><strong>{str(obj(receipt.action).operation, 'Recorded action')}</strong><Badge value={obj(receipt.action).phase || 'RECORDED'} subtle /></div><DetailGrid data={{ 'Identity': obj(obj(receipt.action).principal).id, 'Resource': obj(obj(receipt.action).resource).id, 'Tenant': obj(obj(receipt.action).resource).tenant_id, 'Source': receipt.source_id }} /><JsonDetails data={receipt} label="Receipt and state change" /></div></div>)}
        <JsonDetails data={capture} label="Complete retained capture" /><a href={`/api/backend/v1/runs/${runId}/captures/${selected}`} download={`threatveil-capture-${selected}.json`} className="button outline small"><Download size={14} />Export this capture</a></>}
    </section>}
  </div>;
}
