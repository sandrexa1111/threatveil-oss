'use client';

import { useEffect, useState, type FormEvent } from 'react';
import { ArrowRight, Layers } from 'lucide-react';
import { api, items, str, title, type RecordData } from '@/lib/api';
import { Badge, JsonDetails, type WorkspaceContext } from './workspace-parts';

const emptyBinding = {
  tool: '', tool_version: '', operation: '', boundary: '', witness_id: '',
  principal: { id: '', tenant_id: '', authority: [] },
  resource: { type: '', id: '', tenant_id: '' }, approver_id: '', initial_state: {}, allowed_state: {},
};
export function ToolContractInstaller({ ctx }: { ctx: WorkspaceContext }) {
  const systems = items(ctx.dashboard?.systems);
  const [templates, setTemplates] = useState<RecordData[]>([]);
  const [system, setSystem] = useState(systems[0]?.id || '');
  const [template, setTemplate] = useState('consequential-tool-v1');
  const [binding, setBinding] = useState(JSON.stringify(emptyBinding, null, 2));
  const [reviewed, setReviewed] = useState(false);
  const [result, setResult] = useState<RecordData | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  useEffect(() => { api('/tool-contracts').then(data => setTemplates(items(data))).catch(e => setError(e.message)); }, []);
  const selected = templates.find(t => t.id === template);
  async function install(e: FormEvent) {
    e.preventDefault(); setBusy(true); setError('');
    try {
      const output = await ctx.mutate('/tool-contracts/install', { system_id: system, template_id: template, binding: JSON.parse(binding), reviewed });
      setResult(output); setReviewed(false);
      ctx.notify(`${items(output.items).length} tool-contract property drafts created. Review and approve each property before qualified execution.`);
    } catch (e) { setError(e instanceof SyntaxError ? 'Enter valid JSON for the explicit tool binding.' : e instanceof Error ? e.message : 'The tool contract could not be installed.'); }
    finally { setBusy(false); }
  }
  return <details className="card tool-contract-installer"><summary><span><Layers size={18} />Install a consequential tool contract</span><span className="tag">REVIEWABLE DRAFTS</span></summary><p className="operation-intro">Bind a contract to one tool version, identity, resource, approver, witness, and permitted state transition. Installation creates property drafts; it does not approve them or execute the tool.</p><form onSubmit={install} className="operation-form"><label>Tool contract system<select value={system} required onChange={e => { setSystem(e.target.value); setReviewed(false); }}><option value="">Choose a system</option>{systems.map(s => <option key={s.id} value={s.id}>{title(s)}</option>)}</select></label><label>Tool contract template<select value={template} required onChange={e => { setTemplate(e.target.value); setReviewed(false); }}>{templates.map(t => <option key={t.id} value={t.id}>{title(t)}</option>)}</select></label><label className="wide-field">Tool contract binding (JSON)<textarea className="code-input" rows={15} value={binding} required onChange={e => { setBinding(e.target.value); setReviewed(false); }} /><small className="field-help">Initial and allowed state describe one permitted transition. Use test fixture values; never paste customer credentials or secret values. The approver, principal, tenant, resource, operation, and tool version must reflect the boundary you intend to observe.</small></label>{selected && <div className="wide-field"><JsonDetails data={selected} label="Contract axes, required bindings, and limitations" /></div>}<label className="checkbox-label wide-field"><input type="checkbox" required checked={reviewed} onChange={e => setReviewed(e.target.checked)} />I reviewed the identities, resource, tool version, and permitted transition in this binding.</label><button type="submit" className="button dark small" disabled={busy || !reviewed || !selected || !system}>{busy ? 'Installing drafts…' : 'Install six property drafts'}<ArrowRight size={15} /></button></form>{error && <div role="alert" className="notice error">{error}</div>}{result && <div className="tool-contract-result" role="status"><h3>{items(result.items).length} drafts installed <Badge value={result.status || 'DRAFT'} /></h3><p className="operation-intro">Each property still needs its own security review, source qualification, and evidence. No security result is transferred by template installation.</p><JsonDetails data={result} label="Installed drafts and binding digest" /></div>}</details>;
}
