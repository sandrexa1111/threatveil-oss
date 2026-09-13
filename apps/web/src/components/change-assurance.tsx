'use client';

import Link from 'next/link';
import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { AlertTriangle, ArrowRight, Check, Download, FlaskConical, RefreshCw, ShieldCheck, Plug, CircleHelp, KeyRound } from 'lucide-react';
import { api, items, obj, str, title, date, type RecordData } from '@/lib/api';
import { Badge, JsonDetails, type WorkspaceContext } from './workspace-parts';
import styles from './change-assurance.module.css';

// The activation path: name the system and connect a source, define what it can do,
// confirm its critical claims, establish a baseline, watch for change, decide.
const steps = ['System & source', 'Authority', 'Claims', 'Baseline', 'Watch', 'Decide'];
type View = 'journey' | 'overview' | 'changes' | 'holds' | 'decisions' | 'sources';
// Projections are plain field maps: they are not addressable records with an id.
type Fields = Record<string, unknown>;
type Journey = {system: RecordData; environments: RecordData[]; properties: RecordData[]; assessments: RecordData[]; next_action: string};
const list = (value: unknown) => Array.isArray(value) ? value.map(String) : [];

// Internal semantics are preserved exactly. Only their presentation is translated.
const APPLICABILITY: Record<string, string> = {
  CURRENT: 'The evidence still describes the system running now.',
  STALE: 'The evidence was created for an earlier system state.',
  INVALID: 'A change since this evidence was produced means it no longer applies.',
  UNKNOWN: 'ThreatVeil does not have enough evidence to support this conclusion.',
};
const CLEARANCE: Record<string, {label: string; tone: string; meaning: string}> = {
  CURRENT: {label: 'Cleared', tone: 'ok', meaning: 'This clearance applies to the system as it is right now.'},
  EXPIRED: {label: 'Expired', tone: 'attention', meaning: 'This clearance has passed its lifetime. Nothing was withdrawn; it simply no longer speaks for now.'},
  SUPERSEDED: {label: 'Superseded', tone: 'attention', meaning: 'The system changed after this clearance was issued, so it describes an earlier state.'},
  REASSESS: {label: 'Needs reassessment', tone: 'attention', meaning: 'The evidence behind this clearance has moved. It must be re-established before it speaks again.'},
  REVOKED: {label: 'Revoked', tone: 'stop', meaning: 'Someone withdrew this clearance explicitly.'},
};
const OBLIGATION: Record<string, string> = {
  RE_ESTABLISH: 'Re-establish',
  RE_VERIFY: 'Re-verify',
  CONFIRM: 'Confirm',
  RECONNECT_SOURCE: 'Reconnect source',
  REVIEW: 'Review',
  NONE: 'No action',
};

function headline(decision: Fields, current: Fields) {
  const status = str(decision.current_status);
  if (!decision.id) return 'No clearance has been issued for this boundary yet.';
  if (decision.action === 'BLOCK') return 'This authority cannot be supported.';
  if (status !== 'CURRENT') return 'The earlier clearance no longer speaks for this system.';
  if (decision.action === 'ALLOW' && current.all_supported) return 'Every claim is still supported.';
  return 'Fresh evidence is required before this authority continues.';
}

function tone(decision: Fields) {
  if (decision.action === 'BLOCK') return 'stop';
  if (!decision.id) return 'attention';
  return str(decision.current_status) === 'CURRENT' && decision.action === 'ALLOW' ? 'ok' : 'attention';
}

/** The most important object in the product: a clearance and whether it still holds. */
function AssuranceStatus({scope, journey}: {scope: RecordData | undefined; journey: Journey | null}) {
  const current = obj(scope?.current);
  const decision = obj(scope?.decision);
  const status = str(decision.current_status);
  const clearance = CLEARANCE[status];
  const properties = items(current.properties);
  const holding = properties.filter(p => p.supported);
  const failing = properties.filter(p => !p.supported);
  return <section className={styles.statusCard} data-tone={tone(decision)}>
    <div className={styles.statusHead}>
      <div>
        <div className="eyebrow">CURRENT ASSURANCE</div>
        <h2>{headline(decision, current)}</h2>
        <p className={styles.statusWhy}>{str(journey?.next_action, 'Establish a baseline to see an exact decision.')}</p>
      </div>
      {!!decision.id && <div className={styles.clearance}>
        <Badge value={decision.action}/>
        <strong>{clearance ? clearance.label : 'Unknown'}</strong>
        <small>{clearance ? clearance.meaning : 'The status of this clearance could not be determined.'}</small>
        <small>Issued {date(decision.created_at)} · expires {date(decision.expires_at)}</small>
      </div>}
    </div>
    {!!properties.length && <div className={styles.split}>
      <div>
        <h3>Still supported</h3>
        {holding.length ? <ul>{holding.map(p => <li key={str(p.property_id)}><Check size={15}/><span>{str(p.title)}</span></li>)}</ul> : <p>No claim is currently supported by applicable evidence.</p>}
      </div>
      <div>
        <h3>Needs fresh evidence</h3>
        {failing.length ? <ul>{failing.map(p => <li key={str(p.property_id)}><AlertTriangle size={15}/><span><strong>{str(p.title)}</strong> — {APPLICABILITY[str(p.applicability)] || str(p.applicability)}</span></li>)}</ul> : <p>Nothing is outstanding for this boundary.</p>}
      </div>
    </div>}
  </section>;
}

function Obligations({current}: {current: Fields}) {
  const obligations = items(current.assurance_obligations);
  if (!obligations.length) return null;
  return <section className="card"><div className="eyebrow">WHAT MUST HAPPEN NEXT</div><h2>Your current assurance obligations.</h2>
    <p>Each item restates the assessment above. ThreatVeil never changes your system and never proposes a fix to it.</p>
    <div className={styles.obligations}>{obligations.map((o, index) => <article key={`${str(o.kind)}-${str(o.subject)}-${index}`}>
      <Badge value={OBLIGATION[str(o.kind)] || str(o.kind)} subtle/>
      <div>
        <h3>{str(o.subject)}</h3>
        <p>{str(o.reason)}</p>
        {!!list(o.detail).length && <details><summary>Why ThreatVeil concluded this</summary><ul>{list(o.detail).map(d => <li key={d}>{d}</li>)}</ul></details>}
      </div>
    </article>)}</div>
  </section>;
}

export function ChangeAssurance({ctx, systemId, view = 'journey'}: {ctx: WorkspaceContext; systemId?: string; view?: View}) {
  const systems = items(ctx.dashboard?.systems);
  const [selected, setSelected] = useState(systemId || systems[0]?.id || '');
  const [phase, setPhase] = useState(0);
  const [journey, setJourney] = useState<Journey | null>(null);
  const [environmentId, setEnvironmentId] = useState('');
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');
  const [confirmed, setConfirmed] = useState(false);
  const [manual, setManual] = useState(false);
  const reload = useCallback(async () => {
    if (!selected) { setJourney(null); return; }
    const value = await api<Journey>(`/change-assurance/systems/${selected}`);
    setJourney(value);
  }, [selected]);
  useEffect(() => { reload().catch(e => setError(e.message)); }, [reload]);
  useEffect(() => { if (!selected && systems[0]?.id) setSelected(systems[0].id); }, [systems, selected]);
  const scope = journey?.environments.find(v => obj(v.environment).id === environmentId) || journey?.environments[0];
  const env = obj(scope?.environment);
  const authority = obj(scope?.envelope);
  const current = obj(scope?.current);
  const decision = obj(scope?.decision);
  const synthetic = journey?.system.fixture_profile === 'finance-v1';
  async function perform(label: string, operation: () => Promise<void>) {
    setBusy(label); setError('');
    try { await operation(); await reload(); await ctx.refresh(); }
    catch (e) { setError(e instanceof Error ? e.message : 'Unable to complete this step.'); }
    finally { setBusy(''); }
  }
  async function setup() {
    await perform('Preparing the finance boundary', async () => {
      const value = await ctx.mutate('/change-assurance/finance/setup', {owner: str(ctx.identity?.user.name, 'Workspace owner'), confirm_synthetic_scope: true});
      setSelected(str(value.system_id)); setPhase(2);
      ctx.notify('Three finance properties and their legitimate invoice task are ready for the bounded baseline.');
    });
  }
  /** Verification runs in the isolated worker, so the result is awaited, not assumed. */
  async function assess(version: string) {
    await perform('Verifying against the synthetic finance boundary', async () => {
      const body = {system_id: selected, version, idempotency_key: crypto.randomUUID()};
      let response = await ctx.mutate('/change-assurance/finance/assess', body);
      for (let attempt = 0; attempt < 40 && str(response.status) === 'RUNNING'; attempt++) {
        await new Promise(resolve => setTimeout(resolve, 750));
        response = await ctx.mutate('/change-assurance/finance/assess', body);
      }
      if (str(response.status) === 'RUNNING') throw new Error('Verification is still running. Reopen this system in a moment to read the decision.');
      setPhase(5);
    });
  }
  async function register(e: FormEvent<HTMLFormElement>) {
    e.preventDefault(); const data = new FormData(e.currentTarget);
    await perform('Registering your system', async () => {
      const system = await ctx.mutate('/systems', {name: data.get('name'), description: data.get('purpose'), actions: [], access: []});
      setSelected(system.id); setManual(false); setPhase(1);
    });
  }
  async function define(e: FormEvent<HTMLFormElement>) {
    e.preventDefault(); const data = new FormData(e.currentTarget);
    await perform('Saving the reviewed business boundary', async () => {
      let eid = str(env.id, '');
      if (!eid) {
        const created = await ctx.mutate('/change-assurance/environments', {system_id: selected,
          name: data.get('environment'), purpose: data.get('environment_type'), boundary: data.get('boundary'), owner: data.get('owner')});
        eid = created.id;
      }
      await ctx.mutate('/change-assurance/envelopes', {system_id: selected, environment_id: eid,
        principals: String(data.get('principals')).split('\n').filter(Boolean),
        actions: String(data.get('actions')).split('\n').filter(Boolean),
        resources: String(data.get('resources')).split('\n').filter(Boolean),
        constraints: String(data.get('constraints')).split('\n').filter(Boolean),
        expires_at: new Date(Date.now() + 30 * 86400000).toISOString(),
        ...(authority.id ? {supersedes_id: authority.id} : {})});
      setPhase(2);
    });
  }
  async function activate() {
    await perform('Requesting sandbox activation', async () => {
      await ctx.mutate('/change-assurance/enforcement', {authorization_id: decision.id,
        environment_id: decision.environment_id, state_digest: decision.state_digest,
        audience: decision.audience, expected_prior_epoch: decision.expected_prior_epoch,
        request_nonce: decision.request_nonce, mechanism: 'synthetic_compare_and_set'});
    });
  }
  function download() {
    const url = URL.createObjectURL(new Blob([JSON.stringify(decision.envelope, null, 2)], {type: 'application/json'}));
    const anchor = document.createElement('a'); anchor.href = url; anchor.download = `threatveil-${decision.id}.dsse.json`; anchor.click(); URL.revokeObjectURL(url);
  }

  const picker = <div className={styles.controls}>
    <label>Protected system<select value={selected} onChange={e => {setSelected(e.target.value); setEnvironmentId('');}}><option value="">Choose a system</option>{systems.map(s => <option key={s.id} value={s.id}>{title(s)}</option>)}</select></label>
    {journey && journey.environments.length > 1 && <label>Environment<select value={str(env.id, '')} onChange={e => setEnvironmentId(e.target.value)}>{journey.environments.map(s => <option key={str(obj(s.environment).id)} value={str(obj(s.environment).id)}>{str(obj(s.environment).name)}</option>)}</select></label>}
    <button className="button outline small" disabled={!!busy} onClick={() => reload().catch(e => setError(e.message))}><RefreshCw size={14}/>Refresh assurance</button>
  </div>;
  const banner = <>{error && <div className="notice error" role="alert">{error}</div>}{busy && <p role="status" className={styles.activity}>{busy}…</p>}</>;
  const scopeLine = selected ? <div className={styles.scope}><div><strong>{str(journey?.system.name, 'Loading system')}</strong><span>{str(env.name, 'Environment not defined')}</span></div><Badge value={scope?.stage || 'DECLARED'}/>{synthetic && <span className="tag">Synthetic finance boundary</span>}</div> : null;

  if (view !== 'journey') {
    return <div className={styles.root}>
      {picker}{banner}{scopeLine}
      {!systems.length && <NoSystems onPrepare={setup} confirmed={confirmed} setConfirmed={setConfirmed} busy={!!busy}/>}
      {view === 'overview' && !!systems.length && <>
        <AssuranceStatus scope={scope} journey={journey}/>
        <Obligations current={current}/>
        <SystemList systems={systems} selected={selected} onSelect={setSelected}/>
        {synthetic && <SandboxControls assess={assess} busy={!!busy}/>}
      </>}
      {view === 'changes' && <ChangeTimeline scope={scope} synthetic={synthetic} assess={assess} busy={!!busy}/>}
      {view === 'holds' && <><AssuranceStatus scope={scope} journey={journey}/><ClaimDetail current={current}/><Obligations current={current}/></>}
      {view === 'decisions' && <DecisionDetail scope={scope} journey={journey} download={download} activate={activate} synthetic={synthetic} busy={!!busy}/>}
      {view === 'sources' && !!env.id && <SourceConnections ctx={ctx} systemId={selected} environmentId={str(env.id)} sources={items(scope?.sources)} after={reload}/>}
      {view === 'sources' && !env.id && <section className="card"><h2>No environment is defined yet.</h2><p>Define the operating boundary before connecting a source to it.</p><Link href="/app/systems" className="button dark small">Open your systems <ArrowRight size={15}/></Link></section>}
    </div>;
  }

  return <div className={styles.root}>
    <div className={styles.banner}><ShieldCheck size={30}/><div><div className="eyebrow">AUTONOMOUS CHANGE ASSURANCE</div><h2>Keep the evidence behind your system’s authority.</h2><p>Connect a bounded system, establish its security claims, and see what must change before its permissions can continue.</p></div></div>
    {picker}
    <nav className={styles.steps} aria-label="Protection journey">{steps.map((step, i) => <button key={step} onClick={() => setPhase(i)} aria-current={phase === i ? 'step' : undefined} disabled={!selected && i > 0}><span>{i + 1}</span>{step}</button>)}</nav>
    {banner}
    {scopeLine}
    {phase === 0 && <>
      <div className={styles.two}><section className="card"><div className="eyebrow">YOUR SYSTEM</div><h2>Start with a consequential workflow.</h2><p>A system can span repositories, models, tools, identities and deployments. Give the business workflow a name, then define the environment it operates in.</p><button className="button dark" onClick={() => setManual(!manual)}>Register your system <ArrowRight size={16}/></button>{selected && <button className="text-button" onClick={() => setPhase(1)}>Continue with this system <ArrowRight size={16}/></button>}{manual && <form className={styles.form} onSubmit={register}><label>System name<input name="name" required maxLength={120} placeholder="Accounts payable agent"/></label><label>Business purpose<textarea name="purpose" required maxLength={4000} placeholder="Which useful work does it perform?"/></label><button className="button dark small" disabled={!!busy}>Register system</button></form>}</section>
      <SandboxCard confirmed={confirmed} setConfirmed={setConfirmed} setup={setup} busy={!!busy}/></div>
      {!!env.id && <SourceConnections ctx={ctx} systemId={selected} environmentId={str(env.id)} sources={items(scope?.sources)} after={reload}/>}
    </>}
    {phase === 1 && <section className="card"><div className="eyebrow">DEFINE CONSEQUENTIAL AUTHORITY</div><h2>What can this system change?</h2><p>Record the principals, actions and business resources that the security claims must cover. This describes existing authority; it grants no permissions.</p>{authority.id ? <><div className={styles.three}>{[['Principals', authority.principals], ['Actions', authority.actions], ['Business resources', authority.resources]].map(([label, values]) => <div key={String(label)}><h3>{String(label)}</h3>{list(values).map(v => <p key={v}>{v}</p>)}</div>)}</div><h3>Constraints</h3><ul>{list(authority.constraints).map(v => <li key={v}>{v}</li>)}</ul><p>Reviewed until {date(authority.expires_at)}. Owner: {str(env.owner)}</p><button className="button dark small" onClick={() => setPhase(2)}>Review protection <ArrowRight size={15}/></button><JsonDetails data={authority} label="Inspect the versioned authority boundary"/></> : <form className={styles.form} onSubmit={define}><div className={styles.two}><label>Environment name<input name="environment" required placeholder="Staging" defaultValue={str(env.name, '')}/></label><label>Operating environment<select name="environment_type" defaultValue="STAGING"><option value="STAGING">Staging</option><option value="SANDBOX">Sandbox</option><option value="PRODUCTION">Production — observation acceptance required</option></select></label></div><label>Accountable owner<input name="owner" required defaultValue={str(ctx.identity?.user.name, '')}/></label><label>Operating boundary<textarea name="boundary" minLength={10} required placeholder="Where does it operate, and which resources are in scope?"/></label><div className={styles.two}><label>Principals, one per line<textarea name="principals" required placeholder="finance-agent service identity"/></label><label>Consequential actions, one per line<textarea name="actions" required placeholder="beneficiary.update"/></label><label>Business resources, one per line<textarea name="resources" required placeholder="Staging tenant A supplier records"/></label><label>Constraints, one per line<textarea name="constraints" required placeholder="Human approval is required for beneficiary changes"/></label></div><button className="button dark" disabled={!!busy}>Confirm this boundary <ArrowRight size={16}/></button></form>}</section>}
    {phase === 2 && <section className="card"><div className="eyebrow">PROTECT USEFUL WORK</div><h2>Agree the claims and their observation.</h2><p>Each claim needs a prohibited case, a legitimate task, a qualified observer and an exact test destination.</p><div className={styles.claims}>{journey?.properties.map((p, i) => <article key={p.id}><span className={styles.number}>{i + 1}</span><div><h3>{title(p)}</h3><p>{str(p.description)}</p><p><strong>Useful task:</strong> {str(obj(p.definition).legitimate_task)}</p><Badge value={p.approved ? 'APPROVED' : 'DRAFT'}/><JsonDetails data={p.definition} label="Inspect the approved claim and observation contract"/></div></article>)}</div>{!journey?.properties.length && <><p>No approved claims yet. Start with a reviewed template and supply the actual positive fixture.</p><button className="button dark small" onClick={() => ctx.openForm('property', {id: selected, system_id: selected})}>Add a security property</button></>}<div className={styles.callout}><strong>{synthetic ? 'Observer: committed synthetic SQL state' : 'Observation must be qualified before positive assurance'}</strong><p>{synthetic ? 'Every trial resets its rows, attempts forbidden actions, commits a legitimate invoice update, and reads state back after the transaction. The fixture controller and observer share a process; it is not independent customer evidence.' : 'Register and qualify your target-side observer, including the ground-truth source and legitimate positive control. A tool response alone cannot establish a committed business effect.'}</p></div><div className={styles.actions}><button className="button dark small" onClick={() => setPhase(3)}>Establish baseline <ArrowRight size={16}/></button>{!synthetic && <Link href="/app/targets" className="text-button">Set up target and observation <ArrowRight size={15}/></Link>}</div></section>}
    {phase === 3 && <section className="card"><div className="eyebrow">BASELINE</div><h2>Establish security and useful-task evidence.</h2><p>A baseline is a bounded execution, with the environment and authority conditions retained beside the evidence. Missing ground truth remains inconclusive.</p>{synthetic ? <><button className="button dark" onClick={() => assess('fixed')} disabled={!!busy}>Run finance baseline <ArrowRight size={16}/></button><p>Three properties × two trials, with an approved verification allowance. Verification runs in the isolated worker; no external side effects.</p></> : <><Link href="/app/runs" className="button dark small">Execute approved checks <ArrowRight size={16}/></Link><p>Use your authorized destination and qualified observer.</p></>}<Link href="/app/billing" className="text-button">View verification allowance <ArrowRight size={14}/></Link></section>}
    {phase === 4 && <>
      <ChangeTimeline scope={scope} synthetic={synthetic} assess={assess} busy={!!busy}/>
      {!!env.id && <SourceConnections ctx={ctx} systemId={selected} environmentId={str(env.id)} sources={items(scope?.sources)} after={reload}/>}
    </>}
    {phase === 5 && <><AssuranceStatus scope={scope} journey={journey}/><DecisionDetail scope={scope} journey={journey} download={download} activate={activate} synthetic={synthetic} busy={!!busy}/><Obligations current={current}/></>}
  </div>;
}

function NoSystems({onPrepare, confirmed, setConfirmed, busy}: {onPrepare: () => void; confirmed: boolean; setConfirmed: (v: boolean) => void; busy: boolean}) {
  return <div className={styles.two}>
    <section className="card"><div className="eyebrow">YOUR SYSTEM</div><h2>Nothing is protected yet.</h2><p>Register the consequential workflow you want to keep evidence for, then define the environment it operates in.</p><Link href="/app/systems/new" className="button dark">Connect a system <ArrowRight size={16}/></Link></section>
    <SandboxCard confirmed={confirmed} setConfirmed={setConfirmed} setup={onPrepare} busy={busy}/>
  </div>;
}

function SandboxCard({confirmed, setConfirmed, setup, busy}: {confirmed: boolean; setConfirmed: (v: boolean) => void; setup: () => void; busy: boolean}) {
  return <section className={`card ${styles.demo}`}><FlaskConical size={25}/><div className="eyebrow">EXPERIENCE IT ON FREE</div><h2>Follow the Finance Agent.</h2><p>Three claims. Real commits to isolated synthetic rows. A forbidden beneficiary change, tenant boundaries, and a useful invoice task.</p><label className={styles.check}><input type="checkbox" checked={confirmed} onChange={e => setConfirmed(e.target.checked)}/>I approve these synthetic checks and the legitimate invoice fixture.</label><button className="button outline" disabled={!confirmed || busy} onClick={setup}>Prepare finance example <ArrowRight size={16}/></button><small>A demonstration boundary, clearly labelled as such. No customer systems, real payments or live providers are involved.</small></section>;
}

function SandboxControls({assess, busy}: {assess: (v: string) => void; busy: boolean}) {
  return <section className="card"><div className="eyebrow">DEMONSTRATION BOUNDARY</div><h2>Change something and watch the evidence move.</h2><p>These controls operate the labelled synthetic sandbox only. They can never reach a customer system.</p><div className={styles.actions}>
    <button className="button outline small" disabled={busy} onClick={() => assess('regressed')}>Relax approval policy</button>
    <button className="button outline small" disabled={busy} onClick={() => assess('bad_fix')}>Try a fix that disables updates</button>
    <button className="button dark small" disabled={busy} onClick={() => assess('fixed')}>Restore approved useful behavior</button>
  </div></section>;
}

function SystemList({systems, selected, onSelect}: {systems: RecordData[]; selected: string; onSelect: (id: string) => void}) {
  return <section className="card"><div className="eyebrow">PROTECTED SYSTEMS</div><h2>What are you protecting?</h2><div className={styles.systemGrid}>{systems.map(s => <button key={s.id} className={styles.systemRow} onClick={() => onSelect(s.id)} aria-current={s.id === selected ? 'true' : undefined}>
    <div><strong>{title(s)}</strong><span>{str(s.description, 'No description added.')}</span></div>
    {s.id === selected ? <Badge value="VIEWING" subtle/> : <span>Select</span>}
  </button>)}</div></section>;
}

function ClaimDetail({current}: {current: Fields}) {
  const properties = items(current.properties);
  if (!properties.length) return <section className="card"><h2>No claim has been assessed yet.</h2><p>Establish a baseline so each claim has evidence to reason about.</p></section>;
  return <section className="card"><div className="eyebrow">CLAIM BY CLAIM</div><h2>Which conclusions still apply?</h2><div className={styles.claims}>{properties.map(p => <article key={str(p.property_id)}><div>
    <h3>{str(p.title)}</h3>
    <div className={styles.actions}><Badge value={p.supported ? 'SUPPORTED' : 'NOT SUPPORTED'}/><Badge value={p.security} subtle/><span>Useful task: {str(p.legitimate_task)}</span></div>
    <p>{APPLICABILITY[str(p.applicability)] || str(p.applicability)}</p>
    <details><summary>Why this evidence applies, and its historical comparisons</summary><ul>{list(p.reasons).map(r => <li key={r}>{r}</li>)}</ul><JsonDetails data={p.historical_comparisons}/></details>
  </div></article>)}</div></section>;
}

function ChangeTimeline({scope, synthetic, assess, busy}: {scope: RecordData | undefined; synthetic: boolean; assess: (v: string) => void; busy: boolean}) {
  const transitions = items(scope?.transitions);
  return <>
    <section className="card"><div className="eyebrow">WATCH CHANGE, NOT JUST COMMITS</div><h2>What changed in the operating boundary?</h2><p>Observed changes have already happened. A proposed change can be assessed before activation through a supported control.</p>
      <div className={styles.timeline}>{transitions.map(t => <article key={t.id}><div><Badge value={t.transition}/><time>{date(t.created_at)}</time></div><h3>{str(t.change_type).replaceAll('_', ' ').toLowerCase()}</h3><p>{str(t.reason)}</p>{items(t.impacts).map(p => <div key={str(p.property_id)} className={styles.impact}><strong>{str(p.title)}</strong><span>{list(p.changed_dependencies).length ? `Changed: ${list(p.changed_dependencies).join(', ')}` : 'No changed declared dependency; fresh anchoring still required'}</span></div>)}</article>)}</div>
      {!transitions.length && <p>No state transitions have been recorded for this environment yet.</p>}
    </section>
    {synthetic && <SandboxControls assess={assess} busy={busy}/>}
  </>;
}

function DecisionDetail({scope, journey, download, activate, synthetic, busy}: {scope: RecordData | undefined; journey: Journey | null; download: () => void; activate: () => void; synthetic: boolean; busy: boolean}) {
  const current = obj(scope?.current);
  const decision = obj(scope?.decision);
  const status = str(decision.current_status);
  if (!decision.id) return <section className="card"><div className="eyebrow">DECIDE WITH EVIDENCE</div><h2>No clearance has been issued yet.</h2><p>{str(journey?.next_action, 'Establish a baseline to see an exact decision.')}</p><Link href="/app/systems" className="button dark small">Open your systems <ArrowRight size={15}/></Link></section>;
  return <section className="card"><div className={styles.decisionHead}><div><div className="eyebrow">DECIDE WITH EVIDENCE</div><h2>The exact decision and its scope.</h2></div><div><Badge value={decision.action}/><p>{CLEARANCE[status]?.label || status}</p></div></div>
    <div className={styles.dimensions}>{[['Security assessment', current.security || 'INCONCLUSIVE'], ['Useful business task', current.legitimate_task || 'UNKNOWN'], ['Enforcement', scope?.enforcement || 'NOT_REQUESTED'], ['Exception', current.exception || 'NONE']].map(([label, value]) => <div key={String(label)}><span>{String(label)}</span><Badge value={value}/></div>)}</div>
    <div className={styles.callout}><strong>A clearance is a statement, not a permanent verdict.</strong><p>{CLEARANCE[status]?.meaning || 'The status of this clearance could not be determined.'} The historical record is never rewritten; only its current status is recomputed.</p></div>
    <div className={styles.actions}>
      <button className="button outline small" onClick={download}><Download size={15}/>Export signed scoped record</button>
      {synthetic && decision.action === 'ALLOW' && status === 'CURRENT' && !!current.all_supported && <button className="button dark small" disabled={busy || scope?.enforcement === 'ACKNOWLEDGED'} onClick={activate}>{scope?.enforcement === 'ACKNOWLEDGED' ? <><Check size={16}/>Sandbox activation acknowledged</> : <>Request sandbox activation <ArrowRight size={15}/></>}</button>}
      <Link href="/app/records" className="text-button">Verify a record <ArrowRight size={15}/></Link>
    </div>
    <div className={styles.callout}><strong>Decision and enforcement are separate.</strong><p>{scope?.enforcement === 'ACKNOWLEDGED' ? 'The local sandbox registry acknowledged this exact state. This does not establish a deployed GitHub or cloud control.' : 'Issuing an ALLOW does not establish that an external control activated the intended state.'} Verify exports with an independently trusted key. Offline verification establishes a historical statement; current status requires a fresh check.</p></div>
    <JsonDetails data={decision} label="Inspect exact state, authority, policy, signature and limitations"/>
  </section>;
}

/** Published verification material, so a third party can check a record alone. */
export function TrustRoot() {
  const [directory, setDirectory] = useState<Fields | null>(null);
  const [error, setError] = useState('');
  useEffect(() => { api<Fields>('/trust/keys').then(setDirectory).catch(e => setError(e.message)); }, []);
  const keys = items(directory?.keys);
  return <section className="card"><div className={styles.sourceHead}><div><div className="eyebrow"><KeyRound size={13}/> PUBLISHED TRUST ROOT</div><h2>Anyone can verify these records.</h2></div></div>
    <p>Verification needs the key that signed a record, not an account here. Retiring a key never invalidates what it already signed; revoking one invalidates all of it.</p>
    {error && <p className="notice error" role="alert">{error}</p>}
    <div className={styles.trust}>{keys.map(k => <div key={str(k.keyid)}><Badge value={k.status} subtle/> <code>{str(k.keyid).slice(0, 24)}…</code> <small>{str(k.algorithm)} · valid from {date(k.valid_from)}{k.valid_until ? ` until ${date(k.valid_until)}` : ''}</small></div>)}</div>
    {directory?.trust !== 'OPERATOR_PROVISIONED' && <p className="notice"><CircleHelp size={14}/> This directory was derived from the running signing key rather than an operator-managed rotation history.</p>}
    <JsonDetails data={directory ?? {}} label="Inspect the published key directory"/>
  </section>;
}

function SourceConnections({ctx, systemId, environmentId, sources, after}: {ctx: WorkspaceContext; systemId: string; environmentId: string; sources: RecordData[]; after: () => Promise<void>}) {
  const [open, setOpen] = useState(false); const [kind, setKind] = useState('github');
  const [error, setError] = useState(''); const [busy, setBusy] = useState(false);
  async function connect(e: FormEvent<HTMLFormElement>) {
    e.preventDefault(); const data = new FormData(e.currentTarget); setBusy(true); setError('');
    try {
      const config = kind === 'github' ? {repository: data.get('repository'), repository_id: data.get('repository_id'), ref: data.get('ref')} : kind === 'gcp_cloud_run' ? {service: data.get('service')} : kind === 'mcp' ? {target_id: data.get('target_id'), path: data.get('path')} : {};
      const value = await ctx.mutate('/connectors', {system_id: systemId, environment_id: environmentId,
        connector_id: kind, mode: kind === 'otel' ? 'PUSH' : 'POLL', name: data.get('name'),
        roles: kind === 'otel' ? ['OBSERVE'] : kind === 'gcp_cloud_run' ? ['DISCOVER', 'CHANGE', 'OBSERVE'] : ['DISCOVER', 'CHANGE'],
        configuration: config, credential_id: data.get('credential_id') || null,
        expires_at: new Date(Date.now() + 7 * 86400000).toISOString()});
      if (kind !== 'otel') await ctx.mutate(`/connectors/${value.id}/collect`, {event_id: crypto.randomUUID()});
      setOpen(false); await after();
    } catch(e) { setError(e instanceof Error ? e.message : 'Connection could not be established.'); }
    finally { setBusy(false); }
  }
  return <section className="card"><div className={styles.sourceHead}><div><div className="eyebrow">SOURCES & COVERAGE</div><h2>Know what is connected.</h2></div><button className="button outline small" onClick={() => setOpen(!open)}><Plug size={15}/>Connect a source</button></div><p>GitHub is a change source. MCP describes tools. OpenTelemetry supplies observations. Cloud Run supplies configuration facts. Each has its own coverage and freshness.</p>{sources.map(s => <article className={styles.source} key={str(s.installation_id)}><div><strong>{str(s.name)}</strong><small>{str(s.connector_id)} · last observation {date(s.last_valid_at)}</small></div><Badge value={s.status}/><span>Freshness: {str(s.freshness)}</span><span>{s.connected ? 'Connected' : 'No live connection established'}</span><details><summary>Coverage and limitations</summary><ul>{list(s.limitations).map(v => <li key={v}>{v}</li>)}</ul></details></article>)}{!sources.length && <p>No live sources are connected. Declared setup and synthetic observations remain distinct.</p>}{error && <p role="alert" className="notice error">{error}</p>}{open && <form onSubmit={connect} className={styles.form}><div className={styles.two}><label>Source<select value={kind} onChange={e => setKind(e.target.value)}><option value="github">GitHub repository</option><option value="mcp">Bounded MCP tools</option><option value="otel">OpenTelemetry intake</option><option value="gcp_cloud_run">GCP Cloud Run service</option></select></label><label>Connection name<input name="name" required maxLength={120}/></label></div>{kind === 'github' && <><label>Repository<input name="repository" required placeholder="organization/repository"/></label><label>Numeric repository ID<input name="repository_id" required/></label><label>Branch reference<input name="ref" required defaultValue="refs/heads/main"/></label></>}{kind === 'gcp_cloud_run' && <label>Cloud Run resource<input name="service" required placeholder="projects/project/locations/region/services/service"/></label>}{kind === 'mcp' && <><label>Verified MCP target<select name="target_id" required>{ctx.targets.filter(t => t.system_id === systemId && t.adapter === 'mcp').map(t => <option key={t.id} value={t.id}>{title(t)}</option>)}</select></label><label>Authorized MCP path<input name="path" required defaultValue="/mcp"/></label></>}{['github','gcp_cloud_run'].includes(kind) && <label>Read credential reference ID<input name="credential_id" required placeholder="Reference registered in workspace settings"/></label>}<p>Use a narrowly scoped credential reference. A connection does not qualify business effects or identify every running component.</p><button className="button dark small" disabled={busy}>{busy ? 'Connecting…' : 'Connect and check source'}</button><Link href="/app/settings" className="text-button">Manage credential references <ArrowRight size={14}/></Link></form>}</section>;
}
