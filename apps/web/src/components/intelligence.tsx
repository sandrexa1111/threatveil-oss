'use client';

import Link from 'next/link';
import { useCallback, useEffect, useMemo, useState, type FormEvent } from 'react';
import { AlertTriangle, ArrowRight, Check, CircleHelp, Copy, Download, FlaskConical, KeyRound, RefreshCw, ShieldCheck } from 'lucide-react';
import { api, obj, str, date, type RecordData } from '@/lib/api';
import { verifyEnvelope, type VerificationResult } from '@/lib/verify';
import { Badge, JsonDetails, type WorkspaceContext } from './workspace-parts';
import { usePathname, useRouter, useSearchParams } from 'next/navigation';
import { CLAIM_STATE as CLAIM_VIEW, Drawer, Facts, StatusPill } from './product';
import { ChangeImpact, impactOfChange } from './signature';
import styles from './intelligence.module.css';
import completion from './completion.module.css';

type Fields = Record<string, unknown>;
export type IntelligenceView = 'overview' | 'map' | 'authority' | 'changes' | 'holds' | 'reestablish' | 'decisions'
  | 'passport' | 'claims' | 'mappings' | 'propose';
export const arr = (value: unknown): Fields[] => Array.isArray(value) ? value.filter(v => v && typeof v === 'object') as Fields[] : [];
export const list = (value: unknown): string[] => Array.isArray(value) ? value.map(String) : [];
export const num = (value: unknown) => typeof value === 'number' ? value : Number(value) || 0;
export const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? '' : 's'}`;

// Internal values are preserved exactly; only their presentation is translated.
export const TONE: Record<string, string> = {CLEARED: 'ok', NOT_CLEARED: 'stop', REVOKED: 'stop', NEEDS_REASSESSMENT: 'attention', NOT_ESTABLISHED: 'attention'};
export const STATUS_TEXT: Record<string, string> = {
  CURRENT: 'Still current', EXPIRED: 'Expired', SUPERSEDED: 'Superseded by a later change',
  REASSESS: 'Needs reassessment', REVOKED: 'Revoked', UNKNOWN: 'Unknown',
};
export const CLASSIFICATION: Record<string, {label: string; tone: string}> = {
  AUTHORITY_EXPANDED: {label: 'Authority expanded', tone: 'stop'},
  AUTHORITY_CONTRACTED: {label: 'Authority contracted', tone: 'ok'},
  AUTHORITY_EQUIVALENT: {label: 'Authority unchanged', tone: 'neutral'},
  UNKNOWN_IMPACT: {label: 'Unknown impact', tone: 'attention'},
};
export const EFFECT: Record<string, string> = {
  OPEN: 'Needs re-proof', COVERED_BY_LATER_VERIFICATION: 'Covered by later verification', NO_CLAIM_AFFECTED: 'No claim affected',
  NO_BASELINE: 'Before any baseline', CURRENT_STATE: 'Current state', SUPERSEDED_BY_LATER_STATE: 'Earlier state',
};
export const BASIS: Record<string, string> = {
  DECLARED: 'Declared', CONNECTED: 'Connected', OBSERVED: 'Observed', VERIFIED: 'Verified', UNKNOWN: 'Unknown',
  GOVERNING_CLAIM_DEPENDENCY: 'Claim dependency', SOURCE_NAME_MATCH: 'Reported by a source · unreviewed',
};
/** Claim status in customer language; the canonical value stays in each row's title. */
export const CLAIM_STATE: Record<string, string> = {
  SUPPORTED: 'CURRENT', NEEDS_FRESH_EVIDENCE: 'NEEDS FRESH EVIDENCE', FAILED: 'FAILED',
  UNKNOWN: 'NOT YET SUPPORTED', DEFINED: 'DEFINED',
};
export const ASSURANCE: Record<string, string> = {
  SUPPORTED: 'SUPPORTED', NEEDS_FRESH_EVIDENCE: 'NEEDS FRESH EVIDENCE', FAILED: 'FAILED', UNGOVERNED: 'NO CLAIM COVERS IT', UNKNOWN: 'UNKNOWN',
};
export const GATE_MEANING: [string, string][] = [
  ['CURRENT', 'The latest clearance still speaks for this exact state. Cleared only when the decision is ALLOW.'],
  ['SUPERSEDED', 'The system was observed to change after the clearance was issued.'],
  ['REASSESS', 'Support moved without an observed change: evidence, source continuity or release eligibility.'],
  ['EXPIRED', 'The reviewed authority or exact-state observation behind the clearance lapsed.'],
  ['REVOKED', 'Someone withdrew the clearance explicitly.'],
  ['UNKNOWN', 'ThreatVeil cannot establish clearance. Never treat UNKNOWN as authorization.'],
];

/**
 * One consistent snapshot per protected system, plus the sandbox controls the
 * canonical demonstration needs. Views below render from this snapshot; the
 * system workspace owns the header, the tabs and the contextual next action.
 */
export function useSystemIntelligence(systemId: string, environmentId = '') {
  const [data, setData] = useState<Fields | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState('');
  const load = useCallback(async () => {
    if (!systemId) { setData(null); return; }
    setData(await api<Fields>(`/systems/${systemId}/intelligence${environmentId ? `?environment_id=${environmentId}` : ''}`));
  }, [systemId, environmentId]);
  useEffect(() => {
    let live = true;
    load().then(() => { if (live) setError(''); })
      .catch(e => { if (live) setError(e instanceof Error ? e.message : 'Unable to load this system.'); });
    // The guided tour drives the same fixture from outside this view; it asks for a re-read.
    const reread = () => { load().catch(() => undefined); };
    window.addEventListener(SYSTEM_CHANGED, reread);
    return () => { live = false; window.removeEventListener(SYSTEM_CHANGED, reread); };
  }, [load]);
  return {data, error, busy, setError, reload: load, setBusy};
}

/** Fired after anything outside a system view changes that system's records. */
export const SYSTEM_CHANGED = 'threatveil:system-changed';

type Mutate = WorkspaceContext['mutate'];

/** Change the labelled synthetic tool gateway. It can reach nothing but the sandbox. */
export async function financeChange(mutate: Mutate, systemId: string, change: string) {
  await mutate('/change-assurance/finance/simulate-change', {system_id: systemId, change, idempotency_key: crypto.randomUUID()});
}

/** Verification runs in the isolated worker, so the result is awaited, never assumed. */
export async function financeAssess(mutate: Mutate, systemId: string, version: string, before?: string) {
  if (before) await financeChange(mutate, systemId, before);
  const body = {system_id: systemId, version, idempotency_key: crypto.randomUUID()};
  let response = await mutate('/change-assurance/finance/assess', body);
  for (let attempt = 0; attempt < 40 && str(response.status) === 'RUNNING'; attempt++) {
    await new Promise(resolve => setTimeout(resolve, 750));
    response = await mutate('/change-assurance/finance/assess', body);
  }
  if (str(response.status) === 'RUNNING') throw new Error('Verification is still running. Refresh in a moment to read the decision.');
  return response;
}

/** The labelled synthetic sandbox: change the gateway, then re-prove against it. */
export function useSandbox(ctx: WorkspaceContext, systemId: string,
                          state: ReturnType<typeof useSystemIntelligence>) {
  const {reload, setBusy, setError} = state;
  async function perform(label: string, operation: () => Promise<void>) {
    setBusy(label); setError('');
    try { await operation(); await reload(); }
    catch (e) { setError(e instanceof Error ? e.message : 'Unable to complete this step.'); }
    finally { setBusy(''); }
  }
  async function simulate(change: string, message: string) {
    await perform('Changing the synthetic tool gateway', async () => {
      await financeChange(ctx.mutate, systemId, change);
      ctx.notify(message);
    });
  }
  async function assess(version: string, before?: string) {
    await perform('Verifying against the synthetic finance boundary', async () => {
      await financeAssess(ctx.mutate, systemId, version, before);
    });
  }
  return {simulate, assess, perform};
}

export function SystemSummary({summary, systemId}: {summary: Fields; systemId: string}) {
  const system = obj(summary.system), environment = obj(summary.environment), clearance = obj(summary.clearance), claims = obj(summary.claims), decision = obj(clearance.decision);
  const fresh = num(claims.needs_fresh_evidence) + num(claims.unknown);
  return <section className={styles.summary} data-tone={TONE[str(clearance.state)] || 'attention'} aria-label="Protected system summary">
    <div className={styles.summaryHead}>
      <div>
        <div className="eyebrow">PROTECTED SYSTEM · {str(environment.name, 'No environment yet')}{environment.purpose ? ` · ${str(environment.purpose).toLowerCase()}` : ''}</div>
        <h2>{str(system.name)}</h2>
        {!!system.synthetic && <span className="tag">Synthetic demonstration system</span>}
      </div>
      <div className={styles.clearanceBlock}>
        <span className={styles.overline}>Current clearance</span>
        <strong className={styles.clearanceLabel}>{str(clearance.label)}</strong>
        <small>{str(clearance.meaning)}</small>
      </div>
    </div>
    <div className={styles.why}><span className={styles.overline}>Why</span><p>{str(summary.why)}</p></div>
    <dl className={styles.facts}>
      <div><dt>Consequential powers</dt><dd>{arr(summary.powers).map(p => <span key={str(p.action)} className={styles.power}>{str(p.label)} <Badge value={ASSURANCE[str(p.assurance)] || p.assurance} subtle/></span>)}{!arr(summary.powers).length && 'No authority boundary defined yet'}</dd></div>
      <div><dt>Supported</dt><dd><strong className={styles.big}>{num(claims.supported)} of {num(claims.total)}</strong> critical claims</dd></div>
      <div><dt>Needs fresh evidence</dt><dd><strong className={styles.big}>{fresh}</strong>{plural(fresh, 'claim').replace(/^\d+ /, '')}{num(claims.failed) ? ` · ${num(claims.failed)} failed` : ''}</dd></div>
      <div><dt>Last current clearance</dt><dd>{date(clearance.last_current_clearance_at)}</dd></div>
      <div><dt>Current decision</dt><dd>{decision.id ? <><Badge value={decision.action}/><span>{STATUS_TEXT[str(decision.status)] || str(decision.status)}</span></> : 'None yet'}</dd></div>
    </dl>
    <div className={styles.links}>
      <Link href={`/app/systems/${systemId}/evidence`} className="text-button">Evidence <ArrowRight size={14}/></Link>
      <Link href={`/app/systems/${systemId}/activity`} className="text-button">Activity <ArrowRight size={14}/></Link>
      <Link href={`/app/systems/${systemId}/restore`} className="text-button">Restore assurance <ArrowRight size={14}/></Link>
      <Link href={`/app/systems/${systemId}/share`} className="text-button">Share <ArrowRight size={14}/></Link>
    </div>
    <p className={styles.next}><strong>Next:</strong> {str(summary.next_action)}</p>
  </section>;
}

export function DemoPanel({summary, systemId, busy, simulate, assess}: {summary: Fields; systemId: string; busy: boolean; simulate: (change: string, message: string) => void; assess: (version: string, before?: string) => void}) {
  const clearance = obj(summary.clearance);
  const established = !!obj(clearance.decision).id;
  return <section className={`card ${styles.demo}`}>
    <div className={styles.demoHead}><FlaskConical size={22}/><div>
      <span className="tag">Labelled synthetic sandbox</span>
      <h2>Change the agent, then see which claim stops holding</h2>
      <p className={styles.lead}>These controls operate only the Finance Agent sandbox: a synthetic MCP tool gateway and isolated SQL rows. They cannot reach a customer system, a provider or money.</p>
    </div></div>
    <ol className={styles.demoSteps}>
      <li><strong>1 · Current</strong><span>{established ? `Current clearance: ${str(clearance.label)}.` : 'Establish the baseline: three claims, each with a forbidden case and a useful task.'}</span>{!established && <button className="button dark small" disabled={busy} onClick={() => assess('fixed')}>Establish baseline</button>}</li>
      <li><strong>2 · Change outside code</strong><span>Change a tool permission in the gateway. No repository, no deploy.</span><div className={styles.row}>
        <button className="button dark small" disabled={busy || !established} onClick={() => simulate('beneficiary_approval_relaxed', 'The gateway no longer requires approval for beneficiary updates.')}>Relax beneficiary approval</button>
        <button className="button outline small" disabled={busy || !established} onClick={() => simulate('payment_tool_added', 'The gateway now exposes an unreviewed payment tool.')}>Expose an unreviewed payment tool</button>
      </div></li>
      <li><strong>3 · Consequence</strong><span>See exactly which claim stopped holding, and which still hold.</span><Link className="text-button" href={`/app/systems/${systemId}/activity`}>Open activity <ArrowRight size={14}/></Link></li>
      <li><strong>4 · Restore</strong><span>A security failure, a fix that breaks useful work, then restored assurance.</span><Link className="text-button" href={`/app/systems/${systemId}/restore`}>Open restore assurance <ArrowRight size={14}/></Link></li>
      <li><strong>5 · Machine</strong><span>The Assurance Gate answer another system consumes.</span><Link className="text-button" href={`/app/systems/${systemId}#machine`}>Open machine use <ArrowRight size={14}/></Link></li>
      <li><strong>6 · External party</strong><span>Issue a Passport, verify it, change again: authentic, no longer current.</span><Link className="text-button" href={`/app/systems/${systemId}/share`}>Open Share <ArrowRight size={14}/></Link></li>
    </ol>
  </section>;
}

export function UpgradeMoments({moments, ctx}: {moments: Fields[]; ctx: WorkspaceContext}) {
  const [recorded, setRecorded] = useState('');
  async function interest(topic: string) {
    try { await ctx.mutate('/commercial/interest', {topic, idempotency_key: crypto.randomUUID()}); setRecorded(topic); }
    catch (e) { ctx.notify(e instanceof Error ? e.message : 'Could not record the request.'); }
  }
  return <section className="card">
    <div className="eyebrow">WHEN YOU NEED MORE</div>
    <h2>Grow when the value is already there.</h2>
    <p className={styles.lead}>A plan changes what ThreatVeil may do for you. It never changes a security conclusion.</p>
    {!!moments.length && <div className={styles.moments}>{moments.map(m => <div key={str(m.id)} className={styles.moment}><div>{str(m.message)}<small>{str(m.plan_name)}{m.monthly_usd !== null && m.monthly_usd !== undefined ? ` · $${str(m.monthly_usd)}/month hypothesis` : ''}</small></div><Link href="/app/billing" className="button outline small">See {str(m.plan_name)} <ArrowRight size={14}/></Link></div>)}</div>}
    <div className={styles.row} style={{marginTop: 16}}>
      {[['private_deployment', 'Request private deployment'], ['enterprise_retention', 'Ask about enterprise retention'], ['design_partner', 'Become a design partner']].map(([topic, label]) =>
        <button key={topic} className="button outline small" onClick={() => interest(topic)} disabled={recorded === topic}>{recorded === topic ? <><Check size={14}/>Recorded</> : label}</button>)}
    </div>
    {recorded && <p className={styles.muted}>Recorded for follow-up. ThreatVeil sends nothing automatically.</p>}
  </section>;
}

// --- System map --------------------------------------------------------------

const COLUMNS: [string, string, string[]][] = [
  ['components', 'Components', ['AGENT', 'MCP_SERVER', 'TOOL', 'MODEL', 'PROMPT', 'API', 'MEMORY', 'DATA_SOURCE', 'DEPLOYMENT', 'CODE', 'SUBAGENT', 'CONFIGURATION', 'UNKNOWN']],
  ['authority', 'Authority', ['AUTHORITY_BOUNDARY', 'IDENTITY', 'PERMISSION', 'AUTHORITY_FACT', 'AUTHORITY', 'BUSINESS_RESOURCE']],
  ['claims', 'Claims & effects', ['CLAIM', 'BUSINESS_EFFECT']],
  ['evidence', 'Evidence & decision', ['EVIDENCE', 'DECISION']],
  ['sources', 'Sources & changes', ['SOURCE', 'CHANGE']],
];
const RELATION: Record<string, string> = {
  HAS_COMPONENT: 'has component', DEPENDS_ON: 'depends on', REPORTS: 'reports', DECLARES: 'declares', MAPPED_TO: 'reviewed mapping to',
  BOUND_BY: 'bound by', HOLDS: 'holds', PERMITS: 'permits', COVERS: 'covers', GOVERNS: 'governs', PREVENTS: 'prevents', PRESERVES: 'preserves',
  SUPPORTS: 'supports', NO_LONGER_SUPPORTS: 'no longer supports', INVALIDATES: 'invalidates', REQUIRES_REVIEW_OF: 'requires review of',
  DECLARES_ACCESS: 'declares access to', DELEGATES_TO: 'delegates to (inert)',
};
export const kindLabel = (kind: string) => kind.replaceAll('_', ' ').toLowerCase();

export function SystemMap({graph}: {graph: Fields}) {
  const nodes = arr(graph.nodes), edges = arr(graph.edges);
  const [focus, setFocus] = useState('');
  const byId = useMemo(() => new Map(nodes.map(n => [str(n.id), n])), [nodes]);
  const linked = useMemo(() => new Set(edges.flatMap(e => str(e.source) === focus ? [str(e.target)] : str(e.target) === focus ? [str(e.source)] : [])), [edges, focus]);
  const column = (kind: string) => (COLUMNS.find(([, , kinds]) => kinds.includes(kind)) || COLUMNS[0])[0];
  const trace = edges.filter(e => str(e.source) === focus || str(e.target) === focus);
  return <section className="card">
    <div className="eyebrow">SYSTEM MAP</div>
    <h2>What makes up this system, and what depends on what.</h2>
    <p className={styles.lead}>Select any component, authority, claim, evidence or change to trace its chain. Every relationship cites the record that established it; nothing is inferred, and unknown stays unknown.</p>
    <div className={styles.mapGrid}>{COLUMNS.map(([key, label]) => <div key={key} className={styles.mapColumn}>
      <h3>{label}</h3>
      {nodes.filter(n => column(str(n.kind)) === key).map(n => {
        const id = str(n.id);
        return <button key={id} className={styles.node} aria-pressed={focus === id} data-status={str(n.status, '')} data-state={focus ? (focus === id ? 'focus' : linked.has(id) ? 'linked' : 'dim') : undefined} onClick={() => setFocus(focus === id ? '' : id)}>
          <span className={styles.nodeKind}>{kindLabel(str(n.kind))}</span>
          <strong>{str(n.label)}</strong>
          <small>{str(n.provenance, 'unknown').toLowerCase()}{n.status ? ` · ${str(n.status).replaceAll('_', ' ').toLowerCase()}` : ''}{n.inert ? ' · inert' : ''}</small>
        </button>;
      })}
    </div>)}</div>
    {focus && <div className={styles.trace} aria-live="polite">
      <strong>{str(byId.get(focus)?.label)}</strong> <span className={styles.muted}>{kindLabel(str(byId.get(focus)?.kind))}</span>
      <ul>{trace.map((e, index) => {
        const outgoing = str(e.source) === focus;
        const other = byId.get(outgoing ? str(e.target) : str(e.source));
        const basis = obj(e.basis);
        return <li key={index}><span className={styles.relation}>{outgoing ? '' : '← '}{RELATION[str(e.relation)] || str(e.relation).toLowerCase()}</span><span>{str(other?.label)}</span><span className={styles.basis}>established by {str(basis.record).replaceAll('_', ' ')}{e.authority_basis ? ` · ${str(e.authority_basis).toLowerCase().replaceAll('_', ' ')}` : ''}</span></li>;
      })}</ul>
    </div>}
    <div className={styles.legend}>{list(graph.limitations).map(l => <span key={l} className="tag">{l}</span>)}</div>
  </section>;
}

// --- Authority -----------------------------------------------------------------

export function Conditions({values, changed}: {values: Fields; changed?: Set<string>}) {
  const entries = Object.entries(values);
  if (!entries.length) return <span className={styles.muted}>Not declared</span>;
  return <div className={styles.chips}>{entries.map(([key, value]) => <span key={key} className={styles.chip} data-changed={changed?.has(key) ? 'true' : undefined}>{key} = {typeof value === 'object' ? JSON.stringify(value) : String(value)}</span>)}</div>;
}

export function AuthorityRow({entry}: {entry: Fields}) {
  const conditions = obj(entry.conditions), source = obj(entry.source), environment = obj(entry.environment);
  return <article className={styles.authority}>
    <div className={styles.authorityHead}><h3>{str(entry.label)}</h3><code>{str(entry.action)}</code><Badge value={BASIS[str(entry.basis)] || entry.basis} subtle/><Badge value={ASSURANCE[str(entry.assurance)] || entry.assurance}/></div>
    <dl className={styles.fields}>
      <div><dt>Resources</dt><dd><ul>{list(entry.resources).map(r => <li key={r}>{r}</li>)}</ul></dd></div>
      <div><dt>Principal / identity</dt><dd>{list(entry.principals).join(', ')}</dd></div>
      <div><dt>Environment</dt><dd>{str(environment.name)} · {str(environment.purpose).toLowerCase()}</dd></div>
      <div><dt>Tool / interface</dt><dd><ul>{arr(entry.interfaces).map(i => <li key={str(i.component)}>{str(i.label)} <span className={styles.muted}>· {BASIS[str(i.basis)] || str(i.basis)}</span></li>)}</ul></dd></div>
      <div><dt>Conditions</dt><dd><ul>{list(conditions.declared_boundary).map(c => <li key={c}>{c}</li>)}</ul>{arr(conditions.source_declared).map(s => <div key={str(s.installation_id)}><Conditions values={obj(s.conditions)}/><span className={styles.muted}>Reported by {str(s.source)} · unreviewed · {date(s.valid_at)}</span></div>)}</dd></div>
      <div><dt>Governing claims</dt><dd><ul>{arr(entry.claims).map(c => <li key={str(c.property_id)}>{str(c.title)} <span className={styles.muted}>· {str(c.status_text)}</span></li>)}{!arr(entry.claims).length && <li>No approved claim governs this action.</li>}{arr(entry.claim_definitions).map(c => <li key={str(c.id)}>{str(c.claim)} <span className={styles.muted}>· defined, not yet executable</span></li>)}</ul></dd></div>
      <div><dt>Source</dt><dd>Reviewed authority boundary · epoch {str(source.policy_epoch)}</dd></div>
      <div><dt>Freshness</dt><dd>{str(entry.freshness) === 'EXPIRED' ? 'Review expired' : `Reviewed until ${date(source.reviewed_until)}`}</dd></div>
    </dl>
  </article>;
}

export function AuthorityDiff({item}: {item: Fields}) {
  const classification = CLASSIFICATION[str(item.classification)] || CLASSIFICATION.UNKNOWN_IMPACT;
  const consequence = obj(item.consequence), origin = obj(item.origin), previous = obj(consequence.previous_clearance);
  const dimensions = arr(item.dimensions);
  const changed = new Set(dimensions.filter(d => d.kind === 'AUTHORIZATION').map(d => `${str(d.subject_path)}/${str(d.condition)}`));
  const other = dimensions.filter(d => d.kind !== 'AUTHORIZATION');
  return <article className={styles.diff} data-tone={classification.tone}>
    <div className={styles.diffHead}>
      <div><time>{date(item.recorded_at)}</time><h3>{str(item.headline)}</h3><small>{str(origin.name)} · {str(origin.acquisition).toLowerCase()} · {str(origin.qualification).toLowerCase()}</small></div>
      <span className={styles.classification} data-tone={classification.tone}>{classification.label}</span>
    </div>
    {arr(item.subjects).map(subject => {
      const path = str(subject.subject_path);
      const keys = new Set([...changed].filter(k => k.startsWith(path + '/')).map(k => k.slice(path.length + 1)));
      return <div key={path} className={styles.beforeAfter}>
        <div><span>Authority</span><div className={styles.subjectName}>{str(subject.subject)}</div></div>
        <div><span>Before</span><Conditions values={obj(subject.before)}/></div>
        <div><span>After</span><Conditions values={obj(subject.after)} changed={keys}/></div>
      </div>;
    })}
    {!!other.length && <ul className={styles.claimList}>{other.map((d, index) => <li key={index}><Badge value={(CLASSIFICATION[str(d.direction)] || CLASSIFICATION.UNKNOWN_IMPACT).label} subtle/>{str(d.reason)} <code className={styles.muted}>{str(d.subject)}</code></li>)}</ul>}
    <div className={styles.consequence}>
      <span className={styles.overline}>Consequence</span>
      <ul>
        <li><strong>{plural(num(consequence.claims_affected), 'claim')}</strong> affected</li>
        <li><strong>{num(consequence.evidence_stale)}</strong> evidence {num(consequence.evidence_stale) === 1 ? 'package' : 'packages'} stale</li>
        <li><strong>{num(consequence.still_holds)}</strong> still {num(consequence.still_holds) === 1 ? 'holds' : 'hold'}</li>
        {!!previous.id && <li>Previous clearance: <Badge value={previous.status || 'HISTORICAL'}/></li>}
      </ul>
      {list(consequence.required).map(r => <strong key={r} className={styles.muted} style={{fontSize: 12}}>Required: {r}</strong>)}
    </div>
    <ol className={styles.narrative}>{list(item.explanation).map(line => <li key={line}>{line}</li>)}</ol>
  </article>;
}

export function AuthorityView({authority, changes, systemId, environmentId, ctx, reload}: {authority: Fields; changes: Fields[]; systemId: string; environmentId: string; ctx: WorkspaceContext; reload: () => Promise<void>}) {
  const entries = arr(authority.authorities), undeclared = arr(authority.undeclared_interfaces);
  return <>
    <section className="card">
      <div className="eyebrow">WHAT CAN THIS SYSTEM ACTUALLY DO?</div>
      <h2>Its consequential authority, and whether evidence still supports it.</h2>
      <p className={styles.lead}>Declared authority comes from the customer-reviewed boundary; it grants no permission. Declared, connected, observed and verified are kept distinct, and a tool a source reports is never treated as a granted permission.</p>
      {!entries.length && <p>No authority boundary is defined yet. <Link href={`/app/systems/${systemId}/setup`} className="text-button">Define what this system can change <ArrowRight size={14}/></Link></p>}
      <div className={styles.authorityList}>{entries.map(entry => <AuthorityRow key={str(entry.action)} entry={entry}/>)}</div>
      {!!undeclared.length && <div className={styles.warnBox}><strong><AlertTriangle size={14}/> Reported outside the declared authority boundary</strong><ul>{undeclared.map(u => <li key={str(u.component)}><code>{str(u.label)}</code> — {str(u.note)}</li>)}</ul></div>}
    </section>
    <section className="card">
      <div className="eyebrow">AUTHORITY DIFF</div>
      <h2>How this authority moved, and what it changed.</h2>
      <p className={styles.lead}>Expanded means the new boundary is not contained in the previous one. Unknown impact means ThreatVeil cannot establish the direction from the facts it holds. A configuration change is never called an expansion by default.</p>
      <div className={styles.diffList}>{changes.map(item => <AuthorityDiff key={str(item.change_id)} item={item}/>)}</div>
      {!changes.length && <p>No authority change has been observed for this boundary.</p>}
    </section>
    {/* One place defines a claim: the builder on Security claims. This is the bridge. */}
    {!!entries.length && <section className="card">
      <div className="eyebrow">FROM A CAPABILITY TO A CLAIM</div>
      <h2>Say what must stay true about what it can do.</h2>
      <p className={styles.lead}>
        For each consequential action: the permitted outcome, the forbidden outcome, the legitimate task
        that must keep working, and the ground-truth source that can observe it. A definition establishes
        no evidence.
      </p>
      <div className={styles.row}>
        <Link href={`/app/systems/${systemId}/claims`} className="button dark small">
          Define a security claim <ArrowRight size={15}/>
        </Link>
      </div>
    </section>}
  </>;
}

// --- Change intelligence ---------------------------------------------------------

export function ChangeFeed({changes, synthetic, busy, simulate, ctx, systemId, summary = {}}: {changes: Fields[]; synthetic: boolean; busy: boolean; simulate: (change: string, message: string) => void; ctx: WorkspaceContext; systemId: string; summary?: Fields}) {
  const [all, setAll] = useState(false);
  const [recorded, setRecorded] = useState<Fields>({});
  useEffect(() => { api<Fields>(`/systems/${systemId}/consequence-feedback`).then(r => setRecorded(obj(r.consequences))).catch(() => setRecorded({})); }, [systemId, changes.length]);
  const shown = changes.filter(c => all || (!c.initial && str(obj(c.consequence).effect) !== 'COVERED_BY_LATER_VERIFICATION'));
  return <>
    <label className={styles.filter}><input type="checkbox" checked={all} onChange={e => setAll(e.target.checked)}/>Include first observations and changes already covered by later verification</label>
    <div className={completion.changeDetails}>{shown.map(change => <ChangeCard key={str(change.id)} change={change} ctx={ctx} systemId={systemId}
      summary={summary} recorded={str(obj(recorded[str(change.id)]).mine, '')}/>)}</div>
    {!shown.length && <p className={styles.muted}>No open change. {changes.length ? 'Earlier changes are covered by later verification.' : 'Nothing has changed since this boundary was established.'}</p>}
    {synthetic && <section className="card"><h2>Synthetic example controls <span className="tag">Synthetic sandbox</span></h2><p className={styles.lead}>Each control imports one gateway configuration into the labelled sandbox, and ThreatVeil reads it like any other source.</p><div className={styles.row}>
      <button className="button outline small" disabled={busy} onClick={() => simulate('beneficiary_approval_relaxed', 'Beneficiary approval relaxed in the gateway.')}>Relax beneficiary approval</button>
      <button className="button outline small" disabled={busy} onClick={() => simulate('invoice_tenant_binding_removed', 'Invoice tenant binding removed in the gateway.')}>Remove invoice tenant binding</button>
      <button className="button outline small" disabled={busy} onClick={() => simulate('payment_tool_added', 'An unreviewed payment tool is now exposed.')}>Expose an unreviewed payment tool</button>
      <button className="button outline small" disabled={busy} onClick={() => simulate('gateway_restored', 'The reviewed gateway configuration is restored.')}>Restore the reviewed gateway</button>
    </div></section>}
  </>;
}

/**
 * One recorded change as a Change Impact object. The reasoning, the mapping each affected
 * claim was reached through, and the origin's acquisition sit behind one disclosure.
 */
export function ChangeCard({change, ctx, systemId, recorded, summary = {}}: {change: Fields; ctx: WorkspaceContext; systemId: string; recorded: string; summary?: Fields}) {
  const consequence = obj(change.consequence), origin = obj(change.origin);
  const effect = str(consequence.effect);
  return <ChangeImpact {...impactOfChange(change, summary)} id={`change-${str(change.id)}`} open={effect === 'OPEN'}
    actions={<div className={completion.changeActions}>
      <details className={completion.why}>
        <summary>Why ThreatVeil concluded this</summary>
        <ol>{list(change.explanation).map(line => <li key={line}>{line}</li>)}</ol>
        {!!arr(consequence.claims_affected).length && <ul>{arr(consequence.claims_affected).map(claim => <li key={str(claim.property_id)}>
          {str(claim.title)}: {list(claim.via).length ? `reached via ${list(claim.via).join(', ')}` : 'not scoped by a reviewed mapping'}
        </li>)}</ul>}
        <p className={styles.muted}>{str(origin.name)} · {str(origin.acquisition).toLowerCase()} · {str(origin.qualification).toLowerCase()} · {date(change.recorded_at)}</p>
      </details>
      <Feedback ctx={ctx} systemId={systemId} consequenceId={str(change.id)} recorded={recorded}/>
    </div>}/>;
}

const VERDICTS: [string, string][] = [['CORRECT', 'Correct'], ['PARTIALLY_CORRECT', 'Partly correct'],
  ['INCORRECT', 'Incorrect'], ['NOT_SURE', 'Not sure']];

/** A customer's judgement, recorded beside a consequence. It never changes the consequence. */
export function Feedback({ctx, systemId, consequenceId, recorded}: {ctx: WorkspaceContext; systemId: string; consequenceId: string; recorded: string}) {
  const [sent, setSent] = useState(recorded);
  const [comment, setComment] = useState('');
  const [open, setOpen] = useState(false);
  const [error, setError] = useState('');
  useEffect(() => setSent(recorded), [recorded]);
  async function send(verdict: string) {
    setError('');
    try {
      await ctx.mutate(`/systems/${systemId}/consequences/${consequenceId}/feedback`,
        {verdict, comment: comment.trim() || null, idempotency_key: crypto.randomUUID()});
      setSent(verdict); setOpen(false);
      ctx.notify('Recorded beside this consequence. It changes no claim, no evidence and no clearance.');
    } catch (err) { setError(err instanceof Error ? err.message : 'Could not record your answer.'); }
  }
  return <div className={styles.feedback}>
    {sent ? <span className={styles.muted}>You answered <strong>{VERDICTS.find(([v]) => v === sent)?.[1] || sent}</strong>. Recorded beside this consequence; nothing about it changed.</span> : <>
      <span className={styles.overline}>Was this right?</span>
      <div className={styles.row}>
        {VERDICTS.map(([value, label]) => <button key={value} className="button outline small" onClick={() => send(value)}>{label}</button>)}
        <button className="text-button" onClick={() => setOpen(!open)}>{open ? 'Hide comment' : 'Add a comment'}</button>
      </div>
      {open && <textarea value={comment} maxLength={500} rows={2} onChange={e => setComment(e.target.value)}
        placeholder="Optional: what did ThreatVeil get right or wrong? (500 characters)" aria-label="Comment"/>}
    </>}
    {error && <p className="notice error" role="alert">{error}</p>}
  </div>;
}

// --- Evidence currency -------------------------------------------------------------

export function EvidenceCurrency({evidence, summary}: {evidence: Fields; summary: Fields}) {
  const claims = arr(evidence.claims), counts = obj(evidence.counts);
  return <>
    {/* One line of counts. A zero here is not diagnostic, so it is not rendered. */}
    <div className={styles.countLine}>
      {[['SUPPORTED', num(counts.SUPPORTED), 'current'],
        ['NEEDS_FRESH_EVIDENCE', num(counts.NEEDS_FRESH_EVIDENCE), 'need fresh evidence'],
        ['FAILED', num(counts.FAILED), 'failed verification'],
        ['UNKNOWN, DEFINED', num(counts.UNKNOWN) + num(counts.DEFINED), 'not yet supported'],
      ].filter(([, value]) => value as number).map(([key, value, label]) =>
        <span key={key as string} title={`Canonical status: ${key}`}><b>{value as number}</b> {label as string}</span>)}
      <span className={styles.muted}>Evidence must have been produced for the system as it runs now.</span>
    </div>
    <section className="card">
      <h2>What still holds, and why</h2>
      {claims.map(claim => {
        const record = obj(claim.evidence);
        return <article key={str(claim.property_id || claim.claim_definition_id)} className={styles.claim}>
          <div className={styles.claimHead}><h3>{str(claim.title)}</h3>
            <span title={`Canonical status: ${str(claim.status)}`}>
              <Badge value={CLAIM_STATE[str(claim.status)] || str(claim.status_text)}/>
            </span></div>
          <p className={styles.currency}>{str(claim.currency)}</p>
          <ul className={styles.claimList}>
            <li><span className={styles.muted}>Governs</span>{arr(claim.governs).map(g => str(g.label)).join(', ') || '—'}</li>
            {!!arr(claim.depends_on).length && <li><span className={styles.muted}>Depends on</span><span className={styles.chips}>{arr(claim.depends_on).map(d => <span key={str(d.component)} className={styles.chip}>{str(d.component)}</span>)}</span></li>}
            <li><span className={styles.muted}>Forbidden</span>{str(claim.forbidden_outcome)}</li>
            <li><span className={styles.muted}>Must keep working</span>{str(claim.legitimate_task)}</li>
            <li><span className={styles.muted}>Last verification</span>security <Badge value={claim.security} subtle/> useful task <Badge value={claim.legitimate_task_outcome} subtle/></li>
            {record.id ? <li><span className={styles.muted}>Evidence</span>produced {date(record.produced_at)} · {record.for_current_state ? 'for this state' : 'for an earlier state'}</li> : null}
            {arr(claim.affected_by).map(a => <li key={str(a.change_id)}><AlertTriangle size={14}/>Affected by: {str(a.headline)}</li>)}
          </ul>
          {!!list(claim.reasons).length && <details><summary className={styles.muted}>Why ThreatVeil concluded this</summary><ul className={styles.claimList}>{list(claim.reasons).map(r => <li key={r}>{r}</li>)}</ul></details>}
        </article>;
      })}
      {!claims.length && <p>No claim has an approved executable check yet, so there is no evidence to assess.</p>}
    </section>
  </>;
}

// --- Re-establish ----------------------------------------------------------------

export function Reestablish({plan, synthetic, busy, assess}: {plan: Fields; synthetic: boolean; busy: boolean; assess: (version: string, before?: string) => void}) {
  const outcome = obj(plan.latest_outcome), clearance = obj(plan.clearance);
  const stop = outcome.case === 'SECURITY_FAILED' || outcome.case === 'USEFUL_TASK_FAILED';
  return <>
    <section className="card">
      <div className="eyebrow">RESTORE ASSURANCE</div>
      <h2>{plan.required ? 'What must be re-established before this system is current again.' : 'Nothing needs to be restored.'}</h2>
      <p className={styles.lead}>ThreatVeil coordinates re-proof and records its result. It never changes your system and never proposes a remediation to it. A clearance returns only when the forbidden outcome is prevented and the legitimate task still succeeds.</p>
      {!!outcome.case && <div className={styles.outcome} data-tone={stop ? 'stop' : undefined}><span className={styles.overline}>Latest verification · {str(clearance.label)}</span><strong>{{SECURITY_FAILED: 'Security failed: not cleared.', USEFUL_TASK_FAILED: 'Security held, but useful work broke: not cleared.', RESTORED: 'Clearance restored.', ESTABLISHED: 'Clearance established.', INCONCLUSIVE: 'Inconclusive: not cleared.'}[str(outcome.case)] || str(outcome.case)}</strong><p>{str(outcome.text)}</p></div>}
      <ol className={styles.steps}>{arr(plan.steps).map((step, index) => <li key={str(step.step)}>
        <span className={styles.stepNumber}>{index + 1}</span>
        <div><h3>{str(step.title)}</h3><ul>{arr(step.items).map((item, i) => <li key={i}>{str(item.headline || item.check || item.task ? '' : '')}{item.headline ? str(item.headline) : item.check ? <><strong>{str(item.title)}:</strong> {str(item.check)}</> : item.task ? <><strong>{str(item.title)}:</strong> {str(item.task)}</> : item.criterion ? str(item.criterion) : <>{str(item.title)}{item.currency ? <span className={styles.muted}> — {str(item.currency)}</span> : null}</>}</li>)}{!arr(step.items).length && <li className={styles.muted}>Nothing.</li>}</ul></div>
      </li>)}</ol>
    </section>
    {synthetic ? <section className="card">
      <div className="eyebrow">RUN RE-PROOF · LABELLED SYNTHETIC SANDBOX</div>
      <h2>Three outcomes, one rule.</h2>
      <p className={styles.lead}>Security PASS is not enough. The useful invoice update must still commit.</p>
      <div className={styles.row}>
        <button className="button outline small" disabled={busy} onClick={() => assess('regressed')}>A · Re-prove with approval relaxed</button>
        <button className="button outline small" disabled={busy} onClick={() => assess('bad_fix')}>B · Try a fix that disables updates</button>
        <button className="button dark small" disabled={busy} onClick={() => assess('fixed', 'gateway_restored')}>C · Restore approval and re-prove <ArrowRight size={14}/></button>
      </div>
    </section> : <section className="card"><div className="eyebrow">RUN RE-PROOF</div><h2>Execute the listed checks on your authorized target.</h2><p className={styles.lead}>Use the approved claims, the qualified observer and the exact environment above.</p><Link href="/app/runs" className="button dark small">Execute approved checks <ArrowRight size={14}/></Link></section>}
  </>;
}

// --- Clearance lifecycle, gate and memory ------------------------------------------

export function Clearance({lifecycle, gate, memory, systemId, showGate = true}: {
  lifecycle: Fields; gate: Fields; memory: Fields; systemId: string; showGate?: boolean;
}) {
  const [copied, setCopied] = useState(false);
  const decision = obj(gate.decision), counts = obj(memory.counts), restoration = obj(memory.restoration);
  const origin = typeof window === 'undefined' ? 'https://your-threatveil-host' : window.location.origin;
  const command = `curl -s \\\n  -H "Authorization: Bearer $THREATVEIL_TOKEN" \\\n  -H "X-ThreatVeil-Consumer: ci-gate" \\\n  ${origin}/api/backend/v1/systems/${systemId}/assurance/current`;
  async function exportRecord() {
    if (!decision.id) return;
    const detail = await api<Fields>(`/change-assurance/decisions/${str(decision.id)}`);
    const url = URL.createObjectURL(new Blob([JSON.stringify(detail.envelope, null, 2)], {type: 'application/json'}));
    const anchor = document.createElement('a'); anchor.href = url; anchor.download = `threatveil-${str(decision.id)}.dsse.json`; anchor.click(); URL.revokeObjectURL(url);
  }
  return <>
    {/* The lifecycle is history. Before anything has happened it is seven boxes reading
        "Not yet", so it only appears once a stage has actually been reached. */}
    {arr(lifecycle.stages).some(stage => stage.reached) && <section className="card">
      <h2>Clearance lifecycle</h2>
      <p className={styles.lead}>Historical decisions are immutable. Only their current status is recomputed, so an earlier ALLOW can remain authentic while no longer speaking for the system.</p>
      <ol className={styles.lifecycle}>{arr(lifecycle.stages).map(stage => <li key={str(stage.stage)} data-reached={stage.reached ? 'true' : 'false'} data-current={stage.current ? 'true' : undefined}>
        <strong>{str(stage.title)}</strong><small>{stage.at ? date(stage.at) : stage.reached ? 'Reached' : 'Not yet'}</small>{!!stage.detail && <small>{str(stage.detail).replaceAll('_', ' ').toLowerCase()}</small>}
      </li>)}</ol>
    </section>}
    {showGate && <section className="card">
      <h2><KeyRound size={14} aria-hidden="true"/> Assurance Gate</h2>
      <p className={styles.lead}>The answer a pipeline consumes: is this system still cleared?</p>
      <div className={styles.gate}>
        <div className={styles.gateLine}><Badge value={gate.status}/><strong>{gate.cleared ? 'Cleared' : 'Not cleared'}</strong><span className={styles.muted}>evaluated {date(gate.evaluated_at)} · rely on it until {date(obj(gate.freshness).valid_until)} · never an authorization</span></div>
        {list(gate.reasons).map(r => <p key={r} style={{margin: 0}}>{r}</p>)}
        {!!decision.id && <div className={styles.gateLine}><span>Signed decision <Badge value={decision.action} subtle/></span><span className={styles.muted}>{decision.signed_statement_live ? `signed statement live until ${date(decision.signed_statement_expires_at)}` : 'signed statement lifetime ended; its status is recomputed above'}</span><button className="button outline small" onClick={exportRecord}><Download size={14}/>Export signed record</button><Link href="/app/records" className="text-button">Verify a record <ArrowRight size={14}/></Link></div>}
        <div className={styles.code}>{command}</div>
        <div className={styles.row}><button className="button outline small" onClick={() => {navigator.clipboard?.writeText(command.replaceAll('\\\n  ', '')); setCopied(true);}}><Copy size={14}/>{copied ? 'Copied' : 'Copy command'}</button><span className={styles.muted}>Use a read-only API token from workspace settings. Your policy decides fail-open or fail-closed when ThreatVeil is unavailable.</span></div>
        <div className={styles.tableScroll}><table className={styles.semantics}><thead><tr><th>Status</th><th>Meaning for a consumer</th></tr></thead><tbody>{GATE_MEANING.map(([key, meaning]) => <tr key={key}><td><Badge value={key} subtle/></td><td>{meaning}</td></tr>)}</tbody></table></div>
        <JsonDetails data={gate} label="Inspect the exact gate response"/>
      </div>
    </section>}
    {!!num(counts.observed_changes) && <section className="card">
      <h2>Assurance history</h2>
      <p className={styles.lead}>{str(memory.note)}</p>
      <div className={styles.countLine}>
        <span><b>{num(counts.observed_changes)}</b> observed change{num(counts.observed_changes) === 1 ? '' : 's'}</span>
        {!!num(obj(counts.authority_changes).AUTHORITY_EXPANDED)
          && <span><b>{num(obj(counts.authority_changes).AUTHORITY_EXPANDED)}</b> authority expansion{num(obj(counts.authority_changes).AUTHORITY_EXPANDED) === 1 ? '' : 's'}</span>}
        {!!num(counts.restorations) && <span><b>{num(counts.restorations)}</b> clearance{num(counts.restorations) === 1 ? '' : 's'} restored</span>}
        {restoration.median_seconds !== null && restoration.median_seconds !== undefined
          && <span><b>{Math.round(num(restoration.median_seconds) / 60)} min</b> median time to restore</span>}
        {!!restoration.insufficient_history && <span className={styles.muted}>
          A restore-time pattern is reported only after {plural(3, 'comparable cycle')}.
        </span>}
      </div>
      <div className={styles.tableScroll}><table className={styles.semantics} style={{marginTop: 16}}><thead><tr><th>Claim</th><th>Reached by a change</th><th>Survived a change</th></tr></thead><tbody>{arr(memory.claims).map(c => <tr key={str(c.property_id)}><td>{str(c.title)}</td><td>{num(c.reached)}</td><td>{num(c.survived)}</td></tr>)}</tbody></table></div>
      {arr(memory.patterns).map(p => <p key={str(p.text)} className={styles.muted}>{str(p.text)} ({num(p.observations)} observations)</p>)}
      {!!arr(lifecycle.completed_cycles).length && <div className={styles.tableScroll}><table className={styles.semantics} style={{marginTop: 16}}><thead><tr><th>Cleared</th><th>Lost</th><th>Cause</th><th>Re-proof attempts</th><th>Restored</th></tr></thead><tbody>{arr(lifecycle.completed_cycles).map(c => <tr key={str(c.cleared_by)}><td>{date(c.cleared_at)}</td><td>{date(c.lost_at)}</td><td>{str(c.cause).replaceAll('_', ' ').toLowerCase()}</td><td>{num(c.attempts)}</td><td>{date(c.restored_at)}</td></tr>)}</tbody></table></div>}
    </section>}
  </>;
}

// --- Passport ------------------------------------------------------------------------

export const PASSPORT_TONE: Record<string, string> = {CURRENT: 'ok', SUPERSEDED: 'attention', REASSESS: 'attention', EXPIRED: 'attention', REVOKED: 'stop', UNKNOWN: 'attention'};

export function PassportDocument({passport, status}: {passport: Fields; status?: Fields}) {
  const system = obj(passport.system), environment = obj(passport.environment), clearance = obj(passport.clearance), claims = obj(passport.claims), authority = obj(passport.authority);
  const groups: [string, string][] = [['supported', 'Supported by current evidence'], ['needs_fresh_evidence', 'Needs fresh evidence'], ['failed', 'Failed verification'], ['unknown', 'Not yet supported']];
  return <article className={styles.document} aria-label="Current Assurance Passport">
    <div className={styles.documentHead}>
      <div><div className="eyebrow">CURRENT ASSURANCE PASSPORT</div><h2>{str(system.name)}</h2><p style={{margin: 0}}>{str(obj(passport.organization).name)} · {str(environment.name)} ({str(environment.purpose).toLowerCase()}){system.synthetic ? ' · synthetic demonstration' : ''}</p></div>
      <div className={styles.clearanceBlock}><span className={styles.overline}>Clearance at issue</span><strong className={styles.clearanceLabel} style={{fontSize: 22}}>{str(clearance.label)}</strong><small>Issued {date(passport.issued_at)} · valid until {date(passport.expires_at)}</small><small>For: {str(passport.audience)}</small></div>
    </div>
    {status && <div className={styles.statusBanner} data-tone={PASSPORT_TONE[str(status.status)] || 'attention'}><ShieldCheck size={20}/><div><strong>Current status: {STATUS_TEXT[str(status.status)] || str(status.status)}</strong><p>{str(status.text)} Checked {date(status.checked_at)}.</p></div></div>}
    <div><span className={styles.overline}>Consequential authority</span><div className={styles.chips} style={{marginTop: 8}}>{arr(authority.consequential_actions).map(a => <span key={str(a.action)} className={styles.power}>{str(a.label)} <Badge value={ASSURANCE[str(a.assurance)] || a.assurance} subtle/></span>)}</div>{!!list(authority.interfaces_outside_boundary).length && <p className={styles.muted}>Reported outside the declared boundary: {list(authority.interfaces_outside_boundary).join(', ')}</p>}</div>
    <div className={styles.groups}>{groups.map(([key, label]) => <section key={key}><h3>{label} · {arr(claims[key]).length}</h3><ul>{arr(claims[key]).map(c => <li key={str(c.title)}>{str(c.title)}<small>{str(obj(c.evidence).meaning)}{obj(c.evidence).produced_at ? ` Produced ${date(obj(c.evidence).produced_at)}.` : ''}</small></li>)}{!arr(claims[key]).length && <li><small>None</small></li>}</ul></section>)}</div>
    <div className={styles.fine}><strong>Limitations</strong><ul>{list(passport.limitations).map(l => <li key={l}>{l}</li>)}</ul></div>
    <div className={styles.fine}><strong>What this passport does not claim</strong><ul>{list(passport.not_claims).map(l => <li key={l}>{l}</li>)}</ul></div>
    <div className={styles.fine}><strong>Verification</strong><ul><li>Authenticity: {str(obj(passport.verification).authenticity)}</li><li>Current status: {str(obj(passport.status_check).shared_link)}</li><li>State digest: <code>{str(obj(passport.state).digest).slice(0, 24)}…</code></li></ul></div>
  </article>;
}

export function VerificationPanel({envelope}: {envelope: unknown}) {
  const [result, setResult] = useState<VerificationResult | null>(null);
  async function run() {
    try { setResult(await verifyEnvelope(envelope, await api<Fields>('/trust/keys'))); }
    catch (e) { setResult({ok: false, detail: e instanceof Error ? e.message : 'Verification could not run in this browser.'}); }
  }
  return <div className={styles.verify} data-ok={result ? String(result.ok) : undefined}>
    <div className={styles.row}><button className="button outline small" onClick={run}><KeyRound size={14}/>Verify authenticity in this browser</button><span className={styles.muted}>Checks the signature against the published trust directory. It never establishes current status.</span></div>
    {result && <span>{result.ok ? <><Check size={14}/> Authentic: signed by key <code>{str(result.keyid).slice(0, 16)}…</code> ({str(result.keyStatus).toLowerCase()}).</> : <><CircleHelp size={14}/> {result.detail}</>}</span>}
  </div>;
}

export function PassportWorkspace({ctx, systemId, passports, reload}: {ctx: WorkspaceContext; systemId: string; passports: Fields[]; reload: () => Promise<void>}) {
  const [selected, setSelected] = useState(str(passports[0]?.id, ''));
  const [detail, setDetail] = useState<Fields | null>(null);
  const [link, setLink] = useState('');
  const [error, setError] = useState('');
  const [preview, setPreview] = useState<Fields | null>(null);
  useEffect(() => { if (!selected && passports[0]?.id) setSelected(str(passports[0].id)); }, [passports, selected]);
  useEffect(() => { setPreview(null); }, [selected]);
  useEffect(() => { if (selected) api<Fields>(`/passports/${selected}`).then(setDetail).catch(e => setError(e.message)); else setDetail(null); }, [selected]);
  async function issue(e: FormEvent<HTMLFormElement>) {
    e.preventDefault(); const form = new FormData(e.currentTarget); setError(''); setLink('');
    try {
      const created = await ctx.mutate(`/systems/${systemId}/passports`, {audience: form.get('audience'), valid_days: Number(form.get('days'))});
      await reload(); setSelected(created.id); ctx.notify('Passport issued and signed. It remains authentic even after the system changes.');
    } catch (err) { setError(err instanceof Error ? err.message : 'Could not issue a passport.'); }
  }
  /** Sharing sends data outside the organization, so the exact disclosure is reviewed first. */
  async function reviewDisclosure() {
    setError(''); setLink('');
    try { setPreview(await api<Fields>(`/passports/${selected}/disclosure-preview`)); }
    catch (err) { setError(err instanceof Error ? err.message : 'Could not load what would be shared.'); }
  }
  async function share() {
    setError('');
    try {
      const shared = await ctx.mutate(`/passports/${selected}/share`, {label: str(obj(detail?.passport).audience, 'External review'), valid_days: 14, confirm_disclosure: true});
      setLink(`${window.location.origin}${str(shared.page_path)}`);
      setPreview(null);
    } catch (err) { setError(err instanceof Error ? err.message : 'Could not create a share link.'); }
  }
  function download() {
    const url = URL.createObjectURL(new Blob([JSON.stringify({passport: detail?.passport, envelope: detail?.envelope}, null, 2)], {type: 'application/json'}));
    const anchor = document.createElement('a'); anchor.href = url; anchor.download = `threatveil-passport-${selected}.json`; anchor.click(); URL.revokeObjectURL(url);
  }
  return <>
    <section className="card">
      <div className="eyebrow">CURRENT ASSURANCE PASSPORT</div>
      <h2>Evidence about the agent that exists today, for your customer.</h2>
      <p className={styles.lead}>A portable, signed representation of one bounded assurance case: what the system can do, which claims current evidence supports, what is stale or unknown, and where to check whether it is still true. Not a certification, not a trust score.</p>
      <form className={styles.form} onSubmit={issue} style={{maxWidth: 560}}>
        <label>Who is it for?<input name="audience" required minLength={3} maxLength={120} defaultValue="Enterprise security review"/></label>
        <label>Valid for (days)<input name="days" type="number" min={1} max={90} defaultValue={30}/></label>
        <button className="button dark small">Issue a signed passport</button>
      </form>
      {error && <p className="notice error" role="alert">{error}</p>}
    </section>
    {!!passports.length && <div className={styles.passportGrid}>
      <div className={styles.passportList}>{passports.map(p => <button key={str(p.id)} className={styles.passportItem} aria-current={p.id === selected ? 'true' : undefined} onClick={() => {setSelected(str(p.id)); setLink('');}}>
        <strong>{str(p.audience)}</strong><small>Issued {date(p.issued_at)} · {str(p.clearance)}</small>{!!obj(p.current_status).status && <Badge value={obj(p.current_status).status} subtle/>}
      </button>)}</div>
      <div style={{display: 'grid', gap: 14}}>
        {detail && <>
          <PassportDocument passport={obj(detail.passport)} status={obj(detail.current_status)}/>
          <div className={styles.row}>
            <button className="button dark small" onClick={reviewDisclosure}>Review what would be shared</button>
            <button className="button outline small" onClick={download}><Download size={14}/>Download signed JSON</button>
          </div>
          {preview && <DisclosurePreview preview={preview} onConfirm={share} onCancel={() => setPreview(null)}/>}
          {link && <div className={styles.shareBox}><strong>Share link (shown once)</strong><code>{link}</code><span className={styles.muted}>Anyone with this link sees this passport and its current status. ThreatVeil sends nothing to the recipient. Revoke it at any time.</span><button className="button outline small" onClick={() => navigator.clipboard?.writeText(link)}><Copy size={14}/>Copy link</button></div>}
          <VerificationPanel envelope={detail.envelope}/>
        </>}
      </div>
    </div>}
  </>;
}

export function DisclosurePreview({preview, onConfirm, onCancel}: {preview: Fields; onConfirm: () => void; onCancel: () => void}) {
  const discloses = obj(preview.discloses);
  const rows: [string, string[]][] = [
    ['Organization name', [str(discloses.organization_name)]],
    ['System', [str(discloses.system_name)]],
    ['Environment', [str(discloses.environment)]],
    ['Clearance', [str(discloses.clearance)]],
    ['Claim titles', list(discloses.claim_titles)],
    ['Authority labels', list(discloses.authority_labels)],
    ['Resource names', list(discloses.resource_names)],
    ['Interface names', list(discloses.interface_names)],
    ['Internal identifiers', list(discloses.internal_identifiers)],
  ];
  return <section className={styles.preview} aria-label="What would be shared">
    <div className={styles.overline}>BEFORE YOU SHARE · {str(preview.disclosure)}</div>
    <p className={styles.lead}>{str(preview.meaning)}</p>
    <dl className={styles.fields}>{rows.map(([label, values]) => <div key={label}>
      <dt>{label}</dt><dd>{values.filter(Boolean).length ? values.filter(Boolean).join(', ') : <span className={styles.muted}>Not included</span>}</dd>
    </div>)}</dl>
    {!!list(preview.withheld).length && <p className={styles.muted}>Withheld from the signed document: {list(preview.withheld).join(', ')}.</p>}
    <p className={styles.muted}>{str(preview.note)}</p>
    <div className={styles.row}>
      <button className="button dark small" onClick={onConfirm}>I reviewed this · create the link</button>
      <button className="button outline small" onClick={onCancel}>Cancel</button>
    </div>
  </section>;
}

// --- Failure states, the claim ladder, mapping review and proposed changes --------

export const SEVERITY: Record<string, string> = {BLOCKING_VALUE: 'stop', LIMITS_SCOPE: 'attention', INFORMATIONAL: 'neutral'};

/** Every named limitation, and what ThreatVeil refuses to claim because of it. */
export function GuidancePanel({systemId, environmentId}: {systemId: string; environmentId: string}) {
  const [data, setData] = useState<Fields | null>(null);
  useEffect(() => {
    const controller = new AbortController();
    api<Fields>(`/systems/${systemId}/guidance${environmentId ? `?environment_id=${environmentId}` : ''}`, {signal: controller.signal})
      .then(setData).catch(() => undefined);
    return () => controller.abort();
  }, [systemId, environmentId]);
  if (!data) return null;
  const found = arr(data.items);
  return <section className="card">
    <div className="eyebrow">WHAT LIMITS THIS ANSWER</div>
    {!found.length ? <>
      <h2>Nothing is limiting this answer.</h2>
      <p className={styles.lead}>A baseline exists, every source is current, each observed change is scoped to reviewed dependencies, and a qualified observer can witness the business effect.</p>
    </> : <>
      <h2>{plural(found.length, 'limitation')} on what ThreatVeil will say.</h2>
      <p className={styles.lead}>Each one names what it means, what ThreatVeil will not claim while it holds, and the next step.</p>
      <div className={styles.diffList}>{found.map(item => <article key={str(item.code)} className={styles.diff} data-tone={SEVERITY[str(item.severity)] || 'neutral'}>
        <div className={styles.diffHead}>
          <div><h3>{str(item.title)}</h3><small className="mono">{str(item.code)}</small></div>
          <Badge value={str(item.severity).replaceAll('_', ' ')} subtle/>
        </div>
        <p>{str(item.meaning)}</p>
        {!!item.detail && <p className={styles.muted}>{str(item.detail)}</p>}
        <p className={styles.why}><strong>ThreatVeil will not claim:</strong> {str(item.not_claimed)}</p>
        <p className={styles.next}><ArrowRight size={14}/> {str(item.next_step)}</p>
      </article>)}</div>
    </>}
  </section>;
}

/**
 * The four canonical verification levels, presented in customer language. The exact
 * canonical value stays on every row, in the title attribute and the empty state, so
 * a security engineer reads DECLARED / NOT_YET_VERIFIED / QUALIFIED / CURRENT unchanged.
 */
export const LEVELS: [string, string][] = [['CURRENT', 'Current'], ['QUALIFIED', 'Ready to verify'],
  ['NOT_YET_VERIFIED', 'Needs evidence'], ['DECLARED', 'Defined']];
const LEVEL_LABEL = Object.fromEntries(LEVELS);

/**
 * One claim, inspected in place: what it says, whether it holds, what it depends on and
 * which change reached it; the identifiers a security engineer needs sit under Advanced.
 */
function ClaimDrawer({claim, evidence, onClose}: {claim?: Fields; evidence?: Fields; onClose: () => void}) {
  if (!claim) return <Drawer open={false} title="" onClose={onClose}>{null}</Drawer>;
  const id = str(claim.id);
  const detail = arr(obj(evidence).claims).find(c => str(c.property_id) === id || str(c.claim_definition_id) === id) || {};
  const record = obj(detail.evidence);
  const state = CLAIM_VIEW[str(detail.status || claim.status)];
  const level = LEVEL_LABEL[str(claim.verification)] || str(claim.verification).replaceAll('_', ' ').toLowerCase();
  return <Drawer open title={str(claim.title)} onClose={onClose} subtitle={<>
    <span title={`Canonical status: ${str(claim.verification)}`}><Badge value={level} subtle/></span>
    <span className={styles.muted} aria-hidden="true">↑↓ next claim</span>
    {!!state && <StatusPill label={state.label} tone={state.tone} canonical={str(detail.status || claim.status)}/>}
  </>}>
    <p style={{fontSize: 13, lineHeight: 1.55}}>{str(detail.currency, str(claim.meaning))}</p>
    {!!claim.next_step && <p className={styles.next}>{str(claim.next_step)}</p>}
    {!!arr(detail.affected_by).length && <section>
      <h3 style={{fontSize: 12, marginBottom: 6}}>Reached by</h3>
      <ul className={styles.claimList}>{arr(detail.affected_by).map(a => <li key={str(a.change_id)}>
        <AlertTriangle size={13} aria-hidden="true"/>{str(a.headline)}</li>)}</ul>
    </section>}
    <Facts rows={[
      ['Governs', arr(detail.governs).map(g => str(g.label)).join(', ')],
      ['Forbidden', str(detail.forbidden_outcome, '')],
      ['Must keep working', str(detail.legitimate_task, '')],
      ['Depends on', list(claim.dependencies).length ? <span className="mono" style={{fontSize: 12}}>{list(claim.dependencies).join(', ')}</span> : ''],
      ['Last verification', detail.security ? <>security <Badge value={detail.security} subtle/> useful task <Badge value={detail.legitimate_task_outcome} subtle/></> : ''],
      ['Evidence', record.id ? `produced ${date(record.produced_at)} · ${record.for_current_state ? 'for this state' : 'for an earlier state'}` : ''],
    ]}/>
    {!!list(detail.reasons).length && <details><summary className={styles.muted}>Why ThreatVeil concluded this</summary>
      <ul className={styles.claimList}>{list(detail.reasons).map(r => <li key={r}>{r}</li>)}</ul></details>}
    <details><summary className={styles.muted}>Advanced</summary>
      <Facts rows={[
        ['Claim ID', <span className="mono" style={{fontSize: 12}}>{id}</span>],
        ['Kind', str(claim.kind).replaceAll('_', ' ').toLowerCase()],
        ['Verification level', <span className="mono" style={{fontSize: 12}}>{str(claim.verification)}</span>],
        ['Evidence status', <span className="mono" style={{fontSize: 12}}>{str(detail.status || claim.status)}</span>],
        ['Evidence record', record.id ? <span className="mono" style={{fontSize: 12}}>{str(record.id)}</span> : ''],
      ]}/>
    </details>
  </Drawer>;
}

/** The four verification levels, never merged, plus the guided claim builder. */
export function ClaimLadder({ctx, systemId, environmentId, reload, evidence}: {ctx: WorkspaceContext; systemId: string; environmentId: string; reload: () => Promise<void>; evidence?: Fields}) {
  // The open claim lives in the URL, so an inspected claim is a shareable deep link.
  const router = useRouter();
  const pathname = usePathname();
  const params = useSearchParams();
  const openId = params.get('claim') || '';
  const inspect = useCallback((id: string) => {
    router.replace(id ? `${pathname}?claim=${encodeURIComponent(id)}` : pathname, {scroll: false});
  }, [router, pathname]);
  const [data, setData] = useState<Fields | null>(null);
  const [catalog, setCatalog] = useState<Fields | null>(null);
  const [draft, setDraft] = useState<Fields | null>(null);
  const [error, setError] = useState('');
  const refresh = useCallback(async () => {
    setData(await api<Fields>(`/systems/${systemId}/claims${environmentId ? `?environment_id=${environmentId}` : ''}`));
  }, [systemId, environmentId]);
  useEffect(() => { refresh().catch(e => setError(e instanceof Error ? e.message : 'Unable to load claims.')); }, [refresh]);
  useEffect(() => { api<Fields>('/claim-templates').then(setCatalog).catch(() => undefined); }, []);
  async function build(e: FormEvent<HTMLFormElement>) {
    e.preventDefault(); const form = new FormData(e.currentTarget); setError('');
    try {
      setDraft(await api<Fields>('/claim-templates/draft', {method: 'POST', csrf: ctx.identity?.csrf_token,
        data: {template_id: form.get('template'), resource: form.get('resource'), action: form.get('action') || null}}));
    } catch (err) { setError(err instanceof Error ? err.message : 'Could not build a draft.'); }
  }
  async function save(e: FormEvent<HTMLFormElement>) {
    e.preventDefault(); const form = new FormData(e.currentTarget); setError('');
    try {
      await ctx.mutate(`/systems/${systemId}/claim-definitions`, {
        environment_id: environmentId || null, action: form.get('action'), claim: form.get('claim'),
        permitted_outcome: form.get('permitted'), forbidden_outcome: form.get('forbidden'),
        legitimate_task: form.get('task'), ground_truth_source: form.get('ground'),
        resource: form.get('resource'), template_id: str(draft?.template_id, undefined as unknown as string),
        declared_dependencies: String(form.get('dependencies') || '').split(',').map(v => v.trim()).filter(Boolean)});
      setDraft(null); await refresh(); await reload();
      ctx.notify('Declared. It stays NOT YET VERIFIED until an approved executable check with a qualified observer is bound to it.');
    } catch (err) { setError(err instanceof Error ? err.message : 'Could not save the claim.'); }
  }
  const claims = arr(data?.claims);
  const counts = obj(data?.counts);
  // While a claim is open, ↑/↓ (or k/j) move to the adjacent claim and keep the deep link in
  // step, so a reviewer can walk every claim without closing the panel. Keys typed into a form
  // field are left alone.
  useEffect(() => {
    if (!openId) return;
    function step(event: KeyboardEvent) {
      const target = event.target as HTMLElement | null;
      if (target && (target.isContentEditable || ['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName))) return;
      const delta = event.key === 'ArrowDown' || event.key === 'j' ? 1 : event.key === 'ArrowUp' || event.key === 'k' ? -1 : 0;
      if (!delta) return;
      const index = claims.findIndex(c => str(c.id) === openId);
      const next = claims[index + delta];
      if (index < 0 || !next) return;
      event.preventDefault();
      inspect(str(next.id));
    }
    document.addEventListener('keydown', step);
    return () => document.removeEventListener('keydown', step);
  }, [openId, claims, inspect]);
  return <>
    <section className="card">
      <h2>What must stay true</h2>
      <div className={styles.countLine}>
        {LEVELS.filter(([key]) => num(counts[key])).map(([key, label]) =>
          <span key={key} title={`Canonical status: ${key} — ${str(obj(data?.levels)[key])}`}>
            <b>{num(counts[key])}</b> {label.toLowerCase()}
          </span>)}
        {!LEVELS.some(([key]) => num(counts[key])) && <span>No security claim is defined yet.</span>}
      </div>
      {error && <p className="notice error" role="alert">{error}</p>}
      {!claims.length ? <p>No claims defined. Start from a reviewed pattern below: it costs nothing and it tells ThreatVeil which changes matter.</p>
        : <ul className={styles.claimRows}>{claims.map(claim => <li key={str(claim.id)}>
          <button className={styles.claimRow} onClick={() => inspect(str(claim.id))}
            aria-haspopup="dialog" aria-expanded={openId === str(claim.id)}>
            {str(claim.verification) === 'CURRENT' ? <Check size={14} aria-hidden="true"/> : <CircleHelp size={14} aria-hidden="true"/>}
            <strong>{str(claim.title)}</strong>
            <span title={`Canonical status: ${str(claim.verification)}`}>
              <Badge value={LEVEL_LABEL[str(claim.verification)] || str(claim.verification).replaceAll('_', ' ')} subtle/>
            </span>
            {!!claim.next_step && <span className={styles.muted}>{str(claim.next_step)}</span>}
          </button>
        </li>)}</ul>}
    </section>
    <ClaimDrawer claim={claims.find(c => str(c.id) === openId)} evidence={evidence} onClose={() => inspect('')}/>
    {catalog && <section className="card">
      <h2>Start from a reviewed pattern <span className="tag">{str(catalog.status_label).toLowerCase()}</span></h2>
      <p className={styles.lead}>{str(catalog.note)}</p>
      <form className={styles.form} onSubmit={build} style={{maxWidth: 620}}>
        <label>Pattern<select name="template" required>{arr(catalog.templates).map(t =>
          <option key={str(t.id)} value={str(t.id)}>{str(t.label)} — {str(t.title)}</option>)}</select></label>
        <label>What does it govern?<input name="resource" required minLength={2} maxLength={120} placeholder="customer refunds"/></label>
        <label>Action<select name="action" defaultValue="">{[<option key="" value="">Use the pattern&apos;s action</option>,
          ...arr(catalog.starter_actions).map(a => <option key={str(a.action)} value={str(a.action)}>{str(a.label)} — {str(a.hint)}</option>)]}</select></label>
        <button className="button outline small">Build a draft</button>
      </form>
      {draft && <form className={styles.form} onSubmit={save} style={{marginTop: 18}}>
        <p className={styles.warnBox}>{str(draft.status)}. A draft is not a claim and not evidence. Edit every line before saving.</p>
        <label>Claim<input name="claim" required minLength={10} maxLength={300} defaultValue={str(draft.claim, '')}/></label>
        <label>Action<input name="action" required defaultValue={str(draft.action, '')}/></label>
        <label>Resource<input name="resource" required defaultValue={str(draft.resource, '')}/></label>
        <label>Permitted outcome<input name="permitted" required minLength={5} defaultValue={str(draft.permitted_outcome, '')}/></label>
        <label>Forbidden outcome<input name="forbidden" required minLength={5} defaultValue={str(draft.forbidden_outcome, '')}/></label>
        <label>Legitimate task that must keep working<input name="task" required minLength={5} defaultValue={str(draft.legitimate_task, '')}/></label>
        <label>Ground-truth source<input name="ground" required minLength={3} defaultValue={str(draft.ground_truth_source, '')}/></label>
        <label>Declared dependencies (comma separated)<input name="dependencies" defaultValue={list(draft.declared_dependencies).join(', ')}
          placeholder="permissions:approval, tool:refund.issue"/></label>
        <ol className={styles.narrative}>{list(draft.next_steps).map(step => <li key={step}>{step}</li>)}</ol>
        <button className="button dark small">Save declared claim</button>
      </form>}
    </section>}
  </>;
}

/** Mapping is a reviewed decision: suggestions and proposals are inert until approved. */
export function MappingReview({ctx, systemId, environmentId, reload}: {ctx: WorkspaceContext; systemId: string; environmentId: string; reload: () => Promise<void>}) {
  const [overview, setOverview] = useState<Fields | null>(null);
  const [proposals, setProposals] = useState<Fields | null>(null);
  const [suggested, setSuggested] = useState<Fields | null>(null);
  const [source, setSource] = useState('');
  const [error, setError] = useState('');
  const refresh = useCallback(async () => {
    const [view, queue] = await Promise.all([
      api<Fields>(`/systems/${systemId}/mappings-overview${environmentId ? `?environment_id=${environmentId}` : ''}`),
      api<Fields>(`/systems/${systemId}/mapping-proposals`)]);
    setOverview(view); setProposals(queue);
  }, [systemId, environmentId]);
  useEffect(() => { refresh().catch(e => setError(e instanceof Error ? e.message : 'Unable to load mappings.')); }, [refresh]);
  const sources = arr(overview?.sources);
  useEffect(() => { if (!source && sources[0]) setSource(str(sources[0].installation_id)); }, [sources, source]);
  useEffect(() => {
    if (!source) { setSuggested(null); return; }
    api<Fields>(`/systems/${systemId}/mapping-suggestions?installation_id=${source}`).then(setSuggested).catch(() => setSuggested(null));
  }, [systemId, source]);
  const selected = sources.find(s => str(s.installation_id) === source);
  async function propose(subject: string, dependency: string, reason: string, confidence: string, evidence: string) {
    setError('');
    try {
      await ctx.mutate(`/systems/${systemId}/mapping-proposals`, {environment_id: environmentId, installation_id: source,
        subject, maps_to: [dependency], reason, confidence, origin: 'DETERMINISTIC', evidence});
      await refresh(); ctx.notify('Queued for review. A proposal narrows nothing until it is approved.');
    } catch (err) { setError(err instanceof Error ? err.message : 'Could not queue that proposal.'); }
  }
  async function decide(id: string, decision: string) {
    setError('');
    try {
      await ctx.mutate(`/mapping-proposals/${id}/review`, {decision,
        review_note: decision === 'APPROVED' ? 'Reviewed: this source fact controls that claim dependency.'
          : 'Reviewed: this correspondence is not right for this system.'});
      await refresh(); await reload();
      ctx.notify(decision === 'APPROVED' ? 'Approved. It now narrows which claims a change reaches.' : 'Rejected. Nothing changed.');
    } catch (err) { setError(err instanceof Error ? err.message : 'Could not record that review.'); }
  }
  const open = arr(proposals?.items).filter(p => str(p.status) === 'PROPOSED');
  return <>
    <section className="card">
      <div className="eyebrow">WHAT IS MAPPED, AND WHAT IS NOT</div>
      <h2>Only an approved mapping narrows which claims a change reaches.</h2>
      <p className={styles.lead}>{str(overview?.principle)}</p>
      {error && <p className="notice error" role="alert">{error}</p>}
      {sources.length > 1 && <label className={styles.filter}>Source
        <select value={source} onChange={e => setSource(e.target.value)}>{sources.map(s =>
          <option key={str(s.installation_id)} value={str(s.installation_id)}>{str(s.name)} · {str(s.connector_id)}</option>)}</select></label>}
      {selected && <>
        <h3>Mapped facts</h3>
        {!arr(selected.mapped).length ? <p>Nothing is mapped for this source yet, so every change it reports stays conservative.</p>
          : <ul className={styles.claimList}>{arr(selected.mapped).map(row => <li key={str(row.subject)}>
            <Check size={14}/><strong className="mono">{str(row.subject)}</strong>
            <span>→ {list(row.maps_to).join(', ')}</span>
            <span className={styles.muted}>{str(row.authority_basis)} · approved {date(row.approved_at)} · source record {str(row.source_record).slice(0, 8)}</span>
          </li>)}</ul>}
        <h3>Unmapped facts</h3>
        {!arr(selected.unmapped).length ? <p>Every fact this source reports is mapped.</p>
          : <ul className={styles.claimList}>{arr(selected.unmapped).map(row => <li key={str(row.subject)}>
            <AlertTriangle size={14}/><strong className="mono">{str(row.subject)}</strong>
            <span className={styles.muted}>{str(row.consequence)}</span></li>)}</ul>}
      </>}
    </section>
    {!!arr(suggested?.items).length && <section className="card">
      <div className="eyebrow">DETERMINISTIC SUGGESTIONS</div>
      <h2>Name correspondences ThreatVeil can see, with the reason for each.</h2>
      <p className={styles.lead}>A suggestion is a name match, never a reviewed fact. Queue the ones that are right; a reviewer still has to approve them.</p>
      <div className={styles.diffList}>{arr(suggested?.items).filter(item => arr(item.suggestions).length).map(item =>
        <article key={str(item.subject)} className={styles.diff}>
          <div className={styles.diffHead}><div><h3 className="mono">{str(item.subject)}</h3>
            <small>{kindLabel(str(item.kind))}{list(item.names).length ? ` · ${list(item.names).join(', ')}` : ''}</small></div></div>
          <ul className={styles.claimList}>{arr(item.suggestions).map(s => <li key={str(s.dependency)}>
            <strong>{str(s.dependency)}</strong>
            <Badge value={str(s.confidence).replaceAll('_', ' ')} subtle/>
            <span className={styles.muted}>{str(s.reason_text)} Matched on “{str(s.matched)}”. {str(s.basis) === 'DECLARED_CLAIM' ? 'Declared claim.' : 'Approved claim.'}</span>
            <button className="button outline small" onClick={() => propose(str(item.subject), str(s.dependency), str(s.reason), str(s.confidence),
              `Source record ${str(item.source_record)} reports ${list(item.names).join(', ') || str(item.subject)}`)}>Queue for review</button>
          </li>)}</ul>
        </article>)}</div>
    </section>}
    <section className="card">
      <div className="eyebrow">REVIEW QUEUE</div>
      <h2>{open.length ? plural(open.length, 'proposal') + ' waiting for a decision.' : 'Nothing is waiting for review.'}</h2>
      {!!arr(proposals?.items).length && <div className={styles.diffList}>{arr(proposals?.items).map(p =>
        <article key={str(p.id)} className={styles.diff} data-tone={str(p.status) === 'PROPOSED' ? 'attention' : 'neutral'}>
          <div className={styles.diffHead}>
            <div><h3 className="mono">{str(p.subject)}</h3><small>→ {list(p.maps_to).join(', ')} · {str(p.origin).replaceAll('_', ' ').toLowerCase()}
              {p.model ? ` · ${str(p.model)}` : ''}</small></div>
            <Badge value={str(p.status)} subtle/>
          </div>
          <p>{str(p.evidence)}</p>
          {!!p.note && <p className={styles.muted}>{str(p.note)}</p>}
          {str(p.status) === 'PROPOSED' && <div className={styles.row}>
            <button className="button dark small" onClick={() => decide(str(p.id), 'APPROVED')}>Approve</button>
            <button className="button outline small" onClick={() => decide(str(p.id), 'REJECTED')}>Reject</button>
          </div>}
          {str(p.status) !== 'PROPOSED' && <p className={styles.muted}>{p.affects_scoping ? 'Approved: this mapping narrows which claims a change reaches.' : 'Not applied: nothing changed.'}</p>}
        </article>)}</div>}
    </section>
  </>;
}

/** What would this change break? A dry run that never touches current clearance. */
export function ProposeChange({ctx, systemId}: {ctx: WorkspaceContext; systemId: string}) {
  const [sources, setSources] = useState<Fields[]>([]);
  const [source, setSource] = useState('');
  const [result, setResult] = useState<Fields | null>(null);
  const [history, setHistory] = useState<Fields[]>([]);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const refresh = useCallback(async () => {
    const [view, listed] = await Promise.all([api<Fields>(`/systems/${systemId}/mappings-overview`),
      api<Fields>(`/systems/${systemId}/proposed-changes`)]);
    setSources(arr(view.sources)); setHistory(arr(listed.items));
  }, [systemId]);
  useEffect(() => { refresh().catch(e => setError(e instanceof Error ? e.message : 'Unable to load sources.')); }, [refresh]);
  useEffect(() => { if (!source && sources[0]) setSource(str(sources[0].installation_id)); }, [sources, source]);
  async function run(e: FormEvent<HTMLFormElement>) {
    e.preventDefault(); const form = new FormData(e.currentTarget); setError(''); setResult(null); setBusy(true);
    try {
      const payload = JSON.parse(String(form.get('payload') || '{}'));
      const created = await ctx.mutate(`/systems/${systemId}/proposed-changes`, {
        installation_id: source, payload, idempotency_key: crypto.randomUUID(),
        reference: {type: str(form.get('type'), 'MANUAL'), id: String(form.get('reference') || '') || null,
          url: String(form.get('url') || '') || null}});
      setResult(created); await refresh();
    } catch (err) { setError(err instanceof SyntaxError ? 'That is not valid JSON.' : err instanceof Error ? err.message : 'Could not evaluate that change.'); }
    finally { setBusy(false); }
  }
  const summary = obj(result?.summary), check = obj(result?.check), clearance = obj(result?.clearance);
  return <>
    <section className="card">
      <div className="eyebrow">PROPOSED CHANGE · NOT CURRENT STATE</div>
      <h2>What would this change break?</h2>
      <p className={styles.lead}>Paste the configuration you are about to ship — a tool catalogue or an agent definition — and ThreatVeil answers against your current claims. It reads only: your clearance, evidence and authority are untouched.</p>
      {!sources.length ? <p>Connect or import a source first. A dry run compares a proposal against what ThreatVeil last observed.</p>
        : <form className={styles.form} onSubmit={run}>
          <label>Source<select value={source} onChange={e => setSource(e.target.value)}>{sources.map(s =>
            <option key={str(s.installation_id)} value={str(s.installation_id)}>{str(s.name)} · {str(s.connector_id)}</option>)}</select></label>
          <label>Reference type<select name="type" defaultValue="PULL_REQUEST">{['PULL_REQUEST', 'COMMIT', 'BRANCH', 'MANUAL'].map(t =>
            <option key={t} value={t}>{t.replaceAll('_', ' ').toLowerCase()}</option>)}</select></label>
          <label>Reference<input name="reference" maxLength={120} placeholder="#42"/></label>
          <label>Link (https, optional)<input name="url" maxLength={500} placeholder="https://github.com/example/agent/pull/42"/></label>
          <label>Proposed configuration (JSON)<textarea name="payload" required rows={8} placeholder='{"protocol_version": "2026-07-28", "tools": [], "authorization": {"tools": {}}}'/></label>
          <button className="button dark small" disabled={busy || !source}>{busy ? 'Evaluating…' : 'What would this break?'}</button>
        </form>}
      {error && <p className="notice error" role="alert">{error}</p>}
    </section>
    {result && <section className="card">
      <div className="eyebrow">{str(result.label)}</div>
      <h2>{str(summary.headline)}</h2>
      <div className={styles.row}>
        <Badge value={str(summary.effect).replaceAll('_', ' ')}/>
        {!!summary.classification && <span className={styles.classification} data-tone={CLASSIFICATION[str(summary.classification)]?.tone || 'neutral'}>
          {CLASSIFICATION[str(summary.classification)]?.label || str(summary.classification)}</span>}
        <Badge value={`CHECK: ${str(check.conclusion)} · ${str(check.mode)}`} subtle/>
      </div>
      <p className={styles.why}>Current clearance is <strong>{str(clearance.current)}</strong> and this dry run changed nothing.
        {str(clearance.if_applied) !== str(clearance.current) ? ` If this were applied and nothing else changed, it would become ${str(clearance.if_applied)}.` : ''}</p>
      <ol className={styles.narrative}>{list(result.explanation).map(line => <li key={line}>{line}</li>)}</ol>
      {!!arr(result.claims).length && <ul className={styles.claimList}>{arr(result.claims).map(c => <li key={str(c.property_id)}>
        {c.reached ? <AlertTriangle size={14}/> : <Check size={14}/>}<strong>{str(c.title)}</strong>
        <span className={styles.muted}>now {str(c.current_status).replaceAll('_', ' ').toLowerCase()} → {str(c.outcome).replaceAll('_', ' ').toLowerCase()}</span>
      </li>)}</ul>}
      {!!arr(result.declared_claims).length && <ul className={styles.claimList}>{arr(result.declared_claims).map(c => <li key={str(c.definition_id)}>
        <CircleHelp size={14}/><strong>{str(c.claim)}</strong><Badge value="NOT YET VERIFIED" subtle/></li>)}</ul>}
      <JsonDetails label="Check body that a CI step would publish" data={check}/>
      <ul className={styles.fine}>{list(result.limitations).map(line => <li key={line}>{line}</li>)}</ul>
    </section>}
    {!!history.length && <section className="card">
      <div className="eyebrow">EARLIER DRY RUNS</div>
      <h2>{plural(history.length, 'evaluation')} recorded, none of them current state.</h2>
      <ul className={styles.claimList}>{history.slice(0, 20).map(item => <li key={str(item.id)}>
        <Badge value={str(item.mode)} subtle/><strong>{str(obj(item.summary).headline)}</strong>
        <span className={styles.muted}>{date(item.created_at)} · {str(obj(item.reference).type).replaceAll('_', ' ').toLowerCase()}
          {obj(item.reference).id ? ` ${str(obj(item.reference).id)}` : ''}</span>
      </li>)}</ul>
    </section>}
  </>;
}
