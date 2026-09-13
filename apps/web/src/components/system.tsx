'use client';

/**
 * The system workspace: one canonical layout for the core product object.
 *
 * The header answers "is this system current, and why?", names the stack ThreatVeil
 * has actually established, and carries the one contextual next action. Everything
 * beneath it is a tab over the same snapshot, so nothing is loaded twice and no tab can
 * disagree with the header.
 */

import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useEffect, useState } from 'react';
import { ArrowRight, Check, Download, FlaskConical, Radar } from 'lucide-react';
import { api, items, obj, str } from '@/lib/api';
import {
  ActivityTimeline, EmptyState, FailureState, NEXT_ACTION, PrimaryAction, Skeleton, StatusPill, SystemSwitcher,
  DECISION_STATUS, arr, clearanceView, list, num, plural, type Fields,
} from './product';
import {
  AuthorityView, ClaimLadder, DemoPanel, PassportWorkspace, Reestablish, SystemMap, useSandbox, useSystemIntelligence,
} from './intelligence';
import { ChangeAssurance } from './change-assurance';
import {
  AssuranceChain, ChangeImpact, GateState, PassportState, SetupProgress, chainFromSnapshot, impactOfChange,
  stagesFromSnapshot,
} from './signature';
import { CONNECTOR_ECOSYSTEM, SourceMark } from './ecosystem';
import { ChangePreview } from './change-preview';
import { EvidenceView } from './system-evidence';
import { ActivityView } from './system-activity';
import type { WorkspaceContext } from './workspace-parts';
import styles from './product.module.css';
import sig from './signature.module.css';

export const SYSTEM_TABS = [
  ['', 'Overview'], ['capabilities', 'Capabilities'], ['claims', 'Security claims'],
  ['evidence', 'Evidence'], ['activity', 'Activity'], ['share', 'Share'],
] as const;
/** Contextual views: reachable by deep link and from a call to action, never a tab. */
const CONTEXTUAL = new Set(['map', 'restore', 'setup']);
export const SYSTEM_VIEWS = new Set([...SYSTEM_TABS.map(([key]) => key), ...CONTEXTUAL]);

export function SystemWorkspace({ctx, systemId, view}: {ctx: WorkspaceContext; systemId: string; view: string}) {
  const router = useRouter();
  const systems = items(ctx.dashboard?.systems) as unknown as Fields[];
  const state = useSystemIntelligence(systemId);
  const {data, error, busy, reload} = state;
  const sandbox = useSandbox(ctx, systemId, state);
  const summary = obj(data?.summary);
  const synthetic = data?.fixture_profile === 'finance-v1';
  const environment = obj(summary.environment);
  const clearance = clearanceView(obj(summary.clearance));
  const suffix = view ? `/${view}` : '';
  const action = chooseAction(summary, systemId, `/app/systems/${systemId}${suffix}`);

  return <div>
    {/* A named region, so the status a screen reader lands on is addressable. */}
    <section className={styles.systemHeader} aria-label="System status" data-tour="system-header">
      <div className={styles.systemTop}>
        <div className={styles.systemIdentity}>
          <div className={styles.systemTitleRow}>
            <h1>{str(summary.system ? obj(summary.system).name : '', str(systems.find(s => str(s.id) === systemId)?.name, 'Protected system'))}</h1>
            {data && <StatusPill size="large" label={clearance.label} tone={clearance.tone} canonical={clearance.state}/>}
          </div>
          <div className={styles.systemContext}>
            <span>{str(environment.name, 'No environment yet')}</span>
            {!!environment.purpose && <span className="tag">{str(environment.purpose).toLowerCase()}</span>}
            {!!obj(summary.system).synthetic && <span className="tag">Synthetic example</span>}
            {!!obj(summary.clearance).decision_status && <span>
              {DECISION_STATUS[str(obj(summary.clearance).decision_status)] || str(obj(summary.clearance).decision_status)}
            </span>}
          </div>
          {!!data && <SystemStack items={arr(obj(data.stack).items)} systemId={systemId}/>}
          {!!data && <p className={styles.systemReason}>{str(summary.why, clearance.meaning)}</p>}
        </div>
        <div className={styles.systemActions}>
          <SystemSwitcher systems={systems} selected={systemId}
            onSelect={id => router.push(`/app/systems/${id}${SYSTEM_VIEWS.has(view) ? suffix : ''}`)}/>
          {!!data && action && <PrimaryAction href={action.path(systemId)}>{action.label}</PrimaryAction>}
        </div>
      </div>
      <nav className={styles.tabs} aria-label="System sections">
        {SYSTEM_TABS.map(([key, label]) => <Link key={key || 'overview'}
          href={`/app/systems/${systemId}${key ? `/${key}` : ''}`}
          aria-current={view === key ? 'page' : undefined}>{label}</Link>)}
      </nav>
    </section>

    <div className={styles.systemBody}>
      {error && <div className="notice error" role="alert">{error}</div>}
      {busy && <p role="status" className={styles.muted}>{busy}…</p>}
      {!data ? <Skeleton label="Loading this system" rows={4} header/> : <>
        {view === '' && <Overview data={data} systemId={systemId} synthetic={synthetic}
          busy={!!busy} sandbox={sandbox}/>}
        {view === 'capabilities' && <AuthorityView authority={obj(data.authority)} changes={arr(data.authority_changes)}
          systemId={systemId} ctx={ctx} environmentId={str(environment.id, '')} reload={reload}/>}
        {view === 'claims' && <ClaimLadder ctx={ctx} systemId={systemId}
          environmentId={str(environment.id, '')} reload={reload} evidence={obj(data.evidence)}/>}
        {view === 'evidence' && <EvidenceView ctx={ctx} data={data} systemId={systemId}
          environmentId={str(environment.id, '')} reload={reload}/>}
        {view === 'activity' && <ActivityView ctx={ctx} data={data} systemId={systemId} synthetic={synthetic}
          busy={!!busy} sandbox={sandbox}/>}
        {view === 'share' && <Share ctx={ctx} data={data} systemId={systemId} reload={reload}/>}
        {view === 'map' && <SystemMap graph={obj(data.system_map)}/>}
        {view === 'restore' && <Restore data={data} systemId={systemId} synthetic={synthetic}
          busy={!!busy} assess={sandbox.assess}/>}
        {view === 'setup' && <Setup ctx={ctx} data={data} systemId={systemId} synthetic={synthetic}
          busy={!!busy} assess={sandbox.assess}/>}
        <ChangePreview systemId={systemId} changes={arr(data.changes)} summary={summary}/>
      </>}
    </div>
  </div>;
}

const STACK_RELATION: Record<string, string> = {
  LIVE_SOURCE: 'live source', INSTRUMENTED: 'sends observations', IMPORTED: 'imported', DECLARED: 'declared',
};

/**
 * The stack ThreatVeil has established: one chip per technology, each carrying how it
 * is known. A live dot appears only when the source is actually connected.
 */
function SystemStack({items: stack, systemId}: {items: Fields[]; systemId: string}) {
  if (!stack.length) return null;
  return <ul className={sig.stack} aria-label="System stack">
    {stack.map(item => {
      const live = str(item.relationship) === 'LIVE_SOURCE';
      const relation = live && !item.connected ? 'live source · not connected' : STACK_RELATION[str(item.relationship)];
      return <li key={str(item.id)}>
        <Link href={`/app/systems/${systemId}/evidence#sources`} className={sig.stackItem}
          data-live={item.connected ? 'true' : undefined}
          title={[str(item.basis), ...list(item.also)].join(' · ')}>
          <SourceMark id={str(item.id)} name/><small>{relation}</small>
        </Link>
      </li>;
    })}
  </ul>;
}

/**
 * One dominant next action, in priority order, skipping whichever tab is already open.
 * A change review therefore offers Restore assurance rather than pointing at itself.
 */
function chooseAction(summary: Fields, systemId: string, here: string) {
  const state = str(obj(summary.clearance).state);
  const claims = obj(summary.claims);
  const outstanding = num(claims.needs_fresh_evidence) + num(claims.failed);
  const attention = state === 'NEEDS_REASSESSMENT' || state === 'NOT_CLEARED' || state === 'REVOKED';
  const order = !obj(summary.clearance).decision ? ['SET_UP']
    : arr(summary.open_changes).length ? ['REVIEW_CHANGE', 'RESTORE', 'RE_ESTABLISH']
    : attention ? ['RESTORE', 'RE_ESTABLISH']
    : outstanding ? ['RE_ESTABLISH', 'RESTORE']
    : ['SHARE'];
  return order.map(key => NEXT_ACTION[key]).find(candidate => candidate.path(systemId) !== here);
}

/** Is this system current? Why? What changed? Who relies on it? In that order. */
function Overview({data, systemId, synthetic, busy, sandbox}: {
  data: Fields; systemId: string; synthetic: boolean; busy: boolean; sandbox: ReturnType<typeof useSandbox>;
}) {
  const summary = obj(data.summary);
  const claims = obj(summary.claims);
  const authority = arr(obj(data.authority).authorities);
  const evidence = obj(obj(data.evidence).counts);
  const openChanges = arr(summary.open_changes);
  const changes = arr(data.changes);
  const latest = changes.find(c => !c.initial) || changes[0];
  const openChange = openChanges[0] ? changes.find(c => str(c.id) === str(openChanges[0].id)) : undefined;
  const shown = openChange || latest;
  const clearance = obj(summary.clearance);
  const cleared = str(clearance.state) === 'CLEARED';
  const stale = num(evidence.NEEDS_FRESH_EVIDENCE) + num(evidence.FAILED);
  const passports = arr(data.passports);
  const reliance = obj(data.reliance);

  return <>
    {/* One line of standing facts. A count that is zero and carries no diagnosis is omitted. */}
    <div className={styles.factLine} role="group" aria-label="System at a glance">
      {!!num(claims.total) && <span>
        <b>{num(claims.supported)} of {num(claims.total)}</b>
        <Link href={`/app/systems/${systemId}/claims`}>security claims current</Link>
      </span>}
      {!!num(claims.needs_fresh_evidence) && <span><b>{num(claims.needs_fresh_evidence)}</b> need fresh evidence</span>}
      {!!authority.length && <span>
        <b>{authority.length}</b><Link href={`/app/systems/${systemId}/capabilities`}>capabilities</Link>
      </span>}
      {!!num(evidence.SUPPORTED) && <span>
        <b>{num(evidence.SUPPORTED)}</b><Link href={`/app/systems/${systemId}/evidence`}>evidence current</Link>
      </span>}
      {!!stale && <span><b>{stale}</b> stale</span>}
      {!!clearance.last_current_clearance_at && <span>
        Last cleared <b>{new Date(str(clearance.last_current_clearance_at)).toLocaleString(undefined, {month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'})}</b>
      </span>}
      {!num(claims.total) && <span>No security claim is defined yet.</span>}
    </div>

    <div data-tour="chain"><AssuranceChain links={chainFromSnapshot(data, systemId)}/></div>

    {/* The change is the work object. When one is open it leads; otherwise the latest is history. */}
    {!!shown && <section className={styles.block} aria-labelledby="latest-change" data-tour="change-impact">
      <div className={styles.blockHead}>
        <h2 id="latest-change">{openChanges.length ? `${plural(openChanges.length, 'change')} awaiting review` : 'Latest change'}</h2>
        <Link href={`/app/systems/${systemId}/activity`}>All activity</Link>
      </div>
      <OverviewChange change={shown} summary={summary} systemId={systemId} open={!!openChange}/>
    </section>}

    <SetupProgress stages={stagesFromSnapshot(data, systemId)}/>

    {!!authority.length && <section className={styles.block} aria-labelledby="capabilities">
      <div className={styles.blockHead}>
        <h2 id="capabilities">Capabilities</h2>
        <Link href={`/app/systems/${systemId}/capabilities`}>{authority.length > 4 ? `All ${authority.length}` : 'View all'}</Link>
      </div>
      <div className={styles.rows}>
        {authority.slice(0, 4).map(item => <div key={str(item.id, str(item.subject))} className={styles.row}>
          <div className={styles.rowMain}>
            <strong>{str(item.label || item.subject || item.name)}</strong>
            {!!item.note && <span>{str(item.note)}</span>}
          </div>
          {!!item.basis && <span className="tag">{str(item.basis).replaceAll('_', ' ').toLowerCase()}</span>}
        </div>)}
      </div>
    </section>}

    <section className={styles.block} aria-labelledby="reliance" data-tour="reliance">
      <div className={styles.blockHead}>
        <h2 id="reliance">Who relies on this answer</h2>
        <Link href={`/app/integrations?system=${systemId}#assurance-gate`}>Integrations</Link>
      </div>
      <div className={sig.primitives}>
        <GateState gate={obj(data.gate)} reliance={reliance} action={
          <Link href={`/app/integrations?system=${systemId}#assurance-gate`} className="button outline small">
            {list(reliance.machine_consumers).length ? 'View integration' : 'Set up machine use'} <ArrowRight size={13}/>
          </Link>}/>
        <PassportState passports={passports} reliance={reliance} action={summary.passport_available || passports.length
          ? <Link href={`/app/systems/${systemId}/share`} className="button outline small">
              {passports.length ? 'View and share' : 'Create Passport'} <ArrowRight size={13}/></Link>
          : <Link href={`/app/systems/${systemId}/setup`} className="text-button">Establish verified assurance first <ArrowRight size={13}/></Link>}/>
      </div>
    </section>

    {changes.length > 1 && <section className={styles.block} aria-labelledby="recent">
      <div className={styles.blockHead}>
        <h2 id="recent">Recent activity</h2>
        <Link href={`/app/systems/${systemId}/activity`}>All activity</Link>
      </div>
      <ActivityTimeline events={changes.slice(0, 5).map(event => ({
        id: event.id, at: event.recorded_at, headline: event.headline, href: `?change=${str(event.id)}`,
        connector: obj(event.origin).connector,
        tone: str(obj(event.consequence).effect) === 'OPEN' ? 'attention' : 'neutral',
      }))}/>
    </section>}

    {/* Level 4. Present, addressable, and never the first thing a customer meets. */}
    <GuidanceSection systemId={systemId} environmentId={str(obj(summary.environment).id, '')} collapsed={cleared}/>

    {synthetic && <details className={styles.quiet} data-tour="synthetic-controls">
      <summary><FlaskConical size={13} aria-hidden="true"/>Synthetic example controls</summary>
      <div className={styles.quietBody}>
        <DemoPanel summary={summary} systemId={systemId} busy={busy}
          simulate={sandbox.simulate} assess={sandbox.assess}/>
      </div>
    </details>}

    <div className={styles.secondary}>
      <Link href={`/app/systems/${systemId}/map`} className="button outline small"><Radar size={14}/>System map</Link>
      <Link href={`/app/systems/${systemId}/setup`} className="text-button">Assurance setup <ArrowRight size={13}/></Link>
    </div>
  </>;
}

/**
 * The latest change as a Change Impact object. An open change carries its claims and its
 * two states; a settled one is history and never lists its claims as a warning.
 */
function OverviewChange({change, summary, systemId, open}: {change: Fields; summary: Fields; systemId: string; open: boolean}) {
  const impact = impactOfChange(change, summary);
  const settled = arr(obj(change.consequence).claims_affected).length;
  return <ChangeImpact {...impact} id={`overview-change-${str(change.id)}`} open={open}
    affected={open ? impact.affected : []} holds={open ? impact.holds : []}
    actions={open ? <>
      <Link href={`/app/systems/${systemId}/activity`} className="button outline small">Review change <ArrowRight size={13}/></Link>
      <Link href={`/app/systems/${systemId}/restore`} className="text-button">Restore assurance <ArrowRight size={13}/></Link>
      <Link href={`?change=${str(change.id)}`} scroll={false} className="text-button">Inspect</Link>
    </> : <>
      {!!settled && <span className={styles.muted}>
        <Check size={13} aria-hidden="true"/>{plural(settled, 'claim')} depended on this change and were re-established afterwards.
      </span>}
      <Link href={`?change=${str(change.id)}`} scroll={false} className="text-button">Inspect change</Link>
    </>}/>;
}

/** Every named limitation on this answer, and the next step for each. */
function GuidanceSection({systemId, environmentId, collapsed = false}: {
  systemId: string; environmentId: string; collapsed?: boolean;
}) {
  const [data, setData] = useState<Fields | null>(null);
  useEffect(() => {
    const controller = new AbortController();
    api<Fields>(`/systems/${systemId}/guidance${environmentId ? `?environment_id=${environmentId}` : ''}`,
      {signal: controller.signal}).then(setData).catch(() => undefined);
    return () => controller.abort();
  }, [systemId, environmentId]);
  const found = arr(data?.items);
  if (!data || !found.length) return null;
  // When the system is cleared these are caveats on a good answer, so they fold away.
  return <details className={styles.quiet} open={!collapsed}>
    <summary>{plural(found.length, 'limit')} on what ThreatVeil will say</summary>
    <div className={styles.quietBody}>
      {found.map(item => <FailureState key={str(item.code)} item={item}/>)}
    </div>
  </details>;
}

/** Share the current answer with a customer, a pipeline, or an auditor. */
function Share({ctx, data, systemId, reload}: {
  ctx: WorkspaceContext; data: Fields; systemId: string; reload: () => Promise<void>;
}) {
  const passports = arr(data.passports);
  const summary = obj(data.summary);
  return <>
    <div className={styles.sectionHead}>
      <div>
        <h2>Share current assurance</h2>
        <p>A signed statement about the system that exists today, and a separate check of whether it is still true.</p>
      </div>
    </div>
    <div data-tour="passport"><PassportState passports={passports} reliance={obj(data.reliance)}/></div>
    {!summary.passport_available && !passports.length && <EmptyState
      title="No current Passport."
      body="A Passport represents one bounded assurance case. It can only be issued once a system state exists to describe."
      action={<PrimaryAction href={`/app/systems/${systemId}/setup`}>Establish verified assurance</PrimaryAction>}/>}
    {(!!summary.passport_available || !!passports.length) &&
      <PassportWorkspace ctx={ctx} systemId={systemId} passports={passports} reload={reload}/>}
    <details className={styles.quiet}>
      <summary><Download size={13} aria-hidden="true"/>Signed records and verification details</summary>
      <div className={styles.quietBody}>
        <p className={styles.lead}>
          Verification needs the key that signed a record, not an account here. A scoped report and the
          published trust root let a third party check a record alone.
        </p>
        <div className={styles.secondary}>
          <a className="button outline small" href={`/api/backend/v1/reports/${systemId}`} download="threatveil-report.json">
            <Download size={14}/>Scoped report (JSON)
          </a>
          <a className="button outline small" href={`/api/backend/v1/reports/${systemId}/html`} download="threatveil-report.html">
            <Download size={14}/>Printable report
          </a>
          <Link href="/app/records" className="text-button">Published trust root <ArrowRight size={14}/></Link>
        </div>
      </div>
    </details>
  </>;
}

/** Restore assurance: contextual, reached from a call to action rather than browsed to. */
function Restore({data, systemId, synthetic, busy, assess}: {
  data: Fields; systemId: string; synthetic: boolean; busy: boolean;
  assess: (version: string, before?: string) => void;
}) {
  const plan = obj(data.reestablishment);
  return <>
    <Link href={`/app/systems/${systemId}`} className="back-link">← System overview</Link>
    <div data-tour="restore"><Reestablish plan={plan} synthetic={synthetic} busy={busy} assess={assess}/></div>
  </>;
}

/**
 * Verified assurance setup: a focused checklist tied to this system, shown when the
 * customer asks for a current evidence-backed answer. It is progressive disclosure over
 * the same six-stage workflow, which stays available beneath it for advanced setup.
 */
function Setup({ctx, data, systemId, synthetic, busy, assess}: {
  ctx: WorkspaceContext; data: Fields; systemId: string; synthetic: boolean; busy: boolean;
  assess: (version: string, before?: string) => void;
}) {
  const [guidance, setGuidance] = useState<Fields | null>(null);
  const [advanced, setAdvanced] = useState(false);
  const summary = obj(data.summary);
  const environmentId = str(obj(summary.environment).id, '');
  useEffect(() => {
    api<Fields>(`/systems/${systemId}/guidance${environmentId ? `?environment_id=${environmentId}` : ''}`)
      .then(setGuidance).catch(() => undefined);
  }, [systemId, environmentId]);
  const codes = new Set(arr(guidance?.items).map(item => str(item.code)));
  const claims = obj(summary.claims);
  const steps = [
    {title: 'Connect an evidence source',
      body: 'A source tells ThreatVeil when this system changes. An import is a snapshot you send; a live source is one ThreatVeil reads itself.',
      done: arr(data.sources).length > 0,
      action: <Link href={`/app/integrations?system=${systemId}`} className="button outline small">Connect a source <ArrowRight size={14}/></Link>,
      primary: <PrimaryAction href={`/app/integrations?system=${systemId}`}>Connect a source</PrimaryAction>},
    {title: 'Define what must stay true',
      body: 'One security claim in business language: the action it governs, the forbidden outcome, and the legitimate work that must keep succeeding.',
      done: num(claims.total) + num(claims.declared_not_executable) > 0,
      action: <Link href={`/app/systems/${systemId}/claims`} className="button outline small">Define a security claim <ArrowRight size={14}/></Link>,
      primary: <PrimaryAction href={`/app/systems/${systemId}/claims`}>Define a security claim</PrimaryAction>},
    {title: 'Qualify an observer',
      body: 'Positive assurance needs a qualified observation of the committed business effect. A tool response alone cannot establish one.',
      done: !!guidance && !codes.has('NO_QUALIFIED_OBSERVER'),
      action: <Link href="/app/settings/developer#observers" className="button outline small">Set up evidence <ArrowRight size={14}/></Link>,
      primary: <PrimaryAction href="/app/settings/developer#observers">Set up evidence</PrimaryAction>},
    {title: 'Establish a baseline',
      body: 'One approved verification produces the state a later change can invalidate. Without a baseline there is nothing for a change to affect.',
      done: !!obj(summary.clearance).decision,
      action: synthetic
        ? <button className="button outline small" disabled={busy} onClick={() => assess('fixed')}>Run finance baseline <ArrowRight size={14}/></button>
        : <Link href="/app/runs" className="button outline small">Execute approved checks <ArrowRight size={14}/></Link>,
      primary: synthetic
        ? <PrimaryAction disabled={busy} onClick={() => assess('fixed')}>Run finance baseline</PrimaryAction>
        : <PrimaryAction href="/app/runs">Execute approved checks</PrimaryAction>},
    {title: 'Watch, and restore when required',
      body: 'From here ThreatVeil watches for change, names the claims each one affects, and tells you what must be re-established.',
      done: arr(data.changes).length > 0,
      action: <Link href={`/app/systems/${systemId}/activity`} className="button outline small">View activity <ArrowRight size={14}/></Link>,
      primary: <PrimaryAction href={`/app/systems/${systemId}/activity`}>View activity</PrimaryAction>},
  ];
  // The baseline is what unlocks a real answer, so it leads while it is missing.
  const baseline = steps.findIndex(step => step.title === 'Establish a baseline');
  const lead = steps[baseline].done ? steps.findIndex(step => !step.done) : baseline;
  return <>
    <Link href={`/app/systems/${systemId}`} className="back-link">← System overview</Link>
    <div className={styles.sectionHead}>
      <div>
        <h2>Establish verified assurance</h2>
        <p>Five steps to a current, evidence-backed answer for this system. Each one raises what ThreatVeil can prove.</p>
      </div>
      {lead >= 0 && steps[lead].primary}
    </div>
    <ol className={styles.checklist}>
      {steps.map((step, index) => <li key={step.title} data-done={step.done ? 'true' : 'false'}>
        <span className={styles.checkMark} data-done={step.done ? 'true' : undefined} aria-hidden="true">
          {step.done ? <Check size={13}/> : index + 1}
        </span>
        <div>
          <h3>{step.title}</h3>
          <p>{step.body}</p>
          <span className="sr-only">{step.done ? 'Complete' : 'Not complete'}</span>
        </div>
        {!step.done && index !== lead ? step.action : null}
      </li>)}
    </ol>
    {/* Mounted only when opened, so the advanced workflow always reads current records. */}
    <details className="card" open={advanced} onToggle={event => setAdvanced(event.currentTarget.open)}>
      <summary className={styles.disclosure}>Advanced setup — the full authority, claim and baseline workflow</summary>
      {advanced && <div style={{marginTop: 16}}><ChangeAssurance ctx={ctx} systemId={systemId}/></div>}
    </details>
  </>;
}

export { CONNECTOR_ECOSYSTEM };
