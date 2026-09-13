'use client';

/**
 * Activity is assurance memory, not an audit log: how this system's assurance changed
 * over time. Every event is read from the snapshot — a recorded change, a superseded
 * clearance, a verification decision, a Passport, a machine or external check — and
 * the full change records and the raw lifecycle stay one disclosure away.
 */

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useMemo, useState } from 'react';
import { date, obj, str } from '@/lib/api';
import { EmptyState, PrimaryAction, arr, list, type Fields, type Tone } from './product';
import { ChangeFeed, Clearance, DemoPanel, type useSandbox } from './intelligence';
import { AssuranceGlyph, CONNECTOR_ECOSYSTEM, EvidenceGlyph, GateGlyph, PassportGlyph, SourceMark } from './ecosystem';
import type { WorkspaceContext } from './workspace-parts';
import styles from './product.module.css';
import c from './completion.module.css';

type Kind = 'changes' | 'assurance' | 'verification' | 'external';
type HistoryEvent = {
  id: string; at: string; kind: Kind; title: string; detail?: React.ReactNode; tone: Tone;
  icon: React.ReactNode; href?: string; canonical?: string;
};
const FILTERS: [Kind | 'all', string][] = [
  ['all', 'All'], ['changes', 'Changes'], ['assurance', 'Assurance'], ['verification', 'Verification'], ['external', 'External use'],
];
const OUTCOME: Record<string, string> = {
  PASS: 'passed', FAIL: 'failed', SUCCESS: 'succeeded', FAILURE: 'failed', INCONCLUSIVE: 'inconclusive', UNKNOWN: 'unknown',
};
const shown = (value: unknown, present?: unknown) =>
  present === false || value === null || value === undefined ? 'not set' : typeof value === 'boolean' ? String(value) : str(value);

export function history(data: Fields, pathname: string): HistoryEvent[] {
  const events: HistoryEvent[] = [];
  const superseded = new Set<string>();
  const changes = [...arr(data.changes)].sort((a, b) => str(a.recorded_at).localeCompare(str(b.recorded_at)));
  for (const change of changes) {
    const id = str(change.id);
    const origin = obj(change.origin);
    const consequence = obj(change.consequence);
    const effect = str(consequence.effect);
    const moved = arr(obj(change.authority).dimensions).find(d => str(d.direction) !== 'AUTHORITY_EQUIVALENT');
    events.push({
      id: `change-${id}`, at: str(change.recorded_at), kind: 'changes', title: str(change.headline),
      tone: effect === 'OPEN' ? 'attention' : 'neutral', canonical: effect, href: `${pathname}?change=${id}`,
      icon: origin.connector ? <SourceMark id={CONNECTOR_ECOSYSTEM[str(origin.connector)]}/> : <EvidenceGlyph size={14}/>,
      detail: moved
        ? <><code>{str(moved.subject)} {str(moved.condition, '')}</code> {shown(moved.before, moved.present_before)} → {shown(moved.after, moved.present_after)}</>
        : change.initial ? `First observation · ${str(origin.name)}` : str(origin.name),
    });
    const prior = obj(change.prior_clearance);
    if (prior.id && str(prior.status) === 'SUPERSEDED' && !superseded.has(str(prior.id))) {
      superseded.add(str(prior.id));
      const reached = arr(consequence.claims_affected).filter(claim => claim.open);
      events.push({
        id: `superseded-${id}`, at: str(change.recorded_at), kind: 'assurance', title: 'Previous assurance superseded',
        tone: 'attention', canonical: 'SUPERSEDED', icon: <AssuranceGlyph size={14}/>,
        detail: reached.length ? `${reached.map(claim => str(claim.title)).join(', ')} ${reached.length === 1 ? 'needs' : 'need'} fresh evidence` : undefined,
      });
    }
  }
  // Decisions in order, so "restored" is only ever said after assurance was actually lost.
  const timeline = [...arr(obj(data.lifecycle).timeline)].sort((a, b) => str(a.at).localeCompare(str(b.at)));
  let established = false, lost = false;
  for (const entry of timeline) {
    if (str(entry.kind) !== 'DECISION') { lost = true; continue; }
    const action = str(entry.action), security = str(entry.security), task = str(entry.legitimate_task);
    events.push({
      id: `decision-${str(entry.id)}`, at: str(entry.at), kind: 'verification', canonical: action,
      title: action === 'ALLOW' ? 'Verification passed' : security === 'FAIL' ? 'Security failed'
        : task === 'FAILURE' ? 'Useful task failed' : 'Verification did not clear',
      detail: `Security ${OUTCOME[security] || security.toLowerCase()} · useful task ${OUTCOME[task] || task.toLowerCase()}`,
      tone: action === 'ALLOW' ? 'ok' : 'stop', icon: <EvidenceGlyph size={14}/>,
    });
    if (action === 'ALLOW') {
      events.push({
        id: `assurance-${str(entry.id)}`, at: str(entry.at), kind: 'assurance',
        title: established && lost ? 'Assurance restored' : 'Assurance established', tone: 'ok', canonical: 'CLEARED',
        icon: <AssuranceGlyph size={14}/>,
      });
      established = true; lost = false;
    } else lost = true;
  }
  for (const passport of arr(data.passports)) events.push({
    id: `passport-${str(passport.id)}`, at: str(passport.issued_at), kind: 'external', title: 'Passport issued',
    detail: `For ${str(passport.audience)} · clearance at issue: ${str(passport.clearance)}`, tone: 'neutral',
    icon: <PassportGlyph size={14}/>,
  });
  const reliance = obj(data.reliance);
  if (reliance.last_machine_check_at) events.push({
    id: 'gate-read', at: str(reliance.last_machine_check_at), kind: 'external', title: 'Assurance Gate read by a machine',
    detail: `${list(reliance.machine_consumers).join(', ')} · recorded once per consumer per hour`, tone: 'neutral',
    icon: <GateGlyph size={14}/>,
  });
  if (reliance.last_external_check_at) events.push({
    id: 'passport-check', at: str(reliance.last_external_check_at), kind: 'external',
    title: 'Passport status checked by an outside party', tone: 'neutral', icon: <PassportGlyph size={14}/>,
  });
  return events.sort((a, b) => b.at.localeCompare(a.at));
}

export function ActivityView({ctx, data, systemId, synthetic, busy, sandbox}: {
  ctx: WorkspaceContext; data: Fields; systemId: string; synthetic: boolean; busy: boolean;
  sandbox: ReturnType<typeof useSandbox>;
}) {
  const pathname = usePathname();
  const [filter, setFilter] = useState<Kind | 'all'>('all');
  const events = useMemo(() => history(data, pathname), [data, pathname]);
  const changes = arr(data.changes);
  if (!events.length) return <>
    <EmptyState
      title="No assurance history yet."
      body="When a source reports that this system moved, or a verification runs, ThreatVeil records what changed and which security claims it affected."
      action={<PrimaryAction href="/app/changes/propose">Check a proposed change</PrimaryAction>}/>
    {synthetic && <DemoPanel summary={obj(data.summary)} systemId={systemId} busy={busy}
      simulate={sandbox.simulate} assess={sandbox.assess}/>}
  </>;
  const visible = filter === 'all' ? events : events.filter(event => event.kind === filter);
  return <>
    <section className={styles.block} aria-labelledby="assurance-history">
      <div className={styles.blockHead}>
        <h2 id="assurance-history">Assurance history</h2>
        <div className={c.filters} role="group" aria-label="Filter assurance history">
          {FILTERS.map(([key, label]) => {
            const count = key === 'all' ? events.length : events.filter(event => event.kind === key).length;
            return <button key={key} type="button" aria-pressed={filter === key} onClick={() => setFilter(key)}
              disabled={!count && key !== 'all'}>{label}<small>{count}</small></button>;
          })}
        </div>
      </div>
      <ol className={c.history}>
        {visible.map(event => <li key={event.id} data-tone={event.tone} data-kind={event.kind}>
          <time className={c.historyTime} dateTime={event.at} title={new Date(event.at).toLocaleString()}>{date(event.at)}</time>
          <span className={c.historyIcon} aria-hidden="true">{event.icon}</span>
          <div className={c.historyMain}>
            {event.href
              ? <Link href={event.href} scroll={false}><strong>{event.title}</strong></Link>
              : <strong>{event.title}</strong>}
            {!!event.detail && <span title={event.canonical ? `Canonical status: ${event.canonical}` : undefined}>{event.detail}</span>}
          </div>
        </li>)}
        {!visible.length && <li data-tone="neutral"><span className={c.historyMain}>Nothing of this kind yet.</span></li>}
      </ol>
    </section>

    {!!changes.length && <section className={styles.block} aria-labelledby="change-records">
      <div className={styles.blockHead}><h2 id="change-records">Changes in detail</h2></div>
      <ChangeFeed changes={changes} synthetic={synthetic} busy={busy} simulate={sandbox.simulate}
        ctx={ctx} systemId={systemId} summary={obj(data.summary)}/>
    </section>}

    <details className={styles.quiet}>
      <summary>Clearance lifecycle and record history</summary>
      <div className={styles.quietBody}>
        <Clearance lifecycle={obj(data.lifecycle)} gate={obj(data.gate)} memory={obj(data.memory)} systemId={systemId} showGate={false}/>
      </div>
    </details>
  </>;
}
