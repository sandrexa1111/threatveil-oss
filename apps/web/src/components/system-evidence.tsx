'use client';

/**
 * Evidence: whether current evidence still supports each security claim, and why.
 *
 * One status summary, then one row per claim — status, why, when it was last verified,
 * what observed it, and what to do. A row opens a drawer (`?evidence=`) with the full
 * reasoning; identifiers, digests and canonical values sit under Advanced, never at the
 * first level. Every value shown is read from the evidence record as the API states it.
 */

import Link from 'next/link';
import { usePathname, useRouter, useSearchParams } from 'next/navigation';
import { useCallback, useEffect } from 'react';
import { AlertTriangle, ArrowRight } from 'lucide-react';
import { date, obj, str } from '@/lib/api';
import {
  CLAIM_STATE, Drawer, EmptyState, Facts, PrimaryAction, StatusPill, When, arr, list, num, plural, type Fields, type Tone,
} from './product';
import { MappingReview } from './intelligence';
import { CONNECTOR_ECOSYSTEM, EvidenceGlyph, SourceMark } from './ecosystem';
import type { WorkspaceContext } from './workspace-parts';
import styles from './product.module.css';
import c from './completion.module.css';

const GROUPS: {key: string; statuses: string[]; label: string; tone: Tone}[] = [
  {key: 'current', statuses: ['SUPPORTED'], label: 'Current', tone: 'ok'},
  {key: 'fresh', statuses: ['NEEDS_FRESH_EVIDENCE'], label: 'Needs fresh evidence', tone: 'attention'},
  {key: 'failed', statuses: ['FAILED'], label: 'Failed verification', tone: 'stop'},
  {key: 'unknown', statuses: ['UNKNOWN', 'DEFINED'], label: 'Unknown', tone: 'neutral'},
];
const OUTCOME: Record<string, string> = {
  PASS: 'passed', FAIL: 'failed', INCONCLUSIVE: 'inconclusive', SUCCESS: 'succeeded', FAILURE: 'failed', UNKNOWN: 'unknown',
};
const claimId = (claim: Fields) => str(claim.property_id || claim.claim_definition_id, '');

function why(claim: Fields) {
  const affected = arr(claim.affected_by);
  if (str(claim.status) === 'NEEDS_FRESH_EVIDENCE' && affected.length)
    return `Changed after this evidence was produced: ${str(affected[0].headline)}.`;
  return str(claim.currency);
}

function observedBy(claim: Fields) {
  const evidence = obj(claim.evidence);
  if (!evidence.id) return str(claim.status) === 'DEFINED' ? 'Declared only' : 'No verification yet';
  return str(evidence.ground_truth, evidence.observer_id ? 'Qualified observer' : 'Approved verification');
}

function next(claim: Fields, systemId: string) {
  const status = str(claim.status);
  if (status === 'NEEDS_FRESH_EVIDENCE' || status === 'FAILED') return {label: 'Restore assurance', href: `/app/systems/${systemId}/restore`};
  if (status === 'UNKNOWN' || status === 'DEFINED') return {label: 'Establish evidence', href: `/app/systems/${systemId}/setup`};
  return null;
}

export function EvidenceView({ctx, data, systemId, environmentId, reload}: {
  ctx: WorkspaceContext; data: Fields; systemId: string; environmentId: string; reload: () => Promise<void>;
}) {
  const router = useRouter();
  const pathname = usePathname();
  const params = useSearchParams();
  const evidence = obj(data.evidence);
  const claims = arr(evidence.claims);
  const counts = obj(evidence.counts);
  const sources = arr(data.sources);
  const openId = params.get('evidence') || '';
  const inspect = useCallback((id: string) => {
    router.replace(id ? `${pathname}?evidence=${encodeURIComponent(id)}` : pathname, {scroll: false});
  }, [router, pathname]);

  // ↑/↓ walk adjacent claims while the drawer is open, as the claim drawer does.
  useEffect(() => {
    if (!openId) return;
    function step(event: KeyboardEvent) {
      const target = event.target as HTMLElement | null;
      if (target && (target.isContentEditable || ['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName))) return;
      const delta = event.key === 'ArrowDown' ? 1 : event.key === 'ArrowUp' ? -1 : 0;
      if (!delta) return;
      const index = claims.findIndex(claim => claimId(claim) === openId);
      const neighbour = claims[index + delta];
      if (index < 0 || !neighbour) return;
      event.preventDefault();
      inspect(claimId(neighbour));
    }
    document.addEventListener('keydown', step);
    return () => document.removeEventListener('keydown', step);
  }, [openId, claims, inspect]);

  if (!claims.length && !sources.length) return <EmptyState
    title="No evidence established."
    body="Evidence is produced by an approved verification with a qualified observer. Until then ThreatVeil reports what it cannot claim, never a pass."
    action={<PrimaryAction href={`/app/systems/${systemId}/setup`}>Establish verified assurance</PrimaryAction>}/>;

  const groups = GROUPS.map(group => ({...group, count: group.statuses.reduce((n, s) => n + num(counts[s]), 0)}));
  const open = claims.find(claim => claimId(claim) === openId);

  return <>
    <section className={c.evidenceStatus} aria-labelledby="evidence-status">
      <div className={c.evidenceStatusHead}>
        <EvidenceGlyph size={14}/>
        <h2 id="evidence-status">Evidence status</h2>
        <span className={styles.muted}>Evidence must describe the system as it runs now.</span>
      </div>
      {!!claims.length && <div className={c.evidenceBar} aria-hidden="true">
        {groups.filter(group => group.count).map(group =>
          <span key={group.key} data-status={group.tone} style={{flexGrow: group.count}}/>)}
      </div>}
      <ul className={c.evidenceLegend}>
        {groups.filter(group => group.count || group.key !== 'failed').map(group =>
          <li key={group.key} title={`Canonical status: ${group.statuses.join(', ')}`}>
            <i data-status={group.tone} aria-hidden="true"/><b>{group.count}</b>{group.label}
          </li>)}
      </ul>
    </section>

    <section className={styles.block} aria-labelledby="evidence-by-claim">
      <div className={styles.blockHead}>
        <h2 id="evidence-by-claim">By security claim</h2>
        {!!claims.length && <span className={styles.more}>{plural(claims.length, 'claim')} · ↑↓ inside the panel</span>}
      </div>
      {!claims.length ? <p className={styles.muted}>No claim has an approved executable check yet, so there is no evidence to assess.</p>
        : <div className={c.table}>
          <div className={c.tableHead} aria-hidden="true">
            <span>Claim</span><span>Evidence status</span><span>Why</span><span>Last verified</span><span>Observed by</span><span/>
          </div>
          {claims.map(claim => {
            const id = claimId(claim);
            const state = CLAIM_STATE[str(claim.status)];
            const record = obj(claim.evidence);
            return <button key={id} type="button" className={c.evidenceRow} onClick={() => inspect(id)}
              aria-haspopup="dialog" aria-expanded={openId === id}>
              <strong>{str(claim.title)}</strong>
              <span>{state && <StatusPill label={state.label} tone={state.tone} canonical={str(claim.status)}/>}</span>
              <span className={c.cellMuted}>{why(claim)}</span>
              <span className={c.cellMuted}>{record.produced_at ? date(record.produced_at) : 'Never'}</span>
              <span className={c.cellMuted}>{observedBy(claim)}</span>
              <span className={c.cellAction}>Review</span>
            </button>;
          })}
        </div>}
    </section>

    <section className={styles.block} aria-labelledby="evidence-sources" id="sources">
      <div className={styles.blockHead}>
        <h2 id="evidence-sources">Where changes and observations come from</h2>
        <Link href={`/app/integrations?system=${systemId}`}>Connect a source</Link>
      </div>
      {!sources.length ? <p className={styles.muted}>No source is watching this system.</p>
        : <div className={c.sourceRows}>{sources.map(source => {
          const status = str(source.status);
          const imported = status === 'IMPORTED';
          const relationship = imported ? 'IMPORTED' : str(source.connector_id) === 'otel' ? 'INSTRUMENTED' : 'LIVE_SOURCE';
          const tone: Tone = source.connected ? 'ok' : imported || status === 'DECLARED' ? 'neutral' : 'attention';
          const label = source.connected ? 'Connected' : imported ? 'Imported snapshot'
            : status === 'DECLARED' ? 'No observation yet' : status.replaceAll('_', ' ').toLowerCase();
          return <div key={str(source.installation_id)} className={c.sourceRow}>
            <div>
              <SourceMark id={CONNECTOR_ECOSYSTEM[str(source.connector_id)]} name relationship={relationship}/>
              <p>{str(source.name)} · last observation {source.last_valid_at ? <When at={source.last_valid_at}/> : 'none yet'}</p>
            </div>
            <div className={c.sourceSide}>
              <StatusPill label={label} tone={tone} canonical={status}/>
            </div>
            {!!list(source.limitations).length && <details>
              <summary>Coverage and limitations</summary>
              <ul>{list(source.limitations).map(line => <li key={line}>{line}</li>)}</ul>
            </details>}
          </div>;
        })}</div>}
    </section>

    <details className={styles.quiet}>
      <summary>Dependency mapping — which source facts control which claims</summary>
      <div className={styles.quietBody}>
        <MappingReview ctx={ctx} systemId={systemId} environmentId={environmentId} reload={reload}/>
      </div>
    </details>

    <EvidenceDrawer claim={open} systemId={systemId} principle={str(evidence.principle, '')} onClose={() => inspect('')}/>
  </>;
}

function EvidenceDrawer({claim, systemId, principle, onClose}: {
  claim?: Fields; systemId: string; principle: string; onClose: () => void;
}) {
  if (!claim) return null;
  const record = obj(claim.evidence);
  const state = CLAIM_STATE[str(claim.status)];
  const action = next(claim, systemId);
  const affected = arr(claim.affected_by);
  return <Drawer open title={str(claim.title)} onClose={onClose} subtitle={<>
    {state && <StatusPill label={state.label} tone={state.tone} canonical={str(claim.status)}/>}
    <span className={styles.muted} aria-hidden="true">↑↓ next claim</span>
  </>}>
    <p style={{fontSize: 13, lineHeight: 1.55}}>{str(claim.currency)}</p>
    {!!affected.length && <section>
      <h3 style={{fontSize: 12, marginBottom: 6}}>What moved since this evidence</h3>
      <ul style={{listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 5, fontSize: 12.5}}>
        {affected.map(item => <li key={str(item.change_id)} style={{display: 'flex', gap: 7, alignItems: 'flex-start'}}>
          <AlertTriangle size={13} aria-hidden="true" style={{color: 'var(--amber)', marginTop: 2}}/>
          <Link href={`/app/systems/${systemId}/activity#change-${str(item.change_id)}`}>{str(item.headline)}</Link>
        </li>)}
      </ul>
    </section>}
    <Facts rows={[
      ['Last verified', record.produced_at ? <When at={record.produced_at}/> : 'Never'],
      ['Observed by', observedBy(claim)],
      ['Observation', record.id ? `${record.qualified ? 'Qualified' : 'Not qualified'}${record.coverage_complete === false ? ' · coverage incomplete' : ''}${record.synthetic ? ' · synthetic fixture' : ''}` : ''],
      ['Security', record.id || claim.security !== 'INCONCLUSIVE' ? `Forbidden outcome ${OUTCOME[str(claim.security)] === 'passed' ? 'prevented' : OUTCOME[str(claim.security)] || str(claim.security).toLowerCase()}` : ''],
      ['Useful task', record.id ? OUTCOME[str(claim.legitimate_task_outcome)] || str(claim.legitimate_task_outcome).toLowerCase() : ''],
      ['System state used', record.id ? (record.for_current_state ? 'The system as it runs now' : 'An earlier system state') : ''],
      ['Relied on until', record.expires_at ? <When at={record.expires_at}/> : ''],
      ['Governs', arr(claim.governs).map(g => str(g.label)).join(', ')],
      ['Forbidden', str(claim.forbidden_outcome, '')],
      ['Must keep working', str(claim.legitimate_task, '')],
      ['Ground-truth source', str(claim.ground_truth_source, '')],
    ]}/>
    {!!list(claim.reasons).length && <details><summary className={styles.muted}>Why ThreatVeil concluded this</summary>
      <ul style={{margin: '8px 0 0', paddingLeft: 18, fontSize: 12.5, display: 'grid', gap: 4}}>
        {list(claim.reasons).map(reason => <li key={reason}>{reason}</li>)}</ul></details>}
    {(!!list(record.limitations).length || !!principle) && <section>
      <h3 style={{fontSize: 12, marginBottom: 6}}>Limitations</h3>
      <ul style={{margin: 0, paddingLeft: 18, fontSize: 12, color: 'var(--muted)', display: 'grid', gap: 3}}>
        {list(record.limitations).map(line => <li key={line}>{line}</li>)}
        {!!principle && <li>{principle}</li>}
      </ul>
    </section>}
    <div style={{display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'center'}}>
      {action && <Link href={action.href} className="button dark small">{action.label} <ArrowRight size={13}/></Link>}
      <Link href="/app/records" className="text-button">Signed records <ArrowRight size={13}/></Link>
    </div>
    <details><summary className={styles.muted}>Advanced</summary>
      <Facts rows={[
        ['Claim ID', <span key="id" className="mono" style={{fontSize: 12}}>{claimId(claim)}</span>],
        ['Evidence status', <span key="s" className="mono" style={{fontSize: 12}}>{str(claim.status)}</span>],
        ['Applicability', <span key="a" className="mono" style={{fontSize: 12}}>{str(claim.applicability)}</span>],
        ['Evidence record', record.id ? <span key="r" className="mono" style={{fontSize: 12}}>{str(record.id)}</span> : ''],
        ['Verification run', record.run_id ? <Link key="run" href={`/app/runs/${str(record.run_id)}`} className="mono" style={{fontSize: 12}}>{str(record.run_id)}</Link> : ''],
        ['Evidence digest', record.evidence_digest ? <span key="d" className="mono" style={{fontSize: 12}}>{str(record.evidence_digest)}</span> : ''],
        ['Observer', record.observer_id ? <span key="o" className="mono" style={{fontSize: 12}}>{str(record.observer_id)}</span> : ''],
      ]}/>
    </details>
  </Drawer>;
}
