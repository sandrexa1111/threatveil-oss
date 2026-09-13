'use client';

/**
 * Home: the operating centre. It answers one question — what needs my attention? —
 * and it is the only place a brand-new organization is onboarded.
 */

import Link from 'next/link';
import { useCallback, useEffect, useState } from 'react';
import { ArrowRight, Compass, FlaskConical, GitPullRequest, Plus } from 'lucide-react';
import { api, obj, str } from '@/lib/api';
import {
  ActivityTimeline, AttentionItem, CurrentSystemRow, EmptyState, PrimaryAction, Skeleton,
  arr, num, plural, useListKeys, type Fields,
} from './product';
import { SourceMark, type EcosystemId } from './ecosystem';
import { ChangePreview } from './change-preview';
import styles from './product.module.css';
import c from './completion.module.css';

const ACTIVITY_TONE: Record<string, string> = {OPEN: 'attention', ALLOW: 'ok', BLOCK: 'stop', ISSUED: 'neutral'};

export function Home() {
  const [data, setData] = useState<Fields | null>(null);
  const [error, setError] = useState('');
  const attentionKeys = useListKeys<HTMLDivElement>();
  const currentKeys = useListKeys<HTMLDivElement>();
  const load = useCallback(async () => {
    try { setData(await api<Fields>('/home')); setError(''); }
    catch (e) { setError(e instanceof Error ? e.message : 'Unable to load your systems.'); }
  }, []);
  useEffect(() => { load(); }, [load]);

  if (error) return <div className="notice error" role="alert">{error}<button className="text-button" onClick={load}>Try again</button></div>;
  if (!data) return <Skeleton label="Loading your systems" rows={3} header/>;

  const counts = obj(data.counts);
  if (!num(counts.systems)) return <ZeroState/>;

  const attention = arr(data.attention);
  const current = arr(data.current);
  const activity = arr(data.activity);
  const needsEvidence = num(counts.claims_needing_evidence);
  const awaiting = num(counts.awaiting_review);
  const summary = [
    attention.length ? `${plural(attention.length, 'system')} ${attention.length === 1 ? 'needs' : 'need'} attention` : 'Every system is current',
    needsEvidence ? `${plural(needsEvidence, 'claim')} ${needsEvidence === 1 ? 'needs' : 'need'} fresh evidence` : '',
    awaiting ? `${plural(awaiting, 'dependency mapping')} awaiting review` : '',
  ].filter(Boolean);

  return <div className={styles.root}>
    <section className={styles.attentionSummary} data-tone={attention.length ? 'attention' : 'ok'} aria-label="Attention summary">
      <strong>{summary[0]}</strong>
      {summary.slice(1).map(line => <span key={line}>{line}</span>)}
    </section>

    {attention.length > 0 && <section aria-labelledby="needs-attention">
      <div className={styles.sectionHead}>
        <h2 id="needs-attention">Needs attention</h2>
        <p>What happened, why it matters, and what to do next. ↑↓ moves between systems.</p>
      </div>
      <div className={styles.attentionList} ref={attentionKeys.ref} onKeyDown={attentionKeys.onKeyDown}>
        {attention.map(row => <AttentionItem key={str(row.id)} row={row}/>)}
      </div>
    </section>}

    {current.length > 0 && <section aria-labelledby="current-systems">
      <div className={styles.sectionHead}>
        <h2 id="current-systems">Current systems</h2>
        <Link href="/app/systems" className="text-button">All systems <ArrowRight size={14}/></Link>
      </div>
      <div className={styles.currentList} ref={currentKeys.ref} onKeyDown={currentKeys.onKeyDown}>
        {current.map(row => <CurrentSystemRow key={str(row.id)} row={row}/>)}
      </div>
    </section>}

    {!attention.length && !current.length && <EmptyState
      title="No protected system is ready yet."
      body="Connect a system so ThreatVeil can watch what changes and tell you which security claims it affects."
      action={<PrimaryAction href="/app/systems/new">Connect a system</PrimaryAction>}/>}

    {activity.length > 0 && <section aria-labelledby="recent-activity">
      <div className={styles.sectionHead}><h2 id="recent-activity">Recent activity</h2></div>
      <ActivityTimeline showSystem events={activity.slice(0, 10).map(event => ({
        ...event, tone: ACTIVITY_TONE[str(event.detail)] || 'neutral',
        href: str(event.kind) === 'CHANGE' && event.id ? `/app?change=${str(event.id)}&system=${str(event.system_id)}` : undefined,
      }))}/>
    </section>}

    <section className={styles.quickActions} aria-label="Quick actions">
      <Link href="/app/changes/propose" className="button dark small"><GitPullRequest size={15}/>Check a proposed change</Link>
      <Link href="/app/systems/new" className="button outline small"><Plus size={15}/>Connect a system</Link>
    </section>
    <ChangePreview/>
  </div>;
}

/** The product loop, in the order a customer meets it. */
const FLOW: [string, string, string][] = [
  ['Connect', 'Import or connect', 'ThreatVeil reads what your agent is declared to do.'],
  ['Define', 'Say what must stay true', 'One security claim in business language.'],
  ['Check', 'Check a change first', 'See which claim a change would affect before it ships.'],
  ['Verify', 'Establish evidence', 'A qualified verification makes the answer current.'],
  ['Keep current', 'Watch and restore', 'Machines and customers can check the answer.'],
];

/**
 * Where a customer's agent already lives. Each identity carries its exact relationship:
 * an import is never presented as a live connection, and nothing here implies a partnership.
 */
const ECOSYSTEM_LINE: [EcosystemId, string][] = [
  ['github', 'live source'], ['claude_code', 'import'], ['mcp', 'connect or import'],
  ['langgraph', 'import'], ['crewai', 'import'], ['openai_agents', 'trace import'],
];

/**
 * The single onboarding experience. It appears here and nowhere else, so a new
 * customer meets one explanation of ThreatVeil rather than one per route.
 */
export function ZeroState() {
  const [gallery, setGallery] = useState<Fields | null>(null);
  const [example, setExample] = useState(false);
  useEffect(() => { api<Fields>('/example-gallery').then(setGallery).catch(() => undefined); }, []);
  return <div className={styles.zero} style={{maxWidth: 820}}>
    <div>
      <h1>Protect your first AI system</h1>
      <p>Import the agent definition you already use. ThreatVeil reads it, then asks you what must stay true.</p>
    </div>
    <div className={styles.zeroActions}>
      <PrimaryAction href="/app/systems/new">Import a definition</PrimaryAction>
      <button className="button outline small" aria-expanded={example} onClick={() => setExample(!example)}>
        <FlaskConical size={14}/>{example ? 'Hide the example' : 'Explore an example'}
      </button>
      <Link href="/app?tour=start" className="text-button"><Compass size={14}/>Explore how ThreatVeil works</Link>
    </div>
    <div className={c.ecosystemLine} aria-label="Import or connect from">
      <span>Import or connect from</span>
      <ul>{ECOSYSTEM_LINE.map(([id, relation]) => <li key={id}>
        <SourceMark id={id} name/><small>{relation}</small>
      </li>)}</ul>
    </div>
    <ol className={c.flow} aria-label="How ThreatVeil works">
      {FLOW.map(([step, title, body]) => <li key={step}>
        <span>{step}</span><strong>{title}</strong><small>{body}</small>
      </li>)}
    </ol>
    {example && <ExampleGallery gallery={gallery}/>}
  </div>;
}

/** Exactly one card runs, and it is labelled synthetic. The rest are templates. */
function ExampleGallery({gallery}: {gallery: Fields | null}) {
  if (!gallery) return <Skeleton label="Loading examples" rows={2}/>;
  return <section aria-labelledby="examples">
    <div className={styles.sectionHead}>
      <h2 id="examples">Examples</h2>
      <p>{str(gallery.note)}</p>
    </div>
    <div className={styles.integrationGrid}>
      {arr(gallery.cards).map(card => <article key={str(card.id)} className={styles.integration}>
        <div className={styles.integrationHead}>
          <h3>{str(card.title)}</h3>
          <span className="tag">{card.runnable ? 'Runnable' : 'Template'}</span>
        </div>
        <p>{str(card.shows)}</p>
        <p className={styles.muted}>{str(card.label)}</p>
        {!!card.runnable && <div className={styles.integrationFoot}>
          <Link href="/app/systems/new?example=finance" className="button outline small">
            Run the Finance example <ArrowRight size={14}/>
          </Link>
        </div>}
      </article>)}
    </div>
  </section>;
}
