'use client';

/**
 * ThreatVeil's signature objects. Each answers one question only ThreatVeil asks:
 *
 * - AssuranceChain — why does the current answer hold, and where did it stop holding?
 * - ChangeImpact  — what did this change affect, and what still holds?
 * - GateState     — what does a machine read, and who has read it?
 * - PassportState — what can an outside party verify, and is it still current?
 * - SetupProgress — how far this system's assurance has been established.
 *
 * They present canonical values; they never derive a status the API has not stated.
 * Every link in the chain comes from the system snapshot, and the final link is the
 * clearance itself, so the chain cannot disagree with the header.
 */

import Link from 'next/link';
import { AlertTriangle, ArrowUpRight, Check, CircleHelp } from 'lucide-react';
import { obj, str } from '@/lib/api';
import {
  AUTHORITY_MOVE, AuthorityDiff, DECISION_STATUS, StatusPill, When, arr, clearanceView, list, num, plural,
  type Fields, type Tone,
} from './product';
import {
  AssuranceGlyph, AuthorityGlyph, CONNECTOR_ECOSYSTEM, GateGlyph, PassportGlyph, SourceMark, type EcosystemId,
} from './ecosystem';
import styles from './signature.module.css';

/* --- Assurance chain ------------------------------------------------------------ */

export type ChainState = 'current' | 'changed' | 'affected' | 'stale' | 'attention' | 'stop' | 'none';
export type ChainLink = {
  key: string; label: string; value: string; detail?: string; state: ChainState; canonical?: string; href?: string;
};
const CHAIN_WORD: Record<ChainState, string> = {
  current: 'Holds', changed: 'Changed', affected: 'Affected', stale: 'Needs fresh evidence',
  attention: 'Needs attention', stop: 'Not cleared', none: 'Not established',
};
const capabilities = (n: number) => `${n} ${n === 1 ? 'capability' : 'capabilities'}`;

export function AssuranceChain({links, level = 2}: {links: ChainLink[]; level?: 2 | 3}) {
  const broken = links.findIndex(link => link.state !== 'current');
  const Heading = level === 2 ? 'h2' : 'h3';
  const intact = broken < 0;
  return <section className={styles.chain} aria-label="Assurance chain" data-intact={intact ? 'true' : undefined}>
    <div className={styles.chainHead}>
      <AssuranceGlyph size={14} className={styles.chainGlyph}/>
      <Heading>{intact ? 'Why this answer holds' : 'Where the answer stops holding'}</Heading>
    </div>
    <ol className={styles.chainTrack}>
      {links.map((link, index) => <li key={link.key} className={styles.chainLink} data-state={link.state}
        data-after-break={broken >= 0 && index > broken ? 'true' : undefined}>
        <span className={styles.chainNode} aria-hidden="true"/>
        <span className={styles.chainLabel}>{link.label}</span>
        {link.href
          ? <Link href={link.href} className={styles.chainValue}>{link.value}</Link>
          : <strong className={styles.chainValue}>{link.value}</strong>}
        {!!link.detail && <span className={styles.chainDetail} title={link.detail}>{link.detail}</span>}
        <span className={styles.chainState} title={link.canonical ? `Canonical status: ${link.canonical}` : undefined}>
          {CHAIN_WORD[link.state]}
        </span>
      </li>)}
    </ol>
  </section>;
}

/** The chain for one system snapshot. Every link is read from structured facts. */
export function chainFromSnapshot(data: Fields, systemId: string): ChainLink[] {
  const summary = obj(data.summary);
  const clearance = clearanceView(obj(summary.clearance));
  const claims = obj(summary.claims);
  const environment = obj(summary.environment);
  const authorities = arr(obj(data.authority).authorities);
  const counts = obj(obj(data.evidence).counts);
  const open = arr(data.changes).find(change => str(obj(change.consequence).effect) === 'OPEN');
  const authority = obj(open?.authority);
  const classification = str(authority.classification, '');
  const moved = arr(authority.dimensions).find(d => str(d.direction) !== 'AUTHORITY_EQUIVALENT');
  const affected = arr(obj(open?.consequence).claims_affected);
  const stale = num(counts.NEEDS_FRESH_EVIDENCE) + num(counts.FAILED);
  const base = `/app/systems/${systemId}`;
  const decision = str(obj(summary.clearance).decision_status, '');

  const authorityLink: ChainLink = open && (classification === 'AUTHORITY_EXPANDED' || classification === 'UNKNOWN_IMPACT')
    ? {key: 'authority', label: 'Authority', value: AUTHORITY_MOVE[classification].label, canonical: classification,
        detail: moved ? `${str(moved.subject)} · ${str(moved.condition, '')}` : undefined,
        state: classification === 'AUTHORITY_EXPANDED' ? 'changed' : 'attention', href: `${base}/capabilities`}
    : {key: 'authority', label: 'Authority', value: authorities.length ? capabilities(authorities.length) : 'Not declared',
        state: authorities.length ? 'current' : 'none', href: `${base}/capabilities`};

  const claimLink: ChainLink = affected.length
    ? {key: 'claim', label: 'Security claim', value: `${plural(affected.length, 'claim')} affected`,
        detail: str(affected[0].title), state: 'affected', href: `${base}/claims`}
    : num(claims.total)
      ? {key: 'claim', label: 'Security claims', value: `${num(claims.supported)} of ${num(claims.total)} current`,
          state: num(claims.needs_fresh_evidence) + num(claims.failed) ? 'attention'
            : num(claims.supported) === num(claims.total) ? 'current' : 'none', href: `${base}/claims`}
      : {key: 'claim', label: 'Security claims',
          value: num(claims.defined_not_executable) ? `${num(claims.defined_not_executable)} declared` : 'None defined',
          detail: num(claims.defined_not_executable) ? 'Not yet verified' : undefined, state: 'none', href: `${base}/claims`};

  const evidenceLink: ChainLink = stale
    ? {key: 'evidence', label: 'Evidence', value: `${stale} need${stale === 1 ? 's' : ''} fresh evidence`,
        state: 'stale', canonical: 'NEEDS_FRESH_EVIDENCE', href: `${base}/evidence`}
    : num(counts.SUPPORTED)
      ? {key: 'evidence', label: 'Evidence', value: `${num(counts.SUPPORTED)} current`, state: 'current',
          canonical: 'SUPPORTED', href: `${base}/evidence`}
      : {key: 'evidence', label: 'Evidence', value: 'Not established', state: 'none', href: `${base}/evidence`};

  const tone: Record<Tone, ChainState> = {ok: 'current', attention: 'attention', stop: 'stop', neutral: 'none'};
  return [
    {key: 'system', label: 'System', value: str(obj(summary.system).name, 'System'),
      detail: str(environment.name, 'No environment yet'), state: environment.id ? 'current' : 'none'},
    authorityLink, claimLink, evidenceLink,
    {key: 'assurance', label: 'Current assurance', value: clearance.label, state: tone[clearance.tone],
      canonical: clearance.state, detail: decision ? DECISION_STATUS[decision] || undefined : undefined},
  ];
}

/* --- Change impact ---------------------------------------------------------------- */

export type ImpactSide = {caption: string; label: string; state: string; tone: Tone; note?: string};
export type ImpactSource = {
  connector?: string; name?: string; relationship?: string; reference?: string; url?: string;
};

/** "true" and "false" read as values; absence is never rendered as false. */
function value(raw: unknown, present?: unknown) {
  if (present === false || raw === null || raw === undefined) return 'not set';
  if (typeof raw === 'boolean') return raw ? 'true' : 'false';
  return str(raw);
}

const ACQUISITION: Record<string, string> = {
  IMPORTED: 'IMPORTED', API_OBSERVED: 'LIVE_SOURCE', INSTRUMENTED: 'INSTRUMENTED',
};

/** A source as it appears on a detected change: its identity and how it was acquired. */
export function sourceOfOrigin(origin: Fields): ImpactSource {
  return {connector: str(origin.connector, ''), name: str(origin.name, ''),
    relationship: ACQUISITION[str(origin.acquisition, '')] || undefined};
}

export function ChangeImpact({
  id, source, headline, when, whenLabel = '', dimensions, classification, components = [], affected, holds,
  declared = [], before, after, open = false, actions, level = 3, statesLabel = 'Assurance before and after',
}: {
  id?: string; source: ImpactSource; headline: string; when?: unknown; whenLabel?: string; dimensions: Fields[];
  classification?: string; components?: Fields[]; affected: {key: string; title: string; note?: string}[];
  holds: string[]; declared?: {key: string; title: string}[]; before?: ImpactSide; after?: ImpactSide;
  open?: boolean; actions?: React.ReactNode; level?: 2 | 3; statesLabel?: string;
}) {
  const moved = dimensions.filter(d => str(d.direction) !== 'AUTHORITY_EQUIVALENT');
  const lead = moved[0];
  const move = classification && classification !== 'AUTHORITY_EQUIVALENT' ? AUTHORITY_MOVE[classification] : undefined;
  const Heading = level === 2 ? 'h2' : 'h3';
  const Sub = level === 2 ? 'h3' : 'h4';
  const eco = (CONNECTOR_ECOSYSTEM[source.connector || ''] || 'definition') as EcosystemId;
  const field = lead ? str(lead.condition, str(lead.kind, '').toLowerCase()) : '';
  return <article className={styles.impact} id={id} data-open={open ? 'true' : undefined}>
    <header className={styles.impactHead}>
      <div className={styles.impactSource}>
        <SourceMark id={eco} name relationship={source.relationship}/>
        {!!source.name && <span className={styles.impactOrigin}>{source.name}</span>}
        {!!source.reference && <span className={styles.impactRef}>{source.reference}</span>}
        {!!source.url && <a href={source.url} target="_blank" rel="noreferrer noopener" className={styles.impactLink}>
          Open source <ArrowUpRight size={11}/></a>}
      </div>
      {!!when && <span className={styles.impactWhen}>{whenLabel} <When at={when}/></span>}
    </header>
    <Heading className={styles.impactTitle}>{headline}</Heading>

    {lead ? <div className={styles.transition} data-direction={str(lead.direction)}>
      <div className={styles.transitionSubject}>
        <code>{str(lead.subject)}</code>{field && field !== str(lead.subject) && <span>{field}</span>}
      </div>
      <div className={styles.transitionValues}>
        <span className={styles.transitionBefore}><small>Before</small><b>{value(lead.before, lead.present_before)}</b></span>
        <span className={styles.transitionArrow} aria-hidden="true"/>
        <span className={styles.transitionAfter}><small>After</small><b>{value(lead.after, lead.present_after)}</b></span>
      </div>
      {move && <div className={styles.transitionEffect}>
        <AuthorityGlyph size={13}/>
        <StatusPill label={move.label} tone={move.tone} canonical={classification}/>
      </div>}
    </div> : !!components.length && <ul className={styles.impactComponents} aria-label="What changed">
      {components.slice(0, 8).map(component => <li key={str(component.component)}>
        <span>{str(component.kind).replaceAll('_', ' ').toLowerCase()}</span><code>{str(component.label)}</code>
      </li>)}
    </ul>}
    {moved.length > 1 && <AuthorityDiff dimensions={moved.slice(1)} limit={4}/>}

    {(!!affected.length || !!holds.length || !!declared.length) && <div className={styles.impactClaims}>
      {!!affected.length && <div className={styles.impactAffected}>
        <Sub>Affected</Sub>
        <ul>{affected.map(claim => <li key={claim.key}>
          <AlertTriangle size={13} aria-hidden="true"/>
          <span>{claim.title}{!!claim.note && <small>{claim.note}</small>}</span>
        </li>)}</ul>
      </div>}
      {!!holds.length && <div className={styles.impactHolds}>
        <Sub>Still current</Sub>
        <ul>{holds.map(title => <li key={title}><Check size={13} aria-hidden="true"/><span>{title}</span></li>)}</ul>
      </div>}
      {!!declared.length && <div className={styles.impactDeclared}>
        <Sub>Declared, not yet verified</Sub>
        <ul>{declared.map(claim => <li key={claim.key}>
          <CircleHelp size={13} aria-hidden="true"/>
          <span>{claim.title}<small title="Canonical status: NOT_YET_VERIFIED">ThreatVeil holds no evidence for it yet</small></span>
        </li>)}</ul>
      </div>}
    </div>}

    {before && after && <section className={styles.impactStates} aria-label={statesLabel}>
      <ImpactStateBox side={before}/>
      <span className={styles.impactStatesArrow} aria-hidden="true"/>
      <ImpactStateBox side={after} emphasis/>
    </section>}
    {actions && <div className={styles.impactActions}>{actions}</div>}
  </article>;
}

function ImpactStateBox({side, emphasis = false}: {side: ImpactSide; emphasis?: boolean}) {
  return <div className={styles.impactState} data-tone={emphasis ? side.tone : undefined}>
    <span className={styles.impactStateCaption}>{side.caption}</span>
    <StatusPill size="large" label={side.label} tone={side.tone} canonical={side.state}/>
    {!!side.note && <small>{side.note}</small>}
  </div>;
}

/** A detected change, from the system snapshot, in ChangeImpact's shape. */
export function impactOfChange(change: Fields, summary: Fields) {
  const consequence = obj(change.consequence);
  const authority = obj(change.authority);
  const prior = obj(change.prior_clearance);
  const now = clearanceView(obj(summary.clearance));
  const holds = (Array.isArray(consequence.still_holds) ? consequence.still_holds : [])
    .map(item => typeof item === 'string' ? item : str(obj(item).title)).filter(Boolean);
  const effect = str(consequence.effect);
  return {
    source: sourceOfOrigin(obj(change.origin)),
    headline: str(change.headline), when: change.recorded_at, dimensions: arr(authority.dimensions),
    classification: str(authority.classification, ''), components: arr(change.components),
    affected: arr(consequence.claims_affected).map(claim => ({
      key: str(claim.property_id, str(claim.title)), title: str(claim.title),
      note: claim.open ? 'Needs fresh evidence' : effect === 'OPEN' ? undefined : 'Re-established afterwards',
    })),
    holds,
    declared: arr(consequence.declared_claims_affected).map(claim => ({key: str(claim.definition_id), title: str(claim.claim)})),
    before: prior.action ? {caption: 'Before this change', label: str(prior.action) === 'ALLOW' ? 'Cleared' : 'Not cleared',
      state: str(prior.action), tone: (str(prior.action) === 'ALLOW' ? 'ok' : 'stop') as Tone,
      note: prior.status ? `That clearance is now ${(DECISION_STATUS[str(prior.status)] || str(prior.status)).toLowerCase()}.` : undefined}
      : undefined,
    after: prior.action && effect === 'OPEN' ? {caption: 'Current system', label: now.label, state: now.state, tone: now.tone,
      note: 'As it stands now.'} : undefined,
  };
}

/* --- Assurance Gate ----------------------------------------------------------------- */

export function GateState({gate, reliance, action}: {gate: Fields; reliance: Fields; action?: React.ReactNode}) {
  const cleared = !!gate.cleared;
  const consumers = list(reliance.machine_consumers);
  return <section className={styles.primitive} data-kind="gate" aria-label="Assurance Gate">
    <div className={styles.primitiveHead}>
      <span className={styles.primitiveGlyph}><GateGlyph size={15}/></span>
      <div>
        <h3>Assurance Gate</h3>
        <span>The answer a machine reads before it relies on this system</span>
      </div>
      <span className={styles.primitiveBadge}>Read-only</span>
    </div>
    <div className={styles.gateAnswer}>
      <code>GET …/assurance/current</code>
      <span aria-hidden="true" className={styles.gateArrow}/>
      <StatusPill label={cleared ? 'Cleared' : 'Not cleared'} tone={cleared ? 'ok' : 'attention'} canonical={str(gate.status)}/>
    </div>
    <dl className={styles.primitiveFacts}>
      <div><dt>Last machine check</dt>
        <dd title={str(reliance.note, '')}>{reliance.last_machine_check_at ? <When at={reliance.last_machine_check_at}/> : 'Never'}</dd></div>
      <div><dt>Consumers</dt><dd>{consumers.length ? consumers.join(', ') : '0'}</dd></div>
      <div><dt>Rely on it until</dt><dd><When at={obj(gate.freshness).valid_until}/></dd></div>
    </dl>
    <p className={styles.primitiveNote}>It answers assurance and never grants permission. Your policy decides what happens next.</p>
    {action && <div className={styles.primitiveActions}>{action}</div>}
  </section>;
}

/* --- Passport ---------------------------------------------------------------------- */

const PASSPORT_STATUS: Record<string, {label: string; tone: Tone}> = {
  CURRENT: {label: 'Current', tone: 'ok'}, SUPERSEDED: {label: 'Superseded', tone: 'attention'},
  REASSESS: {label: 'Needs reassessment', tone: 'attention'}, EXPIRED: {label: 'Expired', tone: 'attention'},
  REVOKED: {label: 'Revoked', tone: 'stop'}, UNKNOWN: {label: 'Unknown', tone: 'neutral'},
};

/**
 * Authenticity and currency are shown as two separate facts, because a Passport can be
 * cryptographically authentic and no longer current at the same time.
 */
export function PassportState({passports, reliance, action}: {passports: Fields[]; reliance: Fields; action?: React.ReactNode}) {
  const latest = passports[0];
  const status = obj(latest?.current_status);
  const view = PASSPORT_STATUS[str(status.status, 'UNKNOWN')] || PASSPORT_STATUS.UNKNOWN;
  return <section className={styles.primitive} data-kind="passport" aria-label="External assurance">
    <div className={styles.primitiveHead}>
      <span className={styles.primitiveGlyph}><PassportGlyph size={15}/></span>
      <div>
        <h3>Current Assurance Passport</h3>
        <span>What an outside party can verify without an account</span>
      </div>
      <span className={styles.primitiveBadge}>{latest ? 'Signed' : 'Not issued'}</span>
    </div>
    {latest ? <>
      <div className={styles.passportFacts}>
        <div><span>Authenticity</span><strong><Check size={13} aria-hidden="true"/> Signed · verifiable offline</strong></div>
        <div><span>Current status</span>
          {status.status ? <StatusPill label={view.label} tone={view.tone} canonical={str(status.status)}/> : <strong>Checked on open</strong>}</div>
      </div>
      <dl className={styles.primitiveFacts}>
        <div><dt>Issued</dt><dd><When at={latest.issued_at}/> · {str(latest.audience)}</dd></div>
        <div><dt>Last external check</dt>
          <dd>{reliance.last_external_check_at ? <When at={reliance.last_external_check_at}/> : 'Never'}</dd></div>
      </dl>
    </> : <p className={styles.primitiveNote}>No Passport has been issued. Nothing is ever published automatically.</p>}
    {action && <div className={styles.primitiveActions}>{action}</div>}
  </section>;
}

/* --- Assurance setup ---------------------------------------------------------------- */

export type Stage = {key: string; label: string; done: boolean; detail?: string; action?: {label: string; href: string}};

export function SetupProgress({stages, title = 'Assurance setup', level = 2, action = true}: {
  stages: Stage[]; title?: string; level?: 2 | 3; action?: boolean;
}) {
  const next = stages.find(stage => !stage.done);
  const Heading = level === 2 ? 'h2' : 'h3';
  const groups: [string, string, Stage[]][] = [
    ['impact', 'Useful change impact', stages.slice(0, 3)],
    ['verified', 'Verified current assurance', stages.slice(3)],
  ];
  return <section className={styles.setup} aria-label={title}>
    <div className={styles.setupHead}>
      <Heading>{title}</Heading>
      <span className={styles.setupCount}>{stages.filter(s => s.done).length} of {stages.length}</span>
      {action && next?.action && <Link href={next.action.href} className="button outline small">{next.action.label}</Link>}
    </div>
    <div className={styles.setupGroups}>
      {groups.map(([key, label, items]) => <div key={key} className={styles.setupGroup}>
        <span className={styles.setupGroupLabel}>{label}</span>
        <ol>{items.map(stage => <li key={stage.key} data-done={stage.done ? 'true' : 'false'}
          data-next={stage === next ? 'true' : undefined}>
          <span className={styles.setupMark} aria-hidden="true">{stage.done ? <Check size={11} strokeWidth={2.4}/> : null}</span>
          <span className={styles.setupText}>
            <strong>{stage.label}</strong>
            {!!stage.detail && <small>{stage.detail}</small>}
          </span>
          <span className="sr-only">{stage.done ? 'Complete' : 'Not complete'}</span>
        </li>)}</ol>
      </div>)}
    </div>
  </section>;
}

/** The six stages for one system, from its snapshot. */
export function stagesFromSnapshot(data: Fields, systemId: string): Stage[] {
  const summary = obj(data.summary);
  const claims = obj(summary.claims);
  const sources = arr(data.sources);
  const stack = arr(obj(data.stack).items);
  const reliance = obj(data.reliance);
  const authorities = arr(obj(data.authority).authorities);
  const defined = num(claims.total) + num(claims.defined_not_executable);
  const evaluable = sources.some(source => ['mcp', 'agent_definition'].includes(str(source.connector_id))
    && !!source.last_valid_at);
  const verified = !!obj(summary.clearance).decision || num(obj(obj(data.evidence).counts).SUPPORTED) > 0;
  const live = stack.filter(item => ['LIVE_SOURCE', 'INSTRUMENTED'].includes(str(item.relationship)) && item.connected);
  const relied = num(reliance.machine_check_windows) + num(reliance.external_check_windows) > 0;
  const base = `/app/systems/${systemId}`;
  return [
    {key: 'understood', label: 'System understood', done: sources.length > 0 || authorities.length > 0,
      detail: stack.length ? stack.map(item => str(item.label)).join(' · ')
        : sources.length ? plural(sources.length, 'source') : authorities.length ? capabilities(authorities.length) : 'No source facts yet',
      action: {label: 'Connect a source', href: `/app/integrations?system=${systemId}`}},
    {key: 'claims', label: defined ? `${plural(defined, 'security claim')} defined` : 'Security claims defined', done: defined > 0,
      detail: defined ? undefined : 'Say what must stay true', action: {label: 'Define a security claim', href: `${base}/claims`}},
    {key: 'proposed', label: 'Proposed-change analysis ready', done: evaluable && defined > 0,
      detail: evaluable ? (defined ? 'Check a change before you ship it' : 'Needs a security claim')
        : 'Needs an imported definition or MCP catalog',
      action: {label: 'Check a proposed change', href: '/app/changes/propose'}},
    {key: 'evidence', label: verified ? 'Verified evidence established' : 'Verified evidence', done: verified,
      detail: verified ? undefined : 'Not established', action: {label: 'Establish evidence', href: `${base}/setup`}},
    {key: 'live', label: live.length ? 'Live monitoring connected' : 'Live monitoring', done: live.length > 0,
      detail: live.length ? live.map(item => str(item.label)).join(' · ') : 'No live source connected',
      action: {label: 'Connect a live source', href: `/app/integrations?system=${systemId}`}},
    {key: 'reliance', label: relied ? 'Machine or external reliance' : 'Machine or external reliance', done: relied,
      detail: relied ? undefined : 'No machine consumer or external check yet',
      action: {label: 'Connect a machine consumer', href: '/app/integrations#assurance-gate'}},
  ];
}
