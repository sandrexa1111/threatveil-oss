'use client';

/**
 * The customer-facing vocabulary and the reusable objects built on it.
 *
 * Canonical statuses are never rewritten: every translation here is presentation,
 * and each component keeps the exact canonical value available in a title or a
 * details line so a security engineer can still read the underlying semantics.
 */

import Link from 'next/link';
import { useEffect, useRef, useState } from 'react';
import { AlertTriangle, ArrowRight, Check, ChevronDown, CircleHelp, Plug, ShieldCheck, XCircle } from 'lucide-react';
import { str, date } from '@/lib/api';
import { CONNECTOR_ECOSYSTEM, SourceMark } from './ecosystem';
import styles from './product.module.css';

export type Fields = Record<string, unknown>;
export const arr = (value: unknown): Fields[] => Array.isArray(value) ? value.filter(v => v && typeof v === 'object') as Fields[] : [];
export const list = (value: unknown): string[] => Array.isArray(value) ? value.map(String) : [];
export const num = (value: unknown) => typeof value === 'number' ? value : Number(value) || 0;
export const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? '' : 's'}`;

export type Tone = 'ok' | 'attention' | 'stop' | 'neutral';

/** Clearance states, in the words a customer uses, with the canonical value retained. */
const CLEARANCE: Record<string, {label: string; tone: Tone; meaning: string}> = {
  CLEARED: {label: 'Cleared', tone: 'ok', meaning: 'Every security claim is supported by evidence produced for this system as it runs now.'},
  NEEDS_REASSESSMENT: {label: 'Needs attention', tone: 'attention', meaning: 'The last answer no longer speaks for this system. Something changed, or its evidence moved.'},
  NOT_CLEARED: {label: 'Not cleared', tone: 'stop', meaning: 'The last verification did not support what this system is allowed to do.'},
  REVOKED: {label: 'Revoked', tone: 'stop', meaning: 'Someone withdrew this system’s clearance explicitly.'},
  NOT_ESTABLISHED: {label: 'Not set up yet', tone: 'neutral', meaning: 'No assurance has been established for this system yet.'},
};

/** The status of a clearance that was already issued. */
export const DECISION_STATUS: Record<string, string> = {
  CURRENT: 'Current', EXPIRED: 'Expired', SUPERSEDED: 'Superseded by a later change',
  REASSESS: 'Needs review', REVOKED: 'Revoked', UNKNOWN: 'Unknown',
};

/** Claim verification levels. The canonical value stays available in the title. */
export const CLAIM_LEVEL: Record<string, {label: string; tone: Tone}> = {
  CURRENT: {label: 'Current', tone: 'ok'},
  QUALIFIED: {label: 'Ready to verify', tone: 'attention'},
  NOT_YET_VERIFIED: {label: 'Needs evidence', tone: 'attention'},
  DECLARED: {label: 'Defined', tone: 'neutral'},
};

/** Whether current evidence supports a claim. */
export const CLAIM_STATE: Record<string, {label: string; tone: Tone}> = {
  SUPPORTED: {label: 'Current', tone: 'ok'},
  NEEDS_FRESH_EVIDENCE: {label: 'Needs fresh evidence', tone: 'attention'},
  FAILED: {label: 'Failed', tone: 'stop'},
  UNKNOWN: {label: 'Not yet supported', tone: 'neutral'},
  DEFINED: {label: 'Defined', tone: 'neutral'},
  UNGOVERNED: {label: 'No claim covers it', tone: 'attention'},
};

export const AUTHORITY_MOVE: Record<string, {label: string; tone: Tone}> = {
  AUTHORITY_EXPANDED: {label: 'Authority expanded', tone: 'stop'},
  AUTHORITY_CONTRACTED: {label: 'Authority contracted', tone: 'ok'},
  AUTHORITY_EQUIVALENT: {label: 'Authority unchanged', tone: 'neutral'},
  UNKNOWN_IMPACT: {label: 'Unknown impact', tone: 'attention'},
};

export const CHANGE_EFFECT: Record<string, string> = {
  OPEN: 'Needs review', COVERED_BY_LATER_VERIFICATION: 'Covered by later verification',
  NO_CLAIM_AFFECTED: 'No claim affected', NO_BASELINE: 'Before any baseline',
  CURRENT_STATE: 'Current state', SUPERSEDED_BY_LATER_STATE: 'Earlier state',
};

/** Each next action, as one dominant call to action tied to a route. */
export const NEXT_ACTION: Record<string, {label: string; path: (id: string) => string}> = {
  SET_UP: {label: 'Set up assurance', path: id => `/app/systems/${id}/setup`},
  REVIEW_CHANGE: {label: 'Review change', path: id => `/app/systems/${id}/activity`},
  RESTORE: {label: 'Restore assurance', path: id => `/app/systems/${id}/restore`},
  RE_ESTABLISH: {label: 'Review required evidence', path: id => `/app/systems/${id}/evidence`},
  SHARE: {label: 'Share current assurance', path: id => `/app/systems/${id}/share`},
};

export function clearanceView(clearance: Fields) {
  const state = str(clearance.state, 'NOT_ESTABLISHED');
  const known = CLEARANCE[state];
  return {
    state,
    label: known?.label || str(clearance.label, 'Unknown'),
    tone: known?.tone || 'neutral' as Tone,
    meaning: known?.meaning || str(clearance.meaning, ''),
  };
}

const ICON: Record<Tone, typeof Check> = {ok: Check, attention: AlertTriangle, stop: XCircle, neutral: CircleHelp};

/**
 * Status is the most important object on every screen: a shape, a word and a
 * colour, never colour alone, with the canonical value in the accessible title.
 */
export function StatusPill({label, tone = 'neutral', canonical, size = 'regular'}: {
  label: string; tone?: Tone; canonical?: string; size?: 'regular' | 'large';
}) {
  const Icon = ICON[tone];
  return <span className={styles.pill} data-tone={tone} data-size={size}
    title={canonical ? `Canonical status: ${canonical}` : undefined}>
    <Icon size={size === 'large' ? 15 : 13} strokeWidth={2.1} aria-hidden="true"/>
    <span>{label}</span>
    {canonical && <span className="sr-only"> (canonical status {canonical})</span>}
  </span>;
}

/** One dominant next action. Screens should render exactly one of these. */
export function PrimaryAction({href, onClick, children, disabled}: {
  href?: string; onClick?: () => void; children: React.ReactNode; disabled?: boolean;
}) {
  if (href) return <Link href={href} className={`button dark ${styles.primary}`}>{children}<ArrowRight size={16}/></Link>;
  return <button className={`button dark ${styles.primary}`} onClick={onClick} disabled={disabled}>{children}<ArrowRight size={16}/></button>;
}

/** A system that needs a decision: what happened, why it matters, what to do. */
export function AttentionItem({row}: {row: Fields}) {
  const clearance = clearanceView(obj(row.clearance));
  const id = str(row.id);
  const action = NEXT_ACTION[str(row.next_action)] || NEXT_ACTION.RESTORE;
  const claims = obj(row.claims);
  const outstanding = num(claims.needs_fresh_evidence) + num(claims.failed);
  return <article className={styles.attention} data-tone={clearance.tone}>
    <div className={styles.attentionMain}>
      <div className={styles.attentionHead}>
        <Link href={`/app/systems/${id}`} className={styles.attentionName} data-row-link>{str(row.name)}</Link>
        <StatusPill label={clearance.label} tone={clearance.tone} canonical={clearance.state}/>
        {!!row.synthetic && <span className="tag">Synthetic example</span>}
      </div>
      <p className={styles.attentionWhy}>{str(row.why, clearance.meaning)}</p>
      <p className={styles.attentionDetail}>
        {outstanding > 0 ? `${plural(outstanding, 'security claim')} ${outstanding === 1 ? 'needs' : 'need'} fresh evidence.` :
          !row.baseline ? 'No evidence has been established for this system yet.' :
          `${num(claims.supported)} of ${num(claims.total)} security claims current.`}
      </p>
    </div>
    <PrimaryAction href={action.path(id)}>{action.label}</PrimaryAction>
  </article>;
}

/** A system in good standing. Quiet by design: it needs nothing from the operator. */
export function CurrentSystemRow({row}: {row: Fields}) {
  const clearance = clearanceView(obj(row.clearance));
  const id = str(row.id);
  const at = obj(row.clearance).last_current_clearance_at;
  return <Link href={`/app/systems/${id}`} className={styles.currentRow} data-row-link>
    <div>
      <strong>{str(row.name)}</strong>
      <small>{at ? `Last current ${date(at)}` : str(obj(row.environment).name, 'No environment yet')}</small>
    </div>
    <StatusPill label={clearance.label} tone={clearance.tone} canonical={clearance.state}/>
  </Link>;
}

/** Predictable system context: one switcher, in the system header, not on every page. */
export function SystemSwitcher({systems, selected, onSelect}: {
  systems: Fields[]; selected: string; onSelect: (id: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const holder = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    function away(event: MouseEvent) { if (!holder.current?.contains(event.target as Node)) setOpen(false); }
    function escape(event: KeyboardEvent) { if (event.key === 'Escape') setOpen(false); }
    document.addEventListener('mousedown', away); document.addEventListener('keydown', escape);
    return () => { document.removeEventListener('mousedown', away); document.removeEventListener('keydown', escape); };
  }, [open]);
  if (systems.length < 2) return null;
  const current = systems.find(s => str(s.id) === selected);
  return <div className={styles.switcher} ref={holder}>
    <button className={styles.switcherButton} aria-expanded={open} aria-haspopup="listbox"
      onClick={() => setOpen(!open)}>
      <span>{str(current?.name, 'Choose a system')}</span><ChevronDown size={14}/>
    </button>
    {open && <ul className={styles.switcherMenu} role="listbox" aria-label="Switch protected system">
      {systems.map(system => <li key={str(system.id)} role="option" aria-selected={str(system.id) === selected}>
        <button onClick={() => { onSelect(str(system.id)); setOpen(false); }}>
          {str(system.id) === selected ? <Check size={14}/> : <span className={styles.switcherSpacer}/>}
          {str(system.name)}
        </button>
      </li>)}
    </ul>}
  </div>;
}

/** A purposeful empty state: what is missing, and the one action that fixes it. */
export function EmptyState({title, body, action, icon: Icon = ShieldCheck}: {
  title: string; body: string; action?: React.ReactNode; icon?: typeof ShieldCheck;
}) {
  return <div className={styles.empty}>
    <Icon size={26} strokeWidth={1.3} aria-hidden="true"/>
    <h3>{title}</h3>
    <p>{body}</p>
    {action}
  </div>;
}

/** A named limitation, what ThreatVeil will not claim while it holds, and the next step. */
export function FailureState({item}: {item: Fields}) {
  const severity = str(item.severity);
  const tone: Tone = severity === 'BLOCKING_VALUE' ? 'stop' : severity === 'LIMITS_SCOPE' ? 'attention' : 'neutral';
  return <article className={styles.failure} data-tone={tone}>
    <div className={styles.failureHead}>
      <h3>{str(item.title)}</h3>
      <StatusPill label={severity.replaceAll('_', ' ').toLowerCase()} tone={tone} canonical={str(item.code)}/>
    </div>
    <p>{str(item.meaning)}</p>
    {!!item.detail && <p className={styles.muted}>{str(item.detail)}</p>}
    <p className={styles.failureRefusal}><strong>ThreatVeil will not claim:</strong> {str(item.not_claimed)}</p>
    <p className={styles.failureNext}><ArrowRight size={14} aria-hidden="true"/> {str(item.next_step)}</p>
  </article>;
}

/** A timeline detail in customer words; the canonical value stays in the title. */
const EVENT_DETAIL: Record<string, string> = {
  OPEN: 'needs review', ALLOW: 'cleared', BLOCK: 'not cleared', ISSUED: 'issued',
  ...Object.fromEntries(Object.entries(CHANGE_EFFECT).map(([key, label]) => [key, label.toLowerCase()])),
};

/**
 * "12m ago", with the exact time one hover away (mandate §19). Past a week the absolute
 * date is shorter and more useful than a relative one.
 */
export function ago(value: unknown) {
  if (!value) return '—';
  const at = new Date(String(value)).getTime();
  if (Number.isNaN(at)) return '—';
  const seconds = Math.round((Date.now() - at) / 1000);
  if (seconds < 45) return 'just now';
  if (seconds < 3600) return `${Math.round(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)}h ago`;
  if (seconds < 604800) return `${Math.round(seconds / 86400)}d ago`;
  return date(value);
}

export function When({at}: {at: unknown}) {
  return <time dateTime={str(at, '')} title={at ? new Date(String(at)).toLocaleString() : undefined}>{ago(at)}</time>;
}

/** One chronological record of what happened to a system. One line per event. */
export function ActivityTimeline({events, showSystem = false}: {events: Fields[]; showSystem?: boolean}) {
  if (!events.length) return null;
  return <ol className={styles.timeline}>
    {events.map((event, index) => {
      const detail = str(event.detail, '');
      const meta = [showSystem && event.system ? str(event.system) : '',
        detail ? EVENT_DETAIL[detail] || detail.replaceAll('_', ' ').toLowerCase() : ''].filter(Boolean);
      return <li key={`${str(event.id, String(index))}-${index}`} data-tone={str(event.tone, 'neutral')}>
        <When at={event.at}/>
        <div>
          {!!event.connector && <SourceMark id={CONNECTOR_ECOSYSTEM[str(event.connector)]}/>}
          {event.href
            ? <Link href={str(event.href)} scroll={false}><strong>{str(event.headline)}</strong></Link>
            : <strong>{str(event.headline)}</strong>}
          {!!meta.length && <span className={styles.muted} title={detail ? `Canonical status: ${detail}` : undefined}>
            {meta.join(' · ')}
          </span>}
        </div>
      </li>;
    })}
  </ol>;
}

/**
 * The authority diff, as a diff.
 *
 * `authority.dimensions` already carries {subject, condition, before, after, direction}
 * for every moved field; the product used to render it only as a prose sentence at the
 * bottom of a list. A reviewer reading "what would this break?" needs the before and the
 * after side by side, the way a pull request shows a changed line.
 */
export function AuthorityDiff({dimensions, limit = 6}: {dimensions: Fields[]; limit?: number}) {
  const moved = dimensions.filter(d => str(d.direction) !== 'AUTHORITY_EQUIVALENT');
  if (!moved.length) return null;
  return <ul className={styles.diff}>
    {moved.slice(0, limit).map((d, i) => {
      const tone: Tone = str(d.direction) === 'AUTHORITY_EXPANDED' ? 'stop'
        : str(d.direction) === 'AUTHORITY_CONTRACTED' ? 'ok' : 'attention';
      const subject = str(d.subject);
      const condition = str(d.condition, str(d.kind).toLowerCase());
      return <li key={`${subject}-${condition}-${i}`} data-tone={tone}>
        <div className={styles.diffSubject}>
          <code>{subject}</code>
          {condition !== subject && <span className={styles.diffField}>{condition}</span>}
        </div>
        <div className={styles.diffValues}>
          <span className={styles.diffBefore}>{diffValue(d.before, d.present_before)}</span>
          <span aria-hidden="true" className={styles.diffArrow}>&rarr;</span>
          <span className={styles.diffAfter}>{diffValue(d.after, d.present_after)}</span>
        </div>
      </li>;
    })}
    {moved.length > limit && <li className={styles.diffMore} data-tone="neutral">
      {moved.length - limit} more field{moved.length - limit === 1 ? '' : 's'} moved
    </li>}
  </ul>;
}

/** A declared value, or the explicit absence of one. Absence is never rendered as false. */
function diffValue(value: unknown, present?: unknown) {
  if (present === false) return 'not set';
  if (value === null || value === undefined) return 'not set';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  return str(value);
}

/**
 * A right-side panel for inspecting one object without leaving the list (mandate §12).
 * A modal dialog: Escape and the scrim close it, focus moves into it on open and returns
 * to whatever opened it on close.
 */
export function Drawer({open, title, subtitle, onClose, children}: {
  open: boolean; title: string; subtitle?: React.ReactNode; onClose: () => void; children: React.ReactNode;
}) {
  const close = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    if (!open) return;
    const previous = document.activeElement as HTMLElement | null;
    close.current?.focus();
    function escape(event: KeyboardEvent) { if (event.key === 'Escape') onClose(); }
    document.addEventListener('keydown', escape);
    return () => { document.removeEventListener('keydown', escape); previous?.focus?.(); };
  }, [open, onClose]);
  if (!open) return null;
  return <>
    <button className={styles.drawerScrim} aria-label="Close panel" tabIndex={-1} onClick={onClose}/>
    <aside className={styles.drawer} role="dialog" aria-modal="true" aria-labelledby="drawer-title">
      <header className={styles.drawerHead}>
        <div>
          <h2 id="drawer-title">{title}</h2>
          {subtitle && <div className={styles.drawerSub}>{subtitle}</div>}
        </div>
        <button ref={close} className="icon-button" onClick={onClose} aria-label="Close panel"><XCircle size={16}/></button>
      </header>
      <div className={styles.drawerBody}>{children}</div>
    </aside>
  </>;
}

/** Label and value rows inside a drawer or detail view. */
export function Facts({rows}: {rows: [string, React.ReactNode][]}) {
  const shown = rows.filter(([, value]) => value !== null && value !== undefined && value !== '' && value !== false);
  if (!shown.length) return null;
  return <dl className={styles.facts}>{shown.map(([label, value]) => <div key={label}>
    <dt>{label}</dt><dd>{value}</dd>
  </div>)}</dl>;
}

/**
 * A structured loading state: the shape of what is coming, never a fake value and never
 * a blank panel. Screen readers hear the label once.
 */
export function Skeleton({label, rows = 3, header = false}: {label: string; rows?: number; header?: boolean}) {
  return <div className={styles.skeleton} role="status" aria-live="polite">
    <span className="sr-only">{label}</span>
    {header && <div className={styles.skeletonHeader} aria-hidden="true"><i/><i/></div>}
    <div className={styles.skeletonRows} aria-hidden="true">
      {Array.from({length: rows}, (_, index) => <div key={index} className={styles.skeletonRow}><i/><i/><i/></div>)}
    </div>
  </div>;
}

/**
 * ↑/↓ between the rows of one list. Rows opt in with `data-row-link`; focus only moves
 * when it is already inside the list, and keys typed into a field are left alone.
 */
export function useListKeys<T extends HTMLElement>() {
  const ref = useRef<T>(null);
  function onKeyDown(event: React.KeyboardEvent) {
    if (event.key !== 'ArrowDown' && event.key !== 'ArrowUp') return;
    const target = event.target as HTMLElement;
    if (target.isContentEditable || ['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName)) return;
    const rows = Array.from(ref.current?.querySelectorAll<HTMLElement>('[data-row-link]') || []);
    const index = rows.indexOf(document.activeElement as HTMLElement);
    if (index < 0) return;
    const next = rows[index + (event.key === 'ArrowDown' ? 1 : -1)];
    if (!next) return;
    event.preventDefault();
    next.focus();
  }
  return {ref, onKeyDown};
}

/** Live source coverage, in one line a non-specialist can read. */
export function SourceLine({sources}: {sources: Fields}) {
  const total = num(sources.total), attention = num(sources.needs_attention), live = num(sources.live);
  if (!total) return <span className={styles.muted}><Plug size={12}/> No source is watching this system</span>;
  return <span className={styles.muted}>
    <Plug size={12}/> {plural(total, 'source')} connected{live ? ` · ${live} live` : ''}
    {attention ? ` · ${attention} need attention` : ''}
  </span>;
}

function obj(value: unknown): Fields {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Fields : {};
}
