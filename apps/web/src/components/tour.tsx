'use client';

/**
 * Explore ThreatVeil: a guided path through the real product surfaces, using only the
 * labelled synthetic Finance fixture.
 *
 * It is not a second UI and not a recording. Each step navigates to the actual screen
 * and outlines the actual object; each action calls the fixture's existing controls —
 * the same endpoints the synthetic example controls use — and nothing else. It never
 * counts as customer activity and it cannot reach a customer system.
 */

import { usePathname, useRouter, useSearchParams } from 'next/navigation';
import { useCallback, useEffect, useRef, useState } from 'react';
import { Check, X } from 'lucide-react';
import { api, str } from '@/lib/api';
import { arr, type Fields } from './product';
import { SYSTEM_CHANGED, financeAssess, financeChange } from './intelligence';
import type { WorkspaceContext } from './workspace-parts';
import c from './completion.module.css';

const KEY = 'threatveil.tour';
type Saved = {step: number; systemId: string};
type Step = {
  title: string; body: string; route: (id: string) => string; target?: string;
  action?: {label: string; done: string; run: (ctx: WorkspaceContext, id: string) => Promise<void>};
};

const overview = (id: string) => `/app/systems/${id}`;
const STEPS: Step[] = [
  {title: 'An example AI system',
    body: 'A synthetic finance agent: a tool gateway imported as an MCP snapshot, and isolated ledger rows. Nothing here reaches a customer system, a provider or money.',
    route: overview, target: 'system-header'},
  {title: 'The system is current',
    body: 'Establish the baseline. When every link holds — authority, security claims, evidence — the current answer is Cleared.',
    route: overview, target: 'chain',
    action: {label: 'Establish the baseline', done: 'Baseline established', run: (ctx, id) => financeAssess(ctx.mutate, id, 'fixed').then(() => undefined)}},
  {title: 'A consequential permission changes',
    body: 'The gateway stops requiring approval for beneficiary updates. No repository and no deploy: the change happens outside code.',
    route: overview, target: 'system-header',
    action: {label: 'Relax beneficiary approval', done: 'Gateway changed', run: (ctx, id) => financeChange(ctx.mutate, id, 'beneficiary_approval_relaxed')}},
  {title: 'ThreatVeil shows exactly what moved',
    body: 'The change arrives with its source, and the moved field as a before → after transition. Authority expanded.',
    route: overview, target: 'change-impact'},
  {title: 'One security claim needs fresh evidence',
    body: 'The chain breaks at the claim that depends on that approval. Its evidence was produced for the earlier state, so it no longer applies.',
    route: overview, target: 'chain'},
  {title: 'The other claims remain current',
    body: 'Evidence is scoped. Only the reached claim needs fresh evidence; tenant isolation and invoice authorization still hold.',
    route: id => `/app/systems/${id}/evidence`},
  {title: 'Verification runs — and fails',
    body: 'Re-prove with approval still relaxed. The forbidden beneficiary change commits, so security fails and the system is not cleared.',
    route: id => `/app/systems/${id}/restore`, target: 'restore',
    action: {label: 'Re-prove with approval relaxed', done: 'Verification recorded', run: (ctx, id) => financeAssess(ctx.mutate, id, 'regressed').then(() => undefined)}},
  {title: 'A bad fix is rejected',
    body: 'A fix that simply disables updates stops the forbidden outcome — and breaks the legitimate invoice task. Security alone is not a useful fix.',
    route: id => `/app/systems/${id}/restore`, target: 'restore',
    action: {label: 'Try a fix that disables updates', done: 'Verification recorded', run: (ctx, id) => financeAssess(ctx.mutate, id, 'bad_fix').then(() => undefined)}},
  {title: 'The proper fix restores assurance',
    body: 'Restore the approval requirement and re-prove: the forbidden outcome is prevented and useful work still succeeds.',
    route: id => `/app/systems/${id}/restore`, target: 'restore',
    action: {label: 'Restore approval and re-prove', done: 'Assurance restored', run: (ctx, id) => financeAssess(ctx.mutate, id, 'fixed', 'gateway_restored').then(() => undefined)}},
  {title: 'Machines read the current answer',
    body: 'The Assurance Gate is a read-only answer a pipeline consumes. It never grants permission; the consumer’s policy decides.',
    route: overview, target: 'reliance'},
  {title: 'Anyone can verify the Passport',
    body: 'A signed Passport is verifiable without an account. Authenticity and currency are separate: after a later change it stays authentic and stops being current.',
    route: id => `/app/systems/${id}/share`, target: 'passport'},
];

function read(): Saved | null {
  try { return JSON.parse(window.localStorage.getItem(KEY) || 'null') as Saved | null; } catch { return null; }
}
function write(value: Saved | null) {
  try { if (value) window.localStorage.setItem(KEY, JSON.stringify(value)); else window.localStorage.removeItem(KEY); }
  catch { /* storage unavailable: the tour still runs for this page */ }
}

export function Tour({ctx}: {ctx: WorkspaceContext}) {
  const router = useRouter();
  const pathname = usePathname();
  const params = useSearchParams();
  const [saved, setSaved] = useState<Saved | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [done, setDone] = useState<Record<number, boolean>>({});
  const [confirmed, setConfirmed] = useState(false);

  const update = useCallback((value: Saved | null) => { write(value); setSaved(value); }, []);

  // Start from ?tour=start, or resume a tour already in progress. The start branch must run
  // exactly once: it both fetches and replaces the URL, and re-running it while the replace is
  // still in flight would refetch in a loop and cancel navigation the tour itself just started.
  const started = useRef(false);
  useEffect(() => {
    if (params.get('tour') === 'start') {
      if (started.current) return;
      started.current = true;
      api<Fields>('/home').then(home => {
        const example = arr(home.systems).find(system => system.synthetic);
        update({step: 0, systemId: str(example?.id, '')});
      }).catch(() => update({step: 0, systemId: ''}));
      router.replace(pathname, {scroll: false});
      return;
    }
    setSaved(current => current ?? read());
  }, [params, pathname, router, update]);

  const step = saved ? STEPS[saved.step] : undefined;

  // Outline the real object this step is about, once it has rendered.
  useEffect(() => {
    if (!step?.target || !saved?.systemId) return;
    let found: Element | null = null;
    const timer = window.setInterval(() => {
      const element = document.querySelector(`[data-tour="${step.target}"]`);
      if (!element) return;
      found = element;
      element.setAttribute('data-tour-active', 'true');
      element.scrollIntoView({block: 'center', behavior: 'smooth'});
      window.clearInterval(timer);
    }, 350);
    return () => { window.clearInterval(timer); found?.removeAttribute('data-tour-active'); };
  }, [step, saved?.systemId, pathname]);

  if (!saved || !step) return null;
  const systemId = saved.systemId;
  const go = (index: number) => {
    if (index >= STEPS.length) { update(null); return; }
    update({...saved, step: index});
    setError('');
    if (systemId) router.push(STEPS[index].route(systemId));
  };

  async function prepare() {
    setBusy(true); setError('');
    try {
      const value = await ctx.mutate('/change-assurance/finance/setup', {
        owner: str(ctx.identity?.user.name, 'Workspace owner'), confirm_synthetic_scope: true});
      const id = str(value.system_id);
      update({step: 0, systemId: id});
      router.push(overview(id));
    } catch (e) { setError(e instanceof Error ? e.message : 'Could not prepare the example.'); }
    finally { setBusy(false); }
  }

  async function act() {
    if (!step?.action || !systemId) return;
    setBusy(true); setError('');
    try {
      await step.action.run(ctx, systemId);
      setDone(current => ({...current, [saved!.step]: true}));
      window.dispatchEvent(new Event(SYSTEM_CHANGED));
    } catch (e) { setError(e instanceof Error ? e.message : 'This step could not run.'); }
    finally { setBusy(false); }
  }

  return <aside className={c.tour} role="dialog" aria-modal="false" aria-labelledby="tour-title">
    <div className={c.tourTop}>
      <span>Step {saved.step + 1} of {STEPS.length}</span>
      <span className={c.tourSynthetic}>Synthetic demonstration</span>
      <button type="button" className="icon-button" onClick={() => update(null)} aria-label="Exit tour"><X size={14}/></button>
    </div>
    <div className={c.tourProgress} aria-hidden="true">
      {STEPS.map((_, index) => <i key={index} data-done={index <= saved.step ? 'true' : undefined}/>)}
    </div>
    <h2 id="tour-title">{step.title}</h2>
    <p>{step.body}</p>
    {!systemId ? <>
      <label className="checkbox-label" style={{display: 'flex', gap: 8, alignItems: 'center', margin: 0}}>
        <input type="checkbox" style={{width: 'auto'}} checked={confirmed} onChange={e => setConfirmed(e.target.checked)}/>
        I approve these synthetic checks and the legitimate invoice fixture.
      </label>
      <div className={c.tourActions}>
        <button type="button" className="button dark small" disabled={busy || !confirmed} onClick={prepare}>
          {busy ? 'Preparing…' : 'Prepare the synthetic example'}
        </button>
        <button type="button" className="text-button" onClick={() => update(null)}>Exit tour</button>
      </div>
    </> : <>
      {step.action && (done[saved.step]
        ? <span className={c.tourStatus} role="status"><Check size={13} aria-hidden="true"/>{step.action.done}</span>
        : <button type="button" className="button outline small" disabled={busy} onClick={act}>
            {busy ? 'Running on the synthetic fixture…' : step.action.label}
          </button>)}
      <div className={c.tourActions}>
        <button type="button" className="text-button" disabled={saved.step === 0 || busy} onClick={() => go(saved.step - 1)}>Back</button>
        <button type="button" className="text-button" onClick={() => update(null)}>Exit tour</button>
        <button type="button" className="button dark small" disabled={busy} onClick={() => go(saved.step + 1)}>
          {saved.step === STEPS.length - 1 ? 'Finish' : 'Next'}
        </button>
      </div>
    </>}
    {error && <p className="notice error" role="alert" style={{margin: 0}}>{error}</p>}
  </aside>;
}
