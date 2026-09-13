'use client';

import Link from 'next/link';
import { useEffect, useState, type FormEvent } from 'react';
import { ArrowUpRight, Check, RefreshCw, ShieldCheck } from 'lucide-react';
import { api, date, str, type RecordData } from '@/lib/api';
import type { WorkspaceContext } from './workspace-parts';
import styles from './commercial.module.css';
import completion from './completion.module.css';

type Allowance = {
  protected_system_limit: number; environments_per_system_limit: number;
  approved_property_limit: number; monthly_verification_budget: number;
  retention_days: number; capabilities: string[];
};
type Plan = { id: string; name: string; tagline: string; monthly_usd: number | null;
  sales_assisted: boolean; availability?: string; entitlements: Allowance; checkout_configured: boolean };
type Catalog = { catalog_version: string; plans: Plan[]; mock_available: boolean };
type Commercial = {
  plan: string; status: string; paid: boolean; provider: string; revision: number;
  mock_available: boolean; entitlements: Allowance; offers: Plan[];
  usage: { protected_systems: number; active_properties: number; consumed: number; reserved: number; remaining: number };
  subscription: { period_end: string; scheduled_change: { plan: string; effective_at: string } | null;
    trial: { expires_at: string } | null; promotion: {code: string; percent_off: number; expires_at: string} | null;
    grace_until: string | null } | null;
  events: RecordData[];
};

function message(error: unknown) { return error instanceof Error ? error.message : 'Billing is unavailable. Try again.'; }
function money(value: number | null) { return value === null ? 'Custom' : `$${value.toLocaleString('en-US')}`; }

function PlanCards({ plans, current, busy, select, editable = true }: {
  plans: Plan[]; current?: string; busy?: boolean; editable?: boolean; select?: (plan: Plan) => void;
}) {
  return <div className={styles.plans}>{plans.map(plan => <article key={plan.id} className={`${styles.plan} ${plan.id === current ? styles.selected : ''}`}>
    <div className="eyebrow">{plan.name}{plan.id === current && <span className={styles.current}>Current</span>}</div>
    <h2 className={styles.price}>{plan.availability === 'contact' ? 'Contact us' : money(plan.monthly_usd)}{plan.availability !== 'contact' && plan.monthly_usd !== null && <small>/ month</small>}</h2>
    <p className={styles.tagline}>{plan.tagline}</p>
    <ul>
      <li><Check size={15}/>{plan.sales_assisted ? 'Contract-defined systems' : `${plan.entitlements.protected_system_limit} protected system${plan.entitlements.protected_system_limit === 1 ? '' : 's'}`}</li>
      <li><Check size={15}/>{plan.entitlements.environments_per_system_limit} environment{plan.entitlements.environments_per_system_limit === 1 ? '' : 's'} per system</li>
      <li><Check size={15}/>{plan.entitlements.approved_property_limit} security claims</li>
      <li title="Verification units: one unit per planned trial in a bounded execution.">
        <Check size={15}/>{plan.entitlements.monthly_verification_budget.toLocaleString()} monthly verification capacity</li>
      <li><Check size={15}/>{plan.entitlements.retention_days} days retention allowance</li>
      <li><ShieldCheck size={15}/>Scoped evidence & export</li>
    </ul>
    {plan.availability === 'contact' ? <Link className="button outline small" href="/contact">Talk to us about {plan.name} <ArrowUpRight size={14}/></Link>
      : select ? <button className={`button ${plan.id === current ? 'outline' : 'dark'} small`} disabled={busy || !editable || plan.id === current} onClick={() => select(plan)}>{plan.id === current ? 'Current plan' : `Choose ${plan.name}`}</button>
      : <Link className={`button ${plan.id === 'free' ? 'dark' : 'outline'} small`} href="/login">{plan.id === 'free' ? 'Start free' : `Explore ${plan.name}`}<ArrowUpRight size={14}/></Link>}
  </article>)}</div>;
}

/** Plans side by side: one row per allowance, one column per plan, actions on the last row. */
function PlanComparison({ plans, current, busy, editable, select }: {
  plans: Plan[]; current: string; busy: boolean; editable: boolean; select: (plan: Plan) => void;
}) {
  const rows: [string, (plan: Plan) => React.ReactNode][] = [
    ['Protected systems', plan => plan.sales_assisted ? 'Contract-defined' : plan.entitlements.protected_system_limit.toLocaleString()],
    ['Environments per system', plan => plan.entitlements.environments_per_system_limit.toLocaleString()],
    ['Security claims', plan => plan.entitlements.approved_property_limit.toLocaleString()],
    ['Verification capacity per month', plan => plan.entitlements.monthly_verification_budget.toLocaleString()],
    ['Retention allowance', plan => `${plan.entitlements.retention_days} days`],
    ['Scoped evidence and export', () => <><Check size={14} aria-hidden="true"/><span className="sr-only">Included</span></>],
  ];
  const mark = (plan: Plan) => plan.id === current ? 'true' : undefined;
  return <div className={completion.planTable}><table>
    <thead><tr><th scope="col"><span className="sr-only">Allowance</span></th>{plans.map(plan => <th key={plan.id} scope="col" data-current={mark(plan)}>
      <div className={completion.planName}>
        {plan.id === current && <span className={completion.currentTag}>Current</span>}
        <strong>{plan.name}</strong>
        <b>{plan.availability === 'contact' ? 'Contact us' : money(plan.monthly_usd)}{plan.availability !== 'contact' && plan.monthly_usd !== null && <small>/ month</small>}</b>
        <span>{plan.tagline}</span>
      </div>
    </th>)}</tr></thead>
    <tbody>
      {rows.map(([label, value]) => <tr key={label}><th scope="row">{label}</th>{plans.map(plan => <td key={plan.id} data-current={mark(plan)}>{value(plan)}</td>)}</tr>)}
      <tr className={completion.planActions}><th scope="row"><span className="sr-only">Choose a plan</span></th>{plans.map(plan => <td key={plan.id} data-current={mark(plan)}>
        {plan.availability === 'contact'
          ? <Link className="button outline small" href="/contact">Talk to us about {plan.name} <ArrowUpRight size={14}/></Link>
          : <button className={`button ${plan.id === current ? 'outline' : 'dark'} small`} disabled={busy || !editable || plan.id === current} onClick={() => select(plan)}>{plan.id === current ? 'Current plan' : `Choose ${plan.name}`}</button>}
      </td>)}</tr>
    </tbody>
  </table></div>;
}

export function PricingPlans() {
  const [catalog, setCatalog] = useState<Catalog | null>(null);
  const [error, setError] = useState('');
  useEffect(() => { const controller = new AbortController(); api<Catalog>('/commercial/catalog', {signal:controller.signal}).then(setCatalog).catch(e => { if (!controller.signal.aborted) setError(message(e)); }); return () => controller.abort(); }, []);
  return <section className={styles.pricing} aria-label="Subscription plans">
    {error ? <div className="notice error" role="alert">{error} <Link href="/contact">Discuss a protected-system scope</Link></div> : catalog ? <PlanCards plans={catalog.plans}/> : <p role="status">Loading the current plan catalog…</p>}
    <p className={styles.note}>Initial pricing and usage hypotheses. Enterprise is an annual, sales-assisted contract. Every tier preserves the same security semantics. No automatic paid overages.</p>
    <div className={styles.principles}><article><h3>One meaningful system.</h3><p>A protected system has an owner, an operating boundary, and consequential authority. Repositories, models, replicas, and ephemeral subagents are components of that system.</p></article><article><h3>Real value from Free.</h3><p>Connect one system, check a proposed change before you ship it, see what a change affected, understand missing evidence, and export a scoped decision. A paid plan expands capacity and operational capabilities.</p></article><article><h3>Access that grows with you.</h3><p>Startup, student, open-source, and partner promotions can apply to the same plans. Contact us to discuss a bounded promotional period.</p></article></div>
  </section>;
}

function Meter({ label, used, limit, suffix }: { label: string; used: number; limit: number; suffix?: string }) {
  return <article className={styles.meter}><span>{label}</span><strong>{used.toLocaleString()} <small>/ {limit.toLocaleString()}</small></strong><progress value={Math.min(used, limit)} max={Math.max(1, limit)} aria-label={label}/><small>{suffix || (used >= limit ? 'Allowance reached; current records remain available.' : `${(limit - used).toLocaleString()} available`)}</small></article>;
}

export function CommercialBilling({ ctx }: { ctx: WorkspaceContext }) {
  const [state, setState] = useState<Commercial | null>(null);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);
  const role = str(ctx.identity?.organization.role || ctx.identity?.user.role || ctx.identity?.memberships.find(m => m.organization_id === ctx.identity?.organization.id)?.role);
  const editable = ['owner', 'admin'].includes(role);
  async function load() { try { setState(await api<Commercial>('/commercial')); setError(''); } catch (e) { setError(message(e)); } }
  useEffect(() => { const controller = new AbortController(); api<Commercial>('/commercial', {signal:controller.signal}).then(setState).catch(e => { if (!controller.signal.aborted) setError(message(e)); }); return () => controller.abort(); }, []);
  async function change(action: string, fields: Record<string, unknown> = {}, path = '/commercial/subscription') {
    setBusy(true); setError(''); setNotice('');
    try {
      const result = await api<Commercial>(path, {method:'POST',csrf:ctx.identity?.csrf_token,data:{...(path.endsWith('/subscription') ? {action} : {}),...fields,idempotency_key:crypto.randomUUID(),expected_revision:state?.revision}});
      setState(result); await ctx.refresh();
      setNotice(result.subscription?.scheduled_change ? `The change to ${result.subscription.scheduled_change.plan.toUpperCase()} is scheduled for ${date(result.subscription.scheduled_change.effective_at)}. Existing records remain available.` : 'Commercial entitlements updated. Your evidence and security conclusions are unchanged.');
    } catch (e) { setError(message(e)); await load(); } finally { setBusy(false); }
  }
  async function choose(plan: Plan) {
    if (!state) return;
    if (state.mock_available) { await change(plan.id === 'free' || plan.entitlements.protected_system_limit < state.entitlements.protected_system_limit ? 'downgrade' : 'upgrade', {plan:plan.id}); return; }
    setBusy(true); setError('');
    try { const result = await ctx.mutate('/billing/checkout', {plan:plan.id}); const url = str(result.url, ''); if (!url || new URL(url).protocol !== 'https:') throw new Error('Checkout has not been configured.'); window.location.assign(url); } catch(e) { setError(message(e)); setBusy(false); }
  }
  async function promotion(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); const form = new FormData(event.currentTarget);
    await change('promotion', {code:form.get('code'),kind:form.get('kind'),percent_off:Number(form.get('percent_off')),expires_at:new Date(Date.now() + Number(form.get('days')) * 86400000).toISOString()}, '/commercial/promotion');
  }
  if (!state) return <section className={styles.account}>{error ? <p role="alert">{error}</p> : <p role="status">Loading your plan and usage…</p>}</section>;
  const subscription = state.subscription;
  return <div className={styles.billing}>
    {error && <div className="notice error" role="alert">{error}</div>}{notice && <div className="notice" role="status">{notice}</div>}
    <section className={styles.account} aria-label="Current subscription">
      <div>
        <h2>{state.plan.toUpperCase()} <span className="tag">{state.status.replaceAll('_', ' ')}</span></h2>
        <p>{state.provider === 'mock' ? 'Local billing simulation · No payment collected' : state.paid ? 'Provider-confirmed payment' : state.plan === 'free' ? 'Your first protected system starts here.' : 'Commercial scope retained; no payment asserted.'}</p>
      </div>
      <button className="button outline small" disabled={busy} onClick={load}><RefreshCw size={14}/>Refresh</button>
    </section>
    {subscription?.scheduled_change && <div className="notice">Scheduled: {subscription.scheduled_change.plan.toUpperCase()} on {date(subscription.scheduled_change.effective_at)}. Systems over the new limit remain readable; additional creation pauses.</div>}
    {subscription?.trial && <div className="notice">Trial ends {date(subscription.trial.expires_at)}. It returns to Free unless you explicitly choose a subscription.</div>}
    {subscription?.grace_until && <div className="notice">Payment grace ends {date(subscription.grace_until)}. Capacity remains available during grace, then returns to Free.</div>}
    <section aria-labelledby="usage-heading" className={styles.section}>
      <div className={styles.sectionHead}>
        <h2 id="usage-heading">Usage</h2>
        {subscription && <span>Current period ends {date(subscription.period_end)}</span>}
      </div>
      <div className={styles.meters} aria-label="Usage allowances" role="group">
        <Meter label="Protected systems" used={state.usage.protected_systems} limit={state.entitlements.protected_system_limit}/>
        <Meter label="Security claims" used={state.usage.active_properties} limit={state.entitlements.approved_property_limit}/>
        <Meter label="Verification capacity this month" used={state.usage.consumed + state.usage.reserved} limit={state.entitlements.monthly_verification_budget} suffix={`${state.usage.reserved} reserved · ${state.usage.remaining} available`}/>
      </div>
      <p className={styles.note}>Verification capacity is measured in verification units: one unit per planned trial in a bounded execution, covering both the security control and the legitimate-task control. Units are consumed once execution starts; work that never starts is refunded. No automatic overage charges. Retention is an allowance; plan changes preserve historical records.</p>
    </section>
    <section aria-labelledby="plans-heading" className={styles.section}>
      <div className={styles.sectionHead}>
        <h2 id="plans-heading">Compare plans</h2>
        <span>A plan changes capacity, never a security conclusion. Missing evidence remains missing on every plan.</span>
      </div>
      <PlanComparison plans={state.offers} current={state.plan} busy={busy} editable={editable && (state.mock_available || state.offers.some(p => p.checkout_configured))} select={choose}/>
      {!editable && <p className={styles.note}>An organization owner or admin can change the subscription.</p>}
    </section>
    {subscription?.promotion && <section className={styles.account}><div><h2>{subscription.promotion.code}</h2><p>{subscription.promotion.percent_off}% promotional discount through {date(subscription.promotion.expires_at)}. Commercial discounts do not change security results.</p></div></section>}
    {state.mock_available && editable && subscription && <details className={styles.sandbox}><summary>Local billing sandbox</summary><p>Exercise the commercial lifecycle locally. These controls do not contact a payment provider.</p><div className={styles.actions}>{state.plan === 'free' ? <button className="button outline small" disabled={busy} onClick={() => change('start_trial', {plan:'pro'})}>Start Pro trial</button> : <><button className="button outline small" disabled={busy} onClick={() => change('payment_failed')}>Simulate payment failure</button>{state.status === 'grace' && <button className="button outline small" disabled={busy} onClick={() => change('payment_recovered')}>Simulate payment recovery</button>}<button className="button outline small" disabled={busy} onClick={() => change('cancel')}>Schedule cancellation</button></>}</div><form className={styles.promotion} onSubmit={promotion}><label>Promotion code<input name="code" required maxLength={80} placeholder="BUILDER-ACCESS"/></label><label>Access program<select name="kind"><option value="startup">Startup</option><option value="student">Student</option><option value="open_source">Open source</option><option value="partner">Partner</option></select></label><label>Discount %<input name="percent_off" type="number" min={0} max={100} defaultValue={100} required/></label><label>Duration in days<input name="days" type="number" min={1} max={365} defaultValue={180} required/></label><button className="button outline small" disabled={busy}>Apply local promotion</button></form></details>}
    <details className={styles.sandbox}><summary>Commercial history · every change is recorded</summary><div className={styles.events}>{state.events.slice(0, 12).map(event => <div key={event.id}><strong>{str(event.action).replaceAll('.', ' · ').replaceAll('_', ' ')}</strong><span>{str(event.plan).toUpperCase()} · {str(event.status).replaceAll('_', ' ')}</span><time>{date(event.created_at)}</time></div>)}</div></details>
  </div>;
}
