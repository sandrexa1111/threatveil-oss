'use client';

/**
 * The workspace shell.
 *
 * Primary navigation is four product destinations — Home, Systems, Changes,
 * Integrations — plus a utility group. Every capability that used to have its own
 * global link is still here, reached from the object it belongs to. Old routes keep
 * working: they redirect to the canonical surface rather than 404.
 */

import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  ArrowRight, ArrowUpRight, Boxes, Check, ChevronDown, CircleHelp, CreditCard, GitBranch, Home as HomeIcon,
  LogOut, Menu, Play, Plug, Plus, RefreshCw, Search, Settings, X,
} from 'lucide-react';
import { Brand } from './brand';
import { Home } from './home';
import { ConnectSystem, SystemsInventory } from './systems';
import { Skeleton } from './product';
import { SystemWorkspace, SYSTEM_VIEWS } from './system';
import { Changes } from './changes';
import { Integrations } from './integrations';
import { Settings as SettingsView } from './settings';
import { Tour } from './tour';
import { CommandMenu, rememberSystem } from './command-menu';
import { IntegrityLaunchWorkspace } from './integrity-launch';
import { ReleaseIntegrity } from './release-integrity';
import { TrustRoot } from './change-assurance';
import { ToolContractInstaller } from './tool-contracts';
import {
  api, ApiError, type Dashboard, type Identity, type RecordData, title, items, obj, str, verdict, date,
} from '@/lib/api';
import {
  Badge, Empty, RecordTable, RunDetail, FormDialog, DetailGrid, type FormKind,
  type WorkspaceContext, UtilityPanels,
} from './workspace-parts';

/** Four product destinations. Nothing else earns a global primary link. */
const PRIMARY = [
  {key: '', label: 'Home', icon: HomeIcon},
  {key: 'systems', label: 'Systems', icon: Boxes},
  {key: 'changes', label: 'Changes', icon: GitBranch},
  {key: 'integrations', label: 'Integrations', icon: Plug},
];
const UTILITY = [
  {key: 'billing', label: 'Usage & billing', icon: CreditCard},
  {key: 'settings', label: 'Settings', icon: Settings},
];

/**
 * Old product routes and where they now live. `:id` resolves to the system named in
 * the URL, otherwise the selected system, otherwise the first one.
 */
const MIGRATION: Record<string, string> = {
  overview: '/app',
  assurance: '/app/systems/:id/setup',
  map: '/app/systems/:id/map',
  authority: '/app/systems/:id/capabilities',
  claims: '/app/systems/:id/claims',
  holds: '/app/systems/:id/evidence',
  mappings: '/app/systems/:id/evidence',
  reestablish: '/app/systems/:id/restore',
  decisions: '/app/systems/:id',
  passport: '/app/systems/:id/share',
  sources: '/app/integrations',
  propose: '/app/changes/propose',
};
/** Record-level surfaces kept at their existing URLs, reached from Developer tools. */
const DEVELOPER = new Set(['properties', 'targets', 'runs', 'evidence', 'schedules', 'findings', 'fixes',
  'regressions', 'propagation', 'impact', 'releases', 'records', 'reports', 'gauntlet', 'demo']);

const HEADINGS: Record<string, [string, string]> = {
  billing: ['Usage & billing', 'Protect more systems with a clearly bounded verification capacity.'],
  settings: ['Settings', 'Organization access, role boundaries, and the tools behind the product.'],
  properties: ['Security properties', 'The approved executable claims behind each security conclusion.'],
  targets: ['Authorized targets', 'Every verification is bound by environment, destination, actions and authorization.'],
  runs: ['Execution history', 'Security verdict, legitimate behavior and release decision remain separate.'],
  evidence: ['Evidence ledger', 'Qualified observations, side effects, and the limits of each conclusion.'],
  schedules: ['Schedules', 'Run approved properties on a bounded cadence.'],
  findings: ['Findings', 'Turn a real security lesson into a lasting, executable boundary.'],
  fixes: ['Verified fixes', 'A fix must stop the prohibited outcome and preserve the legitimate task.'],
  regressions: ['Regressions', 'Security properties that failed again after a verified baseline.'],
  propagation: ['Property reuse', 'Review where a proven property may apply to another system.'],
  impact: ['Change explorer', 'Fingerprint diffing, evidence applicability, canaries and selection audits.'],
  releases: ['Releases', 'The historical decision, its evidence applicability and its receipt.'],
  records: ['Signed records', 'Scoped signed records and the published key directory that verifies them.'],
  reports: ['Scoped reports', 'Findings, verification and limitations drawn from actual records.'],
  gauntlet: ['Integrity Launch', 'Establish properties and observation, then leave a release gate installed.'],
  demo: ['Procurement demonstration', 'A synthetic fixture that shows a failure becoming a lasting property.'],
};

const SELECTION_KEY = 'threatveil.selected-system';
/** Topbar contact link. Part of the private launch motion only; set the variable empty to remove it. */
const CONTACT_LABEL = process.env.NEXT_PUBLIC_TV_CONTACT_LABEL ?? '';
const isLocal = (mode: unknown) => /local|development/i.test(String(mode || ''));

export function Workspace() {
  const router = useRouter();
  const path = usePathname();
  const parts = useMemo(() => path.split('/').filter(Boolean), [path]);
  const section = parts[1] || '';
  const [identity, setIdentity] = useState<Identity | null>(null);
  const [dashboard, setDashboard] = useState<Dashboard | null>(null);
  const [targets, setTargets] = useState<RecordData[]>([]);
  const [templates, setTemplates] = useState<RecordData[]>([]);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [menu, setMenu] = useState(false);
  const [filter, setFilter] = useState('');
  const [systemFilter, setSystemFilter] = useState('');
  const [form, setForm] = useState<{kind: FormKind, initial?: RecordData} | null>(null);
  const [detail, setDetail] = useState<RecordData | null>(null);
  const [paging, setPaging] = useState('');
  const [selected, setSelected] = useState('');

  const refresh = useCallback(async () => {
    setError('');
    try {
      const [me, data, ts, tps] = await Promise.all([
        api<Identity>('/auth/me'), api<Dashboard>('/dashboard'),
        api<{items: RecordData[]}>('/targets'), api<{items: RecordData[]}>('/templates')]);
      setIdentity(me); setDashboard(data);
      setTargets(Array.isArray(data.targets) ? data.targets : items(ts)); setTemplates(items(tps));
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) { router.replace('/login'); return; }
      setError(e instanceof Error ? e.message : 'Unable to load workspace.');
    } finally { setLoading(false); }
  }, [router]);
  useEffect(() => { refresh(); }, [refresh]);
  useEffect(() => { setMenu(false); setFilter(''); setDetail(null); }, [path]);

  const systems = items(dashboard?.systems);
  // System context persists across tabs, survives a reload, and follows a direct URL.
  useEffect(() => {
    if (selected) return;
    const stored = typeof window === 'undefined' ? '' : window.localStorage.getItem(SELECTION_KEY) || '';
    if (stored && systems.some(s => s.id === stored)) setSelected(stored);
    else if (systems[0]) setSelected(systems[0].id);
  }, [systems, selected]);
  const urlSystem = section === 'systems' && parts[2] && parts[2] !== 'new' ? parts[2] : '';
  useEffect(() => {
    if (!urlSystem || urlSystem === selected) return;
    setSelected(urlSystem);
    try { window.localStorage.setItem(SELECTION_KEY, urlSystem); } catch { /* private mode */ }
  }, [urlSystem, selected]);
  useEffect(() => { if (urlSystem) rememberSystem(urlSystem); }, [urlSystem]);
  useEffect(() => {
    if (!selected) return;
    try { window.localStorage.setItem(SELECTION_KEY, selected); } catch { /* private mode */ }
  }, [selected]);

  // Old bookmarks keep working: resolve the system they meant, then redirect.
  useEffect(() => {
    const target = MIGRATION[section];
    if (!target) return;
    const named = parts[2] && systems.some(s => s.id === parts[2]) ? parts[2] : '';
    const resolved = named || selected || systems[0]?.id || '';
    if (target.includes(':id')) {
      if (!resolved) { if (!loading) router.replace('/app/systems'); return; }
      router.replace(target.replace(':id', resolved));
    } else router.replace(target);
  }, [section, parts, systems, selected, loading, router]);

  const mutate = useCallback(async (endpoint: string, data: unknown = {}) => {
    if (!identity) throw new Error('Your session is not ready.');
    const result = await api(endpoint, {method: 'POST', data, csrf: identity.csrf_token});
    await refresh();
    return result;
  }, [identity, refresh]);

  const loadMore = useCallback(async (collection: string) => {
    const window_ = dashboard?.pagination?.[collection];
    if (!window_?.next_cursor) return;
    setPaging(collection); setError('');
    try {
      const response = await api(`/workspace/${collection}?cursor=${encodeURIComponent(window_.next_cursor)}&limit=200`);
      const next = items(response);
      setDashboard(current => current ? {...current,
        [collection]: [...items(current[collection as keyof Dashboard]),
          ...next.filter(r => !items(current[collection as keyof Dashboard]).some(old => old.id === r.id))],
        pagination: {...current.pagination, [collection]: obj(response.pagination) as import('@/lib/api').PageWindow}} : current);
      if (collection === 'targets') setTargets(current => [...current, ...next.filter(r => !current.some(old => old.id === r.id))]);
    } catch (e) { setError(e instanceof Error ? e.message : 'Could not load older records.'); }
    finally { setPaging(''); }
  }, [dashboard]);

  const ctx: WorkspaceContext = {identity, dashboard, targets, templates, mutate, refresh, notify: setNotice,
    openForm: (kind, initial) => setForm({kind, initial}), loadMore, paging};

  async function setup() {
    setBusy(true); setError('');
    try { await mutate('/demo/setup'); setNotice('Synthetic procurement fixtures are ready.'); }
    catch (e) { setError(e instanceof Error ? e.message : 'Could not prepare fixtures.'); }
    finally { setBusy(false); }
  }
  async function logout() {
    try { await mutate('/auth/logout'); router.push('/login'); }
    catch (e) { setError(e instanceof Error ? e.message : 'Could not end session.'); }
  }

  const list = (key: keyof Dashboard) => items(dashboard?.[key]).filter(r =>
    (!systemFilter || r.system_id === systemFilter || r.id === systemFilter) &&
    (!filter || JSON.stringify(r).toLowerCase().includes(filter.toLowerCase())));
  const properties = list('properties');
  const runs = list('runs');
  const enabledActions = identity && ['owner', 'admin', 'security', 'developer'].includes(
    str(identity.memberships?.find(m => m.organization_id === identity.organization.id)?.role
      || identity.memberships?.[0]?.role, 'viewer').toLowerCase());
  const heading = HEADINGS[section];
  const inSystem = section === 'systems' && !!urlSystem;
  const systemView = inSystem && SYSTEM_VIEWS.has(parts[3] || '') ? (parts[3] || '') : '';
  const selectedRun = section === 'runs' ? parts[2] : undefined;

  return <div className="workspace">
    <aside className={`sidebar ${menu ? 'is-open' : ''}`}>
      <div className="sidebar-brand"><Brand href="/app"/></div>
      <div className="organization-switch">
        <div className="organization-avatar">{str(identity?.organization?.name, 'T').slice(0, 1).toUpperCase()}</div>
        <div>
          <strong>{str(identity?.organization?.name, 'Workspace')}</strong>
          <small>{identity?.mode?.toLowerCase().includes('local') || identity?.mode === 'development'
            ? 'Local development' : 'Organization workspace'}</small>
        </div>
        <ChevronDown size={14}/>
      </div>
      <nav aria-label="Workspace navigation">
        {PRIMARY.map(item => <Link key={item.key || 'home'} href={item.key ? `/app/${item.key}` : '/app'}
          aria-current={section === item.key ? 'page' : undefined}
          className={`nav-item ${section === item.key ? 'active' : ''}`}>
          <item.icon size={18} strokeWidth={1.65}/><span>{item.label}</span>
        </Link>)}
      </nav>
      <div className="sidebar-bottom">
        {UTILITY.map(item => <Link key={item.key} href={`/app/${item.key}`}
          aria-current={section === item.key ? 'page' : undefined}
          className={`nav-item ${section === item.key ? 'active' : ''}`}>
          <item.icon size={18} strokeWidth={1.65}/><span>{item.label}</span>
        </Link>)}
        <a className="nav-item" href="/docs"><CircleHelp size={18}/><span>Documentation</span><ArrowUpRight size={13}/></a>
        <div className="session-user">
          <div className="user-avatar">{str(identity?.user?.name || identity?.user?.email, 'U').slice(0, 1).toUpperCase()}</div>
          <div>
            <strong>{str(identity?.user?.name, 'Your account')}</strong>
            <small>{str(identity?.user?.email, 'Connecting…')}</small>
          </div>
          <button className="icon-button" onClick={logout} aria-label="Sign out"><LogOut size={16}/></button>
        </div>
      </div>
    </aside>
    {menu && <button className="sidebar-scrim" aria-label="Close navigation" onClick={() => setMenu(false)}/>}

    <div className="workspace-content">
      <header className="workspace-topbar">
        <div className="breadcrumb">
          <button className="mobile-menu icon-button" aria-label="Open navigation" onClick={() => setMenu(!menu)}><Menu size={20}/></button>
          <span>ThreatVeil</span><span>/</span>
          <strong>{PRIMARY.find(item => item.key === section)?.label || heading?.[0]
            || (section === 'systems' ? 'Systems' : str(section).replaceAll('-', ' '))}</strong>
          {inSystem && <><span>/</span><strong>{str(systems.find(s => s.id === urlSystem)?.name, 'System')}</strong></>}
        </div>
        <div className="topbar-actions">
          <CommandMenu systems={systems}/>
          {isLocal(identity?.mode) && <span className="environment" title="Local development workspace"><span/>Local</span>}
          <button className="icon-button" onClick={refresh} aria-label="Refresh workspace"><RefreshCw size={16}/></button>
          {!!CONTACT_LABEL && <Link href="/contact" className="topbar-help">{CONTACT_LABEL} <ArrowUpRight size={13}/></Link>}
        </div>
      </header>

      <main id="main" className="workspace-main">
        {notice && <div className="notice success" role="status"><Check size={16}/><span>{notice}</span>
          <button aria-label="Dismiss notification" className="icon-button" onClick={() => setNotice('')}><X size={15}/></button></div>}
        {error && <div className="notice error" role="alert">{error}
          <button className="text-button" onClick={refresh}>Try again</button></div>}

        {loading ? <Skeleton label="Opening your workspace" rows={4} header/>
        : selectedRun ? <RunDetail id={selectedRun} ctx={ctx}/>
        : inSystem ? <SystemWorkspace ctx={ctx} systemId={urlSystem} view={systemView}/>
        : <>
          {heading && <div className="page-heading">
            <div><h1>{heading[0]}</h1><p>{heading[1]}</p></div>
            <div className="heading-actions">
              {['demo', 'runs'].includes(section)
                ? <button className="button dark small" onClick={() => setForm({kind: 'run'})}
                    disabled={!enabledActions || !properties.length}><Play size={15}/>New run</button>
                : FORM_FOR[section] && <button className="button dark small"
                    onClick={() => setForm({kind: FORM_FOR[section] as FormKind})} disabled={!enabledActions}>
                    <Plus size={16}/>New {FORM_FOR[section] === 'gauntlet' ? 'Integrity Launch' : FORM_FOR[section]}</button>}
            </div>
          </div>}

          {section === '' ? <Home/>
          : section === 'systems' ? (parts[2] === 'new' ? <ConnectSystem ctx={ctx}/> : <SystemsInventory ctx={ctx}/>)
          : section === 'changes' ? <Changes ctx={ctx} tab={parts[2] === 'propose' ? 'proposed' : 'detected'}/>
          : section === 'integrations' ? <Integrations ctx={ctx}/>
          : section === 'settings' ? <SettingsView ctx={ctx} section={parts[2] || 'general'}/>
          : section === 'records' ? <><ReleaseIntegrity ctx={ctx} mode="evidence"/><TrustRoot/></>
          : section === 'releases' ? <ReleaseIntegrity ctx={ctx} mode="releases"/>
          : section === 'gauntlet' ? <IntegrityLaunchWorkspace ctx={ctx}/>
          : section === 'demo' ? <DemoTools ctx={ctx} setup={setup} busy={busy}/>
          : DEVELOPER.has(section) ? <RecordSurface section={section} ctx={ctx} list={list} filter={filter}
              setFilter={setFilter} systemFilter={systemFilter} setSystemFilter={setSystemFilter}
              setDetail={setDetail} setForm={setForm} setError={setError} busy={busy} setBusy={setBusy}
              runs={runs} properties={properties}/>
          : <UtilityPanels section={section} ctx={ctx}/>}
        </>}

        {detail && <RecordDetail record={detail} ctx={ctx} close={() => setDetail(null)}/>}
        <footer className="workspace-footer">
          <span>Prove. Remember. Re-prove.</span><span>Every conclusion has a scope.</span>
        </footer>
      </main>
    </div>
    {identity && <Tour ctx={ctx}/>}
    {form && <FormDialog kind={form.kind} initial={form.initial} ctx={ctx} close={() => setForm(null)}/>}
  </div>;
}

const FORM_FOR: Record<string, string> = {
  properties: 'property', findings: 'finding', targets: 'target', gauntlet: 'gauntlet',
};

/** The original procurement demonstration, kept intact under Developer tools. */
function DemoTools({ctx, setup, busy}: {ctx: WorkspaceContext; setup: () => void; busy: boolean}) {
  const systems = items(ctx.dashboard?.systems);
  const synthetic = systems.find(s => s.demo === true);
  return <>
    <section className="demo-banner">
      <div>
        <div className="eyebrow">CONTROLLED LOCAL DEMONSTRATION</div>
        <h2>See a failure become a lasting property.</h2>
        <p>Synthetic procurement state. Real evaluator, evidence and lineage. No external payments or provider calls.</p>
      </div>
      <button className="button outline small" onClick={setup} disabled={busy}>
        {busy ? 'Preparing…' : synthetic ? 'Refresh demo fixtures' : 'Prepare demo fixtures'}<ArrowRight size={15}/>
      </button>
    </section>
    {synthetic && <DemoRunner ctx={ctx} system={synthetic}/>}
    <section className="card recent-section">
      <div className="card-heading"><div><div className="eyebrow">PERSISTED HISTORY</div><h2>Recent runs</h2></div>
        <Link href="/app/runs" className="text-button">View history <ArrowRight size={14}/></Link></div>
      <RunTable runs={items(ctx.dashboard?.runs).slice(0, 5)} systems={systems}/>
    </section>
  </>;
}

/** The record-level tables, unchanged in behavior and still reachable by URL. */
function RecordSurface({section, ctx, list, filter, setFilter, systemFilter, setSystemFilter, setDetail, setForm,
                        setError, busy, setBusy, runs, properties}: {
  section: string; ctx: WorkspaceContext; list: (key: keyof Dashboard) => RecordData[];
  filter: string; setFilter: (v: string) => void; systemFilter: string; setSystemFilter: (v: string) => void;
  setDetail: (r: RecordData | null) => void; setForm: (f: {kind: FormKind, initial?: RecordData} | null) => void;
  setError: (v: string) => void; busy: boolean; setBusy: (v: boolean) => void;
  runs: RecordData[]; properties: RecordData[];
}) {
  const dashboard = ctx.dashboard;
  if (['impact', 'reports', 'schedules', 'propagation'].includes(section)) return <UtilityPanels section={section} ctx={ctx}/>;
  if (section === 'evidence') return <ReleaseIntegrity ctx={ctx} mode="evidence"/>;
  return <>
    <div className="table-toolbar">
      <div className="input-search"><Search size={16}/>
        <input aria-label={`Search ${section}`} placeholder={`Search loaded ${section}…`}
          value={filter} onChange={e => setFilter(e.target.value)}/></div>
      <select aria-label="Filter by system" value={systemFilter} onChange={e => setSystemFilter(e.target.value)}>
        <option value="">All systems</option>
        {items(dashboard?.systems).map(s => <option key={s.id} value={s.id}>{title(s)}</option>)}
      </select>
      <span className="toolbar-caption">Search applies to loaded records</span>
    </div>
    <WindowControl collection={section === 'gauntlet' ? 'gauntlets' : section === 'regressions' ? 'runs' : section} ctx={ctx}/>
    {section === 'properties' ? <>
      <ToolContractInstaller ctx={ctx}/>
      <RecordTable records={properties} columns={[
        {label: 'Property', render: r => <><strong>{title(r)}</strong><small>{str(r.description, 'Security property')}</small></>},
        {label: 'State', render: r => <Badge value={r.approved ? 'APPROVED' : r.status || r.approval_status || 'DRAFT'}/>},
        {label: 'System', render: r => str(items(dashboard?.systems).find(s => s.id === r.system_id)?.name)},
        {label: 'Created', render: r => date(r.created_at)},
        {label: '', render: r => <button className="text-button" onClick={e => {e.stopPropagation(); setDetail(r);}}>Review <ArrowRight size={14}/></button>},
      ]} onSelect={setDetail} empty="No security properties yet. Create one from a finding or a reviewed template."/>
    </> : section === 'findings' ? <RecordTable records={list('findings')} columns={[
      {label: 'Finding', render: r => <><strong>{title(r)}</strong><small>{str(r.description)}</small></>},
      {label: 'Source', render: r => <span className="tag">{str(r.source_type, 'manual')}</span>},
      {label: 'Created', render: r => date(r.created_at)},
      {label: '', render: r => <button className="text-button" disabled={busy} onClick={async e => {
        e.stopPropagation(); setBusy(true);
        try {
          const proposal = await ctx.mutate('/compiler/propose', {finding_id: r.id});
          setDetail({...proposal, title: 'Review compiler proposal', kind: 'proposal', finding_id: r.id, system_id: r.system_id});
        } catch (err) { setError(err instanceof Error ? err.message : 'Compiler unavailable.'); }
        finally { setBusy(false); }
      }}>Propose property <ArrowRight size={14}/></button>},
    ]} onSelect={setDetail} empty="Capture a finding to start its permanent security memory."/>
    : section === 'targets' ? <RecordTable records={ctx.targets.filter(t => !systemFilter || t.system_id === systemFilter)} columns={[
      {label: 'Target', render: r => <><strong>{title(r)}</strong><small>{str(r.origin, r.adapter === 'synthetic' ? 'Controlled local fixture' : 'No destination')}</small></>},
      {label: 'Adapter', render: r => <span className="tag">{str(r.adapter)}</span>},
      {label: 'Authorization', render: r => <Badge value={r.status || r.authorization_status || (r.verified ? 'VERIFIED' : 'UNVERIFIED')}/>},
      {label: 'Expires', render: r => date(r.expires_at)},
      {label: '', render: r => <button className="text-button" onClick={async e => {
        e.stopPropagation();
        try { const result = await ctx.mutate(`/targets/${r.id}/verify`); setDetail({...r, ...result}); }
        catch (err) { setError(err instanceof Error ? err.message : 'Verification failed.'); }
      }}>Verify <ArrowRight size={14}/></button>},
    ]} onSelect={setDetail} empty="Register an authorized destination before executing a property."/>
    : ['runs', 'regressions'].includes(section)
      ? <RunTable runs={section === 'regressions' ? runs.filter(r => r.regression || obj(r.result).regression) : runs}
          systems={items(dashboard?.systems)}/>
    : section === 'fixes' ? <RecordTable records={list('fixes')} columns={[
      {label: 'Fix', render: r => <><strong>{str(r.description, title(r))}</strong><small className="mono">{r.id.slice(0, 12)}</small></>},
      {label: 'Verification', render: r => <Badge value={r.status || (r.verified ? 'VERIFIED' : 'PENDING')}/>},
      {label: 'Created', render: r => date(r.created_at)},
      {label: '', render: r => r.verification_run_id
        ? <Link href={`/app/runs/${r.verification_run_id}`} className="text-button">View verification <ArrowRight size={14}/></Link> : null},
    ]} onSelect={setDetail} empty="No verified fixes yet. Pair a failing run with a compatible passing verification run."/>
    : <RecordTable records={list('gauntlets')} columns={[
      {label: 'Engagement', render: r => <><strong>{title(r)}</strong><small>{str(r.scope)}</small></>},
      {label: 'Properties', render: r => Array.isArray(r.property_ids) ? r.property_ids.length : 0},
      {label: 'State', render: r => <Badge value={r.status || 'SCOPED'}/>},
      {label: '', render: r => <Link href={`/app/reports?system=${r.system_id}`} className="text-button">View report <ArrowRight size={14}/></Link>},
    ]} onSelect={setDetail} empty="Scope an Integrity Launch to establish one system’s properties, evidence and release workflow."/>}
  </>;
}

export function RunTable({runs, systems}: {runs: RecordData[], systems: RecordData[]}) {
  return <RecordTable records={runs} columns={[
    {label: 'System / candidate', render: r => <Link className="row-title" href={`/app/runs/${r.id}`}>
      <strong>{str(systems.find(s => s.id === r.system_id)?.name, 'System run')}</strong>
      <small className="mono">{str(r.version || obj(r.candidate).version, r.id.slice(0, 12))}</small></Link>},
    {label: 'Security', render: r => <Badge value={verdict(r)}/>},
    {label: 'Task', render: r => <Badge value={r.task_outcome || obj(r.result).task_outcome || 'UNKNOWN'} subtle/>},
    {label: 'Release', render: r => <Badge value={r.release_action || r.release_decision || obj(r.result).release_decision || 'PENDING'} subtle/>},
    {label: 'Executed', render: r => date(r.created_at)},
    {label: '', render: r => <Link href={`/app/runs/${r.id}`} aria-label={`Inspect run ${r.id}`} className="icon-button"><ArrowUpRight size={16}/></Link>},
  ]} empty="No runs in this view. Every result shown here comes from a persisted execution."/>;
}

function DemoRunner({ctx, system}: {ctx: WorkspaceContext, system: RecordData}) {
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');
  const property = items(ctx.dashboard?.properties).find(p => p.system_id === system.id && p.demo === true && p.approved);
  const target = ctx.targets.find(t => t.system_id === system.id && t.adapter === 'synthetic_procurement');
  const router = useRouter();
  async function run(version: string) {
    if (!property || !target) return;
    setBusy(version); setError('');
    try {
      const baseline = items(ctx.dashboard?.baselines).find(f => f.system_id === system.id && f.property_id === property.id && f.target_id === target.id);
      const result = await ctx.mutate('/runs', {system_id: system.id, property_id: property.id, target_id: target.id,
        version, trials: 5, variant_count: 1, idempotency_key: crypto.randomUUID(), ...(baseline?.id ? {baseline_id: baseline.id} : {})});
      router.push(`/app/runs/${result.id}`);
    } catch (e) { setError(e instanceof Error ? e.message : 'Execution failed.'); }
    finally { setBusy(''); }
  }
  return <section className="demo-versions">
    {(!property || !target) && <div className="form-pagination">
      {[...(!property ? ['properties'] : []), ...(!target ? ['targets'] : [])]
        .filter(c => ctx.dashboard?.pagination?.[c]?.next_cursor)
        .map(c => <button key={c} className="button outline small" disabled={!!ctx.paging} onClick={() => ctx.loadMore(c)}>
          Load older demo {c}<ArrowRight size={13}/></button>)}
    </div>}
    <div className="demo-version-head"><h3>Choose a candidate to execute</h3><span>5 trials · 1 variant · synthetic fixture</span></div>
    <div className="demo-version-list">{[
      {v: 'vulnerable', t: '01 · Vulnerable', d: 'Test the authorization boundary'},
      {v: 'fixed', t: '02 · Fixed', d: 'Verify security and useful behavior'},
      {v: 'regressed', t: '03 · Regressed', d: 'Replay against a later version'},
      {v: 'missing_witness', t: '04 · Missing witness', d: 'Observe why uncertainty matters'},
      {v: 'bad_fix', t: '05 · Bad fix', d: 'Security alone is not a useful fix'},
    ].map(v => <button key={v.v} disabled={!!busy || !property || !target} onClick={() => run(v.v)}>
      <strong>{busy === v.v ? 'Executing…' : v.t}</strong><span>{v.d}</span><ArrowUpRight size={14}/>
    </button>)}</div>
    {error && <p className="notice error" role="alert">{error}</p>}
  </section>;
}

function RecordDetail({record: r, ctx, close}: {record: RecordData, ctx: WorkspaceContext, close: () => void}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const isProperty = r.kind === 'property' || Boolean(r.definition);
  const proposal = r.kind === 'proposal';
  async function approve() {
    setBusy(true); setError('');
    try { await ctx.mutate(`/properties/${r.id}/approve`); ctx.notify('A new approved property version has been created.'); close(); }
    catch (e) { setError(e instanceof Error ? e.message : 'Approval failed.'); }
    finally { setBusy(false); }
  }
  return <div className="detail-panel">
    <div className="card-heading">
      <div><div className="eyebrow">{proposal ? 'HUMAN REVIEW REQUIRED' : 'PERSISTED RECORD'}</div><h2>{title(r)}</h2></div>
      <button className="icon-button" onClick={close} aria-label="Close record"><X size={19}/></button>
    </div>
    <p>{str(r.description, 'Inspect the definition, provenance, and recorded state before continuing.')}</p>
    <DetailGrid data={{Identifier: r.id, Kind: r.kind || (isProperty ? 'property' : 'record'), Created: date(r.created_at)}}/>
    {error && <p role="alert" className="notice error">{error}</p>}
    <div className="detail-actions">
      {isProperty && !proposal && !r.approved && r.status !== 'APPROVED' &&
        <button className="button dark small" onClick={approve} disabled={busy}>{busy ? 'Approving…' : 'Approve new version'}<Check size={14}/></button>}
      {proposal && <button className="button dark small" onClick={() => {
        ctx.openForm('property', {...r, title: obj(r.proposal).title || '', description: obj(r.proposal).property || '',
          template_id: obj(r.proposal).suggested_template_id,
          definition: r.definition || ctx.templates.find(t => t.id === obj(r.proposal).suggested_template_id)?.definition});
        close();
      }}>Review in property editor <ArrowRight size={14}/></button>}
      <button className="button outline small" onClick={close}>Close</button>
    </div>
  </div>;
}

function WindowControl({collection, ctx}: {collection: string, ctx: WorkspaceContext}) {
  const page = ctx.dashboard?.pagination?.[collection];
  if (!page) return null;
  const loaded = collection === 'targets' ? ctx.targets.length : items(ctx.dashboard?.[collection as keyof Dashboard]).length;
  return <div className="window-control">
    <span>{loaded} of {page.total} {collection} loaded · newest first{page.next_cursor ? ' · older records remain available' : ''}</span>
    {page.next_cursor && <button className="button outline small" disabled={!!ctx.paging} onClick={() => ctx.loadMore(collection)}>
      {ctx.paging === collection ? 'Loading…' : `Load older ${collection}`}<ArrowRight size={14}/></button>}
  </div>;
}

export { Empty };
