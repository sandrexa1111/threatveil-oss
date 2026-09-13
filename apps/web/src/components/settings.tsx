'use client';

/**
 * Settings, as five sections instead of one long page. Every existing control is kept
 * and only reorganised; role enforcement stays in the API, and export semantics are
 * unchanged. Identifiers are available, but under details rather than as headline facts.
 */

import Link from 'next/link';
import { useEffect, useState, type FormEvent } from 'react';
import { ArrowRight, Building2, Copy, Database, Download, Plus, ShieldCheck, Terminal, Users } from 'lucide-react';
import { api, date, items, obj, str, type RecordData } from '@/lib/api';
import { StatusPill, Skeleton, arr, num, plural, type Fields } from './product';
import { DeveloperTools } from './developer';
import { ObserverManager } from './observers';
import { TokenManager } from './workspace-operate';
import { JsonDetails, type WorkspaceContext } from './workspace-parts';
import { SourceMark } from './ecosystem';
import c from './completion.module.css';

export const SETTINGS_SECTIONS = [
  {key: 'general', label: 'General', icon: Building2},
  {key: 'members', label: 'Members', icon: Users},
  {key: 'security', label: 'Security', icon: ShieldCheck},
  {key: 'developer', label: 'Developer', icon: Terminal},
  {key: 'data', label: 'Data & export', icon: Database},
] as const;

const MODE: Record<string, string> = {
  local: 'Local development sign-in', development: 'Local development sign-in', session: 'Signed-in session',
  firebase: 'Identity provider session', api_token: 'API token',
};

export function Settings({ctx, section}: {ctx: WorkspaceContext; section: string}) {
  const current = SETTINGS_SECTIONS.find(item => item.key === section) ? section : 'general';
  return <div className={c.settings}>
    <nav className={c.settingsNav} aria-label="Settings sections">
      {SETTINGS_SECTIONS.map(item => <Link key={item.key} href={`/app/settings/${item.key}`}
        aria-current={current === item.key ? 'page' : undefined}>
        <item.icon size={14} aria-hidden="true"/>{item.label}
      </Link>)}
    </nav>
    <div className={c.settingsBody}>
      {current === 'general' && <General ctx={ctx}/>}
      {current === 'members' && <Members ctx={ctx}/>}
      {current === 'security' && <Security ctx={ctx}/>}
      {current === 'developer' && <Developer ctx={ctx}/>}
      {current === 'data' && <DataExport/>}
    </div>
  </div>;
}

function role(ctx: WorkspaceContext) {
  const identity = ctx.identity;
  return str(identity?.memberships?.find(m => m.organization_id === identity.organization.id)?.role
    || identity?.memberships?.[0]?.role, 'viewer');
}

function General({ctx}: {ctx: WorkspaceContext}) {
  const identity = ctx.identity;
  const mode = str(identity?.mode, '');
  return <section className={c.settingsSection} aria-labelledby="settings-general">
    <h2 id="settings-general">General</h2>
    <p>Your organization and how you are signed in to it.</p>
    <div className={c.panel}>
      <h3>Organization</h3>
      <dl className={c.kv}>
        <div><dt>Workspace name</dt><dd>{str(identity?.organization.name)}</dd></div>
        <div><dt>Your role</dt><dd>{role(ctx)}</dd></div>
        <div><dt>Signed in as</dt><dd>{str(identity?.user.name, '')} {str(identity?.user.email, '')}</dd></div>
        <div><dt>Authentication</dt><dd>{MODE[mode.toLowerCase()] || mode.replaceAll('_', ' ')}</dd></div>
      </dl>
      <details>
        <summary className="muted" style={{cursor: 'pointer'}}>Technical identifiers</summary>
        <dl className={c.kv} style={{marginTop: 8}}>
          <div><dt>Organization ID</dt><dd className="mono">{str(identity?.organization.id)}</dd></div>
          <div><dt>User ID</dt><dd className="mono">{str(identity?.user.id)}</dd></div>
        </dl>
      </details>
    </div>
  </section>;
}

function Members({ctx}: {ctx: WorkspaceContext}) {
  const [members, setMembers] = useState<RecordData[] | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  useEffect(() => { api('/members').then(r => setMembers(items(r))).catch(e => { setMembers([]); setError(e.message); }); }, []);
  async function invite(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    setBusy(true); setError('');
    try {
      await ctx.mutate('/members/invite', Object.fromEntries(new FormData(form)));
      ctx.notify('Invitation request recorded. Delivery depends on configured transactional email.');
      form.reset();
    } catch (e) { setError(e instanceof Error ? e.message : 'Could not create invitation.'); }
    finally { setBusy(false); }
  }
  return <section className={c.settingsSection} aria-labelledby="settings-members">
    <h2 id="settings-members">Members</h2>
    <p>Who can act in this organization. Role checks are enforced by the API, and the last owner cannot be removed.</p>
    <div className={c.panel}>
      <div className={c.panelHead}><h3>{members ? plural(members.length, 'member') : 'People in this organization'}</h3></div>
      {!members ? <Skeleton label="Loading members" rows={2}/> : <dl className={c.kv}>
        {members.map(member => <div key={member.id}>
          <dt>{str(member.name || obj(member.user).name || member.email)}</dt>
          <dd style={{display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center'}}>
            <span className="tag">{str(member.role)}</span>
            <span className="muted">{str(member.email || obj(member.user).email, '')}</span>
            <span className="muted">joined {date(member.created_at)}</span>
          </dd>
        </div>)}
        {!members.length && <div><dt>No member records were returned for this organization.</dt><dd/></div>}
      </dl>}
    </div>
    <div className={c.panel}>
      <h3>Invite a collaborator</h3>
      <form className="inline-form" onSubmit={invite}>
        <label>Email<input name="email" type="email" required placeholder="colleague@company.com"/></label>
        <label>Role<select name="role">
          <option value="viewer">Viewer</option><option value="developer">Developer</option>
          <option value="security">Security</option><option value="admin">Admin</option>
        </select></label>
        <button className="button dark small" disabled={busy}>Invite <Plus size={15}/></button>
      </form>
      {error && <div className="notice error" role="alert">{error}</div>}
    </div>
  </section>;
}

function Security({ctx}: {ctx: WorkspaceContext}) {
  const [integrations, setIntegrations] = useState<Fields | null>(null);
  const [credentials, setCredentials] = useState<RecordData[] | null>(null);
  const [restricted, setRestricted] = useState(false);
  useEffect(() => { api<Fields>('/integrations').then(setIntegrations).catch(() => setIntegrations({})); }, []);
  useEffect(() => {
    api('/credentials').then(r => setCredentials(items(r))).catch(() => { setRestricted(true); setCredentials([]); });
  }, []);
  const github = arr(integrations?.items).find(item => item.id === 'github');
  const bindings = arr(github?.bindings);
  return <section className={c.settingsSection} aria-labelledby="settings-security">
    <h2 id="settings-security">Security</h2>
    <p>How people and workflows are allowed to act in this organization.</p>
    <div className={c.panel}>
      <h3>Authentication</h3>
      <dl className={c.kv}>
        <div><dt>Current session</dt><dd>{MODE[str(ctx.identity?.mode).toLowerCase()] || str(ctx.identity?.mode)}</dd></div>
        <div><dt>Write protection</dt><dd>Every change is sent with a per-session CSRF token</dd></div>
      </dl>
    </div>
    <div className={c.panel}>
      <div className={c.panelHead}>
        <h3 style={{display: 'flex', gap: 8, alignItems: 'center'}}><SourceMark id="github"/>Trusted workflow bindings</h3>
        <StatusPill label={num(github?.active_bindings) ? `${num(github?.active_bindings)} bound` : 'No active binding'}
          tone={num(github?.active_bindings) ? 'ok' : 'neutral'} canonical={str(github?.status, 'no_active_binding')}/>
      </div>
      <p>A repository binding constrains owner identity, workflow, branch and execution scope. A binding is configuration; it does not demonstrate a successful GitHub run.</p>
      {!!bindings.length && <dl className={c.kv}>{bindings.map(binding => <div key={str(binding.repository_id)}>
        <dt>{str(binding.repository)}</dt>
        <dd><span className="mono">{str(binding.workflow_ref)}</span> · {str(binding.allowed_ref)} · {!binding.enabled ? 'disabled' : binding.owner_authorized ? 'bound' : 'owner authority required'}</dd>
      </div>)}</dl>}
    </div>
    <div className={c.panel}>
      <h3>Credential references</h3>
      <p>Read credentials for live sources are registered as references. ThreatVeil stores the reference, never the secret value.</p>
      {!credentials ? <Skeleton label="Loading credential references" rows={1}/>
        : restricted ? <p>Visible to owners, admins and security members.</p>
        : credentials.length ? <dl className={c.kv}>{credentials.map(credential => <div key={credential.id}>
            <dt>{str(credential.name || credential.label, 'Credential reference')}</dt>
            <dd className="mono">{credential.id}</dd>
          </div>)}</dl>
        : <p>No credential reference is registered, so a live GitHub or Cloud Run source needs configuration first.</p>}
    </div>
  </section>;
}

const CLI = 'threatveil run --system SYSTEM_ID --property PROPERTY_ID --target TARGET_ID --candidate-version "$GITHUB_SHA"';

function Developer({ctx}: {ctx: WorkspaceContext}) {
  const [copied, setCopied] = useState(false);
  const [integrations, setIntegrations] = useState<unknown>(null);
  useEffect(() => { api('/integrations').then(setIntegrations).catch(() => undefined); }, []);
  return <section className={c.settingsSection} aria-labelledby="settings-developer">
    <h2 id="settings-developer">Developer</h2>
    <p>Machine access, the command-line workflow, qualified observers and the record-level tools behind the product.</p>
    <TokenManager ctx={ctx}/>
    <div className={c.panel}>
      <div className={c.panelHead}>
        <h3>Command-line workflow</h3>
        <button className="button outline small" onClick={async () => { await navigator.clipboard.writeText(CLI); setCopied(true); }}>
          <Copy size={14}/>{copied ? 'Copied' : 'Copy example'}
        </button>
      </div>
      <pre className="code-block">{CLI}</pre>
      <p>Set TV_API_URL and TV_API_TOKEN in your environment or CI secret store. Pass an explicit candidate version, and use --observer for qualified customer observations. Never put token values in command history.</p>
    </div>
    <div id="observers"><ObserverManager ctx={ctx}/></div>
    <div className={c.panel}>
      <div className={c.panelHead}>
        <h3>Scheduled verification</h3>
        <Link href="/app/schedules" className="button outline small">Manage schedules <ArrowRight size={14}/></Link>
      </div>
      <p>Run approved checks on authorized targets with a bounded cadence.</p>
    </div>
    <DeveloperTools/>
    <JsonDetails data={integrations || {status: 'loading'}} label="Configured integration status"/>
  </section>;
}

function DataExport() {
  const [commercial, setCommercial] = useState<Fields | null>(null);
  useEffect(() => { api<Fields>('/commercial').then(setCommercial).catch(() => setCommercial({})); }, []);
  const retention = num(obj(commercial?.entitlements).retention_days);
  return <section className={c.settingsSection} aria-labelledby="settings-data">
    <h2 id="settings-data">Data &amp; export</h2>
    <p>What this organization holds, and how to take it with you.</p>
    <div className={c.panel}>
      <div className={c.panelHead}>
        <h3>Security memory</h3>
        <a className="button outline small" href="/api/backend/v1/memory/export" download="threatveil-memory.ndjson">
          <Download size={15}/>Export memory
        </a>
      </div>
      <p>Download the organization’s immutable records and relationships as NDJSON. Detailed captures keep their own access and retention rules.</p>
    </div>
    <div className={c.panel}>
      <h3>Retention</h3>
      <dl className={c.kv}>
        <div><dt>Retention allowance</dt><dd>{commercial ? retention ? `${retention} days on your current plan` : 'Not available' : 'Loading…'}</dd></div>
        <div><dt>History</dt><dd>Records are append-only. Plan changes preserve historical records.</dd></div>
      </dl>
    </div>
    <div className={c.panel}>
      <div className={c.panelHead}>
        <h3>Scoped reports</h3>
        <Link href="/app/reports" className="button outline small">Open reports <ArrowRight size={14}/></Link>
      </div>
      <p>Evidence-supported reports drawn from actual records, with their scope and limitations.</p>
    </div>
  </section>;
}
