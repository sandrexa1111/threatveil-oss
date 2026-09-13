'use client';

/**
 * One way to hand ThreatVeil a definition: drop or choose a file (or paste it), let the
 * server detect the format deterministically, and show what it established. Onboarding,
 * Integrations and the proposed-change check all use this, so a file is read the same
 * way everywhere. An ambiguous file is a question, never a guess.
 */

import { useCallback, useState } from 'react';
import { AlertTriangle, Check, Upload } from 'lucide-react';
import { api, obj, str } from '@/lib/api';
import { list, type Fields } from './product';
import { FORMATS, SourceMark, formatInfo } from './ecosystem';
import type { WorkspaceContext } from './workspace-parts';
import styles from './product.module.css';
import c from './completion.module.css';

export const MAX_DEFINITION_BYTES = 256 * 1024;

export function useDefinition(ctx: WorkspaceContext) {
  const [text, setText] = useState('');
  const [fileName, setFileName] = useState('');
  const [result, setResult] = useState<Fields | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const read = useCallback(async (value: string, name: string, format = 'auto') => {
    setError(''); setBusy(true);
    try {
      setResult(await api<Fields>('/connectors/definition-preview', {method: 'POST', csrf: ctx.identity?.csrf_token,
        data: {format, document: value, filename: name || null}}));
    } catch (e) {
      setResult(null);
      setError(e instanceof Error ? e.message : 'Could not read that definition.');
    } finally { setBusy(false); }
  }, [ctx.identity?.csrf_token]);

  const pick = useCallback(async (file: File) => {
    if (file.size > MAX_DEFINITION_BYTES) { setError('That file is larger than 256 KiB, the bound for one definition.'); return; }
    const value = await file.text();
    setText(value); setFileName(file.name);
    await read(value, file.name);
  }, [read]);

  const reset = useCallback(() => { setText(''); setFileName(''); setResult(null); setError(''); }, []);
  const format = str(result?.format, '');
  return {text, setText, fileName, result, format, detection: obj(result?.detection), error, busy, read, pick, reset};
}
export type Definition = ReturnType<typeof useDefinition>;

/** What an import endpoint receives: parsed JSON when the text is JSON, otherwise the text itself. */
export function documentOf(text: string, format: string): unknown {
  if (format === 'claude_subagent') return text;
  try { return JSON.parse(text); } catch { return text; }
}

export function DropZone({onFile, label = 'Upload configuration file', hint, accept}: {
  onFile: (file: File) => void; label?: string; hint: string; accept?: string;
}) {
  const [over, setOver] = useState(false);
  return <div className={c.drop} data-over={over ? 'true' : undefined}
    onDragOver={event => { event.preventDefault(); setOver(true); }} onDragLeave={() => setOver(false)}
    onDrop={event => { event.preventDefault(); setOver(false); const file = event.dataTransfer.files?.[0]; if (file) onFile(file); }}>
    <Upload size={18} aria-hidden="true"/>
    <strong>Drop a file here</strong>
    <p>{hint}</p>
    <label className="button outline small" style={{cursor: 'pointer', color: 'var(--ink)', fontSize: 12}}>
      Choose file
      <input type="file" className="sr-only" aria-label={label}
        accept={accept || '.json,.yaml,.yml,.md,application/json,text/yaml,text/markdown'}
        onChange={event => { const file = event.target.files?.[0]; if (file) onFile(file); event.target.value = ''; }}/>
    </label>
  </div>;
}

const HINT: Record<string, string> = {
  OPENAI_AGENTS_TRACE: 'This is an OpenAI Agents SDK trace export. It is evidence of what ran, not a definition: import it from Integrations once the system exists.',
  AGENT_SDK_HOOK_EVENTS: 'This looks like a list of agent hook events. They are evidence of what ran, not a definition: import them from Integrations once the system exists.',
};

/** The detection result, and the only place a format is ever chosen by hand. */
export function DetectionBar({definition, allowed}: {definition: Definition; allowed?: string[]}) {
  const {result, detection, error, fileName, text} = definition;
  if (error) return <div className="notice error" role="alert">{error}</div>;
  if (!result) return null;
  const choose = (format: string) => definition.read(text, fileName, format);
  const options = FORMATS.filter(format => !allowed || allowed.includes(format.id));
  if (result.format) {
    const info = formatInfo(result.format);
    const outside = allowed && !allowed.includes(str(result.format));
    return <div className={c.detection} data-status={outside ? 'UNSUPPORTED' : 'DETECTED'} role="status">
      {outside ? <AlertTriangle size={14} aria-hidden="true"/> : <Check size={14} aria-hidden="true"/>}
      <span>{detection.status === 'DETECTED' ? 'Detected' : 'Read as'}</span>
      <SourceMark id={info?.ecosystem}/>
      <strong>{info?.label || str(result.format)}</strong>
      {!!fileName && <span className={c.fileName}>{fileName}</span>}
      {outside && <span>This source cannot read that format.</span>}
      <details style={{marginLeft: 'auto'}}>
        <summary className={styles.muted} style={{cursor: 'pointer'}}>Advanced: choose the format</summary>
        <select aria-label="Definition format" value={str(result.format)} onChange={event => choose(event.target.value)}
          style={{marginTop: 6}}>
          {options.map(format => <option key={format.id} value={format.id}>{format.label} ({format.file})</option>)}
        </select>
      </details>
    </div>;
  }
  if (detection.status === 'AMBIGUOUS') return <div className={c.detection} data-status="AMBIGUOUS" role="status">
    <AlertTriangle size={14} aria-hidden="true"/>
    <span>This file fits more than one format. Which is it?</span>
    {list(detection.candidates).map(format => <button key={format} type="button" className="button outline small"
      onClick={() => choose(format)}>{formatInfo(format)?.label || format}</button>)}
  </div>;
  return <div className={c.detection} data-status="UNSUPPORTED" role="status">
    <AlertTriangle size={14} aria-hidden="true"/>
    <span>{HINT[str(detection.hint)] || 'No supported format matches this file. ThreatVeil reads Claude Code settings and subagents, .mcp.json, MCP tool catalogs, langgraph.json, CrewAI agents.yaml and the ThreatVeil manifest.'}</span>
  </div>;
}

function Group({label, values, empty = 'none declared', children}: {
  label: string; values?: string[]; empty?: string; children?: React.ReactNode;
}) {
  return <div>
    <span className={styles.detectedLabel}>{label}</span>
    {children || (values && values.length
      ? <div className={styles.detectedValues}>{values.slice(0, 12).map(value => <code key={value}>{value}</code>)}
          {values.length > 12 && <span className={styles.muted}>+{values.length - 12} more</span>}</div>
      : <span className={styles.muted}>{empty}</span>)}
  </div>;
}

/** Everything ThreatVeil established from the file, with nothing inferred. */
export function FoundFacts({result}: {result: Fields}) {
  const info = formatInfo(result.format);
  const permissions = result.permissions ? obj(result.permissions) : null;
  const ecosystem = list(result.ecosystem);
  const inherits = list(result.inherits_all_tools);
  return <>
    <div className={c.found}>
      <Group label="Definition"><span style={{display: 'flex', gap: 6, alignItems: 'center', fontSize: 13}}>
        <SourceMark id={info?.ecosystem}/>{info ? info.label : str(result.format)}
      </span></Group>
      <Group label="Detected stack">{ecosystem.length
        ? <span style={{display: 'flex', gap: 10, flexWrap: 'wrap'}}>{ecosystem.map(id => <SourceMark key={id} id={id} name/>)}</span>
        : <span className={styles.muted}>no ecosystem established by this format</span>}</Group>
      <Group label="Models (advertised)" values={list(result.models)}/>
      <Group label="Tools" values={list(result.tools)} empty={inherits.length ? `${inherits.join(', ')} inherits every parent tool` : 'none declared'}/>
      <Group label="MCP servers" values={list(result.mcp_servers)}/>
      <Group label="Agents" values={list(result.agents)}/>
      {permissions && <Group label="Permissions"><span style={{fontSize: 12.5}}>
        {list(permissions.allow).length} allowed · {list(permissions.deny).length} denied · {list(permissions.ask).length} ask first
        {!!permissions.default_mode && ` · default mode ${str(permissions.default_mode)}`}
        {!!list(permissions.deny).length && <span className={styles.detectedValues} style={{marginTop: 4}}>
          {list(permissions.deny).slice(0, 8).map(rule => <code key={`deny-${rule}`}>deny {rule}</code>)}</span>}
      </span></Group>}
      {!!list(result.approval_required).length && <Group label="Requires approval" values={list(result.approval_required)}/>}
      {!!list(result.delegation).length && <Group label="May delegate" values={list(result.delegation)}/>}
      {!!list(result.code_execution).length && <Group label="May execute code" values={list(result.code_execution)}/>}
    </div>
    {result.complete === false && <p className={styles.muted}>
      This format does not declare everything ThreatVeil compares; the parts it omits stay unknown.
    </p>}
    {!!list(result.ignored_fields).length && <p className={styles.muted}>
      {list(result.ignored_fields).length} field(s) have no reviewed semantics and will not be compared.
    </p>}
    <ul className={styles.limits}>{list(result.limitations).map(line => <li key={line}>{line}</li>)}</ul>
  </>;
}
