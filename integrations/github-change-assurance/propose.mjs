#!/usr/bin/env node
// ThreatVeil — Change Assurance, as a pull-request check.
//
// Reads one proposed configuration from the checked-out repository, asks ThreatVeil what it
// would break, and writes the answer to the job summary. The request is read-only with
// respect to current clearance: ThreatVeil records the assessment as PROPOSED, NON-ACTIVE,
// NOT CURRENT STATE, and never changes a claim, evidence or a clearance because of it.
//
// The step does not fail the build unless fail-on is set explicitly. A security answer that
// blocks every pull request by default is a security answer nobody keeps.

import { createHash } from 'node:crypto';
import { readFile, appendFile, stat } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';

const MAX_BYTES = 262_144;
const FORMATS = new Set(['manifest', 'claude_settings', 'mcp_json', 'claude_subagent', 'langgraph', 'crewai']);

function required(name) {
  const value = process.env[name];
  if (!value) { console.error(`${name} is required`); process.exit(1); }
  return value;
}

function inferFormat(path) {
  const name = path.split('/').pop().toLowerCase();
  if (name === 'settings.json' || name === 'settings.local.json') return 'claude_settings';
  if (name === '.mcp.json') return 'mcp_json';
  if (name === 'langgraph.json') return 'langgraph';
  if (name === 'agents.yaml' || name === 'agents.yml') return 'crewai';
  if (path.includes('.claude/agents/') && name.endsWith('.md')) return 'claude_subagent';
  if (name.includes('threatveil') && /\.(json|ya?ml)$/.test(name)) return 'manifest';
  return '';
}

async function payloadFor(path, chosen) {
  const info = await stat(path);
  if (info.size > MAX_BYTES) { console.error('The proposed configuration exceeds 256 KiB'); process.exit(1); }
  const raw = await readFile(path, 'utf8');
  if (!chosen) {
    try { return JSON.parse(raw); }
    catch { console.error('Provide a format for a non-JSON configuration'); process.exit(1); }
  }
  const document = path.endsWith('.json') ? JSON.parse(raw) : raw;
  return { format: chosen, document };
}

function reference() {
  const event = process.env.GITHUB_EVENT_NAME || 'manual';
  const ref = process.env.GITHUB_REF || '';
  const pull = /refs\/pull\/(\d+)\//.exec(ref);
  const sha = process.env.GITHUB_SHA && /^[0-9a-f]{7,64}$/.test(process.env.GITHUB_SHA) ? process.env.GITHUB_SHA : null;
  const server = process.env.GITHUB_SERVER_URL || 'https://github.com';
  const repository = process.env.GITHUB_REPOSITORY || '';
  if (pull) {
    return {type: 'PULL_REQUEST', id: `#${pull[1]}`, revision: sha,
            url: repository ? `${server}/${repository}/pull/${pull[1]}` : null};
  }
  if (event === 'push' && sha) {
    return {type: 'COMMIT', id: null, revision: sha,
            url: repository ? `${server}/${repository}/commit/${sha}` : null};
  }
  return {type: 'MANUAL', id: null, url: null, revision: sha};
}

async function main() {
  const base = required('TV_ACTION_API_URL').replace(/\/+$/, '');
  const token = required('TV_ACTION_API_TOKEN');
  const system = required('TV_ACTION_SYSTEM_ID');
  const installation = required('TV_ACTION_INSTALLATION_ID');
  const file = required('TV_ACTION_FILE');
  const format = (process.env.TV_ACTION_FORMAT || '').trim() || inferFormat(file);
  if (format && !FORMATS.has(format)) { console.error(`Unsupported format ${format}`); process.exit(1); }
  const failOn = (process.env.TV_ACTION_FAIL_ON || 'never').trim().toLowerCase();
  const payload = await payloadFor(file, format);
  // One deterministic key per commit and file, so a re-run reads the same recorded answer.
  const key = createHash('sha256').update(`${process.env.GITHUB_SHA || randomUUID()}:${file}`).digest('hex').slice(0, 48);
  const response = await fetch(`${base}/v1/systems/${system}/proposed-changes`, {
    method: 'POST',
    headers: {'Content-Type': 'application/json', Authorization: `Bearer ${token}`,
              'X-ThreatVeil-Consumer': 'github-actions'},
    body: JSON.stringify({installation_id: installation, payload, reference: reference(), idempotency_key: key}),
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    console.error(`ThreatVeil could not evaluate this change (${response.status}): ${body.detail || 'no detail'}`);
    process.exit(failOn === 'never' ? 0 : 1);
  }
  const summary = body.summary || {};
  const check = body.check || {};
  const lines = [`## ${check.name || 'ThreatVeil — Change Assurance'}`, '', check.summary || summary.headline || '',
                 '', `_${body.label || 'PROPOSED · NON-ACTIVE · NOT CURRENT STATE'}_`];
  if (process.env.GITHUB_STEP_SUMMARY) await appendFile(process.env.GITHUB_STEP_SUMMARY, lines.join('\n') + '\n');
  if (process.env.GITHUB_OUTPUT) {
    await appendFile(process.env.GITHUB_OUTPUT,
      `effect=${summary.effect || 'UNKNOWN'}\nconclusion=${check.conclusion || 'neutral'}\nassessment-id=${body.id || ''}\n`);
  }
  console.log(`${summary.headline || 'No answer'} (${summary.effect || 'UNKNOWN'}); current clearance ${
    (body.clearance || {}).current || 'UNKNOWN'} is unchanged by this check.`);
  const blocking = (failOn === 'reproof' && summary.effect === 'WOULD_REQUIRE_REPROOF')
    || (failOn === 'unknown' && ['WOULD_REQUIRE_REPROOF', 'NO_BASELINE', 'DECLARED_CLAIMS_AFFECTED'].includes(summary.effect));
  process.exit(blocking ? 1 : 0);
}

main().catch(error => { console.error(error instanceof Error ? error.message : String(error)); process.exit(1); });
