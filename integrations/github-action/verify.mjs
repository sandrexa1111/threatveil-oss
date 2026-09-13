import { appendFileSync } from 'node:fs';

const base = new URL(process.env.TV_ACTION_API_URL);
if (base.protocol !== 'https:' || base.username || base.password || base.search || base.hash) throw new Error('ThreatVeil requires an HTTPS API URL without credentials or query.');
if (!['push','workflow_dispatch'].includes(process.env.GITHUB_EVENT_NAME)) throw new Error('Use a trusted push or deployment workflow; fork and pull-request execution are disabled.');
const sha = process.env.GITHUB_SHA;
if (!/^[0-9a-f]{40}$/.test(sha)) throw new Error('Exact candidate SHA required.');
async function identity() {
  const url = new URL(process.env.ACTIONS_ID_TOKEN_REQUEST_URL);
  if (url.protocol !== 'https:') throw new Error('GitHub identity URL must use HTTPS.');
  url.searchParams.set('audience','threatveil-verify');
  const response = await fetch(url,{headers:{Authorization:`Bearer ${process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN}`},redirect:'error',signal:AbortSignal.timeout(15_000)});
  if (!response.ok) throw new Error('GitHub OIDC unavailable; grant id-token: write.');
  return (await response.json()).value;
}
async function api(path,method='GET') {
  const response = await fetch(base.href.replace(/\/$/,'')+path,{method,headers:{Authorization:`Bearer ${await identity()}`},redirect:'error',signal:AbortSignal.timeout(30_000)});
  if (!response.ok) throw new Error(`ThreatVeil rejected the request (${response.status}). Inspect the trusted binding and workspace.`);
  return response.json();
}
const started = await api('/v1/github/runs','POST');
let result;
const deadline=Date.now()+10*60_000;
while(Date.now()<deadline) {
  result=await api(`/v1/github/runs/${started.id}`);
  if (['COMPLETED','ERROR','CANCELLED','TIMEOUT'].includes(result.status)) break;
  await new Promise(resolve=>setTimeout(resolve,5000));
}
if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY,`ThreatVeil run ${started.id}\n\nCandidate: ${sha}\n\nSecurity: ${result?.security_verdict||'INCONCLUSIVE'}\n\nRelease: ${result?.release_action||'BLOCK'}\n`);
if (result?.sha!==sha||result?.status!=='COMPLETED'||result?.release_action!=='ALLOW') throw new Error('Release blocked: qualified exact-candidate assurance has not passed.');
console.log(`ThreatVeil allowed candidate ${sha}; evidence ${result.evidence_digest}.`);
