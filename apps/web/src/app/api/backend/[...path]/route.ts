import { NextRequest } from 'next/server';
export const dynamic = 'force-dynamic';
const methods = new Set(['GET', 'POST', 'PATCH', 'PUT', 'DELETE']);
let serviceIdentity: {token:string; expires:number; audience:string}|null=null;
async function cloudIdentity(audience:string):Promise<string>{
  if(serviceIdentity?.audience===audience&&serviceIdentity.expires>Date.now()+60_000)return serviceIdentity.token;
  const url=new URL('http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity');
  url.searchParams.set('audience',audience);url.searchParams.set('format','full');
  const response=await fetch(url,{headers:{'Metadata-Flavor':'Google'},signal:AbortSignal.timeout(5000),cache:'no-store'});
  if(!response.ok)throw new Error('Service identity unavailable');
  const token=await response.text();if(token.length>16000||token.split('.').length!==3)throw new Error('Invalid service identity');
  const expiry=Number(JSON.parse(Buffer.from(token.split('.')[1],'base64url').toString()).exp)*1000;
  serviceIdentity={token,expires:Number.isFinite(expiry)?expiry:Date.now()+60_000,audience};return token;
}
async function relay(req: NextRequest, { params }: { params: Promise<{ path: string[] }> }) {
  const { path } = await params;
  if (!methods.has(req.method) || path.some(p => !/^[a-zA-Z0-9_-]+$/.test(p)) || path[0] !== 'v1') return Response.json({ detail: 'Invalid API route.' }, { status: 400 });
  if (Number(req.headers.get('content-length') || 0) > 2_000_000) return Response.json({ detail: 'Request is too large.' }, { status: 413 });
  const base = process.env.TV_API_URL || 'http://127.0.0.1:8000';
  const url = new URL(path.join('/'), base.endsWith('/') ? base : base + '/');
  url.search = req.nextUrl.search;
  const headers = new Headers();
  for (const key of ['content-type', 'cookie', 'x-csrf-token', 'origin', 'idempotency-key', 'x-threatveil-consumer']) { const value = req.headers.get(key); if (value) headers.set(key, value); }
  headers.set('accept', 'application/json');
  try {
    const appToken=req.headers.get('authorization');
    if(path[1]==='github'&&appToken?.startsWith('Bearer '))headers.set('Authorization',appToken);
    if(path.join('/')==='v1/webhooks/github'&&req.method==='POST'){
      for(const key of ['x-hub-signature-256','x-github-event','x-github-delivery']){
        const value=req.headers.get(key);if(value)headers.set(key,value);
      }
    }
    if(path.join('/')==='v1/release-machine/decide'&&appToken?.startsWith('Bearer tvrel_'))headers.set('Authorization',appToken);
    if(path[1]==='webhooks'&&path[2]==='stripe'&&req.headers.get('stripe-signature'))headers.set('stripe-signature',req.headers.get('stripe-signature')!);
    if(appToken?.startsWith('Bearer tvk_'))headers.set('X-Threatveil-Token',appToken.slice(7));
    if(process.env.TV_API_AUDIENCE)headers.set('X-Serverless-Authorization',`Bearer ${await cloudIdentity(process.env.TV_API_AUDIENCE)}`);
    const body = ['GET', 'HEAD'].includes(req.method) ? undefined : await req.arrayBuffer();
    if (body && body.byteLength > 2_000_000) return Response.json({ detail: 'Request is too large.' }, { status: 413 });
    const upstream = await fetch(url, { method: req.method, headers, body, redirect: 'manual', cache: 'no-store', signal: AbortSignal.timeout(120_000) });
    const responseHeaders = new Headers({ 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
    for (const key of ['content-type', 'content-disposition', 'content-security-policy']) { const value = upstream.headers.get(key); if (value) responseHeaders.set(key, value); }
    for (const cookie of upstream.headers.getSetCookie()) responseHeaders.append('Set-Cookie', cookie);
    return new Response(upstream.body, { status: upstream.status, headers: responseHeaders });
  } catch { return Response.json({ detail: 'The ThreatVeil API is unavailable. Start the API service and try again.' }, { status: 503 }); }
}
export { relay as GET, relay as POST, relay as PATCH, relay as PUT, relay as DELETE };
