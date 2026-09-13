export type RecordData = { id: string; [key: string]: unknown };
export type Identity = { user: RecordData; organization: RecordData; memberships: RecordData[]; csrf_token: string; mode: string };
export type PageWindow = {total:number;returned:number;limit:number;next_cursor:string|null};
export type Dashboard = { pagination:Record<string,PageWindow>; targets:RecordData[]; systems: RecordData[]; properties: RecordData[]; findings: RecordData[]; runs: RecordData[]; fixes: RecordData[]; baselines: RecordData[]; gauntlets: RecordData[]; usage: Record<string, unknown>; integrations: unknown; summary: Record<string, unknown> };
export class ApiError extends Error { constructor(message: string, public status: number) { super(message); } }
export async function api<T = RecordData>(path: string, options?: { method?: string; data?: unknown; csrf?: string; signal?: AbortSignal }): Promise<T> {
  const response = await fetch(`/api/backend/v1${path}`, { method: options?.method || 'GET', credentials: 'same-origin', cache: 'no-store', headers: { ...(options?.data !== undefined ? { 'Content-Type': 'application/json' } : {}), ...(options?.csrf ? { 'X-CSRF-Token': options.csrf } : {}) }, body: options?.data !== undefined ? JSON.stringify(options.data) : undefined, signal: options?.signal });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) { const detail = payload.detail; throw new ApiError(typeof detail === 'string' ? detail : Array.isArray(detail) ? detail.map((e: { msg?: string; loc?: unknown[] }) => `${e.loc?.slice(1).join('.') || 'Input'}: ${e.msg}`).join('; ') : payload.message || `Request failed (${response.status}).`, response.status); }
  return payload as T;
}
export const str = (value: unknown, fallback = '—') => value === undefined || value === null || value === '' ? fallback : typeof value === 'object' ? JSON.stringify(value) : String(value);
export const obj = (value: unknown): Record<string, unknown> => value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {};
export const items = (value: unknown): RecordData[] => Array.isArray(value) ? value as RecordData[] : Array.isArray(obj(value).items) ? obj(value).items as RecordData[] : [];
export const title = (r: RecordData) => str(r.title || r.name || r.version || r.id);
export const date = (value: unknown) => value ? new Date(String(value)).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : '—';
export function verdict(r: RecordData) { return str(r.security_verdict || obj(r.result).security_verdict || obj(r.summary).security_verdict || obj(r.evaluation).verdict || r.verdict, 'PENDING'); }
