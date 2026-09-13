'use client';

/**
 * One change, inspected without leaving the list it was found in — Home, Changes or a
 * system's Activity. The open change is a deep link (`?change=`, plus `?system=` outside
 * a system), and it matches the claim drawer: Escape closes it and focus returns.
 */

import Link from 'next/link';
import { usePathname, useRouter, useSearchParams } from 'next/navigation';
import { useCallback, useEffect, useState } from 'react';
import { ArrowRight } from 'lucide-react';
import { api, obj, str } from '@/lib/api';
import { AUTHORITY_MOVE, CHANGE_EFFECT, Drawer, Skeleton, StatusPill, arr, type Fields } from './product';
import { ChangeImpact, impactOfChange } from './signature';

export function ChangePreview({systemId, changes, summary}: {systemId?: string; changes?: Fields[]; summary?: Fields}) {
  const params = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();
  const changeId = params.get('change') || '';
  const sid = systemId || params.get('system') || '';
  const [loaded, setLoaded] = useState<{id: string; items: Fields[]; summary: Fields} | null>(null);

  useEffect(() => {
    if (!changeId || !sid || changes || loaded?.id === sid) return;
    let live = true;
    Promise.all([api<Fields>(`/systems/${sid}/changes`), api<Fields>(`/systems/${sid}/summary`)])
      .then(([listed, current]) => { if (live) setLoaded({id: sid, items: arr(listed.items), summary: current}); })
      .catch(() => { if (live) setLoaded({id: sid, items: [], summary: {}}); });
    return () => { live = false; };
  }, [changeId, sid, changes, loaded?.id]);

  const close = useCallback(() => {
    const next = new URLSearchParams(params.toString());
    next.delete('change');
    if (!systemId) next.delete('system');
    const query = next.toString();
    router.replace(query ? `${pathname}?${query}` : pathname, {scroll: false});
  }, [params, pathname, router, systemId]);

  if (!changeId) return null;
  const list = changes || loaded?.items;
  const change = list?.find(item => str(item.id) === changeId);
  const context = summary || loaded?.summary || {};
  const effect = str(obj(change?.consequence).effect, '');
  const classification = str(obj(change?.authority).classification, '');
  const move = AUTHORITY_MOVE[classification];
  const open = effect === 'OPEN';

  return <Drawer open title={change ? str(change.headline) : 'Change'} onClose={close} subtitle={change ? <>
    <StatusPill label={open ? 'Needs review' : CHANGE_EFFECT[effect] || effect.replaceAll('_', ' ').toLowerCase()}
      tone={open ? 'attention' : 'neutral'} canonical={effect}/>
    {move && classification !== 'AUTHORITY_EQUIVALENT' && <StatusPill label={move.label} tone={move.tone} canonical={classification}/>}
  </> : undefined}>
    {!list ? <Skeleton label="Loading this change" rows={3}/>
      : !change ? <p>This change is outside the recent window. Its record remains in the system’s history and exports.</p>
      : <>
        <ChangeImpact {...impactOfChange(change, context)} headline="" level={2} open={open}/>
        <section aria-label="Next action" style={{display: 'grid', gap: 8}}>
          <p style={{fontSize: 13}}>{open
            ? 'The claims above need fresh evidence before this system is current again.'
            : effect === 'NO_CLAIM_AFFECTED' ? 'No security claim depends on what this change touched.'
            : 'This change is settled: a later verification already covers it.'}</p>
          <div style={{display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'center'}}>
            {open && <Link href={`/app/systems/${sid}/restore`} className="button dark small">Restore assurance <ArrowRight size={13}/></Link>}
            <Link href={`/app/systems/${sid}/activity#change-${changeId}`} className="button outline small">
              Open full review <ArrowRight size={13}/>
            </Link>
          </div>
        </section>
      </>}
  </Drawer>;
}
