'use client';

import { useEffect, useState } from 'react';
import { api, obj } from '@/lib/api';
import { Brand } from './brand';
import { PassportDocument, VerificationPanel } from './intelligence';

/** What an external party sees through a shared link. No account is required. */
export function PublicPassport({token}: {token: string}) {
  const [data, setData] = useState<Record<string, unknown> | null>(null);
  const [error, setError] = useState('');
  useEffect(() => {
    api<Record<string, unknown>>(`/public/passports/${encodeURIComponent(token)}`)
      .then(setData).catch(e => setError(e instanceof Error ? e.message : 'This passport could not be loaded.'));
  }, [token]);
  return <main id="main" style={{maxWidth: 980, margin: '0 auto', padding: '32px 20px 64px', display: 'grid', gap: 18}}>
    <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12, flexWrap: 'wrap'}}>
      <Brand href="/"/>
      <span className="tag">Shared with you · verify it yourself</span>
    </div>
    {error && <div className="notice error" role="alert">{error}</div>}
    {!data && !error && <p>Loading the passport and its current status…</p>}
    {data && <>
      <PassportDocument passport={obj(data.passport)} status={obj(data.current_status)}/>
      <VerificationPanel envelope={data.envelope}/>
      <p style={{fontSize: 12, lineHeight: 1.7, color: '#5f6c64'}}>
        Authenticity and current status are separate. The signature proves who issued this statement and when; it stays valid
        after the system changes. The status above is recomputed each time you open this link. Verify offline with
        {' '}<code>threatveil verify-passport</code> and the published trust directory at <code>/v1/trust/keys</code>.
      </p>
    </>}
  </main>;
}
