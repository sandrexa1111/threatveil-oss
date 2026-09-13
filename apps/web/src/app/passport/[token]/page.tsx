import type { Metadata } from 'next';
import { PublicPassport } from '@/components/passport-public';

export const metadata: Metadata = { title: 'Current Assurance Passport', robots: { index: false, follow: false } };

export default async function Page({ params }: { params: Promise<{ token: string }> }) {
  const { token } = await params;
  return <PublicPassport token={token}/>;
}
