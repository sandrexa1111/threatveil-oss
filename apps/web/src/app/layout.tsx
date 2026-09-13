import type { Metadata } from 'next';
import './globals.css';
export const metadata: Metadata = { title: { default: 'ThreatVeil — The security gate for AI releases', template: '%s · ThreatVeil' }, description: 'Autonomous Release Integrity. Know what your AI release invalidated before it ships.' };
export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) { return <html lang="en"><body><a className="skip-link" href="#main">Skip to content</a>{children}</body></html>; }
