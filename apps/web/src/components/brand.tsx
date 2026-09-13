import Link from 'next/link';
export function Mark() { return <svg width="29" height="33" viewBox="0 0 29 33" fill="none" aria-hidden="true"><path d="M14.5 1.5 27 7v9.5c0 7-6 12-12.5 15C8 28.5 2 23.5 2 16.5V7L14.5 1.5Z" stroke="currentColor" strokeWidth="1.8"/><path d="m8 11 6.5 11L21 11M11 11l3.5 6 3.5-6" stroke="currentColor" strokeWidth="1.8"/></svg>; }
export function Brand({ href = '/' }: { href?: string }) { return <Link href={href} className="brand" aria-label="ThreatVeil home"><Mark /><span>THREATVEIL<span className="brand-dot">.</span></span></Link>; }
