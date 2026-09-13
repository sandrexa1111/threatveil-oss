'use client';

/**
 * Cmd/Ctrl-K: jump to any destination, any protected system, or the two actions a
 * customer takes most. Navigation only — it runs nothing, so nothing here needs
 * confirmation, and every entry is also reachable without the keyboard.
 */

import { useRouter } from 'next/navigation';
import { useEffect, useMemo, useRef, useState } from 'react';
import { Boxes, CreditCard, GitBranch, GitPullRequest, Home, Plug, Plus, Search, Settings } from 'lucide-react';
import { str, type RecordData } from '@/lib/api';
import styles from './product.module.css';

type Entry = {id: string; group: string; label: string; hint?: string; href: string; icon: typeof Home};

export const RECENT_KEY = 'threatveil.recent-systems';
/** Remember a visited system, most recent first. Private mode simply keeps no history. */
export function rememberSystem(id: string) {
  try {
    const recent = JSON.parse(window.localStorage.getItem(RECENT_KEY) || '[]') as string[];
    window.localStorage.setItem(RECENT_KEY, JSON.stringify([id, ...recent.filter(item => item !== id)].slice(0, 5)));
  } catch { /* storage unavailable */ }
}
function recentSystems(): string[] {
  try { return JSON.parse(window.localStorage.getItem(RECENT_KEY) || '[]') as string[]; } catch { return []; }
}

const DESTINATIONS: Entry[] = [
  {id: 'home', group: 'Go to', label: 'Home', href: '/app', icon: Home},
  {id: 'systems', group: 'Go to', label: 'Systems', href: '/app/systems', icon: Boxes},
  {id: 'changes', group: 'Go to', label: 'Changes', href: '/app/changes', icon: GitBranch},
  {id: 'integrations', group: 'Go to', label: 'Integrations', href: '/app/integrations', icon: Plug},
  {id: 'billing', group: 'Go to', label: 'Usage & billing', href: '/app/billing', icon: CreditCard},
  {id: 'settings', group: 'Go to', label: 'Settings', href: '/app/settings', icon: Settings},
  {id: 'propose', group: 'Actions', label: 'Check a proposed change', href: '/app/changes/propose', icon: GitPullRequest},
  {id: 'connect', group: 'Actions', label: 'Connect a system', href: '/app/systems/new', icon: Plus},
];

export function CommandMenu({systems}: {systems: RecordData[]}) {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [active, setActive] = useState(0);
  const input = useRef<HTMLInputElement>(null);

  useEffect(() => {
    function toggle(event: KeyboardEvent) {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault(); setOpen(value => !value);
      }
    }
    document.addEventListener('keydown', toggle);
    return () => document.removeEventListener('keydown', toggle);
  }, []);
  const [recent, setRecent] = useState<string[]>([]);
  useEffect(() => { if (open) { setQuery(''); setActive(0); setRecent(recentSystems()); input.current?.focus(); } }, [open]);

  const entries = useMemo(() => {
    const recents = recent.map(id => systems.find(system => system.id === id)).filter(Boolean).slice(0, 3)
      .map(system => ({id: `recent-${system!.id}`, group: 'Recent', label: str(system!.name, 'Protected system'),
        hint: 'Recent', href: `/app/systems/${system!.id}`, icon: Boxes}));
    const all = [...recents, ...DESTINATIONS, ...systems.map(system => ({
      id: `system-${system.id}`, group: 'Systems', label: str(system.name, 'Protected system'),
      hint: 'System', href: `/app/systems/${system.id}`, icon: Boxes,
    }))];
    const q = query.trim().toLowerCase();
    return q ? all.filter(entry => entry.label.toLowerCase().includes(q)) : all;
  }, [systems, query, recent]);
  useEffect(() => { setActive(0); }, [query]);

  function go(entry: Entry | undefined) {
    if (!entry) return;
    setOpen(false); router.push(entry.href);
  }
  function keys(event: React.KeyboardEvent) {
    if (event.key === 'ArrowDown') { event.preventDefault(); setActive(i => Math.min(i + 1, entries.length - 1)); }
    else if (event.key === 'ArrowUp') { event.preventDefault(); setActive(i => Math.max(i - 1, 0)); }
    else if (event.key === 'Enter') { event.preventDefault(); go(entries[active]); }
    else if (event.key === 'Escape') { event.preventDefault(); setOpen(false); }
  }

  const mac = typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.platform);
  return <>
    <button className={styles.cmdTrigger} onClick={() => setOpen(true)} aria-haspopup="dialog"
      aria-keyshortcuts={mac ? 'Meta+K' : 'Control+K'}>
      <Search size={13} aria-hidden="true"/><span>Jump to…</span><kbd>{mac ? '⌘K' : 'Ctrl K'}</kbd>
    </button>
    {open && <>
      <button className={styles.cmdScrim} aria-label="Close command menu" tabIndex={-1} onClick={() => setOpen(false)}/>
      <div className={styles.cmd} role="dialog" aria-modal="true" aria-label="Command menu">
        <input ref={input} value={query} onChange={e => setQuery(e.target.value)} onKeyDown={keys}
          placeholder="Search destinations and systems" aria-label="Search destinations and systems"
          role="combobox" aria-expanded="true" aria-controls="command-list"
          aria-activedescendant={entries[active] ? `cmd-${entries[active].id}` : undefined}/>
        <ul id="command-list" className={styles.cmdList} role="listbox" aria-label="Results">
          {entries.map((entry, index) => {
            const heading = index === 0 || entries[index - 1].group !== entry.group;
            return <li key={entry.id} role="presentation">
              {heading && <div className={styles.cmdGroup} role="presentation">{entry.group}</div>}
              <div id={`cmd-${entry.id}`} role="option" aria-selected={index === active} className={styles.cmdItem}
                onMouseEnter={() => setActive(index)} onClick={() => go(entry)}>
                <entry.icon size={14} aria-hidden="true"/>{entry.label}{entry.hint && <small>{entry.hint}</small>}
              </div>
            </li>;
          })}
          {!entries.length && <li className={styles.cmdEmpty}>Nothing matches “{query}”.</li>}
        </ul>
        <div className={styles.cmdHint}><span>↑↓ to move</span><span>↵ to open</span><span>esc to close</span></div>
      </div>
    </>}
  </>;
}
