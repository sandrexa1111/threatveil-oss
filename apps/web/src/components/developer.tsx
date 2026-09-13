'use client';

/**
 * Developer tools: the mature record-level surfaces, kept whole but moved out of
 * ordinary product navigation. Nothing here was deleted; it is simply no longer
 * something a customer has to learn before getting value.
 */

import Link from 'next/link';
import { ArrowRight } from 'lucide-react';
import styles from './product.module.css';

export type Tool = {key: string; label: string; detail: string; group: string};

/** Every route that used to sit in the Advanced group, with where it lives now. */
export const DEVELOPER_TOOLS: Tool[] = [
  {key: 'properties', label: 'Security properties', group: 'Verification',
    detail: 'Approved executable claims, their definitions, and the tool-contract installer.'},
  {key: 'targets', label: 'Authorized targets', group: 'Verification',
    detail: 'Exact destinations a verification may reach, bounded by environment and authorization.'},
  {key: 'runs', label: 'Execution history', group: 'Verification',
    detail: 'Every bounded execution, with security verdict, useful task and release decision kept separate.'},
  {key: 'evidence', label: 'Evidence ledger', group: 'Verification',
    detail: 'Qualified observations, side effects and the limits of each conclusion.'},
  {key: 'schedules', label: 'Schedules', group: 'Verification',
    detail: 'Run approved properties on a bounded cadence.'},
  {key: 'findings', label: 'Findings', group: 'Security memory',
    detail: 'Turn a real security lesson into a lasting, executable boundary.'},
  {key: 'fixes', label: 'Verified fixes', group: 'Security memory',
    detail: 'A fix must stop the prohibited outcome and preserve the legitimate task.'},
  {key: 'regressions', label: 'Regressions', group: 'Security memory',
    detail: 'Security properties that failed again after a verified baseline.'},
  {key: 'propagation', label: 'Property reuse', group: 'Security memory',
    detail: 'Review where a proven property may apply to another system.'},
  {key: 'impact', label: 'Change explorer', group: 'Release integrity',
    detail: 'Fingerprint diffing, evidence applicability, security canaries and test-selection audits.'},
  {key: 'releases', label: 'Releases', group: 'Release integrity',
    detail: 'The historical release decision, its evidence applicability and its receipt.'},
  {key: 'records', label: 'Signed records & trust root', group: 'Release integrity',
    detail: 'Scoped signed records and the published key directory a third party verifies against.'},
  {key: 'reports', label: 'Scoped reports', group: 'Release integrity',
    detail: 'Evidence-supported reports drawn from actual records, with their scope and limitations.'},
  {key: 'gauntlet', label: 'Integrity Launch', group: 'Engagements',
    detail: 'Establish one system’s properties, evidence and release workflow, then leave a gate installed.'},
  {key: 'demo', label: 'Procurement demonstration', group: 'Engagements',
    detail: 'The original synthetic procurement fixture: five candidates, one property, real evidence.'},
];

const GROUPS = ['Verification', 'Security memory', 'Release integrity', 'Engagements'];

export function DeveloperTools() {
  return <section aria-labelledby="developer-tools">
    <div className={styles.sectionHead}>
      <div>
        <h2 id="developer-tools">Developer tools</h2>
        <p>The record-level surfaces behind the product. Everything here remains available and unchanged.</p>
      </div>
    </div>
    {GROUPS.map(group => <div key={group} className={styles.toolGroup}>
      <h3>{group}</h3>
      <div className={styles.rows}>
        {DEVELOPER_TOOLS.filter(tool => tool.group === group).map(tool =>
          <Link key={tool.key} href={`/app/${tool.key}`} className={styles.row}>
            <span className={styles.rowMain}>
              <strong>{tool.label}</strong>
              <span>{tool.detail}</span>
            </span>
            <ArrowRight size={13} aria-hidden="true"/>
          </Link>)}
      </div>
    </div>)}
  </section>;
}
