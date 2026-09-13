# Invalidation engine

The deterministic evaluator compares canonical fingerprint components and traverses dependencies in both the old and new graph. Component order and provenance formatting do not change configuration identity; version remains visible in change reporting. Historical adverse-memory content identity separately ignores a version label when a digest exists.

STILL_VALID means the declared scope and current qualified conditions support reuse. VOID means a known required component changed or expired. UNKNOWN means incomplete/inferred provenance, a missing dependency, unreviewed graph change or insufficient scope prevents a determination. A known VOID can dominate UNKNOWN in the reported reason; neither permits positive reuse.

Traversal is cycle-safe. Full scopes include all components and approved-property dependencies. Selective scopes require explicit human review. New components not covered by reviewed scope cannot be assumed irrelevant. Evidence lifetime is bounded to 24 hours; current target, observer and approval state are checked in addition to fingerprint comparison.

The evaluator is a conservative rules engine. It does not infer causal independence from language-model prose, learn semantic compatibility, or estimate customer-wide false-ALLOW rates. Those claims require qualified benchmarks and real longitudinal evidence.
