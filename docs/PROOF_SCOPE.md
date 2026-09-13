# ProofScope

A ProofScope binds evidence to its supporting component graph and approved property. The conservative default is FULL_FINGERPRINT. REVIEWED_DEPENDENCIES requires a human review reason, nonempty bindings and inclusion of every dependency declared by the property. UNKNOWN cannot authorize reuse.

Bindings support EXACT, FAMILY and SEMANTIC modes. FAMILY/SEMANTIC are explicit reviewed compatibility sets of SHA-256 digests with rationale; they are not model-inferred equivalence or wildcard trust. An AI proposal cannot grant itself scope authority. Canonical component identities use type and identifier; component types cannot contain the separator colon.

Use POST /v1/proof-scopes to review a scope and GET /v1/proof-scopes/{id} to inspect it. Reviews append scope/evidence versions. A narrower scope can reduce re-proof only when all supporting bindings and the independent exact-candidate deployment anchor remain valid.

Implementation: src/threatveil/core/validity.py and src/threatveil/release_integrity.py. Scope tests include changed dependencies, newly unreviewed components, cycles, provenance uncertainty, compatibility constraints and expiry.
