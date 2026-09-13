# Runner security

The existing execution broker is retained. A short-lived one-time bootstrap is bound to service identity, exact frozen run digest and an ephemeral Ed25519 worker key. Requests use signed nonces, timestamps, lease IDs and fences. Revocation and expiry stop further authorized operations; already committed adverse captures remain evidence.

Cloud workers are designed without database, Secret Manager or evidence-bucket grants. They receive exact run-scoped credentials and submit bounded captures through the broker. The broker/control plane reauthorizes the target and observer, controls budgets and settles execution once. Timed-out work is not blindly rerun. See security/RUNNER_IAM.md and OBSERVATION_QUALIFICATION.md for the existing protocol and collector controls.

System locks are taken before run-state and lease row locks, so organization deletion, finalization and observation do not invert that order. Local synthetic execution runs in the control-plane process for reproducibility; it is not evidence of cloud container isolation. Non-root images, live service identities, denied egress, timeout recovery and crash cleanup must be tested in the deployed environment before a customer blocking gate is enabled.
