# ThreatVeil Verify in GitHub

The initial gate uses GitHub OIDC and the workflow job result. It does not require a permanent customer API token. It supports explicitly trusted `push` and `workflow_dispatch` jobs; pull-request and fork execution are rejected.

The deployment operator first verifies repository ownership, registers the numeric repository/owner IDs, trusted workflow path/ref, active security owner and frozen ThreatVeil run template using `threatveil operator github-bind`. The template references an approved property, active target and qualified observer. The default branch/deployment workflow must run after deploying the candidate to its authorized staging target. The signed target fingerprint must report that exact commit.

Example after copying the reviewed action directory into the customer's repository:

```yaml
name: Release security
on:
  push:
    branches: [main]
permissions:
  contents: read
  id-token: write
jobs:
  verify:
    runs-on: ubuntu-24.04
    steps:
      # Check out a reviewed pinned revision and deploy the exact candidate to staging first.
      - uses: ./integrations/github-action
        with:
          api-url: https://YOUR_THREATVEIL_HOST/api/backend
```

The local action must exist in the checked-out workspace before use; this snippet deliberately does not invent a published ThreatVeil repository or release pin. The operator registration must match the complete workflow reference, such as `owner/repo/.github/workflows/release.yml@refs/heads/main`. Restrict who can change that workflow and configure the deployment dependency/required check in GitHub. Branch protection remains GitHub's control and is not silently installed by this code.

The gate rejects identity mismatch, unknown/revoked bindings, stale membership, missing evidence, timeouts, unobserved candidates and all outcomes other than explicit ALLOW. It never runs submitted customer code on a shared runner and never checks out an untrusted PR head to obtain credentials.

Identity semantics follow [GitHub's OIDC reference](https://docs.github.com/en/actions/reference/security/oidc). Local tests verify signed JWTs, audience/expiry/event restrictions and exact-candidate decisions. A live customer GitHub installation has not yet been exercised.
