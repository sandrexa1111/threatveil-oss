# Activation, time to value and product-qualified signals

`GET /v1/measurements/activation` (tenant-private) is derived entirely from service records. It uses no browser tracker, no cross-customer aggregation, no names and no evidence, and it contacts no one. Synthetic demonstration systems are counted in a separate track, so a demo never counts as customer activation.

## Milestones and funnel

SIGNUP → FIRST_SYSTEM → FIRST_SOURCE → FIRST_BASELINE → FIRST_CURRENT_CLEARANCE → FIRST_OBSERVED_CHANGE → **FIRST_MEANINGFUL_ASSURANCE_EVENT** → FIRST_REESTABLISHMENT → FIRST_PASSPORT_SHARE

Each milestone reports its timestamp and seconds from signup. Each funnel step reports conversion and elapsed seconds.

**The activation event** is `FIRST_MEANINGFUL_ASSURANCE_EVENT`: after a current clearance, ThreatVeil observed a change and established its consequence for at least one claim. It comes from the same deterministic lifecycle the customer sees. Account creation, a GitHub connection or system creation is not activation.

## Product-qualified signals

The endpoint reports these signals:

- a production environment was created
- a third system was requested
- a BLOCK policy was attempted
- an external Passport was shared
- collaborators are active
- collaboration was requested
- verification usage is high
- a qualified observer was requested
- an external assurance consumer was attempted (machine gate checks or consumer acceptance)
- private deployment, enterprise retention, production enforcement or design-partner status was requested

The last group comes from explicit `POST /v1/commercial/interest` records. Signals are recorded for later go-to-market work; nothing is sent automatically.

## Retention and consumption (last 30 days)

- Assurance Gate active hours (and machine-only hours)
- external passport status checks
- passports issued and shared
- observed changes and decisions
- protected systems, environments and members
- self-reported support minutes (existing optional report)

## Upgrade moments

Upgrade prompts come from capabilities and facts, never from plan-name branches. The offered plan is the least expensive self-service catalog plan that carries the missing capability or allowance, so names and prices remain catalog data.

| Moment | Trigger | Missing capability or allowance |
|---|---|---|
| First clearance | an ALLOW exists | `enforcement.ci` |
| System allowance | protected systems ≥ allowance | a higher system limit |
| Production assurance | a PRODUCTION environment exists | `enforcement.production` (with "where a qualified enforcer exists") |
| Shared review | members ≥ 2, or an invitation was refused | `approval.workflow` |
| Verification budget | ≥ 80% used | a higher budget |

Every prompt carries: "A plan changes what ThreatVeil may do for you. It never changes a security conclusion." There are no banners, no fear copy and no dark patterns.
