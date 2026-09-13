# Cost attribution and budget dimensions

ThreatVeil is a per-protected-system product. If cost cannot be attributed to a system, a
customer and a component, pricing is guesswork. This is how cost is made attributable before
the first cloud resource exists.

## 1. Resource labels (applied by Terraform)

Every billable resource carries three dimensions:

| Label | Value | Why |
|---|---|---|
| `application` | `threatveil` | separates this product from anything else in the project |
| `environment` | `dev` / `staging` / `production` | keeps non-production spend out of unit economics |
| `managed_by` | `terraform` | anything unlabelled was created by hand and is a finding |

And one component dimension, from `local.component_labels`:

| `component` | Resources |
|---|---|
| `web` | the Next.js Cloud Run service |
| `api` | the API Cloud Run service |
| `broker` | the run broker |
| `launcher` | the launcher |
| `runner` | the verification job |
| `migration` | the migration job |
| `data` | the Cloud SQL instance |
| `evidence` | the evidence bucket |
| `images` | Artifact Registry |
| `secrets` | Secret Manager containers |

`terraform plan` output is the audit: a resource without `component` is either not billable
or a gap to fix.

## 2. Billing export plan (to set up at activation, not before)

1. Enable **detailed usage cost** BigQuery export in the billing account, into a dataset in
   the same project as the deployment.
2. Partition queries by `project.id` and `labels.environment`; production unit economics
   ignore `dev` and `staging` rows.
3. Three standing queries are enough to run the business:
   - **Cost per component per day** — where the money actually goes.
   - **Cost per environment per month** — what non-production costs to keep.
   - **Run-driven cost** — `component IN (runner, broker)` per day, the only line that scales
     with verification volume rather than with time.
4. Nothing in the export is customer data. It carries resource and label metadata only.

## 3. From cloud cost to unit economics

ThreatVeil's unit is the protected system. Cloud cost per protected system is:

```
fixed_monthly = web + api + data + evidence + secrets + images      # mostly time-based
variable      = runner + broker + launcher                           # verification volume
cost_per_system_month = fixed_monthly / relied_upon_systems + variable_per_system
```

`relied_upon_systems` is the North Star (RPS, `docs/BUSINESS_MEASUREMENT.md`). Dividing fixed
cost by *signups* would flatter the number; dividing by systems someone actually relies on is
the honest denominator.

Two deliberate facts about the shape:

- **Fixed cost dominates at small scale.** At one or two protected systems the per-system
  cloud cost is meaningless, because it is almost entirely the cost of having a deployment at
  all. Do not price from it.
- **Verification is the only variable line.** Monthly verification budgets in the plan catalog
  exist because of that, and they are the right lever when variable cost grows.

## 4. Budget dimensions to configure at activation

| Budget | Scope | Threshold action |
|---|---|---|
| Project total | the whole deployment | alert at 50 / 80 / 100 % of the monthly ceiling |
| `component = runner` | verification execution | alert at 80 %: this is the line an abusive or looping workload moves |
| `component = data` | Cloud SQL | alert on any month-over-month step change; storage only grows |
| AI assistance | `ai_monthly_usd_budget` (application-level, not cloud) | requests are refused when exhausted; see `docs/AI_ASSISTANCE.md` |

Cloud budgets alert; they do not stop work. The two places ThreatVeil stops by itself are the
per-plan verification budget and the AI budget, both application-enforced and both visible to
the customer.

## 5. What is deliberately not instrumented

- **Per-customer cloud cost allocation.** Tenants share the same services. Attributing cloud
  cost per tenant would require per-tenant infrastructure, which is an Enterprise deployment
  decision, not a default.
- **Request-level cost tracing.** The value is low and the retention cost is real.
- **Cost in the product UI.** A customer's plan usage is visible to them (`/v1/commercial`);
  ThreatVeil's own infrastructure cost is not their business.
