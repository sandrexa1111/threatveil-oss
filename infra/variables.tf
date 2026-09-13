variable "project_id" {
  description = "Existing founder-approved GCP project. Terraform never creates a project or billing account."
  type        = string
}
variable "region" {
  description = "One approved region for dev; confirm data residency before provisioning."
  type        = string
  default     = "europe-west1"
}
variable "environment" {
  type    = string
  default = "dev"
  validation {
    condition     = contains(["dev", "staging", "production"], var.environment)
    error_message = "Use a separate approved project/state for dev, staging, or production."
  }
}
variable "name_prefix" {
  type    = string
  default = "threatveil"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,14}$", var.name_prefix))
    error_message = "Use 3–15 lowercase letters, digits or hyphens."
  }
}
variable "deploy_services" {
  description = "Enable only after image digests, DB roles/secret versions and managed identity are configured."
  type        = bool
  default     = false
  validation {
    condition     = !var.deploy_services || (contains(keys(var.images), "python") && contains(keys(var.images), "web") && startswith(var.web_origin, "https://") && !endswith(var.web_origin, ".invalid"))
    error_message = "Service deployment requires reviewed HTTPS web_origin and python/web image digests."
  }
}
variable "images" {
  description = "Immutable Artifact Registry image references, keyed python and web. Never pass tags."
  type        = map(string)
  default     = {}
  validation {
    condition     = alltrue([for image in values(var.images) : can(regex("@sha256:[a-f0-9]{64}$", image))])
    error_message = "Every image must be pinned by sha256 digest."
  }
}
variable "web_origin" {
  description = "Exact reviewed HTTPS origin. Supplied independently to avoid service URL dependency cycles."
  type        = string
  default     = "https://configure-before-deploy.invalid"
}
variable "public_web_enabled" {
  description = "Explicit publication switch; false keeps every service IAM-authenticated. Requires founder review."
  type        = bool
  default     = false
}
variable "operator_invokers" {
  description = "Optional IAM members, e.g. user:founder@example.com, allowed to invoke the private web service."
  type        = set(string)
  default     = []
}
variable "sql_instance_name" {
  description = "Existing instance name for import/reuse, or blank to use the deterministic managed name."
  type        = string
  default     = ""
}
variable "sql_tier" {
  type    = string
  default = "db-custom-1-3840"
}
variable "sql_availability_type" {
  type    = string
  default = "ZONAL"
  validation {
    condition     = contains(["ZONAL", "REGIONAL"], var.sql_availability_type)
    error_message = "Choose ZONAL dev or REGIONAL production after budget review."
  }
}
variable "evidence_bucket_name" {
  description = "Optional existing bucket name; import it before planning, never silently replace it."
  type        = string
  default     = ""
}
variable "database_secret_ids" {
  description = "Secret names only, no secret values in Terraform. Existing secret containers must be imported."
  type        = map(string)
  default     = {}
}
variable "api_secret_bindings" {
  description = "Optional API-only integration environment variable => existing Secret Manager secret ID. Revenue delivery uses revenue_delivery; customer target credentials belong only to the broker."
  type        = map(string)
  default     = {}
  validation {
    condition = length(setintersection(toset(keys(var.api_secret_bindings)), toset([
      "TV_RESEND_API_KEY", "TV_HUBSPOT_TOKEN", "TV_RESEND_DELIVERY_ENABLED", "TV_HUBSPOT_DELIVERY_ENABLED", "TV_EMAIL_FROM", "TV_HUBSPOT_OWNER_ID",
      "TV_GITHUB_APP_ID", "TV_GITHUB_PRIVATE_KEY", "TV_GITHUB_WEBHOOK_SECRET"
    ]))) == 0
    error_message = "Configure delivery through revenue_delivery and GitHub through github_app so publisher credentials are placed narrowly and consistently."
  }
}
variable "github_app" {
  description = "Reviewed GitHub App publication. IDs reference existing secret containers; runner, launcher and web receive no App secrets."
  type = object({
    enabled               = optional(bool, false)
    app_id                = optional(string, "")
    private_key_secret_id = optional(string, "")
    webhook_secret_id     = optional(string, "")
  })
  default = {}
  validation {
    condition = !var.github_app.enabled || (
      can(regex("^[1-9][0-9]{0,19}$", var.github_app.app_id)) &&
      can(regex("^[A-Za-z0-9_-]{1,255}$", var.github_app.private_key_secret_id)) &&
      can(regex("^[A-Za-z0-9_-]{1,255}$", var.github_app.webhook_secret_id))
    )
    error_message = "Enabled GitHub App requires its numeric App ID, private-key secret ID and webhook secret ID."
  }
}
variable "revenue_delivery" {
  description = "Explicitly approved transactional invitation/contact delivery. Secret IDs only; disabled providers receive no secret grants or mounts."
  type = object({
    resend_enabled    = optional(bool, false)
    resend_secret_id  = optional(string, "")
    email_from        = optional(string, "")
    hubspot_enabled   = optional(bool, false)
    hubspot_secret_id = optional(string, "")
    hubspot_owner_id  = optional(string, "")
  })
  default = {}
  validation {
    condition = !var.revenue_delivery.resend_enabled || (
      can(regex("^[A-Za-z0-9_-]{1,255}$", var.revenue_delivery.resend_secret_id)) &&
      can(regex("^[^\\s@<>]+@[^\\s@<>]+\\.[^\\s@<>]+$", var.revenue_delivery.email_from))
    )
    error_message = "Enabling Resend requires an exact existing Secret Manager secret ID and a reviewed sender email address."
  }
  validation {
    condition = !var.revenue_delivery.hubspot_enabled || (
      can(regex("^[A-Za-z0-9_-]{1,255}$", var.revenue_delivery.hubspot_secret_id)) &&
      can(regex("^[0-9]+$", var.revenue_delivery.hubspot_owner_id))
    )
    error_message = "Enabling HubSpot requires an exact existing Secret Manager secret ID and a reviewed numeric owner ID."
  }
}
variable "customer_secret_ids" {
  description = "Exact existing customer credential secret IDs the trusted broker may resolve. No project-wide accessor grant."
  type        = set(string)
  default     = []
}
variable "notification_channels" {
  description = "Existing, verified Monitoring notification channel resource names; an empty list means dashboards only, no delivered alerts."
  type        = list(string)
  default     = []
}
variable "enable_scheduler" {
  description = "Enable reconciliation after broker/launcher cloud integration tests."
  type        = bool
  default     = false
}
variable "github_repository" {
  description = "New repository OWNER/REPO for keyless CI. Empty disables federation. Never use the old ThreatVeil repo."
  type        = string
  default     = ""
}
