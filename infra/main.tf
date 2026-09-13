locals {
  name      = "${var.name_prefix}-${var.environment}"
  sa_prefix = "${substr(var.name_prefix, 0, 10)}-${lookup({ production = "prod", staging = "stg", dev = "dev" }, var.environment)}"
  # Cost attribution: every billable resource carries the same three dimensions, and
  # each module adds its own component label. See docs/COST_ATTRIBUTION.md.
  labels = {
    application = "threatveil"
    environment = var.environment
    managed_by  = "terraform"
  }
  component_labels = {
    web      = merge(local.labels, { component = "web" })
    api      = merge(local.labels, { component = "api" })
    broker   = merge(local.labels, { component = "broker" })
    launcher = merge(local.labels, { component = "launcher" })
    data     = merge(local.labels, { component = "data" })
    evidence = merge(local.labels, { component = "evidence" })
  }
  services = toset(["web", "api", "broker", "launcher", "runner", "migration", "task-delivery", "scheduler", "ci-build", "ci-deploy"])
  apis = toset([
    "run.googleapis.com", "sqladmin.googleapis.com", "storage.googleapis.com",
    "secretmanager.googleapis.com", "artifactregistry.googleapis.com", "cloudtasks.googleapis.com",
    "cloudscheduler.googleapis.com", "logging.googleapis.com", "monitoring.googleapis.com",
    "identitytoolkit.googleapis.com", "iam.googleapis.com", "iamcredentials.googleapis.com",
    "sts.googleapis.com", "cloudresourcemanager.googleapis.com"
  ])
  database_secrets = { for role in ["api", "broker", "migration"] : role => lookup(var.database_secret_ids, role, "${local.name}-${role}-database-url") }
}

resource "google_project_service" "required" {
  for_each           = local.apis
  service            = each.value
  disable_on_destroy = false
}

resource "google_service_account" "service" {
  for_each     = local.services
  account_id   = "${local.sa_prefix}-${each.key}"
  display_name = "ThreatVeil ${var.environment} ${each.key}"
  depends_on   = [google_project_service.required]
}

resource "google_artifact_registry_repository" "images" {
  repository_id = "${local.name}-images"
  location      = var.region
  description   = "Immutable ThreatVeil application images"
  format        = "DOCKER"
  labels        = merge(local.labels, { component = "images" })
  docker_config {
    immutable_tags = true
  }
  depends_on = [google_project_service.required]
  lifecycle { prevent_destroy = true }
}

resource "google_sql_database_instance" "postgres" {
  name                = var.sql_instance_name != "" ? var.sql_instance_name : "${local.name}-postgres"
  database_version    = "POSTGRES_17"
  region              = var.region
  deletion_protection = true
  settings {
    tier                        = var.sql_tier
    edition                     = "ENTERPRISE"
    availability_type           = var.sql_availability_type
    disk_type                   = "PD_SSD"
    disk_size                   = 20
    disk_autoresize             = true
    disk_autoresize_limit       = 100
    deletion_protection_enabled = true
    user_labels                 = local.component_labels["data"]
    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
      start_time                     = "03:00"
      transaction_log_retention_days = 7
      backup_retention_settings { retained_backups = 7 }
    }
    ip_configuration {
      # No authorized networks. Connections use the IAM-authorized Cloud SQL connector.
      ipv4_enabled = true
      ssl_mode     = "ENCRYPTED_ONLY"
    }
    database_flags {
      name  = "password_encryption"
      value = "scram-sha-256"
    }
    maintenance_window {
      day          = 7
      hour         = 4
      update_track = "stable"
    }
  }
  depends_on = [google_project_service.required]
  lifecycle { prevent_destroy = true }
}

resource "google_sql_database" "database" {
  name     = "threatveil"
  instance = google_sql_database_instance.postgres.name
  lifecycle { prevent_destroy = true }
}

resource "google_storage_bucket" "evidence" {
  name                        = var.evidence_bucket_name != "" ? var.evidence_bucket_name : "${var.project_id}-${local.name}-evidence"
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false
  labels                      = local.component_labels["evidence"]
  soft_delete_policy { retention_duration_seconds = 604800 }
  lifecycle_rule {
    condition {
      age            = 30
      matches_prefix = ["raw/"]
    }
    action { type = "Delete" }
  }
  depends_on = [google_project_service.required]
  lifecycle { prevent_destroy = true }
}

# Only containers are managed here. Add secret payloads out of band after DB role setup.
resource "google_secret_manager_secret" "database" {
  for_each  = local.database_secrets
  secret_id = each.value
  labels    = merge(local.labels, { component = "secrets" })
  replication {
    auto {}
  }
  depends_on = [google_project_service.required]
  lifecycle { prevent_destroy = true }
}

resource "google_cloud_tasks_queue" "runs" {
  name     = "${local.name}-runs"
  location = var.region
  rate_limits {
    max_concurrent_dispatches = 10
    max_dispatches_per_second = 2
  }
  retry_config {
    max_attempts       = 8
    max_retry_duration = "900s"
    min_backoff        = "1s"
    max_backoff        = "60s"
    max_doublings      = 5
  }
  stackdriver_logging_config { sampling_ratio = 1 }
  depends_on = [google_project_service.required]
}
