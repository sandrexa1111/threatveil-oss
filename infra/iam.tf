# Additive grants preserve existing project IAM. Never use authoritative project policy bindings.
resource "google_project_iam_member" "sql_clients" {
  for_each = toset(["api", "broker", "migration"])
  project  = var.project_id
  role     = "roles/cloudsql.client"
  member   = google_service_account.service[each.key].member
}

resource "google_secret_manager_secret_iam_member" "database" {
  for_each  = local.database_secrets
  secret_id = google_secret_manager_secret.database[each.key].id
  role      = "roles/secretmanager.secretAccessor"
  member    = google_service_account.service[each.key].member
}

resource "google_secret_manager_secret_iam_member" "api_integrations" {
  for_each  = var.api_secret_bindings
  secret_id = each.value
  role      = "roles/secretmanager.secretAccessor"
  member    = google_service_account.service["api"].member
}

resource "google_secret_manager_secret_iam_member" "github_app" {
  for_each = var.github_app.enabled ? {
    "api.private_key"    = { service = "api", secret = var.github_app.private_key_secret_id }
    "api.webhook"        = { service = "api", secret = var.github_app.webhook_secret_id }
    "broker.private_key" = { service = "broker", secret = var.github_app.private_key_secret_id }
  } : {}
  project   = var.project_id
  secret_id = each.value.secret
  role      = "roles/secretmanager.secretAccessor"
  member    = google_service_account.service[each.value.service].member
}

# API computes truthful routing readiness; broker maintenance performs delivery.
# Neither role receives arbitrary project-level Secret Manager access.
resource "google_secret_manager_secret_iam_member" "revenue_delivery" {
  for_each = {
    for binding in setproduct(["api", "broker"], keys(local.revenue_secret_bindings)) :
    "${binding[0]}.${binding[1]}" => { service = binding[0], secret = local.revenue_secret_bindings[binding[1]] }
  }
  project   = var.project_id
  secret_id = each.value.secret
  role      = "roles/secretmanager.secretAccessor"
  member    = google_service_account.service[each.value.service].member
}

resource "google_secret_manager_secret_iam_member" "broker_credentials" {
  for_each  = var.customer_secret_ids
  secret_id = each.value
  role      = "roles/secretmanager.secretAccessor"
  member    = google_service_account.service["broker"].member
}

resource "google_storage_bucket_iam_member" "evidence_create" {
  for_each = toset(["api", "broker"])
  bucket   = google_storage_bucket.evidence.name
  role     = "roles/storage.objectCreator"
  member   = google_service_account.service[each.key].member
}
resource "google_storage_bucket_iam_member" "evidence_read" {
  for_each = toset(["api", "broker"])
  bucket   = google_storage_bucket.evidence.name
  role     = "roles/storage.objectViewer"
  member   = google_service_account.service[each.key].member
}

resource "google_cloud_tasks_queue_iam_member" "enqueue" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_tasks_queue.runs.name
  role     = "roles/cloudtasks.enqueuer"
  member   = google_service_account.service["api"].member
}
resource "google_service_account_iam_member" "api_delivery_identity" {
  service_account_id = google_service_account.service["task-delivery"].name
  role               = "roles/iam.serviceAccountUser"
  member             = google_service_account.service["api"].member
}

resource "google_project_iam_custom_role" "launch" {
  role_id     = replace("${local.name}_launch", "-", "_")
  title       = "Launch the shared ThreatVeil job with bounded overrides"
  permissions = ["run.jobs.run", "run.jobs.runWithOverrides"]
}
resource "google_cloud_run_v2_job_iam_member" "launcher" {
  count    = var.deploy_services ? 1 : 0
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_job.runner[0].name
  role     = google_project_iam_custom_role.launch.name
  member   = google_service_account.service["launcher"].member
}

locals {
  invocation_edges = {
    web_api            = { caller = "web", target = "api" }
    api_broker         = { caller = "api", target = "broker" }
    runner_broker      = { caller = "runner", target = "broker" }
    launcher_broker    = { caller = "launcher", target = "broker" }
    delivery_launcher  = { caller = "task-delivery", target = "launcher" }
    scheduler_launcher = { caller = "scheduler", target = "launcher" }
  }
}
resource "google_cloud_run_v2_service_iam_member" "invoke" {
  for_each = var.deploy_services ? local.invocation_edges : {}
  project  = var.project_id
  location = var.region
  name     = local.service_names[each.value.target]
  role     = "roles/run.invoker"
  member   = google_service_account.service[each.value.caller].member
}
resource "google_cloud_run_v2_service_iam_member" "operators" {
  for_each = var.deploy_services ? var.operator_invokers : toset([])
  project  = var.project_id
  location = var.region
  name     = local.service_names["web"]
  role     = "roles/run.invoker"
  member   = each.key
}
resource "google_cloud_run_v2_service_iam_member" "public_web" {
  count    = var.deploy_services && var.public_web_enabled ? 1 : 0
  project  = var.project_id
  location = var.region
  name     = local.service_names["web"]
  role     = "roles/run.invoker"
  member   = "allUsers"
}

# CI publishes images; it receives neither Terraform administrator nor deployment rights.
resource "google_artifact_registry_repository_iam_member" "ci_publish" {
  repository = google_artifact_registry_repository.images.name
  location   = var.region
  role       = "roles/artifactregistry.writer"
  member     = google_service_account.service["ci-build"].member
}
resource "google_iam_workload_identity_pool" "github" {
  count                     = var.github_repository != "" ? 1 : 0
  workload_identity_pool_id = "${local.name}-github"
  display_name              = "ThreatVeil trusted GitHub main builds"
}
resource "google_iam_workload_identity_pool_provider" "github" {
  count                              = var.github_repository != "" ? 1 : 0
  workload_identity_pool_id          = google_iam_workload_identity_pool.github[0].workload_identity_pool_id
  workload_identity_pool_provider_id = "github"
  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.repository" = "assertion.repository"
  }
  attribute_condition = "assertion.repository == '${var.github_repository}' && assertion.ref == 'refs/heads/main' && assertion.event_name == 'workflow_dispatch' && assertion.sub == 'repo:${var.github_repository}:environment:gcp-dev'"
  oidc { issuer_uri = "https://token.actions.githubusercontent.com" }
}
resource "google_service_account_iam_member" "github_build" {
  count              = var.github_repository != "" ? 1 : 0
  service_account_id = google_service_account.service["ci-build"].name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github[0].name}/attribute.repository/${var.github_repository}"
}

resource "google_service_account_iam_member" "github_deploy" {
  count              = var.github_repository != "" ? 1 : 0
  service_account_id = google_service_account.service["ci-deploy"].name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github[0].name}/attribute.repository/${var.github_repository}"
}
resource "google_project_iam_custom_role" "update_service" {
  role_id     = replace("${local.name}_update_service", "-", "_")
  title       = "Update approved ThreatVeil service revisions"
  permissions = ["run.services.get", "run.services.update"]
}
resource "google_project_iam_custom_role" "update_job" {
  role_id     = replace("${local.name}_update_job", "-", "_")
  title       = "Update approved ThreatVeil job revisions"
  permissions = ["run.jobs.get", "run.jobs.update"]
}
resource "google_project_iam_custom_role" "read_operations" {
  role_id     = replace("${local.name}_read_operations", "-", "_")
  title       = "Read Cloud Run deployment operation results"
  permissions = ["run.operations.get"]
}
resource "google_project_iam_member" "deploy_operations" {
  project = var.project_id
  role    = google_project_iam_custom_role.read_operations.name
  member  = google_service_account.service["ci-deploy"].member
}
resource "google_cloud_run_v2_service_iam_member" "deploy_services" {
  for_each = var.deploy_services ? local.service_names : {}
  project  = var.project_id
  location = var.region
  name     = each.value
  role     = google_project_iam_custom_role.update_service.name
  member   = google_service_account.service["ci-deploy"].member
}
resource "google_cloud_run_v2_job_iam_member" "deploy_jobs" {
  for_each = var.deploy_services ? { runner = google_cloud_run_v2_job.runner[0].name, migration = google_cloud_run_v2_job.migration[0].name } : {}
  project  = var.project_id
  location = var.region
  name     = each.value
  role     = google_project_iam_custom_role.update_job.name
  member   = google_service_account.service["ci-deploy"].member
}
resource "google_cloud_run_v2_job_iam_member" "run_migration" {
  count    = var.deploy_services ? 1 : 0
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_job.migration[0].name
  role     = "roles/run.invoker"
  member   = google_service_account.service["ci-deploy"].member
}
resource "google_service_account_iam_member" "deploy_runtime_identity" {
  for_each           = toset(["web", "api", "broker", "launcher", "runner", "migration"])
  service_account_id = google_service_account.service[each.key].name
  role               = "roles/iam.serviceAccountUser"
  member             = google_service_account.service["ci-deploy"].member
}
resource "google_artifact_registry_repository_iam_member" "deploy_read" {
  repository = google_artifact_registry_repository.images.name
  location   = var.region
  role       = "roles/artifactregistry.reader"
  member     = google_service_account.service["ci-deploy"].member
}
