output "service_urls" {
  value = var.deploy_services ? {
    web      = module.web[0].uri
    api      = module.api[0].uri
    broker   = module.broker[0].uri
    launcher = module.launcher[0].uri
  } : {}
}
output "image_repository" {
  value = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.images.repository_id}"
}
output "sql_connection_name" { value = google_sql_database_instance.postgres.connection_name }
output "evidence_bucket" { value = google_storage_bucket.evidence.name }
output "database_secret_ids" { value = local.database_secrets }
output "service_accounts" { value = { for role, account in google_service_account.service : role => account.email } }
output "tasks_queue" { value = google_cloud_tasks_queue.runs.id }
output "workload_identity_provider" {
  value = var.github_repository != "" ? google_iam_workload_identity_pool_provider.github[0].name : null
}
