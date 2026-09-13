locals {
  github_env               = var.github_app.enabled ? { TV_GITHUB_APP_ID = var.github_app.app_id } : {}
  github_publisher_secrets = var.github_app.enabled ? { TV_GITHUB_PRIVATE_KEY = var.github_app.private_key_secret_id } : {}
  github_ingress_secrets   = var.github_app.enabled ? { TV_GITHUB_WEBHOOK_SECRET = var.github_app.webhook_secret_id } : {}
  # These fields are intentionally absent from runtime_env, which runners inherit.
  revenue_env = {
    TV_RESEND_DELIVERY_ENABLED  = tostring(var.revenue_delivery.resend_enabled)
    TV_HUBSPOT_DELIVERY_ENABLED = tostring(var.revenue_delivery.hubspot_enabled)
    TV_EMAIL_FROM               = var.revenue_delivery.resend_enabled ? var.revenue_delivery.email_from : ""
    TV_HUBSPOT_OWNER_ID         = var.revenue_delivery.hubspot_enabled ? var.revenue_delivery.hubspot_owner_id : ""
  }
  revenue_secret_bindings = merge(
    var.revenue_delivery.resend_enabled ? { TV_RESEND_API_KEY = var.revenue_delivery.resend_secret_id } : {},
    var.revenue_delivery.hubspot_enabled ? { TV_HUBSPOT_TOKEN = var.revenue_delivery.hubspot_secret_id } : {}
  )
  runtime_env = {
    TV_ENV                = var.environment
    TV_IMAGE_DIGEST       = lookup(var.images, "python", "")
    TV_LOCAL_AUTH         = "false"
    TV_WEB_ORIGIN         = var.web_origin
    TV_FIREBASE_PROJECT   = var.project_id
    TV_SECRET_PROJECT     = var.project_id
    TV_EVIDENCE_BUCKET    = google_storage_bucket.evidence.name
    TV_CLOUD_PROJECT      = var.project_id
    TV_CLOUD_REGION       = var.region
    TV_WORKER_IDENTITY    = google_service_account.service["runner"].email
    TV_LAUNCHER_IDENTITY  = google_service_account.service["launcher"].email
    TV_TASKS_IDENTITY     = google_service_account.service["task-delivery"].email
    TV_SCHEDULER_IDENTITY = google_service_account.service["scheduler"].email
    TV_BROKER_AUDIENCE    = "threatveil-broker"
    TV_LAUNCHER_AUDIENCE  = "threatveil-launcher"
  }
  service_names = var.deploy_services ? {
    web      = module.web[0].name
    api      = module.api[0].name
    broker   = module.broker[0].name
    launcher = module.launcher[0].name
  } : {}
}

module "broker" {
  request_timeout_seconds = 360
  count                   = var.deploy_services ? 1 : 0
  source                  = "./modules/service"
  name                    = "${local.name}-broker"
  location                = var.region
  image                   = var.images["python"]
  service_account         = google_service_account.service["broker"].email
  command                 = ["uvicorn", "threatveil.broker:app", "--host", "0.0.0.0", "--port", "8080"]
  env                     = merge(local.runtime_env, local.revenue_env, local.github_env)
  secret_env              = merge(local.revenue_secret_bindings, local.github_publisher_secrets, { TV_DATABASE_URL = google_secret_manager_secret.database["broker"].secret_id })
  labels                  = local.component_labels["broker"]
  database_connection     = google_sql_database_instance.postgres.connection_name
  custom_audiences        = ["threatveil-broker"]
  depends_on              = [google_secret_manager_secret_iam_member.database, google_secret_manager_secret_iam_member.revenue_delivery, google_secret_manager_secret_iam_member.github_app, google_project_iam_member.sql_clients]
}

module "launcher" {
  request_timeout_seconds = 600
  count                   = var.deploy_services ? 1 : 0
  source                  = "./modules/service"
  name                    = "${local.name}-launcher"
  location                = var.region
  image                   = var.images["python"]
  service_account         = google_service_account.service["launcher"].email
  command                 = ["uvicorn", "threatveil.launcher:app", "--host", "0.0.0.0", "--port", "8080"]
  env = merge(local.runtime_env, {
    TV_BROKER_URL      = module.broker[0].uri
    TV_BROKER_AUDIENCE = "threatveil-broker"
    TV_RUNNER_JOB      = "projects/${var.project_id}/locations/${var.region}/jobs/${local.name}-runner"
  })
  secret_env       = {}
  labels           = local.component_labels["launcher"]
  custom_audiences = ["threatveil-launcher"]
}

module "api" {
  count           = var.deploy_services ? 1 : 0
  source          = "./modules/service"
  name            = "${local.name}-api"
  location        = var.region
  image           = var.images["python"]
  service_account = google_service_account.service["api"].email
  command         = ["uvicorn", "threatveil.api:app", "--host", "0.0.0.0", "--port", "8080"]
  env = merge(local.runtime_env, local.revenue_env, local.github_env, {
    TV_BROKER_URL      = module.broker[0].uri
    TV_BROKER_AUDIENCE = "threatveil-broker"
    TV_LAUNCHER_URL    = module.launcher[0].uri
    TV_TASKS_QUEUE     = google_cloud_tasks_queue.runs.id
  })
  secret_env          = merge(var.api_secret_bindings, local.revenue_secret_bindings, local.github_publisher_secrets, local.github_ingress_secrets, { TV_DATABASE_URL = google_secret_manager_secret.database["api"].secret_id })
  labels              = local.component_labels["api"]
  database_connection = google_sql_database_instance.postgres.connection_name
  depends_on          = [google_secret_manager_secret_iam_member.database, google_secret_manager_secret_iam_member.api_integrations, google_secret_manager_secret_iam_member.revenue_delivery, google_secret_manager_secret_iam_member.github_app, google_project_iam_member.sql_clients]
}

module "web" {
  count           = var.deploy_services ? 1 : 0
  source          = "./modules/service"
  name            = "${local.name}-web"
  location        = var.region
  image           = var.images["web"]
  service_account = google_service_account.service["web"].email
  command         = ["/nodejs/bin/node", "apps/web/server.js"]
  env = {
    NODE_ENV        = "production"
    TV_ENV          = var.environment
    TV_LOCAL_AUTH   = "false"
    TV_API_URL      = module.api[0].uri
    TV_API_AUDIENCE = module.api[0].uri
    HOSTNAME        = "0.0.0.0"
  }
  secret_env = {}
  labels     = local.component_labels["web"]
}

resource "google_cloud_run_v2_job" "runner" {
  count               = var.deploy_services ? 1 : 0
  name                = "${local.name}-runner"
  location            = var.region
  deletion_protection = true
  labels              = merge(local.labels, { component = "runner" })
  template {
    task_count  = 1
    parallelism = 1
    template {
      service_account = google_service_account.service["runner"].email
      max_retries     = 0
      timeout         = "600s"
      containers {
        image   = var.images["python"]
        command = ["python", "-m", "threatveil.worker"]
        resources { limits = { cpu = "1", memory = "512Mi" } }
        dynamic "env" {
          for_each = merge(local.runtime_env, {
            TV_BROKER_URL            = module.broker[0].uri
            TV_BROKER_AUDIENCE       = "threatveil-broker"
            TV_LEASE_TTL_SECONDS     = "120"
            TV_BOOTSTRAP_TTL_SECONDS = "300"
          })
          content {
            name  = env.key
            value = env.value
          }
        }
      }
    }
  }
  lifecycle { prevent_destroy = true }
}

resource "google_cloud_scheduler_job" "reconcile" {
  count            = var.deploy_services && var.enable_scheduler ? 1 : 0
  name             = "${local.name}-reconcile"
  region           = var.region
  description      = "Recover pending outbox work and stale runs; no target credentials in scheduler payloads."
  schedule         = "*/5 * * * *"
  time_zone        = "Etc/UTC"
  attempt_deadline = "600s"
  retry_config { retry_count = 2 }
  http_target {
    http_method = "POST"
    uri         = "${module.launcher[0].uri}/internal/reconcile"
    headers     = { "Content-Type" = "application/json" }
    body        = base64encode("{}")
    oidc_token {
      service_account_email = google_service_account.service["scheduler"].email
      audience              = "threatveil-launcher"
    }
  }
  depends_on = [google_cloud_run_v2_service_iam_member.invoke]
}

resource "google_cloud_run_v2_job" "migration" {
  count               = var.deploy_services ? 1 : 0
  name                = "${local.name}-migration"
  location            = var.region
  deletion_protection = true
  labels              = merge(local.labels, { component = "migration" })
  template {
    task_count  = 1
    parallelism = 1
    template {
      service_account = google_service_account.service["migration"].email
      timeout         = "600s"
      max_retries     = 0
      volumes {
        name = "cloudsql"
        cloud_sql_instance { instances = [google_sql_database_instance.postgres.connection_name] }
      }
      containers {
        image   = var.images["python"]
        command = ["alembic", "upgrade", "head"]
        resources { limits = { cpu = "1", memory = "512Mi" } }
        volume_mounts {
          name       = "cloudsql"
          mount_path = "/cloudsql"
        }
        dynamic "env" {
          for_each = local.runtime_env
          content {
            name  = env.key
            value = env.value
          }
        }
        env {
          name = "TV_ADMIN_DATABASE_URL"
          value_source {
            secret_key_ref {
              secret  = google_secret_manager_secret.database["migration"].secret_id
              version = "latest"
            }
          }
        }
      }
    }
  }
  lifecycle { prevent_destroy = true }
}
