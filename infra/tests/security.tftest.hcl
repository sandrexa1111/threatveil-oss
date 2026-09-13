mock_provider "google" {
  mock_resource "google_service_account" {
    defaults = {
      email  = "mock-worker@threatveil-offline-test.iam.gserviceaccount.com"
      member = "serviceAccount:mock-worker@threatveil-offline-test.iam.gserviceaccount.com"
      name   = "projects/threatveil-offline-test/serviceAccounts/mock-worker@threatveil-offline-test.iam.gserviceaccount.com"
    }
  }
  mock_resource "google_project_iam_custom_role" {
    defaults = { name = "projects/threatveil-offline-test/roles/threatveil_launch" }
  }
}

variables {
  project_id = "threatveil-offline-test"
}

run "reject_incomplete_github_app" {
  command = plan
  variables { github_app = { enabled = true } }
  expect_failures = [var.github_app]
}

run "reject_api_only_github_credentials" {
  command = plan
  variables { api_secret_bindings = { TV_GITHUB_PRIVATE_KEY = "api-only-github" } }
  expect_failures = [var.api_secret_bindings]
}

run "infrastructure_defaults_are_private" {
  command = plan
  assert {
    condition     = length(google_secret_manager_secret_iam_member.revenue_delivery) == 0 && local.revenue_env.TV_RESEND_DELIVERY_ENABLED == "false" && local.revenue_env.TV_HUBSPOT_DELIVERY_ENABLED == "false"
    error_message = "Revenue delivery must have no credential access and remain disabled by default."
  }
  assert {
    condition     = length(google_cloud_run_v2_service_iam_member.public_web) == 0
    error_message = "No public invoker may be granted by default."
  }
  assert {
    condition     = google_sql_database_instance.postgres.deletion_protection && google_storage_bucket.evidence.force_destroy == false
    error_message = "Database and evidence deletion guards must remain enabled."
  }
  assert {
    condition     = !contains(keys(google_project_iam_member.sql_clients), "runner") && !contains(keys(google_secret_manager_secret_iam_member.database), "runner") && !contains(keys(google_storage_bucket_iam_member.evidence_read), "runner")
    error_message = "The runner must never get SQL, database secret, or evidence read roles."
  }
}

run "reject_enabled_incomplete_revenue_configuration" {
  command = plan
  variables { revenue_delivery = { resend_enabled = true, hubspot_enabled = true } }
  expect_failures = [var.revenue_delivery]
}

run "reject_api_only_revenue_secret_configuration" {
  command = plan
  variables { api_secret_bindings = { TV_RESEND_API_KEY = "api-only-resend" } }
  expect_failures = [var.api_secret_bindings]
}

run "shared_runner_is_bounded" {
  # Mock apply resolves provider-computed fields. It performs no GCP requests.
  command = apply
  variables {
    deploy_services = true
    web_origin      = "https://reviewed.example.com"
    images = {
      python = "europe-west1-docker.pkg.dev/test/repo/python@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      web    = "europe-west1-docker.pkg.dev/test/repo/web@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    }
  }
  assert {
    condition     = google_cloud_run_v2_job.runner[0].template[0].task_count == 1 && google_cloud_run_v2_job.runner[0].template[0].template[0].max_retries == 0
    error_message = "Platform retries must not repeat uncertain target side effects."
  }
  assert {
    condition     = google_cloud_run_v2_job.runner[0].template[0].template[0].service_account == google_service_account.service["runner"].email
    error_message = "The runner must use its unprivileged workload identity."
  }
  assert {
    condition     = length([for edge in values(local.invocation_edges) : edge if edge.caller == "runner"]) == 1 && local.invocation_edges.runner_broker.target == "broker"
    error_message = "Runner identity may invoke only the broker; run lease authorization remains application-enforced."
  }
  assert {
    condition     = toset(google_project_iam_custom_role.launch.permissions) == toset(["run.jobs.run", "run.jobs.runWithOverrides"])
    error_message = "Launcher must not receive job configuration or IAM administration rights."
  }
}

run "reject_unconfigured_service_deployment" {
  command = plan
  variables { deploy_services = true }
  expect_failures = [var.deploy_services]
}

run "revenue_delivery_has_matching_scoped_runtime_configuration" {
  command = apply
  variables {
    deploy_services = true
    web_origin      = "https://reviewed.example.com"
    images = {
      python = "europe-west1-docker.pkg.dev/test/repo/python@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      web    = "europe-west1-docker.pkg.dev/test/repo/web@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    }
    revenue_delivery = {
      resend_enabled    = true
      resend_secret_id  = "reviewed-resend"
      email_from        = "invitations@example.com"
      hubspot_enabled   = true
      hubspot_secret_id = "reviewed-hubspot"
      hubspot_owner_id  = "12345"
    }
  }
  assert {
    condition = toset(keys(google_secret_manager_secret_iam_member.revenue_delivery)) == toset([
      "api.TV_RESEND_API_KEY", "api.TV_HUBSPOT_TOKEN", "broker.TV_RESEND_API_KEY", "broker.TV_HUBSPOT_TOKEN"
      ]) && alltrue([for grant in values(google_secret_manager_secret_iam_member.revenue_delivery) :
      grant.role == "roles/secretmanager.secretAccessor" && contains(["reviewed-resend", "reviewed-hubspot"], grant.secret_id)
    ])
    error_message = "Only API and broker may receive exact enabled revenue secret-level accessor grants."
  }
  assert {
    condition = alltrue([for config in [module.api[0], module.broker[0]] :
      config.configured_environment.TV_RESEND_DELIVERY_ENABLED == "true" &&
      config.configured_environment.TV_HUBSPOT_DELIVERY_ENABLED == "true" &&
      config.configured_environment.TV_EMAIL_FROM == "invitations@example.com" &&
      config.configured_environment.TV_HUBSPOT_OWNER_ID == "12345" &&
      config.configured_secret_ids.TV_RESEND_API_KEY == "reviewed-resend" &&
      config.configured_secret_ids.TV_HUBSPOT_TOKEN == "reviewed-hubspot"
    ])
    error_message = "API readiness and broker maintenance must use identical enabled provider bindings."
  }
  assert {
    condition = (length(setintersection(toset(keys(local.revenue_env)), toset(keys(local.runtime_env)))) == 0 &&
      !contains(keys(module.launcher[0].configured_environment), "TV_RESEND_DELIVERY_ENABLED") &&
      !contains(keys(module.web[0].configured_secret_ids), "TV_HUBSPOT_TOKEN") &&
      length(module.launcher[0].configured_secret_ids) == 0 &&
      alltrue([for env in google_cloud_run_v2_job.runner[0].template[0].template[0].containers[0].env :
        !contains(concat(keys(local.revenue_env), keys(local.revenue_secret_bindings)), env.name)
    ]))
    error_message = "Shared runner, launcher and web must not inherit revenue flags or secrets."
  }
}

run "disabled_revenue_does_not_mount_preconfigured_secrets" {
  command = plan
  variables {
    deploy_services = true
    web_origin      = "https://reviewed.example.com"
    images = {
      python = "europe-west1-docker.pkg.dev/test/repo/python@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      web    = "europe-west1-docker.pkg.dev/test/repo/web@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    }
    revenue_delivery = {
      resend_secret_id  = "reviewed-resend"
      email_from        = "invitations@example.com"
      hubspot_secret_id = "reviewed-hubspot"
      hubspot_owner_id  = "12345"
    }
  }
  assert {
    condition     = length(local.revenue_secret_bindings) == 0 && length(google_secret_manager_secret_iam_member.revenue_delivery) == 0 && local.revenue_env.TV_EMAIL_FROM == "" && local.revenue_env.TV_HUBSPOT_OWNER_ID == ""
    error_message = "Preconfiguring secret names must not enable delivery or grant access."
  }
}

run "github_app_credentials_are_narrowly_placed" {
  command = apply
  variables {
    deploy_services = true
    web_origin = "https://reviewed.example.com"
    images = {
      python = "registry.example.com/python@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      web = "registry.example.com/web@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    }
    github_app = { enabled = true, app_id = "123", private_key_secret_id = "reviewed-github-key", webhook_secret_id = "reviewed-webhook" }
  }
  assert {
    condition = alltrue([for config in [module.api[0], module.broker[0]] :
      config.configured_environment.TV_GITHUB_APP_ID == "123" && config.configured_secret_ids.TV_GITHUB_PRIVATE_KEY == "reviewed-github-key"
    ]) && module.api[0].configured_secret_ids.TV_GITHUB_WEBHOOK_SECRET == "reviewed-webhook" && !contains(keys(module.broker[0].configured_secret_ids), "TV_GITHUB_WEBHOOK_SECRET")
    error_message = "API and broker need the same App publishing configuration; only API needs the ingress secret."
  }
  assert {
    condition = (toset(keys(google_secret_manager_secret_iam_member.github_app)) == toset(["api.private_key", "api.webhook", "broker.private_key"]) &&
      length(module.launcher[0].configured_secret_ids) == 0 && length(module.web[0].configured_secret_ids) == 0 &&
      alltrue([for env in google_cloud_run_v2_job.runner[0].template[0].template[0].containers[0].env : !startswith(env.name, "TV_GITHUB_")]))
    error_message = "Runner, launcher and web must not receive GitHub App credential grants or mounts."
  }
}

