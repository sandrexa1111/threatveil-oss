variable "name" { type = string }
variable "location" { type = string }
variable "image" { type = string }
variable "service_account" { type = string }
variable "command" { type = list(string) }
variable "env" { type = map(string) }
variable "secret_env" { type = map(string) }
variable "labels" { type = map(string) }
variable "custom_audiences" {
  type    = list(string)
  default = []
}
variable "database_connection" {
  type    = string
  default = ""
}
variable "max_instances" {
  type    = number
  default = 3
}
variable "request_timeout_seconds" {
  type    = number
  default = 120
  validation {
    condition     = var.request_timeout_seconds >= 1 && var.request_timeout_seconds <= 3600 && floor(var.request_timeout_seconds) == var.request_timeout_seconds
    error_message = "Cloud Run request timeout must be an integer from 1 to 3600 seconds."
  }
}

resource "google_cloud_run_v2_service" "this" {
  name                = var.name
  location            = var.location
  deletion_protection = true
  # IAM requires authentication even though the HTTPS endpoint is internet-addressable.
  ingress          = "INGRESS_TRAFFIC_ALL"
  labels           = var.labels
  custom_audiences = var.custom_audiences
  template {
    service_account                  = var.service_account
    max_instance_request_concurrency = 20
    timeout                          = "${var.request_timeout_seconds}s"
    scaling {
      min_instance_count = 0
      max_instance_count = var.max_instances
    }
    containers {
      image   = var.image
      command = var.command
      ports { container_port = 8080 }
      resources {
        limits   = { cpu = "1", memory = "512Mi" }
        cpu_idle = true
      }
      dynamic "env" {
        for_each = var.env
        content {
          name  = env.key
          value = env.value
        }
      }
      dynamic "env" {
        for_each = var.secret_env
        content {
          name = env.key
          value_source {
            secret_key_ref {
              secret  = env.value
              version = "latest"
            }
          }
        }
      }
      dynamic "volume_mounts" {
        for_each = var.database_connection == "" ? [] : [var.database_connection]
        content {
          name       = "cloudsql"
          mount_path = "/cloudsql"
        }
      }
      startup_probe {
        initial_delay_seconds = 0
        timeout_seconds       = 2
        period_seconds        = 3
        failure_threshold     = 30
        tcp_socket { port = 8080 }
      }
    }
    dynamic "volumes" {
      for_each = var.database_connection == "" ? [] : [var.database_connection]
      content {
        name = "cloudsql"
        cloud_sql_instance { instances = [volumes.value] }
      }
    }
  }
  lifecycle { prevent_destroy = true }
}
output "name" { value = google_cloud_run_v2_service.this.name }
output "uri" { value = google_cloud_run_v2_service.this.uri }
# Nonsecret configuration outputs allow tests to check the actual module wiring.
output "configured_environment" { value = var.env }
output "configured_secret_ids" { value = var.secret_env }
