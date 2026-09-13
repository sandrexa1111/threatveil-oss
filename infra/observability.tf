resource "google_logging_metric" "security_errors" {
  name   = "${local.name}-security-errors"
  filter = "resource.type=\"cloud_run_revision\" AND resource.labels.service_name=~\"^${local.name}-\" AND severity>=ERROR"
  metric_descriptor {
    metric_kind  = "DELTA"
    value_type   = "INT64"
    display_name = "ThreatVeil service errors"
  }
  depends_on = [google_project_service.required]
}

resource "google_monitoring_alert_policy" "service_errors" {
  display_name          = "${local.name}: sustained service errors"
  combiner              = "OR"
  notification_channels = var.notification_channels
  enabled               = length(var.notification_channels) > 0
  conditions {
    display_name = "Five service errors in five minutes"
    condition_threshold {
      filter          = "resource.type = \"cloud_run_revision\" AND metric.type = \"logging.googleapis.com/user/${google_logging_metric.security_errors.name}\""
      comparison      = "COMPARISON_GT"
      threshold_value = 4
      duration        = "0s"
      aggregations {
        alignment_period     = "300s"
        per_series_aligner   = "ALIGN_SUM"
        cross_series_reducer = "REDUCE_SUM"
      }
      trigger { count = 1 }
    }
  }
  documentation {
    mime_type = "text/markdown"
    content   = "Inspect redacted run/correlation IDs, broker denials, dispatch health and evidence writes. Do not paste payloads or credentials into incident tools. See docs/deployment/GCP.md."
  }
}

resource "google_monitoring_alert_policy" "queue_backlog" {
  display_name          = "${local.name}: queue backlog"
  combiner              = "OR"
  notification_channels = var.notification_channels
  enabled               = length(var.notification_channels) > 0
  conditions {
    display_name = "More than 100 tasks for ten minutes"
    condition_threshold {
      filter          = "resource.type = \"cloud_tasks_queue\" AND resource.labels.queue_id = \"${google_cloud_tasks_queue.runs.name}\" AND metric.type = \"cloudtasks.googleapis.com/queue/depth\""
      comparison      = "COMPARISON_GT"
      threshold_value = 100
      duration        = "600s"
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_MAX"
      }
      trigger { count = 1 }
    }
  }
}
