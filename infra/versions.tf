terraform {
  backend "gcs" {}
  required_version = ">= 1.16.1, < 1.17.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "7.46.1"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}
