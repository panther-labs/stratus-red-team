terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 4.57.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.1.0"
    }
  }
}

data "google_client_openid_userinfo" "whoami" {}
data "google_client_config" "current" {}

locals {
  resource_prefix = "stratus-red-team-tbpe" # stratus red team tag-based privilege escalation
  # Use regex instead of endswith to check for service account
  principal_type = can(regex(".+\\.gserviceaccount\\.com$", data.google_client_openid_userinfo.whoami.email)) ? "serviceAccount" : "user"
}

resource "random_string" "suffix" {
  length    = 6
  special   = false
  lower     = true
  upper     = false
  min_lower = 4
}

# Create a tag key
resource "google_tags_tag_key" "env_tag_key" {
  parent      = "projects/${data.google_client_config.current.project}"
  short_name  = "${local.resource_prefix}-tag-key-${random_string.suffix.result}"
  description = "Environment tag used for conditional access"
}

# Create a tag value
resource "google_tags_tag_value" "sandbox_tag_value" {
  parent      = google_tags_tag_key.env_tag_key.id
  short_name  = "${local.resource_prefix}-tag-value-${random_string.suffix.result}"
  description = "Sandbox environment"
}

# Create a VM instance that will be the target for the attack
resource "google_compute_instance" "target_vm" {
  name         = "stratus-vm-${random_string.suffix.result}"
  machine_type = "f1-micro"
  zone         = "us-central1-a"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
    }
  }

  network_interface {
    network = "default"
  }

  metadata = {
    purpose = "Stratus Red Team GCP tag-based privilege escalation scenario"
  }

  service_account {
    scopes = ["cloud-platform"]
  }
}

# Grant the current user roles/resourcemanager.tagUser role
resource "google_project_iam_member" "tag_user_role" {
  project = data.google_client_config.current.project
  role    = "roles/resourcemanager.tagUser"
  member  = "${local.principal_type}:${data.google_client_openid_userinfo.whoami.email}"
}

# Grant the current user roles/viewer role
resource "google_project_iam_member" "viewer_role" {
  project = data.google_client_config.current.project
  role    = "roles/viewer"
  member  = "${local.principal_type}:${data.google_client_openid_userinfo.whoami.email}"
}

# Create a custom IAM binding with a condition to grant compute.admin when a resource has the env=sandbox tag
resource "google_project_iam_member" "conditional_admin" {
  project = data.google_client_config.current.project
  role    = "roles/compute.admin"
  member  = "${local.principal_type}:${data.google_client_openid_userinfo.whoami.email}"

  condition {
    title       = "sandbox_env_condition"
    description = "Grant compute.admin if resource has env=sandbox tag"
    expression  = "resource.matchTag('${google_tags_tag_key.env_tag_key.short_name}', '${google_tags_tag_value.sandbox_tag_value.short_name}')"
  }
}

output "project_id" {
  value = data.google_client_config.current.project
}

output "vm_instance_name" {
  value = google_compute_instance.target_vm.name
}

output "zone" {
  value = google_compute_instance.target_vm.zone
}

output "tag_key" {
  value = google_tags_tag_key.env_tag_key.short_name
}

output "tag_value" {
  value = google_tags_tag_value.sandbox_tag_value.short_name
}

output "tag_value_full_name" {
  value = google_tags_tag_value.sandbox_tag_value.id
}

output "display" {
  value = "Tag-based privilege escalation environment set up:\n  - Target VM: ${google_compute_instance.target_vm.name}\n  - Tag key created: ${google_tags_tag_key.env_tag_key.short_name}\n  - Tag value created: ${google_tags_tag_value.sandbox_tag_value.short_name}\n  - IAM condition: grants compute.admin when resource has ${google_tags_tag_key.env_tag_key.short_name}=${google_tags_tag_value.sandbox_tag_value.short_name} tag"
} 