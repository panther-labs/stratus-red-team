terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 4.54.0, < 5.0.0" # 4.54.0 at least is required for proper AWS SSO support, see #626
    }
  }
}
provider "aws" {
  skip_region_validation      = true
  skip_credentials_validation = true
  skip_get_ec2_platforms      = true
  default_tags {
    tags = {
      StratusRedTeam = true
    }
  }
}

locals {
  num_secrets     = 42
  resource_prefix = "stratus-red-team-retrieve--batch-secret"
}

resource "random_string" "secrets" {
  count     = local.num_secrets
  length    = 16
  min_lower = 16
}

resource "aws_secretsmanager_secret" "secrets" {
  count = local.num_secrets
  name  = "${local.resource_prefix}-${count.index}"

  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "secret-values" {
  count         = local.num_secrets
  secret_id     = aws_secretsmanager_secret.secrets[count.index].id
  secret_string = random_string.secrets[count.index].result
}

output "display" {
  value = format("%s Secrets Manager secrets ready", local.num_secrets)
}