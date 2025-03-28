terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.31.0"
    }
  }
}

provider "aws" {
  skip_region_validation      = true
  skip_credentials_validation = true
  default_tags {
    tags = {
      StratusRedTeam = true
    }
  }
}

resource "random_string" "suffix" {
  length    = 10
  min_lower = 10
  special   = false
}

locals {
  resource_prefix = "stratus-red-team-bedrock"
  # Using Anthropic Claude 3 Haiku as it's commonly available
  model_id = "anthropic.claude-3-haiku-20240307-v1:0"
}

resource "aws_bedrock_guardrail" "test_guardrail" {
  name                      = "${local.resource_prefix}-guardrail-${random_string.suffix.result}"
  description              = "Test guardrail for Stratus Red Team"
  blocked_input_messaging  = "Your questions is bad and you should feel bad"
  blocked_outputs_messaging = "Your questions is bad and you should feel bad"

  content_policy_config {
    filters_config {
      input_strength  = "HIGH"
      output_strength = "HIGH"
      type            = "VIOLENCE"
    }
  }
}

# We don't actually need to create a model, as we can use a built-in one
# This is just to verify the model is available in the account
data "aws_bedrock_foundation_model" "claude" {
  model_id = local.model_id
}

output "bedrock_guardrail_id" {
  value = aws_bedrock_guardrail.test_guardrail.guardrail_id
}

output "bedrock_guardrail_version" {
  value = "DRAFT"
}

output "bedrock_model_id" {
  value = local.model_id
}

output "display" {
  value = format("Bedrock guardrail %s ready with model %s", aws_bedrock_guardrail.test_guardrail.name, local.model_id)
}

output "use_converse_api" {
  value = "false" # Set to "true" to use the Converse API instead of InvokeModel
} 