package runner

import (
	"strings"
	"testing"
)

func TestPreprocessTerraformCode(t *testing.T) {
	testCases := []struct {
		name           string
		terraformCode  string
		expectedModify bool
	}{
		{
			name: "Simple resource_prefix replacement",
			terraformCode: `
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 4.54.0, < 5.0.0"
    }
  }
}
provider "aws" {
  skip_region_validation      = true
  skip_credentials_validation = true
}

resource "random_string" "suffix" {
  length    = 10
  min_lower = 10
  special   = false
}

locals {
  resource_prefix = "stratus-red-team-test"
}
`,
			expectedModify: true,
		},
		{
			name: "Resource_prefix with comment",
			terraformCode: `
locals {
  resource_prefix = "stratus-red-team-ctes" # cloudtrail event selectors
}
`,
			expectedModify: true,
		},
		{
			name: "Resource_prefix with multi-word comment",
			terraformCode: `
locals {
  resource_prefix = "stratus-red-team-ctlr" # cloudtrail lifecycle rule
}
`,
			expectedModify: true,
		},
		{
			name: "Resource_prefix at beginning of file",
			terraformCode: `locals {
  resource_prefix = "stratus-red-team-xyz"
}
`,
			expectedModify: true,
		},
		{
			name: "Alternative resource_prefix pattern",
			terraformCode: `
locals {
  resource_prefix = "stratus-red-team-asdf"
}
`,
			expectedModify: true,
		},
		{
			name: "No resource_prefix",
			terraformCode: `
locals {
  some_other_value = "value"
}
`,
			expectedModify: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Process the code
			processed, err := preprocessTerraformCode([]byte(tc.terraformCode), "custom-prefix")
			if err != nil {
				t.Fatalf("Error processing Terraform code: %v", err)
			}

			processedStr := string(processed)
			t.Logf("Processed code:\n%s\n", processedStr)

			// Verify variable was added
			if !strings.Contains(processedStr, `variable "resource_prefix"`) {
				t.Errorf("Variable resource_prefix wasn't added to the code")
			}

			// Check if resource_prefix was replaced
			if tc.expectedModify {
				if strings.Contains(processedStr, `resource_prefix = "`) {
					t.Errorf("Hardcoded resource_prefix wasn't replaced in case: %s", tc.name)
				}
				if !strings.Contains(processedStr, `resource_prefix = var.resource_prefix`) {
					t.Errorf("Variable reference wasn't added in case: %s", tc.name)
				}

				// Verify comments were preserved if they existed
				if strings.Contains(tc.terraformCode, "#") && !strings.Contains(processedStr, "#") {
					t.Errorf("Comments were not preserved in case: %s", tc.name)
				}
			}
		})
	}
}
