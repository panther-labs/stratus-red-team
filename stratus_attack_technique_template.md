# Stratus Red Team Attack Technique Template Guide

## Structure Overview

A Stratus Red Team attack technique consists of:

1. A Go file (`main.go`) that defines the attack technique and its implementation
2. A Terraform file (`main.tf`) that creates the required infrastructure

## Step-by-Step Implementation

### 1. Choose a Platform and Tactic

Determine the cloud platform (AWS, Azure, GCP) and the MITRE ATT&CK tactic (Impact, Persistence, etc.) that your technique demonstrates.

### 2. Create the Directory Structure

```
v2/internal/attacktechniques/{platform}/{tactic}/{technique-name}/
├── main.go
└── main.tf
```

### 3. Implement `main.go`

```go
package aws  // or azure, gcp depending on platform

import (
	_ "embed"
	"context"
	"fmt"
	"log"
	// Import necessary cloud SDK packages
	// Import stratus packages
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
)

//go:embed main.tf
var tf []byte

const CodeBlock = "```"

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "{platform}.{tactic}.{technique-name}",
		FriendlyName: "Human-readable name of the technique",
		Description: `
Detailed description of what the attack technique does.

References:
- Link to relevant documentation
- Link to blog posts or articles

Warm-up: 
- List of resources created during warm-up

Detonation: 
- Step-by-step explanation of what happens during detonation
`,
		Detection: `
Detection guidance with example logs or events to look for.

` + CodeBlock + `json hl_lines="key_lines"
{
  "sample": "log entry",
  "with": "relevant fields",
  "highlighted": "for emphasis"
}
` + CodeBlock + `
`,
		Platform:                   stratus.AWS,  // or Azure, GCP
		IsIdempotent:               false,        // Whether technique can be run multiple times without reverting
		IsSlow:                     false,        // Set to true if the technique takes >5 minutes to run
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Impact},  // Relevant tactics
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
		Revert:                     revert,       // Optional if IsIdempotent is true
	})
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	// 1. Extract parameters from Terraform outputs
	// e.g., resourceName := params["resource_name"]
	
	// 2. Initialize SDK client(s)
	// For AWS:   client := aws_service.NewFromConfig(providers.AWS().GetConnection())
	// For Azure: cred := providers.Azure().GetCredentials()
	//            client, err := armservice.NewClient(providers.Azure().SubscriptionID, cred, nil)
	
	// 3. Log beginning of attack
	log.Println("Starting attack technique...")
	
	// 4. Implement the attack logic
	// This should match the steps described in the Description.Detonation field
	
	// 5. Log success
	log.Println("Attack technique completed successfully")
	
	return nil
}

func revert(params map[string]string, providers stratus.CloudProviders) error {
	// Implement clean-up logic to revert the effects of the attack
	// Only needed if IsIdempotent is false
	
	return nil
}
```

### 4. Implement `main.tf`

```terraform
terraform {
  required_providers {
    aws = {      # Use appropriate provider
      source  = "hashicorp/aws"
      version = ">= 4.0.0, < 5.0.0"
    }
  }
}

provider "aws" {  # Use appropriate provider
  skip_region_validation      = true
  skip_credentials_validation = true
}

# Generate random identifiers for resources
resource "random_string" "suffix" {
  length    = 6
  min_lower = 6
  special   = false
}

locals {
  resource_prefix = "stratus-red-team-{technique-name}"
  # Define other local variables as needed
}

# Create required infrastructure resources

# Define terraform outputs that will be passed to the Go code as params
output "resource_name" {
  value = aws_resource.name.id
}

# Final display message
output "display" {
  value = "Resources created successfully: {resource_description}"
}
```

## Best Practices

1. **Documentation**:
   - Provide clear descriptions of the attack
   - Include references to external documentation
   - Document detection methods with example logs

2. **Infrastructure**:
   - Use randomization for resource names
   - Keep resource creation idempotent
   - Define all needed permissions

3. **Implementation**:
   - Log each step of the attack process
   - Handle errors properly
   - Clean up resources in the revert function if needed

4. **Testing**:
   - Test on a clean environment
   - Verify that both detonation and revert work as expected
   - Ensure resource cleanup is complete

## Common Patterns

1. **Resource Creation**: Most attack techniques require creating cloud resources for the attack
2. **Permission Management**: Many attacks involve IAM/permissions manipulation
3. **Data Access**: Techniques often demonstrate unauthorized data access or manipulation
4. **Logging**: Comprehensive logging is crucial for demonstration and debugging 