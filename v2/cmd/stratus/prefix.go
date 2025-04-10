package main

import (
	"log"

	"github.com/datadog/stratus-red-team/v2/pkg/stratus/useragent"
	"github.com/spf13/cobra"
)

// setupPrefixFlag adds the custom prefix flag to the root command
// and sets up the validation and initialization logic
func setupPrefixFlag(cmd *cobra.Command) {
	// Add the custom prefix flag to the root command
	cmd.PersistentFlags().StringVar(&customPrefix, "prefix", "stratus-red-team", "Custom prefix for User-Agent string and cloud resource names")

	// Register a hook to validate and apply the custom prefix
	cobra.OnInitialize(validateAndApplyPrefix)
}

// validateAndApplyPrefix validates the custom prefix and applies it if valid
func validateAndApplyPrefix() {
	if customPrefix != "stratus-red-team" {
		// Validate the custom prefix
		if !isValidTerraformIdentifier(customPrefix) {
			log.Fatalf("Invalid prefix: %s. Prefix must contain only letters, numbers, hyphens, and underscores, and cannot start with a number.", customPrefix)
		}
		useragent.SetUserAgentPrefix(customPrefix)
	}
}

// isValidTerraformIdentifier checks if a string is valid for use in Terraform as a variable or resource name
func isValidTerraformIdentifier(s string) bool {
	if len(s) == 0 {
		return false
	}

	// First character must not be a digit
	if s[0] >= '0' && s[0] <= '9' {
		return false
	}

	// Check if it only contains allowed characters (letters, numbers, hyphens, underscores)
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}

	return true
}
