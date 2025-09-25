package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

func buildScenarioCmd() *cobra.Command {
	scenarioCmd := &cobra.Command{
		Use:   "scenario",
		Short: "Execute multi-stage attack scenarios",
		Long:  "Execute complex multi-stage attack scenarios that combine multiple techniques",
	}

	scenarioDetonateCmd := &cobra.Command{
		Use:   "detonate [scenario-name]",
		Short: "Execute a multi-stage attack scenario",
		Example: strings.Join([]string{
			"stratus scenario detonate iam-to-s3-training-data",
		}, "\n"),
		Args: cobra.ExactArgs(1),
		ValidArgs: []string{
			"iam-to-s3-training-data",
		},
		Run: func(cmd *cobra.Command, args []string) {
			scenarioName := args[0]
			doScenarioDetonate(scenarioName)
		},
	}

	scenarioCleanupCmd := &cobra.Command{
		Use:   "cleanup [scenario-name]",
		Short: "Clean up resources from a multi-stage attack scenario",
		Example: strings.Join([]string{
			"stratus scenario cleanup iam-to-s3-training-data",
		}, "\n"),
		Args: cobra.ExactArgs(1),
		ValidArgs: []string{
			"iam-to-s3-training-data",
		},
		Run: func(cmd *cobra.Command, args []string) {
			scenarioName := args[0]
			doScenarioCleanup(scenarioName)
		},
	}

	scenarioCmd.AddCommand(scenarioDetonateCmd)
	scenarioCmd.AddCommand(scenarioCleanupCmd)

	return scenarioCmd
}

func doScenarioDetonate(scenarioName string) {
	scenarioPath := getScenarioPath(scenarioName)
	if scenarioPath == "" {
		fmt.Printf("Error: Scenario '%s' not found\n", scenarioName)
		os.Exit(1)
	}

	fmt.Printf("Executing scenario: %s\n", scenarioName)

	// Change to scenario directory and execute
	originalDir, _ := os.Getwd()
	defer os.Chdir(originalDir)

	if err := os.Chdir(filepath.Dir(scenarioPath)); err != nil {
		fmt.Printf("Error: Failed to change to scenario directory: %v\n", err)
		os.Exit(1)
	}

	// Execute the Go program
	cmd := exec.Command("go", "run", "main.go")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		fmt.Printf("Error executing scenario: %v\n", err)
		os.Exit(1)
	}
}

func doScenarioCleanup(scenarioName string) {
	fmt.Printf("Cleaning up scenario: %s\n", scenarioName)

	switch scenarioName {
	case "iam-to-s3-training-data":
		cleanupIAMToS3Scenario()
	default:
		fmt.Printf("Error: Unknown scenario '%s'\n", scenarioName)
		os.Exit(1)
	}
}

func cleanupIAMToS3Scenario() {
	// Get the current working directory to find the stratus binary
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Printf("Error getting current directory: %v\n", err)
		return
	}

	// Find the stratus binary (assuming it's in bin/ relative to project root)
	stratusPath := filepath.Join(cwd, "bin", "stratus")
	if _, err := os.Stat(stratusPath); os.IsNotExist(err) {
		// Try relative to scenarios directory
		stratusPath = filepath.Join(cwd, "..", "bin", "stratus")
		if _, err := os.Stat(stratusPath); os.IsNotExist(err) {
			fmt.Printf("Error: stratus binary not found. Please run 'make build' first.\n")
			return
		}
	}

	// Clean up IAM technique
	fmt.Println("Cleaning up IAM backdoor user...")
	cmd1 := exec.Command(stratusPath, "cleanup", "aws.persistence.iam-backdoor-user", "--prefix", "security-audit")
	cmd1.Stdout = os.Stdout
	cmd1.Stderr = os.Stderr
	cmd1.Run() // Ignore errors since resources might not exist

	// Clean up S3 technique
	fmt.Println("Cleaning up S3 backdoor...")
	cmd2 := exec.Command(stratusPath, "cleanup", "aws.exfiltration.s3-backdoor-bucket-policy", "--force")
	cmd2.Stdout = os.Stdout
	cmd2.Stderr = os.Stderr
	cmd2.Run() // Ignore errors since resources might not exist

	fmt.Println("Scenario cleanup completed.")
}

func getScenarioPath(scenarioName string) string {
	// Get current working directory
	cwd, err := os.Getwd()
	if err != nil {
		return ""
	}

	// Check if we're in the scenarios directory already
	scenarioPath := filepath.Join(cwd, scenarioName, "main.go")
	if _, err := os.Stat(scenarioPath); err == nil {
		return scenarioPath
	}

	// Check scenarios directory relative to project root
	scenarioPath = filepath.Join(cwd, "scenarios", scenarioName, "main.go")
	if _, err := os.Stat(scenarioPath); err == nil {
		return scenarioPath
	}

	return ""
}