# Stratus Red Team Scenarios

This directory contains multi-stage attack scenarios that orchestrate multiple Stratus Red Team techniques to simulate realistic attack chains. These scenarios are designed for comprehensive end-to-end testing of detection engineering pipelines.

## Available Scenarios

### IAM-to-S3 Training Data Exfiltration (`iam-to-s3-training-data/`)

**Attack Chain:**
1. **Persistence** - `aws.persistence.iam-backdoor-user`
   - Creates IAM user via Terraform
   - Generates access key for the user
   - Logs both Access Key ID and Secret Access Key for capture
   
2. **Defense Evasion** - `aws.exfiltration.s3-backdoor-bucket-policy` 
   - Creates S3 bucket via Terraform
   - Modifies bucket policy to allow access from external AWS account (637423579581)
   - Grants `s3:GetObject`, `s3:GetBucketLocation`, `s3:ListBucket` permissions

3. **Discovery & Attempted Exfiltration** - Custom S3 operations using backdoor credentials
   - Uses captured IAM credentials to authenticate to AWS
   - Enumerates all S3 buckets in the account (`ListBuckets`)
   - Searches for buckets containing "training-data" in the name
   - Attempts to sync data from training buckets to the backdoored bucket
   - **Expected to fail** due to insufficient IAM permissions (realistic scenario)

4. **Discovery** - Cross-region EC2 reconnaissance
   - Scans US regions (us-east-1, us-east-2, us-west-1, us-west-2)
   - Lists running EC2 instances in each region (`DescribeInstances`)
   - Demonstrates lateral movement and infrastructure reconnaissance

**Execution Order:**
1. Cleanup existing IAM technique state (if any)
2. Warmup `aws.persistence.iam-backdoor-user` (creates IAM user)
3. Detonate `aws.persistence.iam-backdoor-user` (creates access key)
4. Parse logs to extract Access Key ID and Secret Access Key
5. Cleanup existing S3 technique state (if any)  
6. Warmup `aws.exfiltration.s3-backdoor-bucket-policy` (creates S3 bucket)
7. Detonate `aws.exfiltration.s3-backdoor-bucket-policy` (modifies bucket policy)
8. Parse logs to extract S3 bucket name
9. **Discovery Phase**: Use backdoor credentials to enumerate all S3 buckets
10. **Target Identification**: Search for buckets containing "training-data"
11. **Attempted Exfiltration**: Try to sync data from training buckets (fails)
12. **Reconnaissance Phase**: Scan US regions for running EC2 instances  
13. **Infrastructure Discovery**: List instance IDs and types in each region
14. Cleanup both techniques when user confirms

**Detection Opportunities:**
- `CreateAccessKey` CloudTrail events from unusual contexts
- `PutBucketPolicy` events that modify bucket permissions  
- `ListBuckets` operations for account-wide S3 discovery
- `ListObjectsV2` operations against multiple buckets (reconnaissance pattern)
- `CopyObject` attempts indicating data exfiltration (will fail due to permissions)
- `DescribeInstances` operations across multiple regions (cross-region scanning)
- Rapid successive API calls across geographic regions from same credential
- Failed S3 operations due to insufficient permissions (Access Denied patterns)
- Cross-technique correlation for multi-stage attack detection
- Time-based correlation between IAM key creation → S3 discovery → EC2 reconnaissance

**Usage:**
```bash
cd scenarios/
go build -o iam-s3-scenario iam-to-s3-training-data/main.go
./iam-s3-scenario

# Or run directly
go run iam-to-s3-training-data/main.go
```

## Running Scenarios

### Prerequisites
- AWS credentials configured (`aws configure` or environment variables)
- Appropriate AWS permissions for IAM and S3 operations
- Go 1.22+ installed

### Execution
```bash
# Navigate to scenarios directory
cd scenarios/

# Build and run specific scenario
make iam-to-s3-training-data
./iam-s3-scenario

# Or run directly without building
go run iam-to-s3-training-data/main.go

# Build all scenarios
make all

# The scenario will:
# 1. Execute the attack chain
# 2. Generate authentic CloudTrail logs
# 3. Show detection opportunities
# 4. Clean up resources after confirmation
```

### Integration with Panther

These scenarios generate authentic AWS CloudTrail logs that can be:

1. **Exported** from CloudTrail to your log pipeline
2. **Ingested** into Panther for detection testing
3. **Used** to validate detection rules end-to-end
4. **Analyzed** for detection coverage gaps

### Best Practices

- **Run in isolated AWS accounts** to avoid impacting production
- **Monitor CloudTrail logs** during execution to verify log generation
- **Test detection rules** against the generated authentic logs
- **Clean up resources** after each scenario run
- **Customize scenarios** for your specific use cases

## Adding New Scenarios

1. Create a new scenario directory: `mkdir scenarios/your-scenario-name/`
2. Create `main.go` with your scenario implementation
3. Create scenario-specific `README.md` with detailed documentation
4. Import required Stratus techniques and helper functions  
5. Orchestrate multiple techniques with realistic timing
6. Include proper cleanup and error handling
7. Add build target to `Makefile`
8. Update this top-level README with scenario summary

## Architecture

Scenarios use the Stratus Red Team programmatic API to:
- Load and execute existing attack techniques
- Capture intermediate results (like credentials)
- Chain techniques together with proper timing
- Manage resource lifecycle and cleanup

This approach ensures scenarios generate the same authentic logs as individual techniques while enabling complex multi-stage attack simulation.