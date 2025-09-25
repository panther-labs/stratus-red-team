# Stratus Red Team Scenarios

This directory contains multi-stage attack scenarios that orchestrate multiple Stratus Red Team techniques to simulate realistic attack chains. These scenarios are designed for comprehensive end-to-end testing of detection engineering pipelines.

## Available Scenarios

### IAM-to-S3 Training Data Exfiltration (`iam-to-s3-training-data/`)

**Attack Chain:**
1. **Persistence** - `aws.persistence.iam-backdoor-user`
2. **Defense Evasion** - `aws.exfiltration.s3-backdoor-bucket-policy`
3. **Discovery & Attempted Exfiltration** - Custom S3 operations using backdoor credentials
4. **Discovery** - Cross-region EC2 reconnaissance

### EC2 Credential Harvesting to Secrets Exfiltration (`ec2-secrets-harvest/`)

**Attack Chain:**
1. **Credential Access** - `aws.credential-access.ec2-steal-instance-credentials`
   - Compromises EC2 instance credentials via metadata service access
   - Simulates SSRF vulnerability, container escape, or insider threat
   - Captures temporary AWS credentials (access key, secret key, session token)

2. **Discovery** - Multi-region secrets enumeration
   - Uses harvested EC2 credentials to scan 5 AWS regions
   - Lists all secrets in Secrets Manager across regions (`ListSecrets`)
   - Identifies high-value targets (database passwords, API keys, certificates)
   - Demonstrates cross-region reconnaissance and credential abuse

3. **Credential Access** - `aws.credential-access.secretsmanager-batch-retrieve-secrets`
   - Attempts bulk retrieval of secrets using compromised EC2 credentials
   - Targets high-value secrets identified in discovery phase
   - Generates multiple `GetSecretValue` operations for detection testing

4. **Defense Evasion** - `aws.defense-evasion.cloudtrail-stop`
   - Attempts to disable CloudTrail logging to cover attack tracks
   - Demonstrates post-compromise defense evasion behavior
   - **Expected to fail** if proper IAM restrictions are in place

**Execution Order:**
1. Cleanup existing EC2 credential technique state (if any)
2. Warmup `aws.credential-access.ec2-steal-instance-credentials` (creates EC2 instance)
3. Detonate `aws.credential-access.ec2-steal-instance-credentials` (harvests credentials)
4. Parse output to extract harvested credentials (access key, secret key, session token)
5. **Multi-region Discovery**: Use harvested credentials to enumerate secrets across 5 regions
6. **Target Identification**: Identify high-value secrets (prod, database, api-key patterns)
7. **Bulk Retrieval**: Attempt batch secret retrieval using harvested credentials
8. **Defense Evasion**: Try to disable CloudTrail logging to cover tracks
9. Cleanup techniques when user confirms

**Detection Opportunities:**
- EC2 instance metadata service abuse patterns
- Cross-region `ListSecrets` operations from EC2 credentials
- Bulk `GetSecretValue` operations in short timeframes
- `StopLogging` CloudTrail events from compromised credentials
- Unusual Secrets Manager access patterns from EC2 instance roles
- Time correlation between credential theft → discovery → bulk retrieval → evasion
- Geographic anomalies (same credentials across multiple regions rapidly)
- Failed secret access attempts (realistic permission boundaries)
- EC2 credential context violations (instance credentials used outside expected scope)

**Usage:**
```bash
cd scenarios/
go build -o iam-s3-scenario iam-to-s3-training-data/main.go
./iam-s3-scenario

# Or run directly
go run iam-to-s3-training-data/main.go
```

```bash
cd scenarios/
go build -o ec2-secrets-scenario ec2-secrets-harvest/main.go
./ec2-secrets-scenario

# Or run directly
go run ec2-secrets-harvest/main.go
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

# Build and run specific scenarios
make iam-to-s3-training-data
./iam-s3-scenario

make ec2-secrets-harvest
./ec2-secrets-scenario

# Or run directly without building
go run iam-to-s3-training-data/main.go
go run ec2-secrets-harvest/main.go

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