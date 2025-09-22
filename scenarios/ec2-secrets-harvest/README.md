# EC2 Credential Harvesting to Secrets Exfiltration Scenario

This scenario simulates a multi-stage attack chain where an attacker compromises EC2 instance credentials and uses them for secrets discovery and bulk exfiltration across multiple AWS regions.

## Attack Chain Overview

### Stage 1: EC2 Credential Harvesting
- **Technique**: `aws.credential-access.ec2-steal-instance-credentials`
- **Simulation**: Compromises EC2 instance credentials via metadata service access
- **Real-world context**: SSRF vulnerability, container escape, or insider threat
- **Generated logs**: Instance metadata access, credential exposure

### Stage 2: Multi-region Secrets Discovery
- **Custom operation**: Cross-region Secrets Manager enumeration
- **Uses harvested credentials** to list secrets across 5 AWS regions
- **Identifies high-value targets**: Secrets containing "prod", "database", "api-key", "password"
- **Generated logs**: `ListSecrets` operations across multiple regions from EC2 credentials

### Stage 3: Bulk Secrets Retrieval
- **Technique**: `aws.credential-access.secretsmanager-batch-retrieve-secrets` (fallback to manual)
- **Attempts bulk secret harvesting** using compromised credentials
- **Targets high-value secrets** identified in discovery phase
- **Generated logs**: Multiple `GetSecretValue` operations, bulk access patterns

### Stage 4: Defense Evasion
- **Technique**: `aws.defense-evasion.cloudtrail-stop`
- **Attempts to disable CloudTrail logging** to cover attack tracks
- **Real-world behavior**: Post-compromise defense evasion
- **Generated logs**: `StopLogging` CloudTrail operations

## Execution Flow

```bash
# Run the scenario
cd scenarios/ec2-secrets-harvest/
go run main.go

# Or build first
go build -o ec2-secrets-scenario main.go
./ec2-secrets-scenario
```

## Detection Opportunities

### Primary Detection Patterns
- **EC2 Instance Metadata Abuse**: Unusual metadata service access patterns
- **Cross-region Enumeration**: `ListSecrets` operations from EC2 credentials across multiple regions
- **Bulk Secret Access**: High-frequency `GetSecretValue` operations in short timeframe
- **CloudTrail Tampering**: `StopLogging` attempts from compromised credentials
- **Credential Context Anomaly**: EC2 instance credentials used outside expected patterns

### Time-based Correlations
- Credential theft → Multi-region discovery → Bulk retrieval → Defense evasion
- Rapid successive API calls across geographic regions from same credential set
- Unusual access patterns from EC2 instance roles to Secrets Manager

### Advanced Detection Logic
```sql
-- Example Panther detection for cross-region secrets enumeration
SELECT *
FROM aws_cloudtrail_logs
WHERE
  eventName = 'ListSecrets'
  AND sourceIPAddress LIKE '10.%'  -- EC2 internal IP
  AND COUNT(DISTINCT awsRegion) > 2  -- Multiple regions
  AND timeframe < 300  -- Within 5 minutes
```

## Prerequisites

### Infrastructure Requirements

**The scenario automatically provisions all required infrastructure:**

1. **VPC and Networking**:
   - New VPC (`10.0.0.0/16`) with public and private subnets
   - NAT Gateway for outbound internet access from private subnet
   - Network interface with static private IP (`10.0.1.10`)

2. **EC2 Instance**:
   - Amazon Linux 2 AMI (`t3.micro` instance type)
   - Deployed in private subnet for security
   - Configured with SSM agent for remote command execution

3. **IAM Resources**:
   - EC2 instance role with `ec2:Describe*` permissions
   - Instance profile attached to EC2 instance
   - `AmazonSSMManagedInstanceCore` policy for SSM connectivity

**No pre-existing EC2 infrastructure required** - the `warmup` phase creates everything needed.

### Software Prerequisites

- AWS credentials configured with appropriate permissions:
  - `ec2:*` for instance and VPC management
  - `iam:*` for role and policy creation
  - `ssm:*` for remote command execution
  - `secretsmanager:*` for secrets operations
- Stratus Red Team binary built (`make build` from project root)
- Go 1.22+ for direct execution

### Time Requirements

- **Warmup**: ~3-5 minutes (EC2 instance provisioning + SSM registration)
- **Execution**: ~2-3 minutes (credential theft + multi-region discovery)
- **Cleanup**: ~2-3 minutes (resource deletion)

## Expected Behavior

### Successful Operations
- EC2 instance credential harvesting
- Multi-region secrets discovery (ListSecrets)
- Some secret retrieval attempts (depending on permissions)
- CloudTrail tampering attempts

### Expected Failures
- Most GetSecretValue operations (insufficient permissions)
- CloudTrail stopping (if proper IAM restrictions in place)

These failures are **realistic and expected** - they demonstrate how proper IAM controls limit attack impact while still generating valuable detection telemetry.

## Integration with Panther

This scenario generates authentic AWS CloudTrail logs that test multiple detection layers:

1. **Infrastructure Security**: EC2 metadata abuse detection
2. **Data Security**: Secrets Manager access anomaly detection
3. **Cross-service Correlation**: EC2 credentials → Secrets Manager access patterns
4. **Defense Evasion**: CloudTrail tampering detection
5. **Geographic Analysis**: Multi-region access pattern detection

## Cleanup

The scenario automatically cleans up resources after execution. For manual cleanup:

```bash
# Clean up all techniques used in the scenario
../bin/stratus cleanup aws.credential-access.ec2-steal-instance-credentials
../bin/stratus cleanup aws.credential-access.secretsmanager-batch-retrieve-secrets
../bin/stratus cleanup aws.defense-evasion.cloudtrail-stop
```

## Customization

### Modify Target Regions
Edit the `targetRegions` array in `performSecretsDiscovery()` to focus on your organization's primary AWS regions.

### Adjust High-value Secret Patterns
Update the string matching in `performSecretsDiscovery()` to match your organization's secret naming conventions.

### Add Custom Detection Points
Insert additional logging or API calls to test specific detection rules in your environment.

## Security Notes

- Run in isolated AWS accounts only
- Monitor CloudTrail during execution to verify log generation
- This scenario uses authentic AWS APIs and generates real audit logs
- Resource cleanup is automated but should be verified post-execution