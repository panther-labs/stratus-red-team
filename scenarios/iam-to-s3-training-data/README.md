# IAM-to-S3 Training Data Exfiltration Scenario

Multi-stage attack scenario demonstrating persistence establishment, discovery operations, attempted data exfiltration, and cross-region reconnaissance.

## Attack Flow

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

## Usage

```bash
cd scenarios/
go build -o iam-s3-scenario iam-to-s3-training-data/main.go
./iam-s3-scenario
```

## Detection Opportunities

- **IAM Events**: `CreateAccessKey` CloudTrail events from unusual contexts
- **S3 Policy Changes**: `PutBucketPolicy` events that modify bucket permissions  
- **Discovery Operations**: `ListBuckets` operations for account-wide S3 discovery
- **Reconnaissance Patterns**: `ListObjectsV2` operations against multiple buckets
- **Failed Exfiltration**: `CopyObject` attempts indicating data exfiltration (will fail due to permissions)
- **Cross-Region Activity**: `DescribeInstances` operations across multiple regions
- **Geographic Patterns**: Rapid successive API calls across geographic regions from same credential
- **Permission Failures**: Failed S3 operations due to insufficient permissions (Access Denied patterns)
- **Time Correlation**: IAM key creation → S3 discovery → EC2 reconnaissance progression

## Prerequisites

- AWS credentials configured (`aws configure` or environment variables)
- Appropriate AWS permissions for IAM and S3 operations
- Isolated test AWS account (recommended)
- Go 1.22+ installed

## Clean Up

The scenario automatically cleans up all created resources when you press Enter at the end. Resources include:
- IAM user and access keys
- S3 bucket and bucket policy
- No persistent infrastructure remains