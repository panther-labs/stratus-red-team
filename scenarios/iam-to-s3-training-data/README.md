# IAM-to-S3 Training Data Exfiltration Scenario

Multi-stage attack scenario demonstrating persistence establishment, discovery operations, attempted data exfiltration, and cross-region reconnaissance.

## Prerequisites & Setup

### Step 1: Create Independent IAM User (Manual Setup)
Before running the main scenario, create an IAM user independently from your SSO session to simulate a more realistic attack:

```bash
cd scenarios/iam-to-s3-training-data/iam-create-log-forwarder
go mod tidy

# Create log forwarder IAM user with access keys
go run main.go detonate
```

This creates:
- IAM user: `log-forwarder`
- Permissions: S3 Full Access + ReadOnly Access (other services)
- Realistic tags: `Purpose: LogForwarding`, `Team: Infrastructure`
- **No stratus-red-team identifiers**
- **Save the Access Key ID and Secret Access Key** - you'll need these for the main scenario

### Step 2: Wait (Optional - for realism)
Real attackers wait between initial compromise and exploitation. Consider waiting 30+ minutes between Step 1 and Step 3.

### Step 3: Run Main Attack Scenario
Use ONLY the created IAM credentials (not your SSO session) for the main scenario.

## Attack Flow

1. **Persistence** - Independent IAM user creation
   - Creates IAM user `log-forwarder` with realistic tags
   - Attaches S3FullAccess and ReadOnlyAccess policies
   - Generates access key for the user
   - **No stratus identifiers or tags**
   
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

### Option 1: Using the new scenario commands (Recommended)
```bash
# Build the stratus binary first
make build

# Run the complete scenario (includes all stages)
./bin/stratus scenario detonate iam-to-s3-training-data

# Clean up when done
./bin/stratus scenario cleanup iam-to-s3-training-data
```

### Option 2: Direct execution
```bash
cd scenarios/iam-to-s3-training-data
go run main.go
```

## Clean Up

### Main Scenario Cleanup
The scenario offers cleanup options at the end, or use:
```bash
./bin/stratus scenario cleanup iam-to-s3-training-data
```

### Independent IAM User Cleanup
Clean up the manually created log forwarder IAM user:
```bash
cd scenarios/iam-to-s3-training-data/iam-create-log-forwarder
go run main.go revert
```

## Detection Opportunities

### Expected Panther Rule Triggers

Based on the `log-forwarder` IAM user's permissions (S3FullAccess + ReadOnlyAccess) and scenario activities, these Panther rules should trigger:

#### High Priority Triggers
1. **`AWS.IAM.CreateUser.Demo`** - IAM User Created
   - **Trigger**: Creating the `log-forwarder` IAM user
   - **Why**: Detects any IAM user creation (policy: only IAM roles should be used)
   - **Context**: User created with business tags (`Purpose: LogForwarding`, `Team: Infrastructure`)

2. **`aws_iam_user_key_created_demo.py`** - IAM Access Key Created
   - **Trigger**: Creating access keys for `log-forwarder` user
   - **Why**: Detects when access keys are created for IAM users
   - **Context**: Should capture the access key ID and show it was created by your SSO session

3. **`aws_s3_access_to_training_data_demo.py`** - S3 Training Data Access
   - **Trigger**: Any attempts to access training data buckets
   - **Why**: Monitors access to sensitive ML training datasets
   - **Context**: Should trigger on `ListBuckets` and any access to buckets with "training-data" in name

#### Medium Priority Triggers
4. **`AWS S3 Large Download`** (Scheduled Query) - Bulk Data Access
   - **Trigger**: High-volume S3 operations during discovery phase
   - **Why**: Detects unusual data access patterns
   - **Context**: May trigger on multiple `ListBuckets`/`ListObjectsV2` operations

5. **S3 Bucket Policy Changes** - Defense Evasion Detection
   - **Trigger**: `PutBucketPolicy` events from S3 backdoor technique
   - **Why**: Detects unauthorized bucket policy modifications
   - **Context**: Should show policy changes allowing external account access

#### Behavioral Detections
6. **Cross-Region Activity Patterns**
   - **Trigger**: `DescribeInstances` calls across multiple US regions
   - **Why**: Unusual geographic access patterns from single credential
   - **Context**: Rapid API calls across us-east-1, us-east-2, us-west-1, us-west-2

7. **Permission Boundary Violations**
   - **Trigger**: Failed S3 operations due to insufficient permissions
   - **Why**: Attempts to access resources beyond granted permissions
   - **Context**: Expected failures when trying to copy training data

### Detection Timeline
```
Time 0:    IAM User Creation → AWS.IAM.CreateUser.Demo
Time +30s: Access Key Creation → aws_iam_user_key_created_demo
Time +60s: S3 Discovery → aws_s3_access_to_training_data_demo
Time +90s: Cross-Region EC2 → Geographic anomaly detection
Time +120s: Failed Operations → Permission boundary alerts
```

### Rule Customization Notes
- **False Positive Reduction**: Rules may need tuning for legitimate `log-forwarder` service accounts
- **Tag-Based Filtering**: Consider excluding accounts with `Purpose: LogForwarding` tags from high-severity alerts
- **Time Correlation**: Most effective when rules correlate the full attack chain progression
- **Scoped Permissions**: Unlike full admin users, this account's limited permissions create realistic detection boundaries

## Detection Improvements

This approach provides better detection testing by:

1. **Session Separation**: IAM user creation happens independently from main attack activities
2. **Realistic Timing**: Optional delays between compromise and exploitation
3. **Clean Attribution**: No stratus-red-team identifiers in logs
4. **Realistic Tags**: Uses business-appropriate tags (`Purpose: LogForwarding`, `Team: Infrastructure`)
5. **Scoped Permissions**: S3FullAccess + ReadOnlyAccess (more realistic than full admin)
6. **Simple Execution**: Single command execution mimicking stratus technique patterns
7. **Consistent Naming**: Uses `log-forwarder` for realistic service account naming

## System Requirements

- AWS credentials configured (`aws configure` or environment variables)
- Appropriate AWS permissions for IAM and S3 operations
- Isolated test AWS account (recommended)
- Go 1.22+ installed