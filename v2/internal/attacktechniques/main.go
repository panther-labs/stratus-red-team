package attacktechniques

import (
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/aws/credential-access/ec2-get-password-data"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/aws/credential-access/ec2-steal-instance-credentials"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/aws/credential-access/secretsmanager-batch-retrieve-secrets"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/aws/credential-access/secretsmanager-retrieve-secrets"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/aws/credential-access/ssm-retrieve-securestring-parameters"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/aws/defense-evasion/bedrock-model-invocation-logging-delete"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/aws/defense-evasion/cloudtrail-delete"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/aws/defense-evasion/cloudtrail-event-selectors"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/aws/defense-evasion/cloudtrail-lifecycle-rule"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/aws/defense-evasion/cloudtrail-stop"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/aws/defense-evasion/dns-delete-logs"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/aws/defense-evasion/organizations-leave"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/aws/defense-evasion/vpc-remove-flow-logs"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/aws/discovery/ec2-enumerate-from-instance"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/aws/discovery/ec2-get-user-data"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/aws/discovery/ses-enumerate"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/aws/execution/ec2-launch-unusual-instances"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/aws/execution/ec2-user-data"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/aws/execution/ssm-send-command"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/aws/execution/ssm-start-session"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/aws/exfiltration/ec2-security-group-open-port-22-ingress"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/aws/exfiltration/ec2-share-ami"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/aws/exfiltration/ec2-share-ebs-snapshot"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/aws/exfiltration/rds-share-snapshot"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/aws/exfiltration/s3-backdoor-bucket-policy"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/aws/impact/bedrock-invoke-model"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/aws/impact/s3-ransomware-batch-deletion"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/aws/impact/s3-ransomware-client-side-encryption"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/aws/impact/s3-ransomware-individual-deletion"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/aws/initial-access/console-login-without-mfa"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/aws/lateral-movement/ec2-send-serial-console-send-ssh-public-key"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/aws/lateral-movement/ec2-send-ssh-public-key"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/aws/persistence/iam-backdoor-role"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/aws/persistence/iam-backdoor-user"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/aws/persistence/iam-create-admin-user"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/aws/persistence/iam-create-backdoor-role"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/aws/persistence/iam-create-user-login-profile"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/aws/persistence/lambda-backdoor-function"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/aws/persistence/lambda-layer-extension"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/aws/persistence/lambda-overwrite-code"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/aws/persistence/rolesanywhere-create-trust-anchor"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/aws/persistence/sts-federation-token"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/aws/privilege-escalation/change-iam-user-password"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/azure/execution/vm-custom-script-extension"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/azure/execution/vm-run-command"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/azure/exfiltration/disk-export"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/azure/persistence/create-bastion-shareable-link"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/eks/lateral-movement/create-access-entry"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/eks/persistence/backdoor-aws-auth-configmap"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/entra-id/persistence/backdoor-application"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/entra-id/persistence/backdoor-application-sp"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/entra-id/persistence/guest-user"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/entra-id/persistence/hidden-au"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/entra-id/persistence/new-application"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/entra-id/persistence/restricted-au"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/gcp/credential-access/secretmanager-retrieve-secrets"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/gcp/exfiltration/share-compute-disk"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/gcp/exfiltration/share-compute-image"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/gcp/exfiltration/share-compute-snapshot"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/gcp/persistence/backdoor-service-account-policy"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/gcp/persistence/create-admin-service-account"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/gcp/persistence/create-service-account-key"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/gcp/persistence/invite-external-user"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/gcp/privilege-escalation/impersonate-service-accounts"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/k8s/credential-access/dump-secrets"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/k8s/credential-access/steal-serviceaccount-token"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/k8s/persistence/create-admin-clusterrole"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/k8s/persistence/create-client-certificate"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/k8s/persistence/create-token"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/k8s/privilege-escalation/hostpath-volume"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/k8s/privilege-escalation/nodes-proxy"
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques/k8s/privilege-escalation/privileged-pod"
)
