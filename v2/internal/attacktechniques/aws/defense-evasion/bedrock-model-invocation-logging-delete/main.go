package aws

import (
	"context"
	_ "embed"
	"errors"
	"log"

	"github.com/aws/aws-sdk-go-v2/service/bedrock"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
)

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:                 "aws.defense-evasion.bedrock-model-invocation-logging-delete",
		FriendlyName:       "Delete Bedrock Model Invocation Logging",
		Platform:           stratus.AWS,
		MitreAttackTactics: []mitreattack.Tactic{mitreattack.DefenseEvasion},
		Description: `
Delete Amazon Bedrock model invocation logging configuration. Simulates an attacker disrupting AI activity monitoring.

Warm-up: 

- Create a Bedrock model invocation logging configuration.

Detonation: 

- Delete the Bedrock model invocation logging configuration.
`,
		Detection: `
Identify when Bedrock model invocation logging is deleted, through CloudTrail's <code>DeleteModelInvocationLogging</code> event.
`,
		IsIdempotent:               false, // can't delete logging config twice
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
	})
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	bedrockClient := bedrock.NewFromConfig(providers.AWS().GetConnection())
	loggingConfigID := params["bedrock_logging_config_id"]

	log.Println("Deleting Bedrock model invocation logging configuration " + loggingConfigID)

	_, err := bedrockClient.DeleteModelInvocationLoggingConfiguration(context.Background(), &bedrock.DeleteModelInvocationLoggingConfigurationInput{})

	if err != nil {
		return errors.New("unable to delete Bedrock model invocation logging configuration: " + err.Error())
	}

	return nil
}
