package main

import (
	"context"
	"errors"
	"log"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

var userName = aws.String("log-forwarder")
var s3PolicyArn = aws.String("arn:aws:iam::aws:policy/AmazonS3FullAccess")
var readOnlyPolicyArn = aws.String("arn:aws:iam::aws:policy/ReadOnlyAccess")

func main() {
	if len(os.Args) < 2 {
		log.Println("Usage: go run main.go [detonate|revert]")
		log.Println("  detonate - Create log forwarder IAM user with S3 and ReadOnly access")
		log.Println("  revert   - Clean up all resources")
		os.Exit(1)
	}

	command := os.Args[1]
	switch command {
	case "detonate":
		log.Println("Starting detonation phase...")
		if err := detonate(); err != nil {
			log.Fatalf("Detonation failed: %v", err)
		}
	case "revert":
		log.Println("Starting cleanup...")
		if err := revert(); err != nil {
			log.Fatalf("Cleanup failed: %v", err)
		}
		log.Println("Cleanup completed successfully")
	default:
		log.Printf("Unknown command: %s", command)
		os.Exit(1)
	}
}

func detonate() error {
	// Load AWS config
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		return err
	}

	iamClient := iam.NewFromConfig(cfg)

	log.Println("Creating log forwarder IAM user")
	_, err = iamClient.CreateUser(context.Background(), &iam.CreateUserInput{
		UserName: userName,
		Tags: []types.Tag{
			{Key: aws.String("Purpose"), Value: aws.String("LogForwarding")},
			{Key: aws.String("Team"), Value: aws.String("Infrastructure")},
		},
	})
	if err != nil {
		return err
	}

	log.Println("Attaching S3 Full Access policy to the log forwarder user")
	_, err = iamClient.AttachUserPolicy(context.Background(), &iam.AttachUserPolicyInput{
		UserName:  userName,
		PolicyArn: s3PolicyArn,
	})
	if err != nil {
		return err
	}

	log.Println("Attaching ReadOnly Access policy to the log forwarder user")
	_, err = iamClient.AttachUserPolicy(context.Background(), &iam.AttachUserPolicyInput{
		UserName:  userName,
		PolicyArn: readOnlyPolicyArn,
	})
	if err != nil {
		return err
	}

	log.Println("Creating an access key for the log forwarder user")
	result, err := iamClient.CreateAccessKey(context.Background(), &iam.CreateAccessKeyInput{
		UserName: userName,
	})
	if err != nil {
		return err
	}

	log.Println("Created access key ID: " + *result.AccessKey.AccessKeyId)
	log.Println("Secret access key: " + *result.AccessKey.SecretAccessKey)

	return nil
}

func revert() error {
	// Load AWS config
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		return err
	}

	iamClient := iam.NewFromConfig(cfg)

	result, err := iamClient.ListAccessKeys(context.Background(), &iam.ListAccessKeysInput{
		UserName: userName,
	})
	if err != nil {
		return errors.New("unable to clean up IAM user access keys: " + err.Error())
	}

	for i := range result.AccessKeyMetadata {
		accessKeyId := result.AccessKeyMetadata[i].AccessKeyId
		_, err := iamClient.DeleteAccessKey(context.Background(), &iam.DeleteAccessKeyInput{
			UserName:    userName,
			AccessKeyId: accessKeyId,
		})
		if err != nil {
			return errors.New("unable to remove IAM user access key " + *accessKeyId + ": " + err.Error())
		}
		log.Println("Removed access key " + *accessKeyId)
	}

	log.Println("Detaching S3 Full Access policy")
	_, err = iamClient.DetachUserPolicy(context.Background(), &iam.DetachUserPolicyInput{
		UserName:  userName,
		PolicyArn: s3PolicyArn,
	})
	if err != nil {
		return err
	}

	log.Println("Detaching ReadOnly Access policy")
	_, err = iamClient.DetachUserPolicy(context.Background(), &iam.DetachUserPolicyInput{
		UserName:  userName,
		PolicyArn: readOnlyPolicyArn,
	})
	if err != nil {
		return err
	}

	log.Println("Removing log forwarder IAM user")
	_, err = iamClient.DeleteUser(context.Background(), &iam.DeleteUserInput{UserName: userName})
	return err
}
