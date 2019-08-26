package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/joho/godotenv"
	"gopkg.in/src-d/go-git.v4"
	"log"
	"os"
)

func parsePolicyName(policyArn string) (*string, error) {
	return nil, nil
}

func audit(ctx context.Context, evt events.SQSEvent) (*string, error) {
	// Initialize dotenv
	err := godotenv.Load()
	checkError(err, fmt.Sprintf("Error loading .env file: %s", err))

	// Checkout the audit repo
	gitRepoUrl := os.Getenv("GIT_REPO")
	gitRepo, err := git.PlainClone(os.TempDir(), false, &git.CloneOptions{
		URL:      gitRepoUrl,
		Progress: os.Stdout,
	})
	checkError(err, fmt.Sprintf("Error cloning git repo: %s", err))
	workingTree, err := gitRepo.Worktree()
	checkError(err, fmt.Sprintf("Error cloning git repo: %s", err))

	// Audit the intended records in sequence for each to be a single git commit for the right date time
	const AttachedPoliciesDirName = "attachedPolicies"
	const PoliciesDirName = "policies"
	const RolesDirName = "roles"
	for i := 0; i < len(evt.Records); i++ {
		var cloudTrailEvt CloudTrailEvent
		err := json.Unmarshal([]byte(evt.Records[i].Body), &cloudTrailEvt)
		checkError(err, fmt.Sprintf("Error unmarshalling CloudTrail event: %s", err))
		switch eventName := cloudTrailEvt.EventName; eventName {
		case "AttachRolePolicy":
			roleDir := os.TempDir() + "/" + RolesDirName + "/" + cloudTrailEvt.RequestParameters.RoleName
			attachedPolicyFile := roleDir + "/" + AttachedPoliciesDirName + "/" + cloudTrailEvt.RequestParameters.PolicyName
			attachedPolicyFileHandle, err := os.OpenFile(attachedPolicyFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			checkError(err, fmt.Sprintf("Error opening attached policy file: %s", err))
			_, err = attachedPolicyFileHandle.WriteString(cloudTrailEvt.RequestParameters.PolicyArn)
			checkError(err, fmt.Sprintf("Error appending attached policy file: %s", err))
			err = attachedPolicyFileHandle.Close()
			checkError(err, fmt.Sprintf("Error closing attached policy file: %s", err))
			_, err = workingTree.Add(attachedPolicyFile)
			checkError(err, fmt.Sprintf("Error adding attached policy file to working tree: %s", err))
		case "CreatePolicy":
			policyFile := os.TempDir() + "/" + PoliciesDirName + "/" + cloudTrailEvt.RequestParameters.PolicyName
			policyFileHandle, err := os.Create(policyFile)
			checkError(err, fmt.Sprintf("Error creating policy file: %s", err))
			_, err = policyFileHandle.WriteString(cloudTrailEvt.RequestParameters.PolicyDocument)
			checkError(err, fmt.Sprintf("Error writing policy file: %s", err))
			err = policyFileHandle.Close()
			checkError(err, fmt.Sprintf("Error closing policy file: %s", err))
			_, err = workingTree.Add(policyFile)
			checkError(err, fmt.Sprintf("Error adding policy file to working tree: %s", err))
		case "CreatePolicyVersion":
			policyFile := os.TempDir() + "/" + PoliciesDirName + "/" + cloudTrailEvt.RequestParameters.PolicyName
			policyFileHandle, err := os.OpenFile(policyFile, os.O_WRONLY, 0644)
			checkError(err, fmt.Sprintf("Error opening policy file: %s", err))
			err = policyFileHandle.Truncate(0)
			checkError(err, fmt.Sprintf("Error truncating policy file: %s", err))
			_, err = policyFileHandle.Seek(0, 0)
			checkError(err, fmt.Sprintf("Error seeking policy file: %s", err))
			_, err = policyFileHandle.WriteString(cloudTrailEvt.RequestParameters.PolicyDocument)
			checkError(err, fmt.Sprintf("Error writing policy file: %s", err))
			_, err = workingTree.Add(policyFile)
			checkError(err, fmt.Sprintf("Error adding policy file to working tree: %s", err))
		case "CreateRole":
			roleDir := os.TempDir() + "/" + RolesDirName + "/" + cloudTrailEvt.RequestParameters.RoleName
			err = os.Mkdir(roleDir, os.ModeDir)
			checkError(err, fmt.Sprintf("Error creating role directory: %s", err))
			inlinePolicyFile := roleDir + "/" + cloudTrailEvt.RequestParameters.RoleName
			_, err = os.Create(inlinePolicyFile)
			checkError(err, fmt.Sprintf("Error creating inline policy file: %s", err))
			_, err = workingTree.Add(inlinePolicyFile)
			checkError(err, fmt.Sprintf("Error adding inline policy file to working tree: %s", err))
		case "DeletePolicy":
			policyName, err := parsePolicyName(cloudTrailEvt.RequestParameters.PolicyArn)
			checkError(err, fmt.Sprintf("Error parsing policy arn: %s", err))
			policyFile := os.TempDir() + "/" + PoliciesDirName + "/" + *policyName
			_, err = workingTree.Remove(policyFile)
			checkError(err, fmt.Sprintf("Error removing policy file from working tree: %s", err))
		case "DeleteRole":
			roleDir := os.TempDir() + "/" + RolesDirName + "/" + cloudTrailEvt.RequestParameters.RoleName
			_, err = workingTree.Remove(roleDir)
			checkError(err, fmt.Sprintf("Error removing role directory from working tree: %s", err))
		case "DeleteRolePolicy":
			roleDir := os.TempDir() + "/" + RolesDirName + "/" + cloudTrailEvt.RequestParameters.RoleName
			inlinePolicyFile := os.TempDir() + "/" + roleDir + "/_inline"
			_, err = workingTree.Remove(inlinePolicyFile)
			checkError(err, fmt.Sprintf("Error removing inline policy from working tree: %s", err))
		case "DetachRolePolicy":
			roleDir := os.TempDir() + "/" + RolesDirName + "/" + cloudTrailEvt.RequestParameters.RoleName
			attachedPolicyFile := os.TempDir() + "/" + roleDir + "/" + AttachedPoliciesDirName + "/" +
				cloudTrailEvt.RequestParameters.PolicyName
			_, err = workingTree.Remove(attachedPolicyFile)
			checkError(err, fmt.Sprintf("Error removing attached policy from working tree: %s", err))
		case "PutRolePolicy":
			roleDir := os.TempDir() + "/" + RolesDirName + "/" + cloudTrailEvt.RequestParameters.RoleName
			inlinePolicyFile := roleDir + "/_inline"
			inlinePolicyFileHandle, err := os.OpenFile(inlinePolicyFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			checkError(err, fmt.Sprintf("Error opening inline policy file: %s", err))
			_, err = inlinePolicyFileHandle.WriteString(cloudTrailEvt.RequestParameters.PolicyArn)
			checkError(err, fmt.Sprintf("Error appending inline policy file: %s", err))
			err = inlinePolicyFileHandle.Close()
			checkError(err, fmt.Sprintf("Error closing inline policy file: %s", err))
			_, err = workingTree.Add(inlinePolicyFile)
			checkError(err, fmt.Sprintf("Error adding inline policy file to working tree: %s", err))
		case "SetDefaultPolicyVersion":
			// get policy via GetPolicyVersion by cloudTrailEvt.RequestParameters.PolicyArn and cloudTrailEvt.RequestParameters.VersionId
			// set contents of file to PolicyVersion.Document
		default:
			log.Print("EventName not supported:")
		}
	}

	// Push all the changes to the remote Git repo

	return nil, nil
}

func main() {
	lambda.Start(audit)
}
