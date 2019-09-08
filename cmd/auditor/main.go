package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/dlabey/iam-git-auditor/pkg/cloudtrail"
	"github.com/dlabey/iam-git-auditor/pkg/utils"
	"gopkg.in/src-d/go-git.v4"
	"gopkg.in/src-d/go-git.v4/plumbing/object"
	"gopkg.in/src-d/go-git.v4/plumbing/transport"
	"gopkg.in/src-d/go-git.v4/plumbing/transport/http"
	"log"
	"os"
	"strings"
	"time"
)

type Response struct {
	Added   int
	Removed int
	Ignored int
}

func parsePolicyName(policyArn string) string {
	segments := strings.Split(policyArn, "/")

	return segments[len(segments)-1]
}

// Audits the intended records in sequence for each to be a single Git commit for the right datetime.
func Auditor(ctx context.Context, evt events.SQSEvent, gitAuth transport.AuthMethod, gitRepo Repository,
	gitWorktree Worktree, iamSvc iamiface.IAMAPI) (*Response, error) {
	// Assign common constants.
	const AttachedPoliciesDirName = "attachedPolicies"
	const PoliciesDirName = "policies"
	const RolesDirName = "roles"

	// Instantiate the response.
	response := &Response{}

	// Handle the event and commit it to the Git work tree.
	validEvent := true
	for i := 0; i < len(evt.Records); i++ {
		var cloudTrailEvt cloudtrail.CloudTrailEvent
		err := json.Unmarshal([]byte(evt.Records[i].Body), &cloudTrailEvt)
		utils.CheckError(err, fmt.Sprintf("Error unmarshalling CloudTrail event: %s", err))
		eventName := cloudTrailEvt.EventName
		switch eventName {
		case "AttachRolePolicy":
			roleDir := os.TempDir() + "/" + RolesDirName + "/" + cloudTrailEvt.RequestParameters.RoleName
			attachedPolicyFile := roleDir + "/" + AttachedPoliciesDirName + "/" + cloudTrailEvt.RequestParameters.PolicyName
			attachedPolicyFileHandle, err := os.OpenFile(attachedPolicyFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			utils.CheckError(err, fmt.Sprintf("Error opening attached policy file: %s", err))
			_, err = attachedPolicyFileHandle.WriteString(cloudTrailEvt.RequestParameters.PolicyArn)
			utils.CheckError(err, fmt.Sprintf("Error appending attached policy file: %s", err))
			err = attachedPolicyFileHandle.Close()
			utils.CheckError(err, fmt.Sprintf("Error closing attached policy file: %s", err))
			_, err = gitWorktree.Add(attachedPolicyFile)
			utils.CheckError(err, fmt.Sprintf("Error adding attached policy file to Git work tree: %s", err))
			response.Added++
		case "CreatePolicy":
			policyFile := os.TempDir() + "/" + PoliciesDirName + "/" + cloudTrailEvt.RequestParameters.PolicyName
			policyFileHandle, err := os.Create(policyFile)
			utils.CheckError(err, fmt.Sprintf("Error creating policy file: %s", err))
			_, err = policyFileHandle.WriteString(cloudTrailEvt.RequestParameters.PolicyDocument)
			utils.CheckError(err, fmt.Sprintf("Error writing policy file: %s", err))
			err = policyFileHandle.Close()
			utils.CheckError(err, fmt.Sprintf("Error closing policy file: %s", err))
			_, err = gitWorktree.Add(policyFile)
			utils.CheckError(err, fmt.Sprintf("Error adding policy file to Git work tree: %s", err))
			response.Added++
		case "CreatePolicyVersion":
			policyFile := os.TempDir() + "/" + PoliciesDirName + "/" + cloudTrailEvt.RequestParameters.PolicyName
			policyFileHandle, err := os.OpenFile(policyFile, os.O_WRONLY, 0644)
			utils.CheckError(err, fmt.Sprintf("Error opening policy file: %s", err))
			err = policyFileHandle.Truncate(0)
			utils.CheckError(err, fmt.Sprintf("Error truncating policy file: %s", err))
			_, err = policyFileHandle.Seek(0, 0)
			utils.CheckError(err, fmt.Sprintf("Error seeking policy file: %s", err))
			_, err = policyFileHandle.WriteString(cloudTrailEvt.RequestParameters.PolicyDocument)
			utils.CheckError(err, fmt.Sprintf("Error writing policy file: %s", err))
			_, err = gitWorktree.Add(policyFile)
			utils.CheckError(err, fmt.Sprintf("Error adding policy file to Git work tree: %s", err))
			response.Added++
		case "CreateRole":
			roleDir := os.TempDir() + "/" + RolesDirName + "/" + cloudTrailEvt.RequestParameters.RoleName
			err = os.Mkdir(roleDir, os.ModeDir)
			utils.CheckError(err, fmt.Sprintf("Error creating role directory: %s", err))
			inlinePolicyFile := roleDir + "/" + cloudTrailEvt.RequestParameters.RoleName
			_, err = os.Create(inlinePolicyFile)
			utils.CheckError(err, fmt.Sprintf("Error creating inline policy file: %s", err))
			_, err = gitWorktree.Add(inlinePolicyFile)
			utils.CheckError(err, fmt.Sprintf("Error adding inline policy file to Git work tree: %s", err))
			response.Added++
		case "DeletePolicy":
			policyName := parsePolicyName(cloudTrailEvt.RequestParameters.PolicyArn)
			utils.CheckError(err, fmt.Sprintf("Error parsing policy arn: %s", err))
			policyFile := os.TempDir() + "/" + PoliciesDirName + "/" + policyName
			_, err = gitWorktree.Remove(policyFile)
			utils.CheckError(err, fmt.Sprintf("Error removing policy file from Git work tree: %s", err))
			response.Removed++
		case "DeleteRole":
			roleDir := os.TempDir() + "/" + RolesDirName + "/" + cloudTrailEvt.RequestParameters.RoleName
			_, err = gitWorktree.Remove(roleDir)
			utils.CheckError(err, fmt.Sprintf("Error removing role directory from Git work tree: %s", err))
			response.Removed++
		case "DeleteRolePolicy":
			roleDir := os.TempDir() + "/" + RolesDirName + "/" + cloudTrailEvt.RequestParameters.RoleName
			inlinePolicyFile := os.TempDir() + "/" + roleDir + "/_inline"
			_, err = gitWorktree.Remove(inlinePolicyFile)
			utils.CheckError(err, fmt.Sprintf("Error removing inline policy from Git work tree: %s", err))
			response.Removed++
		case "DetachRolePolicy":
			roleDir := os.TempDir() + "/" + RolesDirName + "/" + cloudTrailEvt.RequestParameters.RoleName
			attachedPolicyFile := os.TempDir() + "/" + roleDir + "/" + AttachedPoliciesDirName + "/" +
				cloudTrailEvt.RequestParameters.PolicyName
			_, err = gitWorktree.Remove(attachedPolicyFile)
			utils.CheckError(err, fmt.Sprintf("Error removing attached policy from Git work tree: %s", err))
			response.Removed++
		case "PutRolePolicy":
			roleDir := os.TempDir() + "/" + RolesDirName + "/" + cloudTrailEvt.RequestParameters.RoleName
			inlinePolicyFile := roleDir + "/_inline"
			inlinePolicyFileHandle, err := os.OpenFile(inlinePolicyFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			utils.CheckError(err, fmt.Sprintf("Error opening inline policy file: %s", err))
			_, err = inlinePolicyFileHandle.WriteString(cloudTrailEvt.RequestParameters.PolicyArn)
			utils.CheckError(err, fmt.Sprintf("Error appending inline policy file: %s", err))
			err = inlinePolicyFileHandle.Close()
			utils.CheckError(err, fmt.Sprintf("Error closing inline policy file: %s", err))
			_, err = gitWorktree.Add(inlinePolicyFile)
			utils.CheckError(err, fmt.Sprintf("Error adding inline policy file to Git work tree: %s", err))
			response.Added++
		case "SetDefaultPolicyVersion":
			policyVersionOutput, err := iamSvc.GetPolicyVersion(&iam.GetPolicyVersionInput{
				PolicyArn: aws.String(cloudTrailEvt.RequestParameters.PolicyArn),
				VersionId: aws.String(cloudTrailEvt.RequestParameters.VersionId),
			})
			utils.CheckError(err, fmt.Sprintf("Error getting policy version output: %s", err))
			policyName := parsePolicyName(cloudTrailEvt.RequestParameters.PolicyName)
			policyFile := os.TempDir() + "/" + PoliciesDirName + "/" + policyName
			policyFileHandle, err := os.OpenFile(policyFile, os.O_WRONLY, 0644)
			utils.CheckError(err, fmt.Sprintf("Error opening policy file: %s", err))
			err = policyFileHandle.Truncate(0)
			utils.CheckError(err, fmt.Sprintf("Error truncating policy file: %s", err))
			_, err = policyFileHandle.Seek(0, 0)
			utils.CheckError(err, fmt.Sprintf("Error seeking policy file: %s", err))
			_, err = policyFileHandle.WriteString(*policyVersionOutput.PolicyVersion.Document)
			utils.CheckError(err, fmt.Sprintf("Error writing policy file: %s", err))
			_, err = gitWorktree.Add(policyFile)
			utils.CheckError(err, fmt.Sprintf("Error adding policy file to Git work tree: %s", err))
			response.Added++
		default:
			validEvent = false
			response.Ignored++
			log.Print("EventName not supported:")
		}

		// Commit the change with the right datetime if a valid event.
		if validEvent {
			when, err := time.Parse(time.RFC3339, cloudTrailEvt.EventTime)
			utils.CheckError(err, fmt.Sprintf("Error parsing time: %s", err))
			commit, err := gitWorktree.Commit(eventName+" by "+cloudTrailEvt.UserIdentity.UserName, &git.CommitOptions{
				Author: &object.Signature{
					Name:  cloudTrailEvt.UserIdentity.UserName,
					Email: "<>",
					When:  when,
				},
			})
			utils.CheckError(err, fmt.Sprintf("Error creating Git work tree commit: %s", err))
			commitLog, err := gitRepo.CommitObject(commit)
			utils.CheckError(err, fmt.Sprintf("Error committing to Git work tree: %s", err))
			log.Println(commitLog)
		}
	}

	// Push all the changes to the remote Git repo.
	err := gitRepo.Push(&git.PushOptions{
		Auth:     gitAuth,
		Progress: os.Stdout,
	})

	return response, err
}

func handler(ctx context.Context, evt events.SQSEvent) (*Response, error) {
	// Initialize an AWS session.
	sess := session.Must(session.NewSession())

	// Initialize the Secrets Manager service.
	secretsManagerSvc := secretsmanager.New(sess)

	// Get the Git repo username.
	gitUsername := os.Getenv("GIT_USERNAME")
	if gitUsername == "" {
		gitUsername = "token"
	}

	// Get the Git repo password or token.
	gitPasswordTokenSecretValue, err := secretsManagerSvc.GetSecretValue(&secretsmanager.GetSecretValueInput{
		SecretId: aws.String(os.Getenv("GitPasswordToken")),
	})
	utils.CheckError(err, fmt.Sprintf("Error getting Git password token from Secrets Manager: %s", err))

	// Initialize the Git auth.
	gitAuth := &http.BasicAuth{
		Username: gitUsername,
		Password: gitPasswordTokenSecretValue.GoString(),
	}

	// Checkout the audit repo.
	gitRepoUrl := os.Getenv("GIT_REPO")
	_, err = git.PlainClone(os.TempDir(), false, &git.CloneOptions{
		Auth:     gitAuth,
		URL:      gitRepoUrl,
		Progress: os.Stdout,
	})
	utils.CheckError(err, fmt.Sprintf("Error cloning Git repo: %s", err))

	// Initialize the Git repo.
	utils.CheckError(err, fmt.Sprintf("Error cloning Git repo: %s", err))
	gitRepo, err := git.PlainOpen(os.TempDir())
	utils.CheckError(err, fmt.Sprintf("Error initializing Git repo: %s", err))

	// Get the Git worktree.
	gitWorkTree, err := gitRepo.Worktree()
	utils.CheckError(err, fmt.Sprintf("Error getting Git repo work tree: %s", err))

	// Initialize the IAM service.
	iamSvc := iam.New(sess)

	return Auditor(ctx, evt, gitAuth, gitRepo, gitWorkTree, iamSvc)
}

func main() {
	lambda.Start(handler)
}
