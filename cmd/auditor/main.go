package main

import (
	"context"
	"encoding/json"
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
	for i := 0; i < len(evt.Records); i++ {
		var cloudTrailEvt cloudtrail.CloudTrailEvent
		err := json.Unmarshal([]byte(evt.Records[i].Body), &cloudTrailEvt)
		utils.CheckError(err, "msg=\"Error unmarshalling CloudTrail event\" err=\"%s\"")
		log.Printf("msg=\"Auditing CloudTrail event\" eventName=%s", cloudTrailEvt.EventName)
		eventName := cloudTrailEvt.EventName
		validEvent := true
		switch eventName {
		case "AttachRolePolicy":
			roleDir := os.TempDir() + "/" + RolesDirName + "/" + cloudTrailEvt.RequestParameters.RoleName
			attachedPolicyFile := roleDir + "/" + AttachedPoliciesDirName + "/" + cloudTrailEvt.RequestParameters.PolicyName
			attachedPolicyFileHandle, err := os.OpenFile(attachedPolicyFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			utils.CheckError(err, "msg=\"Error opening attached policy file\" err=\"%s\"")
			_, err = attachedPolicyFileHandle.WriteString(cloudTrailEvt.RequestParameters.PolicyArn)
			utils.CheckError(err, "msg=\"Error appending attached policy file\" err=\"%s\"")
			err = attachedPolicyFileHandle.Close()
			utils.CheckError(err, "msg=\"Error closing attached policy file\" err=\"%s\"")
			_, err = gitWorktree.Add(attachedPolicyFile)
			utils.CheckError(err, "msg=\"Error adding attached policy file to Git work tree\" err=\"%s\"")
			log.Printf("msg=\"Git Add\" file=\"%s\"", attachedPolicyFile)
			response.Added++
		case "CreatePolicy":
			policyFile := os.TempDir() + "/" + PoliciesDirName + "/" + cloudTrailEvt.RequestParameters.PolicyName
			policyFileHandle, err := os.Create(policyFile)
			utils.CheckError(err, "msg=\"Error creating policy file\" err=\"%s\"")
			_, err = policyFileHandle.WriteString(cloudTrailEvt.RequestParameters.PolicyDocument)
			utils.CheckError(err, "msg=\"Error writing policy file\" err=\"%s\"")
			err = policyFileHandle.Close()
			utils.CheckError(err, "msg=\"Error closing policy file\" err=\"%s\"")
			_, err = gitWorktree.Add(policyFile)
			utils.CheckError(err, "msg=\"Error adding policy file to Git work tree\" err=\"%s\"")
			log.Printf("msg=\"Git Add\" file=\"%s\"", policyFile)
			response.Added++
		case "CreatePolicyVersion":
			policyFile := os.TempDir() + "/" + PoliciesDirName + "/" + cloudTrailEvt.RequestParameters.PolicyName
			policyFileHandle, err := os.OpenFile(policyFile, os.O_WRONLY, 0644)
			utils.CheckError(err, "msg=\"Error opening policy file\" err=\"%s\"")
			err = policyFileHandle.Truncate(0)
			utils.CheckError(err, "msg=\"Error truncating policy file\" err=\"%s\"")
			_, err = policyFileHandle.Seek(0, 0)
			utils.CheckError(err, "msg=\"Error seeking policy file\" err=\"%s\"")
			_, err = policyFileHandle.WriteString(cloudTrailEvt.RequestParameters.PolicyDocument)
			utils.CheckError(err, "msg=\"Error writing policy file\" err=\"%s\"")
			_, err = gitWorktree.Add(policyFile)
			utils.CheckError(err, "msg=\"Error adding policy file to Git work tree\" err=\"%s\"")
			log.Printf("msg=\"Git Add\" file=\"%s\"", policyFile)
			response.Added++
		case "CreateRole":
			roleDir := os.TempDir() + "/" + RolesDirName + "/" + cloudTrailEvt.RequestParameters.RoleName
			err = os.Mkdir(roleDir, os.ModeDir)
			utils.CheckError(err, "msg=\"Error creating role directory\" err=\"%s\"")
			inlinePolicyFile := roleDir + "/" + cloudTrailEvt.RequestParameters.RoleName
			_, err = os.Create(inlinePolicyFile)
			utils.CheckError(err, "msg=\"Error creating inline policy file\" err=\"%s\"")
			_, err = gitWorktree.Add(inlinePolicyFile)
			utils.CheckError(err, "msg=\"Error adding inline policy file to Git work tree\" err=\"%s\"")
			log.Printf("msg=\"Git Add\" file=\"%s\"", inlinePolicyFile)
			response.Added++
		case "DeletePolicy":
			policyName := parsePolicyName(cloudTrailEvt.RequestParameters.PolicyArn)
			utils.CheckError(err, "msg=\"Error parsing policy arn\" err=\"%s\"")
			policyFile := os.TempDir() + "/" + PoliciesDirName + "/" + policyName
			_, err = gitWorktree.Remove(policyFile)
			utils.CheckError(err, "msg=\"Error removing policy file from Git work tree\" err=\"%s\"")
			log.Printf("msg=\"Git Remove\" file=\"%s\"", policyFile)
			response.Removed++
		case "DeleteRole":
			roleDir := os.TempDir() + "/" + RolesDirName + "/" + cloudTrailEvt.RequestParameters.RoleName
			_, err = gitWorktree.Remove(roleDir)
			utils.CheckError(err, "msg=\"Error removing role directory from Git work tree\" err=\"%s\"")
			log.Printf("msg=\"Git Remove\" dir=\"%s\"", roleDir)
			response.Removed++
		case "DeleteRolePolicy":
			roleDir := os.TempDir() + "/" + RolesDirName + "/" + cloudTrailEvt.RequestParameters.RoleName
			inlinePolicyFile := os.TempDir() + "/" + roleDir + "/_inline"
			_, err = gitWorktree.Remove(inlinePolicyFile)
			utils.CheckError(err, "msg=\"Error removing inline policy from Git work tree\" err=\"%s\"")
			log.Printf("msg=\"Git Remove\" file=\"%s\"", inlinePolicyFile)
			response.Removed++
		case "DetachRolePolicy":
			roleDir := os.TempDir() + "/" + RolesDirName + "/" + cloudTrailEvt.RequestParameters.RoleName
			attachedPolicyFile := os.TempDir() + "/" + roleDir + "/" + AttachedPoliciesDirName + "/" +
				cloudTrailEvt.RequestParameters.PolicyName
			_, err = gitWorktree.Remove(attachedPolicyFile)
			utils.CheckError(err, "msg=\"Error removing attached policy from Git work tree\" err=\"%s\"")
			response.Removed++
		case "PutRolePolicy":
			roleDir := os.TempDir() + "/" + RolesDirName + "/" + cloudTrailEvt.RequestParameters.RoleName
			inlinePolicyFile := roleDir + "/_inline"
			inlinePolicyFileHandle, err := os.OpenFile(inlinePolicyFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			utils.CheckError(err, "msg=\"Error opening inline policy file\" err=\"%s\"")
			_, err = inlinePolicyFileHandle.WriteString(cloudTrailEvt.RequestParameters.PolicyArn)
			utils.CheckError(err, "msg=\"Error appending inline policy file\" err=\"%s\"")
			err = inlinePolicyFileHandle.Close()
			utils.CheckError(err, "msg=\"Error closing inline policy file\" err=\"%s\"")
			_, err = gitWorktree.Add(inlinePolicyFile)
			utils.CheckError(err, "msg=\"Error adding inline policy file to Git work tree\" err=\"%s\"")
			log.Printf("msg=\"Git Add\" file=\"%s\"", inlinePolicyFile)
			response.Added++
		case "SetDefaultPolicyVersion":
			policyVersionOutput, err := iamSvc.GetPolicyVersion(&iam.GetPolicyVersionInput{
				PolicyArn: aws.String(cloudTrailEvt.RequestParameters.PolicyArn),
				VersionId: aws.String(cloudTrailEvt.RequestParameters.VersionId),
			})
			utils.CheckError(err, "msg=\"Error getting policy version output\" err=\"%s\"")
			policyName := parsePolicyName(cloudTrailEvt.RequestParameters.PolicyName)
			policyFile := os.TempDir() + "/" + PoliciesDirName + "/" + policyName
			policyFileHandle, err := os.OpenFile(policyFile, os.O_WRONLY, 0644)
			utils.CheckError(err, "msg=\"Error opening policy file\" err=\"%s\"")
			err = policyFileHandle.Truncate(0)
			utils.CheckError(err, "msg=\"Error truncating policy file\" err=\"%s\"")
			_, err = policyFileHandle.Seek(0, 0)
			utils.CheckError(err, "msg=\"Error seeking policy file\" err=\"%s\"")
			_, err = policyFileHandle.WriteString(*policyVersionOutput.PolicyVersion.Document)
			utils.CheckError(err, "msg=\"Error writing policy file\" err=\"%s\"")
			_, err = gitWorktree.Add(policyFile)
			utils.CheckError(err, "msg=\"Error adding policy file to Git work tree\" err=\"%s\"")
			log.Printf("msg=\"Git Add\" file=\"%s\"", policyFile)
			response.Added++
		default:
			validEvent = false
			response.Ignored++
			log.Print("EventName not supported:")
		}

		// Commit the change with the right datetime if a valid event.
		if validEvent {
			when, err := time.Parse(time.RFC3339, cloudTrailEvt.EventTime)
			utils.CheckError(err, "msg=\"Error parsing time\" err=\"%s\"")
			commit, err := gitWorktree.Commit(eventName+" by "+cloudTrailEvt.UserIdentity.UserName, &git.CommitOptions{
				Author: &object.Signature{
					Name:  cloudTrailEvt.UserIdentity.UserName,
					Email: "<>",
					When:  when,
				},
			})
			utils.CheckError(err, "msg=\"Error creating Git work tree commit\" err=\"%s\"")
			commitLog, err := gitRepo.CommitObject(commit)
			utils.CheckError(err, "msg=\"Error committing to Git work tree\" err=\"%s\"")
			log.Printf("msg=\"Git Commit\" commit=\"%s\"",
				strings.Replace(commitLog.String(), "\"", "\\\"", -1))
		}
	}

	// Push all the changes to the remote Git repo.
	log.Printf("msg=\"Git Push\"")
	err := gitRepo.Push(&git.PushOptions{
		Auth:     gitAuth,
		Progress: os.Stdout,
	})

	log.Printf("msg=\"Response\" added=%d removed=%d ignored=%d", response.Added, response.Removed,
		response.Ignored)

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
	utils.CheckError(err, "msg=\"Error getting Git password token from Secrets Manager\" err=\"%s\"")

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
	utils.CheckError(err, "msg=\"Error cloning Git repo\" err=\"%s\"")

	// Initialize the Git repo.
	utils.CheckError(err, "msg=\"Error cloning Git repo\" err=\"%s\"")
	gitRepo, err := git.PlainOpen(os.TempDir())
	utils.CheckError(err, "msg=\"Error initializing Git repo\" err=\"%s\"")

	// Get the Git worktree.
	gitWorkTree, err := gitRepo.Worktree()
	utils.CheckError(err, "msg=\"Error getting Git repo work tree\" err=\"%s\"")

	// Initialize the IAM service.
	iamSvc := iam.New(sess)

	return Auditor(ctx, evt, gitAuth, gitRepo, gitWorkTree, iamSvc)
}

func main() {
	lambda.Start(handler)
}
