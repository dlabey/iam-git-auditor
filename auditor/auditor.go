package auditor

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/dlabey/iam-git-auditor/pkg"
	"github.com/joho/godotenv"
	"gopkg.in/src-d/go-git.v4"
	"gopkg.in/src-d/go-git.v4/plumbing/object"
	"log"
	"os"
	"strings"
	"time"
)

func parsePolicyName(policyArn string) string {
	segments := strings.Split(policyArn, "/")

	return segments[len(segments)-1]
}

// Audits the intended records in sequence for each to be a single Git commit for the right datetime.
func Auditor(ctx context.Context, evt events.SQSEvent, gitRepoSvc *git.Repository, iamSvc *iam.IAM) (*string, error) {
	const AttachedPoliciesDirName = "attachedPolicies"
	const PoliciesDirName = "policies"
	const RolesDirName = "roles"

	// Get the Git work tree.
	workTree, err := gitRepoSvc.Worktree()
	pkg.CheckError(err, fmt.Sprintf("Error getting git repo work tree: %s", err))

	// Handle the event and commit it to the Git work tree.
	validEvent := true
	for i := 0; i < len(evt.Records); i++ {
		var cloudTrailEvt pkg.CloudTrailEvent
		err := json.Unmarshal([]byte(evt.Records[i].Body), &cloudTrailEvt)
		pkg.CheckError(err, fmt.Sprintf("Error unmarshalling CloudTrail event: %s", err))
		eventName := cloudTrailEvt.EventName
		switch eventName {
		case "AttachRolePolicy":
			roleDir := os.TempDir() + "/" + RolesDirName + "/" + cloudTrailEvt.RequestParameters.RoleName
			attachedPolicyFile := roleDir + "/" + AttachedPoliciesDirName + "/" + cloudTrailEvt.RequestParameters.PolicyName
			attachedPolicyFileHandle, err := os.OpenFile(attachedPolicyFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			pkg.CheckError(err, fmt.Sprintf("Error opening attached policy file: %s", err))
			_, err = attachedPolicyFileHandle.WriteString(cloudTrailEvt.RequestParameters.PolicyArn)
			pkg.CheckError(err, fmt.Sprintf("Error appending attached policy file: %s", err))
			err = attachedPolicyFileHandle.Close()
			pkg.CheckError(err, fmt.Sprintf("Error closing attached policy file: %s", err))
			_, err = workTree.Add(attachedPolicyFile)
			pkg.CheckError(err, fmt.Sprintf("Error adding attached policy file to Git work tree: %s", err))
		case "CreatePolicy":
			policyFile := os.TempDir() + "/" + PoliciesDirName + "/" + cloudTrailEvt.RequestParameters.PolicyName
			policyFileHandle, err := os.Create(policyFile)
			pkg.CheckError(err, fmt.Sprintf("Error creating policy file: %s", err))
			_, err = policyFileHandle.WriteString(cloudTrailEvt.RequestParameters.PolicyDocument)
			pkg.CheckError(err, fmt.Sprintf("Error writing policy file: %s", err))
			err = policyFileHandle.Close()
			pkg.CheckError(err, fmt.Sprintf("Error closing policy file: %s", err))
			_, err = workTree.Add(policyFile)
			pkg.CheckError(err, fmt.Sprintf("Error adding policy file to Git work tree: %s", err))
		case "CreatePolicyVersion":
			policyFile := os.TempDir() + "/" + PoliciesDirName + "/" + cloudTrailEvt.RequestParameters.PolicyName
			policyFileHandle, err := os.OpenFile(policyFile, os.O_WRONLY, 0644)
			pkg.CheckError(err, fmt.Sprintf("Error opening policy file: %s", err))
			err = policyFileHandle.Truncate(0)
			pkg.CheckError(err, fmt.Sprintf("Error truncating policy file: %s", err))
			_, err = policyFileHandle.Seek(0, 0)
			pkg.CheckError(err, fmt.Sprintf("Error seeking policy file: %s", err))
			_, err = policyFileHandle.WriteString(cloudTrailEvt.RequestParameters.PolicyDocument)
			pkg.CheckError(err, fmt.Sprintf("Error writing policy file: %s", err))
			_, err = workTree.Add(policyFile)
			pkg.CheckError(err, fmt.Sprintf("Error adding policy file to Git work tree: %s", err))
		case "CreateRole":
			roleDir := os.TempDir() + "/" + RolesDirName + "/" + cloudTrailEvt.RequestParameters.RoleName
			err = os.Mkdir(roleDir, os.ModeDir)
			pkg.CheckError(err, fmt.Sprintf("Error creating role directory: %s", err))
			inlinePolicyFile := roleDir + "/" + cloudTrailEvt.RequestParameters.RoleName
			_, err = os.Create(inlinePolicyFile)
			pkg.CheckError(err, fmt.Sprintf("Error creating inline policy file: %s", err))
			_, err = workTree.Add(inlinePolicyFile)
			pkg.CheckError(err, fmt.Sprintf("Error adding inline policy file to Git work tree: %s", err))
		case "DeletePolicy":
			policyName := parsePolicyName(cloudTrailEvt.RequestParameters.PolicyArn)
			pkg.CheckError(err, fmt.Sprintf("Error parsing policy arn: %s", err))
			policyFile := os.TempDir() + "/" + PoliciesDirName + "/" + policyName
			_, err = workTree.Remove(policyFile)
			pkg.CheckError(err, fmt.Sprintf("Error removing policy file from Git work tree: %s", err))
		case "DeleteRole":
			roleDir := os.TempDir() + "/" + RolesDirName + "/" + cloudTrailEvt.RequestParameters.RoleName
			_, err = workTree.Remove(roleDir)
			pkg.CheckError(err, fmt.Sprintf("Error removing role directory from Git work tree: %s", err))
		case "DeleteRolePolicy":
			roleDir := os.TempDir() + "/" + RolesDirName + "/" + cloudTrailEvt.RequestParameters.RoleName
			inlinePolicyFile := os.TempDir() + "/" + roleDir + "/_inline"
			_, err = workTree.Remove(inlinePolicyFile)
			pkg.CheckError(err, fmt.Sprintf("Error removing inline policy from Git work tree: %s", err))
		case "DetachRolePolicy":
			roleDir := os.TempDir() + "/" + RolesDirName + "/" + cloudTrailEvt.RequestParameters.RoleName
			attachedPolicyFile := os.TempDir() + "/" + roleDir + "/" + AttachedPoliciesDirName + "/" +
				cloudTrailEvt.RequestParameters.PolicyName
			_, err = workTree.Remove(attachedPolicyFile)
			pkg.CheckError(err, fmt.Sprintf("Error removing attached policy from Git work tree: %s", err))
		case "PutRolePolicy":
			roleDir := os.TempDir() + "/" + RolesDirName + "/" + cloudTrailEvt.RequestParameters.RoleName
			inlinePolicyFile := roleDir + "/_inline"
			inlinePolicyFileHandle, err := os.OpenFile(inlinePolicyFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			pkg.CheckError(err, fmt.Sprintf("Error opening inline policy file: %s", err))
			_, err = inlinePolicyFileHandle.WriteString(cloudTrailEvt.RequestParameters.PolicyArn)
			pkg.CheckError(err, fmt.Sprintf("Error appending inline policy file: %s", err))
			err = inlinePolicyFileHandle.Close()
			pkg.CheckError(err, fmt.Sprintf("Error closing inline policy file: %s", err))
			_, err = workTree.Add(inlinePolicyFile)
			pkg.CheckError(err, fmt.Sprintf("Error adding inline policy file to Git work tree: %s", err))
		case "SetDefaultPolicyVersion":
			policyVersionOutput, err := iamSvc.GetPolicyVersion(&iam.GetPolicyVersionInput{
				PolicyArn: aws.String(cloudTrailEvt.RequestParameters.PolicyArn),
				VersionId: aws.String(cloudTrailEvt.RequestParameters.VersionId),
			})
			pkg.CheckError(err, fmt.Sprintf("Error getting policy version output: %s", err))
			policyName := parsePolicyName(cloudTrailEvt.RequestParameters.PolicyName)
			policyFile := os.TempDir() + "/" + PoliciesDirName + "/" + policyName
			policyFileHandle, err := os.OpenFile(policyFile, os.O_WRONLY, 0644)
			pkg.CheckError(err, fmt.Sprintf("Error opening policy file: %s", err))
			err = policyFileHandle.Truncate(0)
			pkg.CheckError(err, fmt.Sprintf("Error truncating policy file: %s", err))
			_, err = policyFileHandle.Seek(0, 0)
			pkg.CheckError(err, fmt.Sprintf("Error seeking policy file: %s", err))
			_, err = policyFileHandle.WriteString(*policyVersionOutput.PolicyVersion.Document)
			pkg.CheckError(err, fmt.Sprintf("Error writing policy file: %s", err))
			_, err = workTree.Add(policyFile)
			pkg.CheckError(err, fmt.Sprintf("Error adding policy file to Git work tree: %s", err))
		default:
			validEvent = false
			log.Print("EventName not supported:")
		}

		// Commit the change with the right datetime if a valid event.
		if validEvent {
			when, err := time.Parse(time.RFC3339, cloudTrailEvt.EventTime)
			pkg.CheckError(err, fmt.Sprintf("Error parsing time: %s", err))
			commit, err := workTree.Commit(eventName+" by "+cloudTrailEvt.UserIdentity.UserName, &git.CommitOptions{
				Author: &object.Signature{
					Name:  cloudTrailEvt.UserIdentity.UserName,
					Email: "<>",
					When:  when,
				},
			})
			pkg.CheckError(err, fmt.Sprintf("Error creating Git work tree commit: %s", err))
			commitLog, err := gitRepoSvc.CommitObject(commit)
			pkg.CheckError(err, fmt.Sprintf("Error commigint to Git work tree: %s", err))
			log.Println(commitLog)
		}
	}

	// Push all the changes to the remote Git repo.
	err = gitRepoSvc.Push(&git.PushOptions{
		Progress: os.Stdout,
	})

	return nil, err
}

func handler(ctx context.Context, evt events.SQSEvent) (*string, error) {
	// Initialize dotenv.
	err := godotenv.Load()
	pkg.CheckError(err, fmt.Sprintf("Error loading .env file: %s", err))

	// Checkout the audit repo.
	gitRepoUrl := os.Getenv("GIT_REPO")
	_, err = git.PlainClone(os.TempDir(), false, &git.CloneOptions{
		URL:      gitRepoUrl,
		Progress: os.Stdout,
	})
	pkg.CheckError(err, fmt.Sprintf("Error cloning Git repo: %s", err))

	// Initialize the repo service.
	pkg.CheckError(err, fmt.Sprintf("Error cloning Git repo: %s", err))
	gitRepoSvc, err := git.PlainOpen(os.TempDir())

	// Initialize the IAM service.
	sess := session.Must(session.NewSession())
	iamSvc := iam.New(sess)

	return Auditor(ctx, evt, gitRepoSvc, iamSvc)
}

func main() {
	lambda.Start(handler)
}
