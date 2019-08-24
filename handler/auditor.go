package main

import (
	"context"
	"fmt"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/joho/godotenv"
	"gopkg.in/src-d/go-git.v4"
	"gopkg.in/src-d/go-git.v4/storage/memory"
	"log"
	"os"
	"strings"
	"sync"
)

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
	workTree, err := gitRepo.Worktree()
	checkError(err, fmt.Sprintf("Error cloning git repo: %s", err))

	// Audit the intended records
	recordsLength := len(evt.Records)
	var waitGroup sync.WaitGroup
	waitGroup.Add(recordsLength)

	for i := 0; i < recordsLength; i++ {
		go func(i int) {
			defer waitGroup.Done()

			cloudTrailEvt := evt.Records[i]
			switch eventName := cloudTrailEvt.EventName; eventName {
			case "AttachRolePolicy":
				roleDir := os.TempDir() + "/" + cloudTrailEvt.RequestParameters.RoleName
			case "CreatePolicy":
			case "CreatePolicyVersion":
			case "CreateRole":
				errMsg := "Error auditing CreateRole evt: %s"
				roleDir := os.TempDir() + "/" + cloudTrailEvt.RequestParameters.RoleName
				err = os.Mkdir(roleDir, os.ModeDir)
				checkError(err, fmt.Sprintf(errMsg, err))
				inlinePolicyFile := roleDir + "/" + cloudTrailEvt.RequestParameters.RoleName
				_, err = os.Create(inlinePolicyFile)
				checkError(err, fmt.Sprintf(errMsg, err))
				_, err = workTree.Add(inlinePolicyFile)
				checkError(err, fmt.Sprintf(errMsg, err))
			case "DeletePolicy":
			case "DeletePolicyVersion":
			case "DeleteRole":
				roleDir := os.TempDir() + "/" + cloudTrailEvt.RequestParameters.RoleName
				err := os.RemoveAll(roleDir)
				checkError(err, fmt.Sprintf("Error auditing DeleteRole evt: %s", err))
			case "DeleteRolePolicy":
				roleDir := os.TempDir() + "/" + cloudTrailEvt.RequestParameters.RoleName
			case "DetachRolePolicy":
				roleDir := os.TempDir() + "/" + cloudTrailEvt.RequestParameters.RoleName
			case "PutRolePolicy":
				roleDir := os.TempDir() + "/" + cloudTrailEvt.RequestParameters.RoleName
			case "SetDefaultPolicyVersion":
			case "UpdateRole":
				roleDir := os.TempDir() + "/" + cloudTrailEvt.RequestParameters.RoleName
			default:
				log.Print("EventName not supported:")
			}
		}(i)
	}
	waitGroup.Wait()

	// commit all the changes to git

	return nil, nil
}

func main() {
	lambda.Start(audit)
}
