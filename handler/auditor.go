package main

import (
	"context"
	"fmt"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/joho/godotenv"
	"gopkg.in/src-d/go-git.v4"
	"gopkg.in/src-d/go-git.v4/storage/memory"
	"log"
	"os"
	"strings"
	"sync"
)

func audit(evt SQSEvent, ctx context.Context) (*string, error) {
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

	recordsLength := len(evt.Records)
	var waitGroup sync.WaitGroup
	waitGroup.Add(recordsLength)

	// if recordLength > 1 checkout project and continue

	for i := 0; i < recordsLength; i++ {
		go func(i int) {
			defer waitGroup.Done()

			cloudWatchEvt := evt.Records[i]
			switch eventName := cloudWatchEvt.EventName; eventName {
			case "AttachRolePolicy":
				roleDir := os.TempDir() + "/" + cloudWatchEvt.RequestParameters.RoleName
			case "CreatePolicy":
			case "CreatePolicyVersion":
			case "CreateRole":
				errMsg := "Error auditing CreateRole evt: %s"
				roleDir := os.TempDir() + "/" + cloudWatchEvt.RequestParameters.RoleName
				err = os.Mkdir(roleDir, os.ModeDir)
				checkError(err, fmt.Sprintf(errMsg, err))
				inlinePolicyFile := roleDir + "/" + cloudWatchEvt.RequestParameters.RoleName
				_, err = os.Create(inlinePolicyFile)
				checkError(err, fmt.Sprintf(errMsg, err))
				_, err = workTree.Add(inlinePolicyFile)
				checkError(err, fmt.Sprintf(errMsg, err))
			case "DeletePolicy":
			case "DeletePolicyVersion":
			case "DeleteRole":
				roleDir := os.TempDir() + "/" + cloudWatchEvt.RequestParameters.RoleName
				err := os.RemoveAll(roleDir)
				checkError(err, fmt.Sprintf("Error auditing DeleteRole evt: %s", err))
			case "DeleteRolePolicy":
				roleDir := os.TempDir() + "/" + cloudWatchEvt.RequestParameters.RoleName
			case "DetachRolePolicy":
				roleDir := os.TempDir() + "/" + cloudWatchEvt.RequestParameters.RoleName
			case "PutRolePolicy":
				roleDir := os.TempDir() + "/" + cloudWatchEvt.RequestParameters.RoleName
			case "SetDefaultPolicyVersion":
			case "UpdateRole":
				roleDir := os.TempDir() + "/" + cloudWatchEvt.RequestParameters.RoleName
			default:
				log.Print("EventName not supported:")
			}
		}(i)
	}
	waitGroup.Wait()

	// commit all the changes to git

	return "end", nil
}

func main() {
	lambda.Start(audit)
}
