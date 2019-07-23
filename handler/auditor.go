package main

import (
	"context"
	"github.com/aws/aws-lambda-go/lambda"
	"log"
	"sync"
)

type LambdaEvent struct {
	Records []CloudTrailEvent `json:"Records"`
}

type CloudTrailEvent struct {
	ErrorCode         string            `json:"errorCode"`
	EventID           string            `json:"eventID"`
	EventName         string            `json:"eventName"`
	EventTime         string            `json:"eventTime"`
	EventType         string            `json:"eventType"`
	RequestParameters RequestParameters `json:"requestParameters"`
	ResponseElements  ResponseElements  `json:"responseElements"`
	UserIdentity      UserIdentity      `json:"userIdentity"`
}

func HandleRequest(event LambdaEvent, ctx context.Context) (string, error) {
	recordsLength := len(event.Records)
	var waitGroup sync.WaitGroup
	waitGroup.Add(recordsLength)

	// if recordLength > 1 checkout project and continue

	for i := 0; i < recordsLength; i++ {
		go func(i int) {
			defer waitGroup.Done()

			cloudWatchEvent := event.Records[i]
			supportedEventTypes := []string{
				"attachRolePolicy",
				"CreatePolicy",
				"CreatePolicyVersion",
				"CreateRole",
				"DeletePolicy",
				"DeletePolicyVersion",
				"DeleteRole",
				"DeleteRolePolicy",
				"DetachRolePolicy",
				"PutRolePolicy",
				"SetDefaultPolicyVersion",
				"UpdateRole",
			}

			if contains(supportedEventTypes, cloudWatchEvent.EventType) {
				// queue up a commit for the change for a Git commit
			} else {
				log.Print("EventType not supported:")
			}
		}(i)
	}
	waitGroup.Wait()

	// commit all the changes to git

	return "end", nil
}

func contains(strs []string, str string) bool {
	for _, contains := range strs {
		if contains == str {
			return true
		}
	}
	return false
}

func main() {
	lambda.Start(HandleRequest)
}
