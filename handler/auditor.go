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

	for i := 0; i < recordsLength; i++ {
		go func(i int) {
			defer waitGroup.Done()

			cloudWatchEvent := event.Records[i]
			switch eventType := cloudWatchEvent.EventType; eventType {
			case "AttachRolePolicy":
			case "CreatePolicy":
			case "CreatePolicyVersion":
			case "CreateRole":
			case "DeletePolicy":
			case "DeletePolicyVersion":
			case "DeleteRole":
			case "DeleteRolePolicy":
			case "DetachRolePolicy":
			case "PutRolePolicy":
			case "SetDefaultPolicyVersion":
			case "UpdateRole":
			default:
				log.Print("EventType not supported:")
			}
		}(i)
	}

	waitGroup.Wait()
}

func main() {
	lambda.Start(HandleRequest)
}
