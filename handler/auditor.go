package main

import (
	"context"
	"github.com/aws/aws-lambda-go/lambda"
)

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

func HandleRequest(ctx context.Context) (string, error) {
	// todo: add logic to switch between EventType
}

func main() {
	lambda.Start(HandleRequest)
}
