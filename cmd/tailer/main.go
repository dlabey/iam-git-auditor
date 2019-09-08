package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/dlabey/iam-git-auditor/pkg/cloudtrail"
	"github.com/dlabey/iam-git-auditor/pkg/utils"
	"github.com/joho/godotenv"
	"os"
	"sync"
	"sync/atomic"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
)

type response struct {
	Successful int32 `json:"Successful"`
	Failed     int32 `json:"Failed"`
}

// Tails CloudTrail events into an SQS queue for synchronous processing to Git.
func Tailer(ctx context.Context, evt cloudtrail.CloudTrailEvents, sqsSvc sqsiface.SQSAPI) (*response, error) {

	// Partition the CloudTrail event records into partitions of up to 10.
	records := evt.Records
	partitionSize := 10
	var partitions [][]cloudtrail.CloudTrailEvent
	for partitionSize < len(evt.Records) {
		records, partitions = records[partitionSize:], append(partitions, records[0:partitionSize:partitionSize])
	}
	partitions = append(partitions, records)

	// Concurrently go over each partition and batch it to the SQS queue.
	partitionsLen := len(partitions)
	var waitGroup sync.WaitGroup
	waitGroup.Add(partitionsLen)
	var successful int32
	var failed int32
	for i := 0; i < len(partitions); i++ {
		go func(i int) {
			// Close the channel when complete.
			defer waitGroup.Done()

			// Initialize an array of SendMessageBatchRequestEntry.
			entries := make([]*sqs.SendMessageBatchRequestEntry, len(partitions[i]))

			// Go over each partition and prepare it for the request.
			for j := 0; j < len(partitions[i]); j++ {
				messageBody, err := json.Marshal(partitions[i][j])
				utils.CheckError(err, fmt.Sprintf("Error marshalling CloudTrailEvent: %s", err))
				entries[j] = &sqs.SendMessageBatchRequestEntry{
					DelaySeconds: aws.Int64(10),
					Id:           aws.String(partitions[i][j].EventID),
					MessageBody:  aws.String(string(messageBody)),
				}
			}

			// Send the message to the SQS queue to be processed synchronously for Git.
			queueUrl := os.Getenv("QUEUE_URL")
			res, err := sqsSvc.SendMessageBatch(&sqs.SendMessageBatchInput{
				Entries:  entries,
				QueueUrl: aws.String(queueUrl),
			})
			utils.CheckError(err, fmt.Sprintf("Error sending SQS message: %s", err))

			// Evaluate the response.
			atomic.AddInt32(&successful, int32(len(res.Successful)))
			atomic.AddInt32(&failed, int32(len(res.Failed)))
		}(i)
	}
	waitGroup.Wait()

	// Initialize the result.
	result := &response{
		Successful: successful,
		Failed:     failed,
	}

	// If there is an error, use the result JSON as the error message.
	var err error
	if failed > 0 {
		errJson, err := json.Marshal(result)
		utils.CheckError(err, fmt.Sprintf("Error marshalling result: %s", err))
		err = errors.New(string(errJson))
	}

	return result, err
}

func handler(ctx context.Context, evt cloudtrail.CloudTrailEvents) (*response, error) {
	// Initialize dotenv.
	err := godotenv.Load()
	utils.CheckError(err, fmt.Sprintf("Error loading .env file: %s", err))

	// Initialize the SQS service.
	sess, err := session.NewSession(&aws.Config{})
	sqsSvc := sqs.New(sess)

	return Tailer(ctx, evt, sqsSvc)
}

func main() {
	lambda.Start(handler)
}
