package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/joho/godotenv"
	"os"
	"sync"
	"sync/atomic"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sqs"
)

type TailResponse struct {
	Successful int64 `json:"Successful"`
	Failed     int64 `json:"Failed"`
}

func Tail(ctx context.Context, evt CloudTrailEvents) (*TailResponse, error) {
	// Initialize dotenv
	err := godotenv.Load()
	checkError(err, fmt.Sprintf("Error loading .env file: %s", err))

	// Partition the CloudTrail event records into partitions of up to 10
	records := evt.Records
	partitionSize := 10
	var partitions [][]CloudTrailEvent
	for partitionSize < len(evt.Records) {
		records, partitions = records[partitionSize:], append(partitions, records[0:partitionSize:partitionSize])
	}
	partitions = append(partitions, records)

	// Initialize SQS
	sess, err := session.NewSession(&aws.Config{})
	sqsClient := sqs.New(sess)

	// Get the queue URL
	queueUrl, err := sqsClient.GetQueueUrl(&sqs.GetQueueUrlInput{
		QueueName: aws.String(os.Getenv("QUEUE_NAME")),
	})
	checkError(err, fmt.Sprintf("Error getting queue URL: %s", err))

	// Concurrently go over each partition and batch it to the SQS queue
	partitionsLen := len(partitions)
	var waitGroup sync.WaitGroup
	waitGroup.Add(partitionsLen)
	var successful int64
	var failed int64
	for i := 0; i < len(partitions); i++ {
		go func(i int) {
			// Close the channel when complete
			defer waitGroup.Done()

			// Initialize an array of SendMessageBatchRequestEntry
			entries := make([]*sqs.SendMessageBatchRequestEntry, len(partitions[i]))

			// Go over each partition and prepare it for the request
			for j := 0; j < len(partitions[i]); j++ {
				messageBody, err := json.Marshal(partitions[i][j])
				checkError(err, fmt.Sprintf("Error marshalling CloudTrailEvent: %s", err))
				entries[j] = &sqs.SendMessageBatchRequestEntry{
					DelaySeconds: aws.Int64(10),
					Id:           aws.String(partitions[i][j].EventID),
					MessageBody:  aws.String(string(messageBody)),
				}
			}

			// Send the message to the SQS queue to be processed synchronously for Git
			res, err := sqsClient.SendMessageBatch(&sqs.SendMessageBatchInput{
				Entries:  entries,
				QueueUrl: queueUrl.QueueUrl,
			})
			checkError(err, fmt.Sprintf("Error sending SQS message: %s", err))

			// Evaluate the response
			atomic.AddInt64(&successful, int64(len(res.Successful)))
			atomic.AddInt64(&failed, int64(len(res.Failed)))
		}(i)
	}

	// Initialize the result
	result := &TailResponse{
		Successful: successful,
		Failed:     failed,
	}

	// If there is an error, use the result JSON as the error message
	err = nil
	if failed > 0 {
		errJson, err := json.Marshal(result)
		checkError(err, fmt.Sprintf("Error marshalling result: %s", err))
		err = errors.New(string(errJson))
	}

	return result, err
}

func main() {
	lambda.Start(Tail)
}
