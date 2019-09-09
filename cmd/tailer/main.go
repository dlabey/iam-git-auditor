package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/dlabey/iam-git-auditor/pkg/cloudtrail"
	"github.com/dlabey/iam-git-auditor/pkg/utils"
	"log"
	"os"
	"sync"
	"sync/atomic"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
)

type response struct {
	Successful int32 `json:"Successful"`
	Failed     int32 `json:"Failed"`
}

// Tails CloudTrail events into an SQS queue for synchronous processing to Git.
func Tailer(ctx context.Context, s3Evt events.S3Event, s3Svc s3iface.S3API, sqsSvc sqsiface.SQSAPI) (*response, error) {
	// Get the S3 compressed log object.
	getObjectOutput, err := s3Svc.GetObject(&s3.GetObjectInput{
		Bucket: aws.String(s3Evt.Records[0].S3.Bucket.Name),
		Key:    aws.String(s3Evt.Records[0].S3.Object.Key),
	})
	utils.CheckError(err, "msg=\"Error getting S3 object\" err=\"%s\"")
	var buf bytes.Buffer
	_, err = buf.ReadFrom(getObjectOutput.Body)
	utils.CheckError(err, "msg=\"Error buffering S3 object\" err=\"%s\"")

	// Unmarshal the CloudTrail events.
	var cloudTrailEvt cloudtrail.CloudTrailEvents
	err = json.Unmarshal(buf.Bytes(), &cloudTrailEvt)
	utils.CheckError(err, "msg=\"Error unmarshalling CloudTrail events\" err=\"%s\"")

	// Partition the CloudTrail event records into partitions of up to 10.
	records := cloudTrailEvt.Records
	partitionSize := 10
	var partitions [][]cloudtrail.CloudTrailEvent
	for partitionSize < len(cloudTrailEvt.Records) {
		records, partitions = records[partitionSize:], append(partitions, records[0:partitionSize:partitionSize])
	}
	partitions = append(partitions, records)

	// Concurrently go over each partition and batch it to the SQS queue.
	partitionsLen := len(partitions)
	log.Printf("msg=\"Processesing partitions\" partitionsLen=%d", partitionsLen)
	var waitGroup sync.WaitGroup
	waitGroup.Add(partitionsLen)
	var successful int32
	var failed int32
	for i := 0; i < len(partitions); i++ {
		go func(i int) {
			log.Printf("msg=\"Processesing partition\" partitionIdx=%d", i)

			// Close the channel when complete.
			defer waitGroup.Done()

			// Initialize an array of SendMessageBatchRequestEntry.
			entries := make([]*sqs.SendMessageBatchRequestEntry, len(partitions[i]))

			// Go over each partition and prepare it for the request.
			for j := 0; j < len(partitions[i]); j++ {
				messageBody, err := json.Marshal(partitions[i][j])
				utils.CheckError(err, "msg=\"Error marshalling CloudTrailEvent\" err=\"%s\"")
				entries[j] = &sqs.SendMessageBatchRequestEntry{
					DelaySeconds: aws.Int64(10),
					Id:           aws.String(partitions[i][j].EventID),
					MessageBody:  aws.String(string(messageBody)),
				}
			}

			// Send the message to the SQS queue to be processed synchronously for Git.
			queueUrl := os.Getenv("QUEUE_URL")
			sendMessageBatchOutput, err := sqsSvc.SendMessageBatch(&sqs.SendMessageBatchInput{
				Entries:  entries,
				QueueUrl: aws.String(queueUrl),
			})
			utils.CheckError(err, "msg=\"Error sending SQS message\" err=\"%s\"")
			log.Printf("msg=\"Sent message batch to SQS\" entriesLen=%d", len(entries))

			// Evaluate the response.
			atomic.AddInt32(&successful, int32(len(sendMessageBatchOutput.Successful)))
			atomic.AddInt32(&failed, int32(len(sendMessageBatchOutput.Failed)))
		}(i)
	}
	waitGroup.Wait()

	// Initialize the result.
	response := &response{
		Successful: successful,
		Failed:     failed,
	}

	// If there is an error, use the result JSON as the error message.
	if failed > 0 {
		errJson, err := json.Marshal(response)
		utils.CheckError(err, "msg=\"Error marshalling result\" err=\"%s\"")
		err = errors.New(string(errJson))
	}

	log.Printf("msg=\"Response\" successful=%d failed=%d", response.Successful, response.Failed)

	return response, err
}

func handler(ctx context.Context, s3Evt events.S3Event) (*response, error) {
	// Initialize an AWS session.
	sess := session.Must(session.NewSession())

	// Initialize the S3 service.
	s3Svc := s3.New(sess)

	// Initialize the SQS service.
	sqsSvc := sqs.New(sess)

	return Tailer(ctx, s3Evt, s3Svc, sqsSvc)
}

func main() {
	lambda.Start(handler)
}
