package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/dlabey/iam-git-auditor/pkg/cloudtrail"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"io/ioutil"
	"testing"
)

type MockS3Svc struct {
	s3.S3
	mock.Mock
}

func (m *MockS3Svc) GetObject(input *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
	args := m.Called(input)

	return args.Get(0).(*s3.GetObjectOutput), args.Error(1)
}

type MockSQSSvc struct {
	sqs.SQS
	mock.Mock
}

func (m *MockSQSSvc) SendMessageBatch(input *sqs.SendMessageBatchInput) (*sqs.SendMessageBatchOutput, error) {
	args := m.Called(input)

	return args.Get(0).(*sqs.SendMessageBatchOutput), args.Error(1)
}

func TestTailer(t *testing.T) {
	ctx := new(context.Context)

	s3Evt := events.S3Event{
		Records: []events.S3EventRecord{{
			S3: events.S3Entity{
				Bucket: events.S3Bucket{
					Name: "test",
				},
				Object: events.S3Object{
					Key: "test",
				},
			},
		}},
	}

	cloudTrailEvt1 := cloudtrail.CloudTrailEvent{
		EventName: "CreatePolicy",
		RequestParameters: cloudtrail.RequestParameters{
			PolicyName:     "policyName",
			PolicyDocument: "policyDocument",
		},
		EventTime: "2012-11-01T22:08:41+00:00",
	}
	cloudTrailEvt2 := cloudtrail.CloudTrailEvent{
		EventName: "DeletePolicy",
		RequestParameters: cloudtrail.RequestParameters{
			PolicyName:     "policyName",
			PolicyDocument: "policyDocument",
		},
		EventTime: "2012-11-01T22:09:41+00:00",
	}
	cloudTrailEvt3 := cloudtrail.CloudTrailEvent{
		EventName: "DeleteRolePermissionsBoundary",
		RequestParameters: cloudtrail.RequestParameters{
			RoleName: "roleName",
		},
		EventTime: "2012-11-01T22:10:41+00:00",
	}
	cloudTrailEvts := cloudtrail.CloudTrailEvents{
		Records: []cloudtrail.CloudTrailEvent{
			cloudTrailEvt1,
			cloudTrailEvt2,
			cloudTrailEvt3,
		},
	}

	cloudTrailEvtsJson, _ := json.Marshal(cloudTrailEvts)
	body := ioutil.NopCloser(bytes.NewBuffer(cloudTrailEvtsJson))

	s3SvcMock := new(MockS3Svc)
	s3SvcMock.On("GetObject", mock.AnythingOfType("*s3.GetObjectInput")).Return(
		&s3.GetObjectOutput{
			Body: body,
		}, nil)

	sqsSvcMock := new(MockSQSSvc)
	sqsSvcMock.On("SendMessageBatch", mock.AnythingOfType("*sqs.SendMessageBatchInput")).Return(
		&sqs.SendMessageBatchOutput{
			Successful: []*sqs.SendMessageBatchResultEntry{{}, {}, {}},
			Failed:     []*sqs.BatchResultErrorEntry{},
		}, nil)

	response, err := Tailer(*ctx, s3Evt, s3SvcMock, sqsSvcMock)
	assert.Nil(t, err)
	assert.Equal(t, int32(3), response.Successful)
}
