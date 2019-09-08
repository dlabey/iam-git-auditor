package main

import (
	"context"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/dlabey/iam-git-auditor/pkg/cloudtrail"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"testing"
)

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

	sqsSvcMock := new(MockSQSSvc)

	sqsSvcMock.On("SendMessageBatch", mock.AnythingOfType("*sqs.SendMessageBatchInput")).Return(
		&sqs.SendMessageBatchOutput{
			Successful: []*sqs.SendMessageBatchResultEntry{{}, {}, {}},
			Failed:     []*sqs.BatchResultErrorEntry{},
		}, nil)

	response, err := Tailer(*ctx, cloudTrailEvts, sqsSvcMock)
	assert.Nil(t, err)
	assert.Equal(t, int32(3), response.Successful)
}
