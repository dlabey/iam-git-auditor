package main

import (
	"context"
	"encoding/json"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/dlabey/iam-git-auditor/pkg/cloudtrail"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"gopkg.in/src-d/go-git.v4"
	"gopkg.in/src-d/go-git.v4/plumbing"
	"gopkg.in/src-d/go-git.v4/plumbing/object"
	"gopkg.in/src-d/go-git.v4/plumbing/transport/http"
	"testing"
)

type MockGitRepo struct {
	mock.Mock
}

func (m *MockGitRepo) CommitObject(hash plumbing.Hash) (*object.Commit, error) {
	args := m.Called(hash)

	return args.Get(0).(*object.Commit), args.Error(1)
}

func (m *MockGitRepo) Push(pushOpts *git.PushOptions) error {
	args := m.Called(pushOpts)

	return args.Error(0)
}

type MockGitWorktree struct {
	git.Worktree
	mock.Mock
}

func (m *MockGitWorktree) Add(path string) (plumbing.Hash, error) {
	args := m.Called(path)

	return args.Get(0).(plumbing.Hash), args.Error(1)
}

func (m *MockGitWorktree) Commit(msg string, opts *git.CommitOptions) (plumbing.Hash, error) {
	args := m.Called(msg, opts)

	return args.Get(0).(plumbing.Hash), args.Error(1)
}

func (m *MockGitWorktree) Remove(path string) (plumbing.Hash, error) {
	args := m.Called(path)

	return args.Get(0).(plumbing.Hash), args.Error(1)
}

type MockIamSvc struct {
	mock.Mock
	iam.IAM
}

func (m *MockIamSvc) GetPolicyVersion(input *iam.GetPolicyVersionInput) (*iam.GetPolicyVersionOutput, error) {
	args := m.Called(input)

	return args.Get(0).(*iam.GetPolicyVersionOutput), args.Error(1)
}

func TestAuditor(t *testing.T) {
	ctx := new(context.Context)
	cloudTrailEvt1 := cloudtrail.CloudTrailEvent{
		EventName: "CreatePolicy",
		RequestParameters: cloudtrail.RequestParameters{
			PolicyName:     "policyName",
			PolicyDocument: "policyDocument",
		},
		EventTime: "2012-11-01T22:08:41+00:00",
	}
	cloudTrailEvt1Json, _ := json.Marshal(cloudTrailEvt1)
	cloudTrailEvt2 := cloudtrail.CloudTrailEvent{
		EventName: "DeletePolicy",
		RequestParameters: cloudtrail.RequestParameters{
			PolicyName:     "policyName",
			PolicyDocument: "policyDocument",
		},
		EventTime: "2012-11-01T22:09:41+00:00",
	}
	cloudTrailEvt2Json, _ := json.Marshal(cloudTrailEvt2)
	cloudTrailEvt3 := cloudtrail.CloudTrailEvent{
		EventName: "DeleteRolePermissionsBoundary",
		RequestParameters: cloudtrail.RequestParameters{
			RoleName: "roleName",
		},
		EventTime: "2012-11-01T22:10:41+00:00",
	}
	cloudTrailEvt3Json, _ := json.Marshal(cloudTrailEvt3)
	sqsEvt := events.SQSEvent{
		Records: []events.SQSMessage{{
			Body: string(cloudTrailEvt1Json),
		}, {
			Body: string(cloudTrailEvt2Json),
		}, {
			Body: string(cloudTrailEvt3Json),
		}},
	}
	gitAuth := &http.BasicAuth{}
	gitRepoMock := new(MockGitRepo)
	gitWorktreeMock := new(MockGitWorktree)
	iamSvcMock := new(MockIamSvc)

	gitWorktreeMock.On("Add", mock.AnythingOfType("string")).Return(plumbing.Hash{}, nil)
	gitWorktreeMock.On("Commit", mock.AnythingOfType("string"),
		mock.AnythingOfType("*git.CommitOptions")).Return(plumbing.Hash{}, nil)
	gitWorktreeMock.On("Remove", mock.AnythingOfType("string")).Return(plumbing.Hash{}, nil)

	gitRepoMock.On("CommitObject", mock.AnythingOfType("plumbing.Hash")).Return(&object.Commit{}, nil)
	gitRepoMock.On("Push", mock.AnythingOfType("*git.PushOptions")).Return(nil)

	iamSvcMock.On("GetPolicyVersion", mock.AnythingOfType("*iam.GetPolicyVersionInput")).Return(
		&iam.GetPolicyVersionOutput{}, nil)

	response, err := Auditor(*ctx, sqsEvt, gitAuth, gitRepoMock, gitWorktreeMock, iamSvcMock)
	assert.Nil(t, err)
	assert.Equal(t, 1, response.Added)
	assert.Equal(t, 1, response.Removed)
	assert.Equal(t, 1, response.Ignored)
}
