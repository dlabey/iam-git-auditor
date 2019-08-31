package auditor

import (
	"github.com/stretchr/testify/mock"
	"testing"
)

type MockCtx struct {
	mock.Mock
}

type MockGitRepoSvc struct {
	mock.Mock
}

type MockIamSvc struct {
	mock.Mock
}

func TestAuditorWithOneEvent(test *testing.T) {

}

func TestAuditorWithMultipleEvents(test *testing.T) {

}

func TestAuditorWithIgnoredEvent(test *testing.T) {

}
