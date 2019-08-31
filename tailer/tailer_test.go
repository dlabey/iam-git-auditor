package tailer

import (
	"github.com/stretchr/testify/mock"
	"testing"
)

type MockCtx struct {
	mock.Mock
}

type MockSQSSvc struct {
	mock.Mock
}

func TestTailer(test *testing.T) {

}
