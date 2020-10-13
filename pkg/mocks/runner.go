package mocks

import (
	"github.com/port-scanner/pkg/wrapper"
	"github.com/port-scanner/pkg/config"
)

type RunnerMock struct {
	wrapper.Runner
	ResettableMock
}

func (n *RunnerMock) Execute(configObject config.BaseConfig) error {
	args := n.Called(nil)
	if args.Get(0) == nil {
		return args.Error(0)
	} else {
		return args.Error(0)
	}
}
