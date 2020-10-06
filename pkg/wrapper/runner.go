package wrapper

import "github.com/port-scanner/pkg/config"

type Runner interface {
	SetupRunner(config *config.BaseConfig) error
	Run() error
}
