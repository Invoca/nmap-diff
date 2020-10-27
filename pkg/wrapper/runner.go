package wrapper

import "github.com/port-scanner/pkg/config"

type Runner interface {
	Execute(configObject config.BaseConfig) error
}
