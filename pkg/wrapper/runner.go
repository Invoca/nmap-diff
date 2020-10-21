package wrapper

import "github.com/Invoca/nmap-diff/pkg/config"

type Runner interface {
	Execute(configObject config.BaseConfig) error
}
