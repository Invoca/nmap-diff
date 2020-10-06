package wrapper

import "github.com/port-scanner/pkg/server"

type SlackInterface interface {
	PrintOpenedPorts(host server.Server, ports []uint16) error
	PrintClosedPorts(host server.Server, ports []uint16) error
}
