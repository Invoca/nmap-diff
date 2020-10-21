package wrapper

import "github.com/Invoca/nmap-diff/pkg/server"

type SlackSvc interface {
	PrintOpenedPorts(host server.Server, ports []uint16) error
	PrintClosedPorts(host server.Server, ports []uint16) error
}
