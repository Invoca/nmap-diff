package server

type Server struct {
	Name        string
	Address     string
	ClosedPorts []uint16
	OpenedPorts []uint16
	Tags        map[string]string
}
