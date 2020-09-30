package server

type Server struct {
	Name    string
	Address string
	//Ports []uint16
	ClosedPorts []uint16
	OpenedPorts []uint16
	Tags        map[string]string
}
