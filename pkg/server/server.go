package server

type Server struct {
	Name string
	Address string
	Ports []uint16
	Tags map[string] string
}
