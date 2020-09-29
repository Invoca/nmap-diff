package wrapper

import "github.com/Ullaakut/nmap"

type NmapClientWrapper interface {
	Run() (result *nmap.Run, warnings []string, err error)
}
