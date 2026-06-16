//go:build !linux && !windows

package keychainauth

import (
	"net"
)

// dialCLOEXEC connects to a Unix domain socket on non-Linux, non-Windows platforms (e.g. macOS).
func dialCLOEXEC(sockPath string) (net.Conn, error) {
	return net.Dial("unix", sockPath)
}
