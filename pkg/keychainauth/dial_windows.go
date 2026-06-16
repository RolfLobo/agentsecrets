//go:build windows

package keychainauth

import (
	"net"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

// dialCLOEXEC connects to the Windows Named Pipe.
func dialCLOEXEC(sockPath string) (net.Conn, error) {
	h, err := windows.CreateFile(
		windows.StringToUTF16Ptr(sockPath),
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		0,
		nil,
		windows.OPEN_EXISTING,
		0,
		0,
	)
	if err != nil {
		return nil, err
	}
	return &PipeConn{handle: h}, nil
}

// PipeConn implements net.Conn for a Windows Named Pipe.
type PipeConn struct {
	handle windows.Handle
}

func (c *PipeConn) Read(b []byte) (int, error) {
	var done uint32
	err := windows.ReadFile(c.handle, b, &done, nil)
	if err != nil {
		if err == windows.ERROR_BROKEN_PIPE {
			return 0, os.ErrClosed
		}
		return 0, err
	}
	return int(done), nil
}

func (c *PipeConn) Write(b []byte) (int, error) {
	var done uint32
	err := windows.WriteFile(c.handle, b, &done, nil)
	if err != nil {
		return 0, err
	}
	return int(done), nil
}

func (c *PipeConn) Close() error {
	return windows.CloseHandle(c.handle)
}

type pipeAddr string

func (a pipeAddr) Network() string { return "pipe" }
func (a pipeAddr) String() string  { return string(a) }

func (c *PipeConn) LocalAddr() net.Addr  { return pipeAddr("keychain-auth-pipe") }
func (c *PipeConn) RemoteAddr() net.Addr { return pipeAddr("keychain-auth-pipe") }

func (c *PipeConn) SetDeadline(t time.Time) error      { return nil }
func (c *PipeConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *PipeConn) SetWriteDeadline(t time.Time) error { return nil }
