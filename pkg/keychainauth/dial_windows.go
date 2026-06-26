//go:build windows

package keychainauth

import (
	"net"
	"os"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modkernel32       = syscall.NewLazyDLL("kernel32.dll")
	procPeekNamedPipe = modkernel32.NewProc("PeekNamedPipe")
)

func peekNamedPipe(handle windows.Handle, lpTotalBytesAvail *uint32) error {
	r1, _, err := procPeekNamedPipe.Call(
		uintptr(handle),
		0,
		0,
		0,
		uintptr(unsafe.Pointer(lpTotalBytesAvail)),
		0,
	)
	if r1 == 0 {
		return err
	}
	return nil
}

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
	handle       windows.Handle
	readDeadline time.Time
}

type pipeError struct {
	error
	timeout bool
}

func (e *pipeError) Timeout() bool   { return e.timeout }
func (e *pipeError) Temporary() bool { return e.timeout }

func (c *PipeConn) Read(b []byte) (int, error) {
	if !c.readDeadline.IsZero() {
		// Poll for data until the deadline
		for {
			var avail uint32
			err := peekNamedPipe(c.handle, &avail)
			if err != nil {
				return 0, err
			}
			if avail > 0 {
				break // data is ready to be read
			}
			if time.Now().After(c.readDeadline) {
				return 0, &pipeError{error: os.ErrDeadlineExceeded, timeout: true}
			}
			time.Sleep(10 * time.Millisecond)
		}
	}

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

func (c *PipeConn) SetDeadline(t time.Time) error {
	c.readDeadline = t
	return nil
}

func (c *PipeConn) SetReadDeadline(t time.Time) error {
	c.readDeadline = t
	return nil
}

func (c *PipeConn) SetWriteDeadline(t time.Time) error {
	return nil
}
