package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/The-17/agentsecrets/pkg/config"
)

// PIDFilePath returns the path to the proxy PID file (~/.agentsecrets/proxy.pid).
func PIDFilePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	return filepath.Join(home, ".agentsecrets", "proxy.pid"), nil
}

// WritePIDFile writes the current PID and start time to the PID file.
func WritePIDFile(port int) error {
	path, err := PIDFilePath()
	if err != nil {
		return err
	}
	data := fmt.Sprintf("%d\n%d\n%d", os.Getpid(), time.Now().Unix(), port)
	return os.WriteFile(path, []byte(data), 0600)
}

// RemovePIDFile cleans up the PID file on shutdown.
func RemovePIDFile() {
	path, err := PIDFilePath()
	if err != nil {
		return
	}
	os.Remove(path)
}

// ReadPIDFile reads the PID, start time, and port from the PID file.
func ReadPIDFile() (pid int, startTime time.Time, port int, err error) {
	path, err := PIDFilePath()
	if err != nil {
		return 0, time.Time{}, 0, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, time.Time{}, 0, err
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) < 3 {
		return 0, time.Time{}, 0, fmt.Errorf("invalid PID file format")
	}
	pid, err = strconv.Atoi(lines[0])
	if err != nil {
		return 0, time.Time{}, 0, fmt.Errorf("invalid PID: %w", err)
	}
	ts, err := strconv.ParseInt(lines[1], 10, 64)
	if err != nil {
		return 0, time.Time{}, 0, fmt.Errorf("invalid timestamp: %w", err)
	}
	port, err = strconv.Atoi(lines[2])
	if err != nil {
		return 0, time.Time{}, 0, fmt.Errorf("invalid port: %w", err)
	}
	return pid, time.Unix(ts, 0), port, nil
}

// IsProcessAlive checks if a process with the given PID is running.
func IsProcessAlive(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// On Unix, FindProcess always succeeds; send signal 0 to probe.
	err = p.Signal(syscall.Signal(0))
	return err == nil
}

// IsProxyRunning checks if a proxy process is alive AND its port is actively listening.
// If the process is dead or port unreachable, it cleans up the stale PID file and returns false.
func IsProxyRunning() (pid int, port int, running bool) {
	var err error
	var startTime time.Time
	pid, startTime, port, err = ReadPIDFile()
	if err != nil {
		return 0, 0, false
	}
	_ = startTime

	if !IsProcessAlive(pid) {
		RemovePIDFile()
		return 0, 0, false
	}

	// Verify the port is actively listening
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond)
	if err != nil {
		RemovePIDFile()
		return 0, 0, false
	}
	conn.Close()
	return pid, port, true
}

// StartTransientProxy starts a proxy server in a background goroutine.
// Returns the port it's listening on and a listener/server close function.
func StartTransientProxy() (int, func(), error) {
	project, err := config.LoadProjectConfig()
	if err != nil || project.ProjectID == "" {
		return 0, nil, fmt.Errorf("no project configured — run 'agentsecrets init' first")
	}

	engine, err := NewEngine(project.ProjectID)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to initialize proxy engine: %w", err)
	}
	engine.Transient = true

	// Listen on a free TCP port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, nil, fmt.Errorf("failed to listen on a free port: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port

	// Generate and write session token securely for the transient session
	sessionToken, err := GenerateSessionToken()
	if err != nil {
		listener.Close()
		return 0, nil, fmt.Errorf("failed to generate session token: %w", err)
	}
	if err := WriteSessionToken(sessionToken); err != nil {
		listener.Close()
		return 0, nil, fmt.Errorf("failed to write session token: %w", err)
	}

	server := NewServer(port, engine)
	server.SetSessionToken(sessionToken)

	httpServer := &http.Server{
		Handler: server.mux,
	}

	go func() {
		_ = httpServer.Serve(listener)
	}()

	closeFunc := func() {
		if engine.Audit != nil {
			_ = engine.Audit.SyncUnpushedLogs()
		}
		// Graceful shutdown drains the in-flight request (the response may still
		// be streaming) instead of dropping it as httpServer.Close would.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
		_ = listener.Close()
	}

	return port, closeFunc, nil
}

// CallViaProxy sends a request to the running proxy server or starts a transient one if none is running.
func CallViaProxy(req CallRequest) (*CallResult, error) {
	_, port, running := IsProxyRunning()
	var closeFunc func()
	var err error

	if !running {
		var transPort int
		transPort, closeFunc, err = StartTransientProxy()
		if err != nil {
			return nil, fmt.Errorf("failed to start transient proxy: %w", err)
		}
		port = transPort
	}

	if closeFunc != nil {
		defer closeFunc()
	}

	proxyURL := fmt.Sprintf("http://127.0.0.1:%d/proxy", port)

	// Build HTTP request to the local proxy
	httpReq, err := http.NewRequest(req.Method, proxyURL, bytes.NewReader(req.Body))
	if err != nil {
		return nil, fmt.Errorf("failed to build proxy request: %w", err)
	}

	// Add pre-shared session token
	sessionToken, err := ReadSessionToken()
	if err == nil && sessionToken != "" {
		httpReq.Header.Set("X-AS-Session-Token", sessionToken)
	}

	// Add proxy headers
	httpReq.Header.Set("X-AS-Target-URL", req.TargetURL)
	if req.Method != "" {
		httpReq.Header.Set("X-AS-Method", req.Method)
	}
	if req.AgentID != "" {
		httpReq.Header.Set("X-AS-Agent-ID", req.AgentID)
	}

	// Pass token if we have it
	agentToken := req.AgentToken
	if agentToken == "" {
		agentToken = os.Getenv("AS_AGENT_TOKEN")
	}
	if agentToken != "" {
		httpReq.Header.Set("X-AS-Agent-Token", agentToken)
	}

	// Add injections
	for _, inj := range req.Injections {
		switch inj.Style {
		case "bearer":
			httpReq.Header.Set("X-AS-Inject-Bearer", inj.SecretKey)
		case "basic":
			httpReq.Header.Set("X-AS-Inject-Basic", inj.SecretKey)
		case "header":
			httpReq.Header.Set(fmt.Sprintf("X-AS-Inject-Header-%s", inj.Target), inj.SecretKey)
		case "query":
			httpReq.Header.Set(fmt.Sprintf("X-AS-Inject-Query-%s", inj.Target), inj.SecretKey)
		case "body":
			target := strings.ReplaceAll(inj.Target, ".", "-")
			httpReq.Header.Set(fmt.Sprintf("X-AS-Inject-Body-%s", target), inj.SecretKey)
		case "form":
			httpReq.Header.Set(fmt.Sprintf("X-AS-Inject-Form-%s", inj.Target), inj.SecretKey)
		}
	}

	// Add other non-AS headers
	for k, v := range req.Headers {
		if !strings.HasPrefix(strings.ToLower(k), "x-as-") {
			httpReq.Header.Set(k, v)
		}
	}

	client := &http.Client{
		Timeout: 60 * time.Second,
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to proxy: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response from proxy: %w", err)
	}

	// Build CallResult
	resultHeaders := make(map[string][]string)
	for k, v := range resp.Header {
		resultHeaders[k] = v
	}

	return &CallResult{
		StatusCode: resp.StatusCode,
		Headers:    resultHeaders,
		Body:       respBody,
	}, nil
}
