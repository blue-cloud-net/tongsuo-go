//go:build tongsuocli

package tls

import (
	"bytes"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/internal/testutil"
)

// TestCLIOurClientToOpenSSLServer 验证我们的 NTLS 客户端可与 openssl s_server
// （国密双证书）完成握手与数据交互。
func TestCLIOurClientToOpenSSLServer(t *testing.T) {
	cfg := testNTLSConfig(t)

	dir := t.TempDir()
	write := func(name string, data []byte) string {
		p := dir + "/" + name
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	signCertFile := write("sign.pem", mustPEM(t, cfg.SignCert))
	encCertFile := write("enc.pem", mustPEM(t, cfg.EncCert))
	signKeyFile := write("signkey.pem", mustKeyPEM(t, cfg.SignKey))
	encKeyFile := write("enckey.pem", mustKeyPEM(t, cfg.EncKey))

	// 获取空闲端口。
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	cmd := exec.Command(testutil.OpenSSLBin(), "s_server",
		"-ntls", "-enable_ntls", "-accept", addr,
		"-sign_cert", signCertFile, "-sign_key", signKeyFile,
		"-enc_cert", encCertFile, "-enc_key", encKeyFile,
		"-www", "-quiet")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start s_server: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	// 等待服务就绪（轮询重试握手）。
	var conn net.Conn
	var dialErr error
	for i := 0; i < 10; i++ {
		conn, dialErr = Dial("tcp", addr, &Config{NTLS: true})
		if dialErr == nil {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if dialErr != nil {
		t.Fatalf("dial after retries: %v\ns_server stderr: %s", dialErr, stderr.String())
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("GET / HTTP/1.0\r\nHost: test\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Contains(buf[:n], []byte("200 ok")) {
		t.Fatalf("unexpected response: %q", buf[:n])
	}
}

// TestCLIOpenSSLClientToOurServer 验证官方 openssl s_client（-ntls -enable_ntls）
// 可与我们实现的 NTLS 服务器完成握手与数据交互。
func TestCLIOpenSSLClientToOurServer(t *testing.T) {
	cfg := testNTLSConfig(t)
	server, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	serverErr := make(chan error, 1)
	got := make(chan []byte, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		conn, err := server.Accept(raw)
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		buf := make([]byte, 512)
		n, err := conn.Read(buf)
		if err != nil {
			serverErr <- err
			return
		}
		got <- buf[:n]
	}()

	cmd := exec.Command(testutil.OpenSSLBin(), "s_client",
		"-ntls", "-enable_ntls", "-quiet", "-connect", ln.Addr().String())
	cmd.Stdin = bytes.NewBufferString("ping from openssl s_client\n")
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start s_client: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case data := <-got:
		if !bytes.Contains(data, []byte("ping from openssl")) {
			t.Fatalf("unexpected server-received data: %q", data)
		}
	case err := <-serverErr:
		t.Fatalf("server: %v\ns_client stderr: %s", err, stderr.String())
	case err := <-done:
		t.Fatalf("s_client exited early: %v\ns_client stderr: %s", err, stderr.String())
	case <-time.After(10 * time.Second):
		t.Fatalf("timeout waiting for handshake\no: %q\nerr: %s", out.String(), stderr.String())
	}

	select {
	case err := <-done:
		if err != nil {
			t.Logf("s_client exit: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("s_client did not exit")
	}
}

func mustPEM(t *testing.T, cert interface{ MarshalPEM() ([]byte, error) }) []byte {
	t.Helper()
	pem, err := cert.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	return pem
}

func mustKeyPEM(t *testing.T, key interface{ MarshalPEM() ([]byte, error) }) []byte {
	t.Helper()
	pem, err := key.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	return pem
}
