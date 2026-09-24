//go:build tongsuocli

package tls

import (
	"bytes"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/asym"
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
		if tc, ok := conn.(*Conn); ok {
			if err := tc.Handshake(); err != nil {
				serverErr <- err
				return
			}
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

// mustKeyPEM 把 asym 私钥导出为 PEM。
//
// mustKeyPEM serializes an asym private key to PEM.
func mustKeyPEM(t *testing.T, key asym.PrivateKey) []byte {
	t.Helper()
	pem, err := key.MarshalPrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	return pem
}

// cliCipherID 把 `openssl ciphers -V` 里的 "0x13,0x01" 形式解析为 16 位 ID。
//
// cliCipherID parses the "0x13,0x01" form printed by `openssl ciphers -V` into
// a 16-bit ID.
func cliCipherID(t *testing.T, text string) (uint16, bool) {
	t.Helper()
	parts := strings.SplitN(text, ",", 2)
	if len(parts) != 2 {
		return 0, false
	}
	hi, err := strconv.ParseUint(strings.TrimPrefix(parts[0], "0x"), 16, 8)
	if err != nil {
		return 0, false
	}
	lo, err := strconv.ParseUint(strings.TrimPrefix(parts[1], "0x"), 16, 8)
	if err != nil {
		return 0, false
	}
	return uint16(hi)<<8 | uint16(lo), true
}

// TestCLICipherSuiteByName 与 `openssl ciphers -V` 逐件对拍 CipherSuiteByName：
// 逐行取「0xA,0xB - <Name>」，要求
//
//  1. 本库按名查到同一 ID；
//  2. 本库按该 ID 反查回同一 Name。
//
// 覆盖 CLI 默认名单里的**全部**套件（不抽样）。若 CLI 列出而本库查不到，
// 说明探测面比 CLI 窄，测试直接失败——这是本对拍的验收点。
//
// TestCLICipherSuiteByName cross-checks CipherSuiteByName against
// `openssl ciphers -V` line by line ("0xA,0xB - <Name>"), requiring that the
// library resolves the same ID from the name and the same name from the ID. It
// covers **every** suite in the CLI's default list rather than sampling: a name
// the CLI knows but the library cannot resolve fails the test, which is exactly
// what this interop check is for.
func TestCLICipherSuiteByName(t *testing.T) {
	if !testutil.OpenSSLAvailable() {
		t.Skip("Tongsuo openssl CLI not available")
	}
	out, err := exec.Command(testutil.OpenSSLBin(), "ciphers", "-V").Output()
	if err != nil {
		t.Fatalf("openssl ciphers -V: %v", err)
	}
	type entry struct {
		name string
		id   uint16
	}
	var entries []entry
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || !strings.HasPrefix(fields[0], "0x") {
			continue
		}
		id, ok := cliCipherID(t, fields[0])
		if !ok {
			continue
		}
		entries = append(entries, entry{name: fields[2], id: id})
	}
	if len(entries) == 0 {
		t.Fatal("openssl ciphers -V 未解析出任何套件")
	}
	t.Logf("openssl ciphers -V 共 %d 个套件", len(entries))

	for _, e := range entries {
		byName, err := CipherSuiteByName(e.name)
		if err != nil {
			t.Errorf("%s: CipherSuiteByName 未命中（openssl ID 0x%04x）: %v", e.name, e.id, err)
			continue
		}
		if byName.ID != e.id {
			t.Errorf("%s: 本库 ID 0x%04x, openssl 0x%04x", e.name, byName.ID, e.id)
		}
		byID, err := CipherSuiteByName(suiteIDText(e.id))
		if err != nil {
			t.Errorf("0x%04x (%s): 按 ID 反查失败: %v", e.id, e.name, err)
			continue
		}
		if byID.Name != e.name {
			t.Errorf("0x%04x: 本库按 ID 反查得 %q, openssl 为 %q", e.id, byID.Name, e.name)
		}
	}
}
