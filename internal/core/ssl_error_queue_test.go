//go:build linux || darwin

package core

import (
	"errors"
	"os"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/internal/native"
)

// TestNTLSReadIgnoresStaleErrors 验证 NTLS 读取不会把旧线程错误当作本次连接故障。
//
// TestNTLSReadIgnoresStaleErrors checks that NTLS reads do not treat stale thread errors as connection failures.
func TestNTLSReadIgnoresStaleErrors(t *testing.T) {
	serverCtx, err := NewNTLSContext()
	if err != nil {
		t.Fatal(err)
	}
	defer serverCtx.Close()
	for i, usage := range []string{"critical,digitalSignature", "critical,keyEncipherment,dataEncipherment,keyAgreement"} {
		key, err := GenerateSM2Key()
		if err != nil {
			t.Fatal(err)
		}
		defer key.Close()
		cert, err := NewCertificate()
		if err != nil {
			t.Fatal(err)
		}
		defer cert.Close()
		name, err := NewName()
		if err != nil {
			t.Fatal(err)
		}
		defer name.Close()
		for _, err := range []error{name.AddEntry("CN", "ntls-regression"), cert.SetVersion(2), cert.SetSerial(int64(i + 1)), cert.SetIssuer(name), cert.SetSubject(name), cert.SetValidity(time.Now().Add(-time.Hour), time.Now().Add(time.Hour)), cert.SetPublicKey(key), cert.AddBasicConstraints(true), cert.AddKeyUsage(usage), cert.Sign(key, SM3())} {
			if err != nil {
				t.Fatal(err)
			}
		}
		if i == 0 {
			err = serverCtx.UseSignCertificate(cert, key)
		} else {
			err = serverCtx.UseEncryptCertificate(cert, key)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	clientCtx, err := NewNTLSContext()
	if err != nil {
		t.Fatal(err)
	}
	defer clientCtx.Close()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, fd := range fds {
		if err := syscall.SetNonblock(fd, true); err != nil {
			syscall.Close(fds[0])
			syscall.Close(fds[1])
			t.Fatal(err)
		}
	}
	server, err := NewSSLConn(serverCtx, fds[0])
	if err != nil {
		syscall.Close(fds[1])
		t.Fatal(err)
	}
	defer server.Close()
	client, err := NewSSLConn(clientCtx, fds[1])
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server.SetDeadline(time.Now().Add(5 * time.Second))
	client.SetDeadline(time.Now().Add(5 * time.Second))
	done := make(chan error, 1)
	go func() { done <- server.Accept() }()
	if err := client.Connect(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	defer native.ERR_clear_error()
	if native.SSL_CTX_set_cipher_list(serverCtx.handle.Ptr(), "INVALID-CIPHER-FOR-REGRESSION") {
		t.Fatal("invalid cipher accepted")
	}
	server.SetDeadline(time.Now().Add(20 * time.Millisecond))
	_, err = server.Read(make([]byte, 1))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Read = %v, want timeout while peer sends no application data", err)
	}
}
