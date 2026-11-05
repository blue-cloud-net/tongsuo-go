package core

import (
	"errors"
	"syscall"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/internal/native"
)

func sslTestSocket(t *testing.T) int {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Close(fds[1]) })
	if err := syscall.SetNonblock(fds[0], true); err != nil {
		_ = syscall.Close(fds[0])
		t.Fatal(err)
	}
	return fds[0]
}

func requireSSLFDClosed(t *testing.T, fd int) {
	t.Helper()
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); !errors.Is(err, syscall.EBADF) {
		t.Fatalf("owned socket %d was not closed: %v", fd, err)
	}
}

// TestSSLConnConstructorOwnsFD 验证构造失败仍释放已接管的 socket。
//
// TestSSLConnConstructorOwnsFD verifies failed construction closes the transferred socket.
func TestSSLConnConstructorOwnsFD(t *testing.T) {
	fd := sslTestSocket(t)
	if conn, err := NewSSLConn(nil, fd); err == nil || conn != nil {
		t.Fatal("nil context accepted")
	}
	requireSSLFDClosed(t, fd)
}

// TestSSLConnReleaseOwnsFD 验证 Close 和 Handle 释放路径均关闭 socket 副本。
//
// TestSSLConnReleaseOwnsFD verifies Close and Handle release both close the socket duplicate.
func TestSSLConnReleaseOwnsFD(t *testing.T) {
	for _, releaseHandle := range []bool{false, true} {
		ctx, err := NewClientTLSContext()
		if err != nil {
			t.Fatal(err)
		}
		fd := sslTestSocket(t)
		conn, err := NewSSLConn(ctx, fd)
		if err != nil {
			_ = ctx.Close()
			t.Fatal(err)
		}
		// SSL_new retains the context; closing its original owner must be safe.
		if err := ctx.Close(); err != nil {
			t.Fatal(err)
		}
		if releaseHandle {
			// Exercise exactly the same destructor used by Handle.finalize without
			// depending on the nondeterministic timing of garbage collection.
			if err := conn.handle.Close(); err != nil {
				t.Fatal(err)
			}
		} else {
			if err := conn.Close(); err != nil {
				t.Fatal(err)
			}
		}
		requireSSLFDClosed(t, fd)
		if err := conn.Close(); err != nil {
			t.Fatal(err)
		}
		if err := conn.Connect(); err == nil {
			t.Fatal("released SSL accepted handshake")
		}
	}
}

// TestSSLConnCapturesSyscallError 验证断开 socket 的真实 errno 可跨线程解包。
//
// TestSSLConnCapturesSyscallError verifies disconnected socket errno remains available across threads.
func TestSSLConnCapturesSyscallError(t *testing.T) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.SetNonblock(fds[0], true); err != nil {
		_ = syscall.Close(fds[0])
		_ = syscall.Close(fds[1])
		t.Fatal(err)
	}
	if err := syscall.Close(fds[1]); err != nil {
		_ = syscall.Close(fds[0])
		t.Fatal(err)
	}
	ctx, err := NewClientTLSContext()
	if err != nil {
		_ = syscall.Close(fds[0])
		t.Fatal(err)
	}
	defer ctx.Close()
	conn, err := NewSSLConn(ctx, fds[0])
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	err = conn.Connect()
	var failure *SSLOperationError
	if !errors.As(err, &failure) || failure.SSLCode != native.SSLErrorSyscall || !(errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET)) {
		t.Fatalf("lost syscall details: %v", err)
	}
}
