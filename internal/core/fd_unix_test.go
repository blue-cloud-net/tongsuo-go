//go:build linux || darwin

package core

import (
	"errors"
	"syscall"
	"testing"
	"time"
)

// TestDupFDKeepsSocketAlive 验证 DupFD 的副本独立于原描述符：关闭原 fd 后副本仍可用。
//
// 这是 P1011 修复的核心契约 —— 交给 OpenSSL 的必须是**自己持有**的副本，否则上层
// net.Conn 一关闭，fd 号就会被内核回收给新连接，SSL 随后就会读写别的连接。
//
// TestDupFDKeepsSocketAlive verifies that the DupFD duplicate is independent of the
// original descriptor: the duplicate stays usable after the original is closed.
//
// This is the core contract of the P1011 fix — OpenSSL must be given a duplicate we
// own, otherwise closing the upper net.Conn lets the kernel recycle the fd number
// for a new connection and the SSL layer starts touching another connection's
// socket.
func TestDupFDKeepsSocketAlive(t *testing.T) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	orig, peer := fds[0], fds[1]
	defer func() { _ = syscall.Close(peer) }()

	dup, err := DupFD(orig)
	if err != nil {
		t.Fatalf("DupFD: %v", err)
	}
	if dup == orig {
		t.Fatal("DupFD must return a distinct descriptor")
	}

	// 关闭原 fd：副本必须仍然有效（可 fstat、可读到对端写入的数据）。
	if err := syscall.Close(orig); err != nil {
		t.Fatalf("close orig: %v", err)
	}
	if _, err := syscall.Fstat(dup); err != nil {
		t.Fatalf("duplicate should stay valid after closing the original: %v", err)
	}
	if _, err := syscall.Write(peer, []byte("x")); err != nil {
		t.Fatalf("write peer: %v", err)
	}
	buf := make([]byte, 1)
	if _, err := syscall.Read(dup, buf); err != nil {
		t.Fatalf("read duplicate: %v", err)
	}

	// 关闭副本后立即失效；重复关闭返回 nil（幂等）。
	if err := CloseFD(dup); err != nil {
		t.Fatalf("CloseFD: %v", err)
	}
	if _, err := syscall.Fstat(dup); !errors.Is(err, syscall.EBADF) {
		t.Fatalf("fstat after CloseFD = %v, want EBADF", err)
	}
	if err := CloseFD(dup); err != nil {
		t.Fatalf("CloseFD twice: %v", err)
	}
}

// TestShutdownFDWakesBlockedRead 验证 shutdown(2) 能唤醒阻塞中的 read。
//
// tls.Conn.Close 依赖该行为：给 SSL 的是 dup 副本，单靠 close(raw) 既不会关闭套接字
// 也唤不醒在途等待，所以必须显式 shutdown。
//
// TestShutdownFDWakesBlockedRead verifies that shutdown(2) wakes a blocked read.
//
// tls.Conn.Close relies on it: the SSL handle holds a dup, so closing the raw
// socket alone neither closes the connection nor wakes an in-flight wait.
func TestShutdownFDWakesBlockedRead(t *testing.T) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	reader, peer := fds[0], fds[1]
	defer func() { _ = syscall.Close(peer) }()

	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 1)
		// 阻塞读：对端不写数据，只有 shutdown 或 close(reader) 能让它返回。
		n, rerr := syscall.Read(reader, buf)
		if n == 0 && rerr == nil {
			rerr = errors.New("EOF")
		}
		done <- rerr
	}()

	// 给 read 一点时间进入阻塞。
	time.Sleep(50 * time.Millisecond)
	start := time.Now()
	if err := ShutdownFD(reader); err != nil {
		t.Fatalf("ShutdownFD: %v", err)
	}
	select {
	case <-done:
		if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
			t.Fatalf("shutdown did not wake the blocked read promptly (took %v)", elapsed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ShutdownFD did not wake the blocked read")
	}
	_ = CloseFD(reader)
}

// TestSSLConnCloseClosesDupFD 验证 *SSLConn.Close 会关闭它持有的 socket 副本
// （不泄漏描述符），并保持幂等。
//
// TestSSLConnCloseClosesDupFD verifies that *SSLConn.Close releases the socket
// duplicate it owns (no descriptor leak) and stays idempotent.
func TestSSLConnCloseClosesDupFD(t *testing.T) {
	ctx, err := NewClientTLSContext()
	if err != nil {
		t.Fatalf("NewClientTLSContext: %v", err)
	}
	defer func() { _ = ctx.Close() }()

	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	defer func() { _ = syscall.Close(fds[1]) }()

	dup, err := DupFD(fds[0])
	if err != nil {
		t.Fatalf("DupFD: %v", err)
	}
	// 原 fd 交出去后由 SSLConn 持有副本，这里先关掉原 fd（模拟上层 net.Conn 关闭）。
	if err := syscall.Close(fds[0]); err != nil {
		t.Fatalf("close orig: %v", err)
	}

	ssl, err := NewSSLConn(ctx, dup)
	if err != nil {
		t.Fatalf("NewSSLConn: %v", err)
	}
	if err := ssl.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := syscall.Fstat(dup); !errors.Is(err, syscall.EBADF) {
		t.Fatalf("SSLConn.Close must close the duplicate it owns; fstat = %v, want EBADF", err)
	}
	// 幂等：重复 Close / 关闭后再 Stop 都不应 panic 或报错。
	if err := ssl.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	ssl.Stop()
}
