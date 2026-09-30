//go:build linux || darwin

package core

import (
	"errors"
	"fmt"
	"syscall"
)

// DupFD 复制一个文件描述符，返回由调用方持有的**新**描述符。
//
// 用途：把底层 socket 交给 OpenSSL（`SSL_set_fd`）时，必须交出一份**自己持有**的
// 副本。否则交给 SSL 的只是「fd 号」，而上层 `net.Conn` 一关闭，该号码就会被内核
// 回收并可能分配给新连接 —— SSL 的 BIO 仍记着这个号码，之后的 `SSL_read` /
// `SSL_write` 就会读写**别的连接**（跨连接数据串扰、握手随机失败）。持有副本后，
// 该描述符在上述生命周期内不会被回收。
//
// 契约：返回的 fd 所有权归调用方，必须由调用方 `CloseFD`（本仓库由
// `(*SSLConn).Close` 负责）。`dup(2)` 共享同一 open file description，因此
// O_NONBLOCK 等状态不变。
//
// DupFD duplicates a file descriptor and returns a new descriptor owned by the
// caller.
//
// The reason is ownership: handing out a bare fd number to OpenSSL means the
// upper net.Conn can close it, after which the kernel may recycle that number for
// a brand-new connection while the SSL BIO still remembers it — subsequent
// SSL_read / SSL_write then touch another connection's socket (cross-connection
// crosstalk and intermittent handshake failures). Owning a duplicate removes that
// class of bug.
//
// The returned descriptor is owned by the caller and must be released with
// CloseFD. dup(2) shares the same open file description, so flags such as
// O_NONBLOCK are preserved.
func DupFD(fd int) (int, error) {
	dup, err := syscall.Dup(fd)
	if err != nil {
		return -1, fmt.Errorf("tls: dup fd %d: %w", fd, err)
	}
	return dup, nil
}

// ShutdownFD 关闭描述符上的双向传输（`shutdown(2)`，SHUT_RDWR）。
//
// 用途：连接关闭时立刻唤醒阻塞在 `select` / `recv` 上的在途 SSL 调用，并让对端
// 看到 FIN。`close(2)` 做不到这两点 —— 只要还有副本存在，套接字就不会关闭。
//
// 已断开或已关闭的描述符返回的错误被忽略（ENOTCONN / EBADF），本函数幂等。
//
// ShutdownFD shuts the descriptor down for both directions (shutdown(2) with
// SHUT_RDWR).
//
// It immediately wakes in-flight SSL calls blocked in select / recv and makes the
// peer observe a FIN — neither of which close(2) can do while a duplicate still
// holds the socket open. Errors for an already disconnected or closed descriptor
// (ENOTCONN / EBADF) are ignored, making the call idempotent.
func ShutdownFD(fd int) error {
	if err := syscall.Shutdown(fd, syscall.SHUT_RDWR); err != nil &&
		!errors.Is(err, syscall.ENOTCONN) && !errors.Is(err, syscall.EBADF) {
		return fmt.Errorf("tls: shutdown fd %d: %w", fd, err)
	}
	return nil
}

// CloseFD 关闭描述符。已关闭的描述符返回 nil（幂等）。
//
// CloseFD closes the descriptor. Closing an already closed descriptor returns nil,
// so the call is idempotent.
func CloseFD(fd int) error {
	if err := syscall.Close(fd); err != nil && !errors.Is(err, syscall.EBADF) {
		return fmt.Errorf("tls: close fd %d: %w", fd, err)
	}
	return nil
}
