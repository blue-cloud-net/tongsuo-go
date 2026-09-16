//go:build darwin

// Per-OS implementation of waitFD for macOS.
//
// BSD select(2) 同样有 FD_SETSIZE=1024 限制；为统一避免越界，本实现
// 对 fd >= 1024 返回明确错误，等待引入 x/sys/unix 后改走 poll(2)。
package core

import (
	"fmt"
	"syscall"
	"time"
)

// fdSetSize 是 macOS 上 FD_SETSIZE 的位容量上限（1024）。fd >= 此值时
// syscall.Select 无法安全处理，本实现直接报错。
//
// fdSetSize is the FD_SETSIZE cap (1024) on macOS; fds at or above
// this value cannot be handled by syscall.Select safely without
// poll/kqueue.
const fdSetSize = 1024

// waitFD 等待 fd 可读（write=false）或可写（write=true），最长 timeout 时间。
// timeout <= 0 退化为 1μs 立即超时。fd >= FD_SETSIZE 直接返回明确错误。
// Select 返回 0（本次切片超时）时返回 errWaitFDTimeout，与 linux 路径一致。
//
// waitFD blocks until fd becomes ready for read (write=false) or write
// (write=true), or until timeout elapses. fd >= 1024 returns a clear
// error rather than risking OOB. A Select return of 0 (slice timeout)
// surfaces as errWaitFDTimeout, matching the linux implementation so the
// outer retry loop has an actual upper bound instead of silently
// retrying on a kernel-side timeout.
func waitFD(fd int, write bool, timeout time.Duration) error {
	if fd < 0 {
		return fmt.Errorf("tls: wait fd: invalid fd %d", fd)
	}
	if timeout <= 0 {
		timeout = time.Microsecond
	}
	if fd >= fdSetSize {
		return fmt.Errorf("tls: wait fd: fd %d >= FD_SETSIZE; rebuild with x/sys/unix poll(2) support", fd)
	}
	var rfds, wfds syscall.FdSet
	if write {
		wfds.Bits[fd/64] |= 1 << (uint(fd) % 64)
	} else {
		rfds.Bits[fd/64] |= 1 << (uint(fd) % 64)
	}
	tv := &syscall.Timeval{
		Sec:  int64(timeout / time.Second),
		Usec: int32((timeout % time.Second) / time.Microsecond),
	}
	var (
		n      int
		selErr error
	)
	if write {
		n, selErr = syscall.Select(fd+1, nil, &wfds, nil, tv)
	} else {
		n, selErr = syscall.Select(fd+1, &rfds, nil, nil, tv)
	}
	if selErr != nil {
		return fmt.Errorf("tls: wait fd: %w", selErr)
	}
	// Select 返回 0 表示本次切片超时：返回 errWaitFDTimeout 与 linux 路径保持
	// 一致，交由 waitReady 按"是否为终止切片"决定继续重试还是上抛 timeoutError。
	// 若把 n == 0 当成"就绪"返回 nil，retry 会立刻重试 SSL_* 并再次空转，
	// 退化成忙轮询而非按切片节奏轮询。
	//
	// A Select return of 0 means this slice timed out: return errWaitFDTimeout to
	// match the linux path, letting waitReady decide between retrying and
	// surfacing a timeoutError. Treating n == 0 as "ready" would make retry spin
	// in a busy loop rather than polling at the slice cadence.
	if n == 0 {
		return errWaitFDTimeout
	}
	return nil
}
