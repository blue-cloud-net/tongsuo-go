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
//
// waitFD blocks until fd becomes ready for read (write=false) or write
// (write=true), or until timeout elapses. fd >= 1024 returns a clear
// error rather than risking OOB.
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
	var selErr error
	if write {
		selErr = syscall.Select(fd+1, nil, &wfds, nil, tv)
	} else {
		selErr = syscall.Select(fd+1, &rfds, nil, nil, tv)
	}
	if selErr != nil {
		return fmt.Errorf("tls: wait fd: %w", selErr)
	}
	return nil
}