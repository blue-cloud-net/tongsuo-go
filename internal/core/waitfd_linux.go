//go:build linux

// Per-OS implementation of waitFD for Linux.
//
// Linux syscall.Timeval 字段类型为 int64（Sec / Usec 都是），syscall.Select
// 返回 (int, error)；这两点与 macOS 不同，所以保持 file-per-OS 实现以
// 规避编译期类型差异。
//
// fd>=FD_SETSIZE 风险：syscall.FdSet.Bits 长度固定（1024 位 / 128 字节），
// 越界写会触发 panic 或内存破坏；目前实现对 fd >= 1024 返回明确错误，
// 等待引入 x/sys/unix 后改走 poll(2) 路径。
package core

import (
	"fmt"
	"syscall"
	"time"
)

// fdSetSize 是 syscall.FdSet 的位容量上限（FD_SETSIZE）。fd 大于等于
// 此值时 syscall.Select 无法安全处理，本实现直接报错以避免越界。
//
// fdSetSize is the FD_SETSIZE cap of syscall.FdSet (1024 on Linux).
// fds at or above this value cannot be handled by syscall.Select safely
// without an alternative syscall (poll/epoll); we surface a clear
// error instead of risking OOB.
const fdSetSize = 1024

// waitFD 等待 fd 可读（write=false）或可写（write=true），最长 timeout 时间。
// timeout <= 0 退化为 1μs 立即超时。fd >= FD_SETSIZE 直接返回明确错误。
//
// waitFD blocks until fd becomes ready for read (write=false) or write
// (write=true), or until timeout elapses. timeout <= 0 reduces to a
// near-immediate poll. fd >= 1024 returns a clear error rather than
// risking OOB on syscall.FdSet.
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
		Usec: int64((timeout % time.Second) / time.Microsecond),
	}
	n, err := func() (int, error) {
		if write {
			return syscall.Select(fd+1, nil, &wfds, nil, tv)
		}
		return syscall.Select(fd+1, &rfds, nil, nil, tv)
	}()
	if err != nil {
		return fmt.Errorf("tls: wait fd: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("tls: wait fd timeout")
	}
	return nil
}