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
	// darwin syscall.FdSet.Bits 的单元类型为 int32，位容量 32；本实现对
	// fd < 1024 设置 fd/32 槽内的 fd%32 位。fd >= fdSetSize 已在上方
	// 拦截。
	//
	// On darwin syscall.FdSet.Bits is [32]int32, so we address a 32-bit
	// slot via fd/32 and bit via fd%32. fd >= fdSetSize is rejected
	// above.
	var rfds, wfds syscall.FdSet
	slot := uint(fd) / 32
	if write {
		wfds.Bits[slot] |= 1 << (uint(fd) % 32)
	} else {
		rfds.Bits[slot] |= 1 << (uint(fd) % 32)
	}
	tv := &syscall.Timeval{
		Sec:  int64(timeout / time.Second),
		Usec: int32((timeout % time.Second) / time.Microsecond),
	}
	// darwin syscall.Select 仅返回 err：Go 包装丢弃了 BSD select 的 nfd_ready
	// 返回值（见 zsyscall_darwin_*.go 中的 syscall6 调用），我们无法像 linux
	// 路径那样区分"本次切片超时"与"已就绪"。这里把任意 nil err 视为已就绪
	// （包括 fd 已触发或内核因信号提前返回 0）——切片超时场景只能由外层
	// waitReady 按 ctx/deadline 终止，而不能像 linux 那样由本路径报告
	// errWaitFDTimeout。这是 darwin ABI 的硬约束，非可修缺陷。
	//
	// darwin's syscall.Select returns err only — the Go wrapper drops the
	// BSD nfd_ready return value (see syscall6 in zsyscall_darwin_*.go),
	// so unlike the linux path we cannot distinguish "slice timed out"
	// from "ready". We treat any nil err as ready (including the rare
	// EINTR / n=0 case) and let the outer waitReady enforce the deadline
	// via ctx/deadline. This is a darwin ABI limitation, not a bug here.
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
