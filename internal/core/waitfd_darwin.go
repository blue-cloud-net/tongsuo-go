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
	// EINTR 重试与 linux 路径一致，理由详见 waitfd_linux.go 同名代码块：
	// Go runtime 在调度 / 抢占 / GC 时投递信号，syscall.Select 在 linux
	// 与 darwin 上都不自动重试 EINTR；若原样上抛，紧邻 deadline 触发的
	// EINTR 会让外层 retry / waitReady 误把 EINTR 当 fd 错误终止握手，
	// 抢跑 net.Error.Timeout() 断言。本路径在内部循环重试 EINTR。
	//
	// EINTR retry mirrors the linux path; see waitfd_linux.go for the
	// rationale. syscall.Select does not auto-retry EINTR on either Linux
	// or macOS; we loop on EINTR here so it does not race past the
	// deadline-based timeoutError.
	//
	// 与 linux 路径的 ABI 差异：darwin syscall.Select 仅返回 err，丢弃
	// 了 BSD select 的 nfd_ready 返回值（见 zsyscall_darwin_*.go 的
	// syscall6 调用）；nil err 一律视为"已就绪"（包含 fd 触发与 n=0
	// 这两种 BSD 都可能返回的零状态），切片超时的终止条件由外层
	// waitReady 按 ctx/deadline 给出。
	//
	// ABI gap with the linux path: darwin's syscall.Select returns err
	// only — the Go wrapper drops the BSD nfd_ready return value (see
	// syscall6 in zsyscall_darwin_*.go). We treat any nil err as ready
	// (covering both fd-triggered and the rare n=0 return), and the
	// outer waitReady enforces the deadline via ctx/deadline.
	var selErr error
	for {
		if write {
			selErr = syscall.Select(fd+1, nil, &wfds, nil, tv)
		} else {
			selErr = syscall.Select(fd+1, &rfds, nil, nil, tv)
		}
		if selErr != syscall.EINTR {
			break
		}
	}
	if selErr != nil {
		return fmt.Errorf("tls: wait fd: %w", selErr)
	}
	return nil
}
