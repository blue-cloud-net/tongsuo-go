//go:build darwin

// Per-OS implementation of waitFD for macOS.
//
// BSD select(2) 同样有 FD_SETSIZE=1024 限制；为统一避免越界，本实现
// 对 fd >= 1024 返回明确错误，等待引入 x/sys/unix 后改走 poll(2)。
//
// 与 linux 的最大差异：darwin 的 syscall.Select 只返回 err（Go 包装丢弃
// 了 BSD select 的 nfd_ready 返回值，见 zsyscall_darwin_*.go 的 syscall6
// 调用），无法用 n==0 精确判别"切片到期"；本实现改用墙钟 elapsed 判别，
// 详见 waitFD 内注释。
//
// Biggest divergence from the linux path: darwin's syscall.Select returns
// err only — the Go wrapper drops the BSD nfd_ready return value (see
// syscall6 in zsyscall_darwin_*.go), so the n==0 trick is unavailable and
// this file discriminates a slice timeout via wall-clock elapsed instead.
// See the comments inside waitFD.
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
// EINTR 与"本次切片到期"均返回 errWaitFDTimeout，与 linux 路径语义一致
// （linux 用 n==0 判别到期，darwin 用 elapsed 判别，见函数内注释）。
//
// waitFD blocks until fd becomes ready for read (write=false) or write
// (write=true), or until timeout elapses. fd >= 1024 returns a clear error
// rather than risking OOB. Both EINTR and an expired slice surface as
// errWaitFDTimeout, matching the linux contract (linux detects expiry via
// n==0, darwin via elapsed; see the comments inside the function).
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
	// Timeval 精度为微秒，向上取整：保证内核实际等待不短于请求值。
	// 下面的 elapsed 判据依赖这一点——若截断向下取整，实际等待可能
	// 短于 waited，到期返回会被误判成"fd 已就绪"。
	//
	// Timeval has microsecond resolution; round up so the kernel never
	// waits less than requested. The elapsed check below relies on it:
	// truncating down could make the real wait shorter than `waited`,
	// misreading a timeout as "fd ready".
	usecs := int64((timeout + time.Microsecond - 1) / time.Microsecond)
	waited := time.Duration(usecs) * time.Microsecond
	tv := &syscall.Timeval{
		Sec:  usecs / 1000000,
		Usec: int32(usecs % 1000000),
	}
	start := time.Now()
	// EINTR 处理与 linux 路径一致：把 EINTR 翻译成 errWaitFDTimeout，
	// 由外层 waitReady 按 ctx/deadline 重新计算剩余预算。详细理由与
	// 「不要在循环里重试 EINTR」的原因见 waitfd_linux.go 同名代码块。
	//
	// EINTR handling mirrors the linux path: translate EINTR to
	// errWaitFDTimeout so the outer waitReady recomputes the remaining
	// budget. See waitfd_linux.go for the full rationale; we deliberately
	// do NOT loop on EINTR because the kernel's tv-update behavior after
	// EINTR is platform-dependent and reusing tv would skew timing.
	var selErr error
	if write {
		selErr = syscall.Select(fd+1, nil, &wfds, nil, tv)
	} else {
		selErr = syscall.Select(fd+1, &rfds, nil, nil, tv)
	}
	if selErr == syscall.EINTR {
		return errWaitFDTimeout
	}
	if selErr != nil {
		return fmt.Errorf("tls: wait fd: %w", selErr)
	}
	// darwin 的 syscall.Select 只返回 err：Go 包装丢弃了 BSD select 的
	// nfd_ready 返回值（见 zsyscall_darwin_*.go 的 syscall6 调用），
	// "至少一个 fd 就绪"与"tv 到期"都是 nil err，无法从返回值区分。
	// select 只可能因这两种情况返回，因此「已耗时 >= 本次 tv」等价于
	// 「tv 到期」，用墙钟即可可靠判别。
	//
	// 缺这个判据时 waitFD 永远不会返回 errWaitFDTimeout，外层 waitReady
	// 的 deadline 终止条件随之失效：waitPlan 在 deadline 耗尽后给出
	// slice=0（本函数退化为 1μs 轮询且恒报"就绪"），调用方 Read / Write /
	// Connect 便陷入每秒数十万次的 SSL_* 重试死循环，CI 表现为
	// `panic: test timed out after 10m0s`。这是 darwin-only 的缺陷：
	// linux 用 select 的 n==0 精确判别，darwin 只能靠 elapsed。
	//
	// darwin's syscall.Select returns err only (the Go wrapper drops the
	// BSD nfd_ready return value — see syscall6 in zsyscall_darwin_*.go),
	// so "at least one fd ready" and "tv expired" both surface as nil.
	// Since select can only return for those two reasons, "elapsed >= the
	// tv we passed" is equivalent to "tv expired" — the wall clock is a
	// reliable discriminator. Without it waitFD can never report
	// errWaitFDTimeout, the outer waitReady deadline never fires (waitPlan
	// yields slice=0 once the deadline is exhausted, degrading this
	// function to a 1μs poll that always claims "ready"), and the
	// Read/Write/Connect retry loops spin endlessly — CI symptom:
	// `panic: test timed out after 10m0s`. Darwin-only gap: linux uses
	// select's n==0 for an exact answer, darwin must fall back to elapsed.
	if time.Since(start) >= waited {
		return errWaitFDTimeout
	}
	return nil
}
