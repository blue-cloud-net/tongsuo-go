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
// 超时返回 errWaitFDTimeout（可经 errors.Is 判别），调用方据此决定"继续重试"
// 还是"终止"——切片超时不等于连接失败，见 waitPlan 注释。
//
// waitFD blocks until fd becomes ready for read (write=false) or write
// (write=true), or until timeout elapses. timeout <= 0 reduces to a
// near-immediate poll. fd >= 1024 returns a clear error rather than
// risking OOB on syscall.FdSet. A timeout is reported as errWaitFDTimeout.
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
	// Go runtime 在调度 / 抢占 / GC 时会向 syscall 阻塞线程投递信号，
	// syscall.Select 在 Linux 与 macOS 上均不自动重试 EINTR。若原样上
	// 抛，紧邻 deadline 触发的 EINTR 会让外层 retry / waitReady 误把
	// EINTR 当 fd 错误终止握手，抢跑 net.Error.Timeout() 断言。把 EINTR
	// 当 nil（视为 fd 已就绪）则会立刻让外层重试 SSL_*，而 fd 实际并
	// 未就绪 → 错误地驱动 SSL_* 调用，与对端时序错位甚至产生 bad record
	// MAC；高并发 / 高信号频率下还会把外层 SSL_* 驱动成紧密 spin。
	//
	// 正确语义：EINTR 表示本次切片被信号打断、tv 已被部分消耗，等价于
	// 「切片到期」——把 EINTR 直接翻译成 errWaitFDTimeout，外层 waitReady
	// 会基于 deadline 计算剩余预算并按需转 timeoutError。这避免「把
	// EINTR 当就绪」的时序错位，也不需要在循环里复用 tv（EINTR 后内核
	// 是否更新 tv 跨平台行为不一致，复用会引入微妙偏差）。
	//
	// Go's runtime signals the syscall thread during scheduling, preemption
	// and GC; syscall.Select does NOT auto-retry EINTR on either Linux or
	// macOS. If EINTR surfaced unchanged, an EINTR that races the deadline
	// would terminate the handshake as a generic fd error and defeat the
	// net.Error.Timeout() assertion. Treating EINTR as nil ("fd ready")
	// would instead make the outer SSL_* retry run on an fd that is not
	// actually ready, racing the peer's message boundary (bad record MAC)
	// and spinning under heavy signal load. The correct semantics: EINTR
	// means the slice was cut short by a signal — translate it to
	// errWaitFDTimeout so the outer waitReady recomputes the remaining
	// budget via waitPlan (and turns into a timeoutError when terminal).
	// We avoid looping on EINTR because the kernel's tv-update behavior
	// after EINTR is platform-dependent and reusing tv would skew timing.
	var (
		n   int
		err error
	)
	if write {
		n, err = syscall.Select(fd+1, nil, &wfds, nil, tv)
	} else {
		n, err = syscall.Select(fd+1, &rfds, nil, nil, tv)
	}
	if err == syscall.EINTR {
		return errWaitFDTimeout
	}
	if err != nil {
		return fmt.Errorf("tls: wait fd: %w", err)
	}
	if n == 0 {
		return errWaitFDTimeout
	}
	return nil
}
