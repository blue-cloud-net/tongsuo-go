//go:build darwin

// Per-OS implementation of waitFD for macOS.
//
// 与 Linux 路径有两点差异：
//
//  1. syscall.Timeval 字段类型不同：darwin 上 Sec int64 / Usec int32，
//     Linux 上两者都是 int64。本文件直接把 waitFDTimeout 拆成
//     秒 + 微秒两个值，分别写入 Timeval 字段，避免任何 int->int32
//     隐式转换在编译期报"cannot use ... as int32"。
//
//  2. syscall.Select 返回签名不同：darwin 上返回 (err error)，
//     Linux 上返回 (n int, err error)。darwin 路径丢弃 BSD select(2)
//     返回的就绪 fd 数，但 BSD 语义下 timeout 触发时 select 直接返回 0
//     且 errno 不被设置（与 Linux 行为一致），所以 selErr==nil 即视为
//     "select 成功返回（无论就绪或超时）"；上层调用方只关心"出错或
//     就绪可以重试"，超时由内核保证 deadline 触发，无需 Go 这层再计
//     时。这是与 Linux 路径唯一的可观察差异。
package core

import (
	"fmt"
	"syscall"
	"time"
)

// waitFD 等待 fd 可读（write=false）或可写（write=true）。
//
// waitFD blocks until fd becomes ready for read (write=false) or write
// (write=true) and returns any syscall failure.
func waitFD(fd int, write bool) error {
	var rfds, wfds syscall.FdSet
	if write {
		wfds.Bits[fd/64] |= 1 << (uint(fd) % 64)
	} else {
		rfds.Bits[fd/64] |= 1 << (uint(fd) % 64)
	}
	timeout := &syscall.Timeval{
		Sec:  int64(waitFDTimeout / time.Second),
		Usec: int32((waitFDTimeout % time.Second) / time.Microsecond),
	}
	var selErr error
	if write {
		selErr = syscall.Select(fd+1, nil, &wfds, nil, timeout)
	} else {
		selErr = syscall.Select(fd+1, &rfds, nil, nil, timeout)
	}
	if selErr != nil {
		return fmt.Errorf("tls: wait fd: %w", selErr)
	}
	return nil
}
