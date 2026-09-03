//go:build linux

// Per-OS implementation of waitFD for Linux.
//
// The Linux syscall.Timeval fields are int64 (Sec and Usec both) and
// syscall.Select returns (int, error); these differ from macOS, so
// keeping the implementation file-per-OS is the simplest way to stay
// type-correct across platforms without runtime dispatch.
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
		Usec: int64((waitFDTimeout % time.Second) / time.Microsecond),
	}
	n, err := func() (int, error) {
		if write {
			return syscall.Select(fd+1, nil, &wfds, nil, timeout)
		}
		return syscall.Select(fd+1, &rfds, nil, nil, timeout)
	}()
	if err != nil {
		return fmt.Errorf("tls: wait fd: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("tls: wait fd timeout")
	}
	return nil
}
