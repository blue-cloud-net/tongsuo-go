package core

import (
	"os"
	"syscall"
	"testing"
	"time"
)

func TestDupFDHasCloseOnExec(t *testing.T) {
	file, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	fd, err := DupFD(int(file.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	defer CloseFD(fd)
	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFD, 0)
	if errno != 0 {
		t.Fatal(errno)
	}
	if flags&syscall.FD_CLOEXEC == 0 {
		t.Fatal("duplicate does not have FD_CLOEXEC")
	}
}

// TestWaitHighFD 验证超出 select 位图范围的合法描述符可等待。
//
// TestWaitHighFD verifies readiness for a valid descriptor beyond a select bitmap.
func TestWaitHighFD(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	const highDescriptor = 1024
	fd, _, errno := syscall.Syscall(syscall.SYS_FCNTL, reader.Fd(), syscall.F_DUPFD_CLOEXEC, highDescriptor)
	if errno == syscall.EINVAL || errno == syscall.EMFILE {
		t.Skipf("descriptor limit prevents allocating a high fd: %v", errno)
	}
	if errno != 0 {
		t.Fatal(errno)
	}
	defer CloseFD(int(fd))
	if _, err := writer.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := waitFD(int(fd), false, time.Second); err != nil {
		t.Fatal(err)
	}
}
