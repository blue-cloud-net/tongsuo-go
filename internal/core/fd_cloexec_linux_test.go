package core

import (
	"os"
	"syscall"
	"testing"
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
