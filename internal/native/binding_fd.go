//go:build linux || darwin

package native

/*
#include <fcntl.h>
#include <errno.h>
#include <poll.h>

static int X_fcntl_dupfd_cloexec(int fd) {
    return fcntl(fd, F_DUPFD_CLOEXEC, 0);
}

static int X_poll_fd(int fd, int write, int timeout_ms) {
    struct pollfd pfd = { .fd = fd, .events = write ? POLLOUT : POLLIN };
    int n = poll(&pfd, 1, timeout_ms);
    if (n > 0 && (pfd.revents & POLLNVAL) != 0) {
        errno = EBADF;
        return -1;
    }
    return n;
}
*/
import "C"

// X_fcntl_dupfd_cloexec 原子复制文件描述符，并将副本标记为 exec 时关闭。
//
// X_fcntl_dupfd_cloexec atomically duplicates a descriptor with close-on-exec set.
func X_fcntl_dupfd_cloexec(fd int) (int, error) {
	dup, err := C.X_fcntl_dupfd_cloexec(C.int(fd))
	if dup < 0 {
		return -1, err
	}
	return int(dup), nil
}

// X_poll_fd 等待单个文件描述符，返回是否已就绪或原生错误。
//
// X_poll_fd waits on one descriptor and reports readiness or a native error.
func X_poll_fd(fd int, write bool, timeoutMS int) (bool, error) {
	var event C.int
	if write {
		event = 1
	}
	ready, err := C.X_poll_fd(C.int(fd), event, C.int(timeoutMS))
	if ready < 0 {
		return false, err
	}
	return ready > 0, nil
}
