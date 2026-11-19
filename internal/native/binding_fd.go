//go:build linux || darwin

package native

/*
#include <fcntl.h>

static int X_fcntl_dupfd_cloexec(int fd) {
    return fcntl(fd, F_DUPFD_CLOEXEC, 0);
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
