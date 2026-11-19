//go:build linux || darwin

package core

import (
	"errors"
	"fmt"
	"math"
	"syscall"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/internal/native"
)

// waitFD performs one bounded readiness wait. The caller recomputes the
// remaining deadline or cancellation budget if the wait expires or gets interrupted.
func waitFD(fd int, write bool, timeout time.Duration) error {
	if fd < 0 || fd > math.MaxInt32 {
		return fmt.Errorf("tls: wait fd: invalid fd %d", fd)
	}
	ms := timeout / time.Millisecond
	if timeout > 0 && timeout%time.Millisecond != 0 {
		ms++
	}
	ms = min(max(ms, 0), math.MaxInt32)
	ready, err := native.X_poll_fd(fd, write, int(ms))
	if errors.Is(err, syscall.EINTR) || (err == nil && !ready) {
		return errWaitFDTimeout
	}
	if err != nil {
		return fmt.Errorf("tls: wait fd: %w", err)
	}
	return nil
}
