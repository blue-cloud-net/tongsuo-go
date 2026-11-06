package core

import (
	"errors"
	"fmt"
	"io"
	"runtime"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/internal/native"
)

// SSLOperationError 保存原生调用线程上的完整失败信息。
//
// SSLOperationError preserves failure details captured on the native call's thread.
type SSLOperationError struct {
	// Op 为原生操作名。
	//
	// Op is the native operation name.
	Op string
	// SSLCode 是 SSL_get_error 返回值。
	//
	// SSLCode is the result of SSL_get_error.
	SSLCode int
	// VerifyCode 是对端证书验证结果。
	//
	// VerifyCode is the peer certificate verification result.
	VerifyCode int
	// Codes 是原始错误队列的副本。
	//
	// Codes is a copy of the original error queue.
	Codes []uint64
	// Err 是可解包的原生错误。
	//
	// Err is the wrapped native error.
	Err error
}

// Error 返回操作失败详情。
//
// Error returns the operation failure details.
func (e *SSLOperationError) Error() string { return fmt.Sprintf("tls: %s: %v", e.Op, e.Err) }

// Unwrap 返回底层错误。
//
// Unwrap returns the underlying error.
func (e *SSLOperationError) Unwrap() error { return e.Err }

func deadlineValue(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()
}

// SetReadDeadline 仅更新读取期限，不改变写入期限。
//
// SetReadDeadline changes only the read deadline, leaving writes unchanged.
func (s *SSLConn) SetReadDeadline(t time.Time) error {
	if s == nil || s.handle == nil || s.handle.IsClosed() {
		return errors.New("tls: SSL closed")
	}
	s.readDeadline.Store(deadlineValue(t))
	return nil
}

// SetWriteDeadline 仅更新写入期限，不改变读取期限。
//
// SetWriteDeadline changes only the write deadline, leaving reads unchanged.
func (s *SSLConn) SetWriteDeadline(t time.Time) error {
	if s == nil || s.handle == nil || s.handle.IsClosed() {
		return errors.New("tls: SSL closed")
	}
	s.writeDeadline.Store(deadlineValue(t))
	return nil
}

func (s *SSLConn) runSSL(op string, buf []byte) error { _, err := s.runIO(op, buf); return err }

func (s *SSLConn) runIO(op string, buf []byte) (n int, err error) {
	if s == nil {
		return 0, errors.New("tls: connection closed")
	}
	if op == "SSL_read" {
		s.readMu.Lock()
		defer s.readMu.Unlock()
	}
	if op == "SSL_write" {
		s.writeMu.Lock()
		defer s.writeMu.Unlock()
		if s.writeErr != nil {
			return 0, s.writeErr
		}
	}
	// SSL_read/SSL_write take signed C int lengths; process larger slices in chunks.
	const maxSSLBuffer = 1<<31 - 1
	if len(buf) > maxSSLBuffer {
		buf = buf[:maxSSLBuffer]
	}
	stepped := false
	defer func() {
		if op == "SSL_write" && stepped && err != nil {
			s.writeErr = err
		}
	}()
	if (op == "SSL_read" || op == "SSL_write") && len(buf) == 0 {
		return 0, nil
	}
	if s == nil || !s.begin() {
		return 0, errors.New("tls: connection closed")
	}
	defer s.inflight.Done()
	// Reads remain pinned across retries; writes use C-owned copied buffers.
	var pin runtime.Pinner
	if len(buf) > 0 && op != "SSL_write" {
		pin.Pin(&buf[0])
		defer pin.Unpin()
	}
	for {
		s.mu.Lock()
		stopped := s.stopped
		s.mu.Unlock()
		if stopped {
			return 0, errors.New("tls: connection closed")
		}
		deadline := s.readDeadline.Load()
		if wd := s.writeDeadline.Load(); wd != 0 && (deadline == 0 || wd < deadline) {
			deadline = wd
		}
		switch op {
		case "SSL_read":
			deadline = s.readDeadline.Load()
		case "SSL_write":
			deadline = s.writeDeadline.Load()
		}
		if deadline != 0 && time.Now().UnixNano() >= deadline {
			return 0, &timeoutError{op: op}
		}
		stepped = true
		ret, code, failure := s.sslStep(op, buf)
		if ret > 0 {
			return ret, nil
		}
		if failure != nil {
			return 0, failure
		}
		if code == native.SSLErrorZeroReturn {
			return 0, io.EOF
		}
		slice := waitFDTimeout
		if deadline != 0 && time.Until(time.Unix(0, deadline)) < slice {
			slice = time.Until(time.Unix(0, deadline))
		}
		err := waitFD(s.fd, code == native.SSLErrorWantWrite, slice)
		if err != nil && !errors.Is(err, errWaitFDTimeout) {
			return 0, err
		}
	}
}

func (s *SSLConn) sslStep(op string, buf []byte) (int, int, error) {
	s.ioMu.Lock()
	defer s.ioMu.Unlock()
	s.mu.Lock()
	stopped := s.stopped
	s.mu.Unlock()
	if stopped {
		return 0, 0, errors.New("tls: connection closed")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	native.ERR_clear_error()
	ret, systemErr := native.X_SSL_operation(s.handle.Ptr(), op, buf)
	if ret > 0 {
		return ret, native.SSLErrorNone, nil
	}
	code := native.SSL_get_error(s.handle.Ptr(), ret)
	if code == native.SSLErrorWantRead || code == native.SSLErrorWantWrite || code == native.SSLErrorZeroReturn {
		return ret, code, nil
	}
	var codes []uint64
	for c := native.PopError(); c != 0; c = native.PopError() {
		codes = append(codes, c)
	}
	var cause error = io.ErrUnexpectedEOF
	if code == native.SSLErrorSyscall && systemErr != nil {
		cause = fmt.Errorf("tls: native syscall: %w", systemErr)
	}
	if len(codes) > 0 {
		cause = NewOpError(op, codes[0])
	}
	return ret, code, &SSLOperationError{Op: op, SSLCode: code, VerifyCode: native.SSL_get_verify_result(s.handle.Ptr()), Codes: codes, Err: cause}
}
