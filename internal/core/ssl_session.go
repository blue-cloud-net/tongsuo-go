package core

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"runtime"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/internal/native"
)

// SessionInfo 保存独立会话元数据。
//
// SessionInfo holds independent session metadata.
type SessionInfo struct {
	// Peer 是会话原生对端叶证书。
	//
	// Peer is the native session peer leaf certificate.
	Peer []byte

	// Version 为协议版本。
	//
	// Version is the protocol version.
	Version uint16
	// Created 为创建时间。
	//
	// Created is the creation time.
	Created time.Time
	// Expires 为到期时间。
	//
	// Expires is the expiration time.
	Expires time.Time
	// HasTicket 标记存在票据。
	//
	// HasTicket reports whether a ticket is present.
	HasTicket bool
	// Resumable 为原生恢复标志。
	//
	// Resumable is the native resumability flag.
	Resumable bool
	// ID 为会话标识副本。
	//
	// ID is a copied session identifier.
	ID []byte
}

// DecodeSession 校验有大小限制的完整会话 DER，不保留原生句柄。
//
// DecodeSession validates bounded complete session DER without retaining a native handle.
func DecodeSession(data []byte) (SessionInfo, []byte, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	native.ERR_clear_error()
	info, der := native.SSL_SESSION_decode(data)
	if der == nil {
		return SessionInfo{}, nil, NewOpError("tls: decode session", native.PopError())
	}
	if info.Timeout < 0 || info.Timeout > int64(time.Duration(1<<63-1)/time.Second) {
		return SessionInfo{}, nil, errors.New("tls: invalid session lifetime")
	}
	created := time.Unix(info.Created, 0)
	return SessionInfo{info.Peer, info.Version, created, created.Add(time.Duration(info.Timeout) * time.Second), info.HasTicket, info.Resumable, info.ID}, der, nil
}

// ConfigureSessions 在上下文发布前设置会话回调与票据策略。
//
// ConfigureSessions sets session callbacks and ticket policy before publishing a context.
func (c *TLSContext) ConfigureSessions(server, disabled bool, tickets int, domain []byte, get func([]byte) []byte, put func([]byte, []byte), key func([]byte, bool) ([]byte, int)) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.handle == nil || c.handle.IsClosed() {
		return errors.New("tls: context closed")
	}
	if !native.X_SSL_CTX_sessions(c.handle.Ptr(), server, disabled, tickets, domain) {
		return NewOpError("tls: configure sessions", native.PopError())
	}
	c.sessionDomain = append([]byte(nil), domain...)
	c.sessionGet, c.sessionPut, c.ticketKey = get, put, key
	return nil
}

// SetSession 安装会话副本，必须在握手前调用。
//
// SetSession installs a copied session before the handshake.
func (s *SSLConn) SetSession(data []byte) error {
	if !s.begin() {
		return errors.New("tls: connection closed")
	}
	defer s.inflight.Done()
	s.ioMu.Lock()
	defer s.ioMu.Unlock()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	native.ERR_clear_error()
	if !native.SSL_set_session(s.handle.Ptr(), data) {
		return NewOpError("tls: set session", native.PopError())
	}
	return nil
}

// SessionDER 返回最新回调收到的会话副本；无票据时为空。
//
// SessionDER returns a copy of the latest callback session, or nil before receipt.
func (s *SSLConn) SessionDER() []byte {
	if !s.begin() {
		return nil
	}
	defer s.inflight.Done()
	s.ioMu.Lock()
	defer s.ioMu.Unlock()
	return append([]byte(nil), s.callbacks.Session...)
}

// SessionReused 返回实际恢复状态。
//
// SessionReused reports actual session resumption.
func (s *SSLConn) SessionReused() bool {
	if !s.begin() {
		return false
	}
	defer s.inflight.Done()
	s.ioMu.Lock()
	defer s.ioMu.Unlock()
	return native.SSL_session_reused(s.handle.Ptr())
}

// ReverifySession 对恢复连接重新执行当前信任验证。
//
// ReverifySession reruns current trust verification for a resumed connection.
func (s *SSLConn) ReverifySession(chain [][]byte) error {
	if !s.begin() {
		return errors.New("tls: connection closed")
	}
	defer s.inflight.Done()

	if s.dispatch != nil {
		s.deliveryMu.Lock()
		defer s.deliveryMu.Unlock()
	}
	err := func() error {
		s.ioMu.Lock()
		defer s.ioMu.Unlock()
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		native.ERR_clear_error()
		if !native.X_SSL_reverify(s.handle.Ptr(), bytes.Join(chain, nil)) {
			if code := native.PopError(); code != 0 {
				return NewOpError("tls: reverify session", code)
			}
			code := native.SSL_get_verify_result(s.handle.Ptr())
			return fmt.Errorf("tls: reverify session: %s (verify code %d)", native.X509_verify_cert_error_string(code), code)
		}
		return nil
	}()
	if s.dispatch != nil {
		_, _, err = s.finishDiagnosticStep(0, 0, err)
	}
	return err
}

// PumpSession 处理握手后消息，最多读取 maxRead 字节应用数据；不修改期限。
//
// PumpSession reads up to maxRead application bytes while processing post-handshake messages without changing deadlines.
func (s *SSLConn) PumpSession(ctx context.Context, maxRead int, previousSession []byte) ([]byte, error) {
	if maxRead <= 0 {
		return nil, errors.New("tls: session wait application buffer limit")
	}
	if ctx == nil {
		return nil, errors.New("tls: nil session context")
	}
	s.readMu.Lock()
	defer s.readMu.Unlock()
	if !s.begin() {
		return nil, errors.New("tls: connection closed")
	}
	defer s.inflight.Done()
	buf := make([]byte, min(maxRead, 16*1024))
	var pin runtime.Pinner
	pin.Pin(&buf[0])
	defer pin.Unpin()
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if d := loadDeadline(&s.readDeadline); !d.IsZero() && !time.Now().Before(d) {
			return nil, &timeoutError{op: "wait session"}
		}
		if data := s.SessionDER(); len(data) > 0 && !bytes.Equal(data, previousSession) {
			return nil, nil
		}
		n, code, err := s.diagnosticStep("SSL_read", buf)
		if n > 0 {
			return buf[:n], err
		}
		if err != nil {
			return nil, err
		}
		if data := s.SessionDER(); len(data) > 0 && !bytes.Equal(data, previousSession) {
			return nil, nil
		}
		if code == native.SSLErrorZeroReturn {
			return nil, errors.New("tls: peer closed before session receipt")
		}
		budget := 25 * time.Millisecond
		if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < budget {
			budget = time.Until(deadline)
		}
		if d := loadDeadline(&s.readDeadline); !d.IsZero() {
			budget = min(budget, time.Until(d))
		}
		if budget <= 0 {
			continue
		}
		if err := waitFD(s.fd, code == native.SSLErrorWantWrite, budget); err != nil && !errors.Is(err, errWaitFDTimeout) {
			return nil, err
		}
	}
}
