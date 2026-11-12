package core

import (
	"errors"
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/internal/native"
)

// ErrTLSUnsupported 表示原生 TLS 能力不可用。
//
// ErrTLSUnsupported indicates an unavailable native TLS capability.
var ErrTLSUnsupported = native.ErrTLSUnsupported

// ErrTLSLimit 表示诊断暂存超过限额。
//
// ErrTLSLimit indicates a diagnostic buffer limit was exceeded.
var ErrTLSLimit = native.ErrTLSLimit

// TLSEvent 保存不包含原生资源的诊断事件。
//
// TLSEvent holds a diagnostic event without native resources.
type TLSEvent struct {
	// Err 为生命周期或自定义验证错误。
	//
	// Err is a lifecycle or custom verification error.
	Err error
	// Kind 是诊断类别。
	//
	// Kind is the diagnostic category.
	Kind int
	// Write 标记发送方向。
	//
	// Write identifies outgoing observations.
	Write bool
	// Version 是原生协议版本。
	//
	// Version is the native protocol version.
	Version int
	// Type 是内容类型或状态标志。
	//
	// Type is the content type or state flags.
	Type int
	// Code 是原生返回值或验证结果。
	//
	// Code is the native result or verification code.
	Code int
	// Depth 是验证深度。
	//
	// Depth is the verification depth.
	Depth int
	// Data 为可保留的独立副本。
	//
	// Data is an independent copy that may be retained.
	Data []byte
}

// TLSAcknowledge 表示派发函数；不得重入同一连接。
//
// TLSAcknowledge dispatches observations and must not reenter the connection.
type TLSAcknowledge func(TLSEvent) error

func (s *SSLConn) diagnosticStep(op string, buf []byte) (int, int, error) {
	if s.dispatch == nil {
		return s.sslStep(op, buf)
	}
	s.deliveryMu.Lock()
	defer s.deliveryMu.Unlock()
	n, code, nativeErr := s.sslStep(op, buf)
	// The caller is admitted via begin/inflight; Close cannot release callbacks.
	s.ioMu.Lock()
	cb := s.callbacks
	events, captureErr := cb.Events, cb.DiagnosticErr
	cb.Events, cb.EventBytes = nil, 0
	s.ioMu.Unlock()
	for _, event := range events {
		if s.diagnosticErr != nil {
			break
		}
		e := TLSEvent{Err: event.Err, Kind: event.Kind, Write: event.Write, Version: event.Version, Type: event.Type, Code: event.Code, Depth: event.Depth, Data: event.Data}
		if err := s.dispatch(e); err != nil {
			s.diagnosticErr = fmt.Errorf("tls: diagnostic output: %w", err)
		}
	}
	s.diagnosticErr = errors.Join(captureErr, s.diagnosticErr)
	if s.diagnosticErr != nil {
		// Stop performs native work only after its own ioMu acquisition.
		snapshot, snapshotErr := s.State()
		s.diagnosticErr = errors.Join(s.diagnosticErr, snapshotErr)
		s.mu.Lock()
		s.terminalState = &snapshot
		s.mu.Unlock()
		s.Stop()
		return n, code, errors.Join(nativeErr, s.diagnosticErr)
	}
	return n, code, nativeErr
}

// ObserveTLSEvent 派发生命周期事件；调用方不得处于原生调用锁内。
//
// ObserveTLSEvent dispatches a lifecycle event outside the native operation lock.
func (s *SSLConn) ObserveTLSEvent(kind int, cause error) error {
	if s == nil || s.dispatch == nil {
		return nil
	}
	s.deliveryMu.Lock()
	defer s.deliveryMu.Unlock()
	if s.diagnosticErr != nil {
		return errors.Join(cause, s.diagnosticErr)
	}
	if err := s.dispatch(TLSEvent{Kind: kind, Err: cause}); err != nil {
		s.diagnosticErr = fmt.Errorf("tls: diagnostic event: %w", err)
		snapshot, snapshotErr := s.State()
		s.diagnosticErr = errors.Join(s.diagnosticErr, snapshotErr)
		s.mu.Lock()
		s.terminalState = &snapshot
		s.mu.Unlock()
		s.Stop()
		return errors.Join(cause, s.diagnosticErr)
	}
	return nil
}

func cloneTLSState(in TLSState) TLSState {
	copyDER := func(list [][]byte) [][]byte {
		if list == nil {
			return nil
		}
		out := make([][]byte, len(list))
		for i := range list {
			out[i] = append([]byte(nil), list[i]...)
		}
		return out
	}
	out := in
	out.PeerCertificates = copyDER(in.PeerCertificates)
	out.VerifiedChain = copyDER(in.VerifiedChain)
	out.SignedCertificateTimestamps = copyDER(in.SignedCertificateTimestamps)
	out.Failures = append([]TLSVerificationFailure(nil), in.Failures...)
	for i := range out.Failures {
		out.Failures[i].Certificate = append([]byte(nil), out.Failures[i].Certificate...)
	}
	return out
}
