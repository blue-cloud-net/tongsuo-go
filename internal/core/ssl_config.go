package core

import (
	"errors"
	"fmt"
	"net"
	"runtime"
	"strings"

	"github.com/blue-cloud-net/tongsuo-go/internal/native"
)

// TLSSettings 描述构造时固定的握手配置。
//
// TLSSettings describes handshake settings fixed at construction.
type TLSSettings struct {
	// RFC8998 启用国密 TLS 1.3 严格模式。
	//
	// RFC8998 enables strict ShangMi TLS 1.3.
	RFC8998 bool
	// CaptureSCT 开启 TLS 扩展 SCT 快照。
	//
	// CaptureSCT enables TLS extension SCT snapshots.
	CaptureSCT bool
	// DiagnosticFlags 控制事件、trace 和 keylog。
	//
	// DiagnosticFlags controls events, trace and keylog.
	DiagnosticFlags int
	// MaxEvents 限制本次调用暂存的事件数量。
	//
	// MaxEvents limits observations buffered per operation.
	MaxEvents int
	// MaxBytes 限制本次调用暂存的载荷字节数。
	//
	// MaxBytes limits payload bytes buffered per operation.
	MaxBytes int
	// Dispatch 在原生调用锁外同步派发，不得重入连接。
	//
	// Dispatch runs outside the native lock and must not reenter the connection.
	Dispatch func() TLSAcknowledge
	// Tag 关联 API 配置的不透明标记。
	//
	// Tag is an opaque tag associating the API configuration.
	Tag any
	// Protocols 按服务端优先级排列的 ALPN 列表。
	//
	// Protocols lists ALPN protocols in server preference order.
	Protocols []string
	// Groups 传给原生层的冒号分隔命名组。
	//
	// Groups contains colon-separated native named groups.
	Groups string
	// Signatures 传给原生层的冒号分隔签名算法。
	//
	// Signatures contains colon-separated native signature algorithms.
	Signatures string
	// LegacyCiphers TLS 1.2 及 NTLS 的有效套件列表。
	//
	// LegacyCiphers contains effective TLS 1.2 and NTLS cipher suites.
	LegacyCiphers string
	// TLS13Ciphers TLS 1.3 的有效套件列表。
	//
	// TLS13Ciphers contains effective TLS 1.3 cipher suites.
	TLS13Ciphers string
	// DHParameters PEM 编码的 DH 参数副本。
	//
	// DHParameters contains copied PEM-encoded DH parameters.
	DHParameters []byte
	// Options 需要增加的原生 SSL 选项。
	//
	// Options contains native SSL options to enable.
	Options uint64
	// Modes 需要增加的原生 SSL 模式。
	//
	// Modes contains native SSL modes to enable.
	Modes int64
	// Continue 指定原生验证失败后是否继续。
	//
	// Continue controls continuation after native verification failure.
	Continue bool
	// VerifyEnabled 指定是否将原生验证结果作为信任验证。
	//
	// VerifyEnabled reports whether native checks count as trust verification.
	VerifyEnabled bool
	// SelectContext 为当前 ClientHello 创建连接独享的上下文。
	//
	// SelectContext creates a connection-owned context for the ClientHello.
	SelectContext func(string, bool) (*TLSContext, error)
}

// ConfigureTLS 设置参数和连接回调；须在 SSL 构造前调用。
//
// ConfigureTLS sets parameters and connection callbacks before SSL construction.
func (c *TLSContext) ConfigureTLS(settings TLSSettings) error {
	if c == nil || c.handle == nil || c.handle.IsClosed() {
		return errors.New("tls: context closed")
	}
	if settings.RFC8998 && !native.X_SSL_CTX_rfc8998(c.handle.Ptr()) {
		return ErrTLSUnsupported
	}
	if !native.X_SSL_CTX_parameters(c.handle.Ptr(), settings.Groups, settings.Signatures, settings.DHParameters, settings.Options, settings.Modes) {
		return NewOpError("tls: handshake parameters", native.PopError())
	}
	var wire []byte
	for _, proto := range settings.Protocols {
		if len(proto) == 0 || len(proto) > 255 {
			return errors.New("tls: invalid ALPN protocol length")
		}
		wire = append(wire, byte(len(proto)))
		wire = append(wire, proto...)
	}
	if len(wire) > 65535 {
		return errors.New("tls: ALPN list too long")
	}
	if !native.SSL_CTX_set_alpn_protos(c.handle.Ptr(), wire) {
		return NewOpError("tls: ALPN", native.PopError())
	}
	native.X_SSL_CTX_callbacks(c.handle.Ptr())
	native.X_SSL_CTX_keylog(c.handle.Ptr(), settings.DiagnosticFlags&4 != 0)
	c.settings = settings
	return nil
}

// EnableMixedNTLS 为 TLS 服务端开启同端口 NTLS。
//
// EnableMixedNTLS enables NTLS on the same TLS server port.
func (c *TLSContext) EnableMixedNTLS() error {
	if c == nil || c.handle == nil || c.handle.IsClosed() {
		return errors.New("tls: context closed")
	}
	native.SSL_CTX_enable_ntls(c.handle.Ptr())
	return nil
}

// AddChainCertificate 为当前凭证添加中间证书，原对象仍由调用方持有。
//
// AddChainCertificate adds an intermediate for the current credential; the caller retains the source.
func (c *TLSContext) AddChainCertificate(cert *Certificate) error {
	if cert == nil || cert.handle == nil || cert.handle.IsClosed() {
		return errors.New("tls: chain certificate closed")
	}
	if !native.X_SSL_CTX_add_chain(c.handle.Ptr(), cert.handle.Ptr()) {
		return NewOpError("tls: add chain", native.PopError())
	}
	return nil
}

// AddClientCA 添加请求客户端证书时发送的 CA 名称。
//
// AddClientCA adds a CA name sent when requesting client certificates.
func (c *TLSContext) AddClientCA(cert *Certificate) error {
	if cert == nil || cert.handle == nil || cert.handle.IsClosed() {
		return errors.New("tls: client CA closed")
	}
	if !native.X_SSL_CTX_add_client_ca(c.handle.Ptr(), cert.handle.Ptr()) {
		return NewOpError("tls: client CA", native.PopError())
	}
	return nil
}

// SetVerifyName 分别配置 DNS/IP 和邮箱验证。
//
// SetVerifyName configures DNS/IP and email verification independently.
func (s *SSLConn) SetVerifyName(host, email string, flags uint32) error {
	if s == nil || !s.begin() {
		return errors.New("tls: connection closed")
	}
	defer s.inflight.Done()
	s.ioMu.Lock()
	defer s.ioMu.Unlock()
	if !native.X_SSL_set_verify_name(s.handle.Ptr(), host, net.ParseIP(host) != nil, flags, email) {
		return NewOpError("tls: verification name", native.PopError())
	}
	return nil
}

// CheckName 使用指定 flags 检查证书的 DNS/IP 或邮箱。
//
// CheckName checks a certificate DNS/IP or email using the supplied flags.
func (c *Certificate) CheckName(name string, email bool, flags uint32) error {
	if c == nil || c.handle == nil || c.handle.IsClosed() {
		return errors.New("tls: certificate closed")
	}
	if name == "" || strings.ContainsRune(name, 0) {
		return errors.New("tls: invalid verification name")
	}
	kind := 0
	if net.ParseIP(name) != nil {
		kind = 1
	}
	if email {
		kind = 2
	}
	if !native.X_SSL_name_check(c.handle.Ptr(), name, kind, flags) {
		return fmt.Errorf("tls: certificate does not match %q", name)
	}
	return nil
}

// TLSState 为不持有原生资源的状态快照。
//
// TLSState is a state snapshot holding no native resources.
type TLSState struct {
	// SecureRenegotiation 为原生 RFC 5746 支持标志。
	//
	// SecureRenegotiation is the native RFC 5746 support flag.
	SecureRenegotiation bool
	// SignedCertificateTimestamps 为 TLS 扩展 SCT 的独立 wire 编码。
	//
	// SignedCertificateTimestamps holds independent TLS extension SCT wire encodings.
	SignedCertificateTimestamps [][]byte
	// Version 实际协商的协议版本号。
	//
	// Version is the actually negotiated wire version.
	Version uint16
	// CipherSuite 协商套件的 wire ID。
	//
	// CipherSuite is the negotiated cipher wire ID.
	CipherSuite uint16
	// CipherName 协商套件的铜锁名称。
	//
	// CipherName is the Tongsuo name of the negotiated suite.
	CipherName string
	// ServerName 当前连接发送或接收的 SNI。
	//
	// ServerName is the SNI sent or received by this connection.
	ServerName string
	// Protocol 协商的 ALPN 协议，未协商时为空。
	//
	// Protocol is the negotiated ALPN protocol, empty if absent.
	Protocol string
	// Group 协商组的原生名称，不可用时为空。
	//
	// Group is the native negotiated group name, empty if unavailable.
	Group string
	// Signature 原生报告的对端签名算法名称。
	//
	// Signature is the peer signature algorithm name reported natively.
	Signature string
	// VerifyCode 原生最近一次验证结果。
	//
	// VerifyCode is the most recent native verification result.
	VerifyCode int
	// VerifyEnabled 指定是否将原生验证结果作为信任验证。
	//
	// VerifyEnabled reports whether native checks count as trust verification.
	VerifyEnabled bool
	// VerificationPerformed 标记内建验证回调实际执行过。
	//
	// VerificationPerformed reports whether the built-in verification callback actually ran.
	VerificationPerformed bool
	// PeerCertificates 对端叶证书与链的独立 DER。
	//
	// PeerCertificates contains independent peer leaf and chain DER.
	PeerCertificates [][]byte
	// VerifiedChain 原生最近一次验证通过的链 DER。
	//
	// VerifiedChain contains DER of the most recently verified native chain.
	VerifiedChain [][]byte
	// Failures 按发生顺序保存原生验证失败副本。
	//
	// Failures preserves native verification failures in occurrence order.
	Failures []TLSVerificationFailure
}

// TLSVerificationFailure 保存证书验证失败信息。
//
// TLSVerificationFailure holds certificate verification failure details.
type TLSVerificationFailure struct {
	// Code 原生 X509 验证错误码。
	//
	// Code is the native X509 verification error code.
	Code int
	// Depth 失败证书的验证链深度。
	//
	// Depth is the failing certificate depth.
	Depth int
	// Certificate 失败证书的独立 DER 副本。
	//
	// Certificate is independent DER of the failing certificate.
	Certificate []byte
}

// State 复制连接状态，可在失败握手后调用。
//
// State copies connection state and is available after a failed handshake.
func (s *SSLConn) State() (TLSState, error) {
	if s == nil || !s.begin() {
		if s != nil {
			s.mu.Lock()
			cached := s.terminalState
			s.mu.Unlock()
			if cached != nil {
				return cloneTLSState(*cached), nil
			}
		}
		return TLSState{}, errors.New("tls: connection closed")
	}
	defer s.inflight.Done()
	s.ioMu.Lock()
	defer s.ioMu.Unlock()
	n := native.X_SSL_snapshot(s.handle.Ptr())
	secure, scts, err := native.X_SSL_extra_state(s.handle.Ptr(), s.callbacks != nil && s.callbacks.CaptureSCT)
	if err != nil {
		return TLSState{}, err
	}
	out := TLSState{SecureRenegotiation: secure, SignedCertificateTimestamps: scts, Version: n.Version, CipherSuite: n.CipherSuite, CipherName: n.CipherName, ServerName: n.ServerName, Protocol: n.Protocol, Group: n.Group, Signature: n.Signature, VerifyCode: n.VerifyCode, PeerCertificates: n.PeerCertificates, VerifiedChain: n.VerifiedChain, VerifyEnabled: s.callbacks.VerifyEnabled, VerificationPerformed: s.callbacks.VerificationPerformed}
	if s.callbacks != nil {
		for _, failure := range s.callbacks.Failures {
			out.Failures = append(out.Failures, TLSVerificationFailure{failure.Code, failure.Depth, append([]byte(nil), failure.Certificate...)})
		}
	}
	return out, nil
}

// CallbackError 返回当前连接回调报告的错误。
//
// CallbackError returns an error reported by a callback on this connection.
func (s *SSLConn) CallbackError() error {
	if s == nil || s.callbacks == nil {
		return nil
	}
	s.ioMu.Lock()
	defer s.ioMu.Unlock()
	return s.callbacks.Err
}

func (s *SSLConn) attachCallbacks(ctx *TLSContext) error {
	settings := ctx.settings
	cb := &native.TLSCallbacks{Protocols: append([]string(nil), settings.Protocols...), Continue: settings.Continue, VerifyEnabled: settings.VerifyEnabled, Tag: settings.Tag}
	cb.DiagnosticFlags, cb.MaxEvents, cb.MaxBytes, cb.CaptureSCT = settings.DiagnosticFlags, settings.MaxEvents, settings.MaxBytes, settings.CaptureSCT
	if settings.Dispatch != nil {
		s.dispatch = settings.Dispatch()
	}
	selected := []*TLSContext{}
	cb.Select = func(name string, ntls bool) (*native.TLSSelection, error) {
		if settings.SelectContext == nil {
			return nil, nil
		}
		next, err := settings.SelectContext(name, ntls)
		if err != nil || next == nil {
			return nil, err
		}
		selected = append(selected, next)
		cfg := next.settings
		cb.Continue = cfg.Continue
		cb.VerifyEnabled = cfg.VerifyEnabled
		cb.Tag = cfg.Tag
		return &native.TLSSelection{RFC8998: cfg.RFC8998, Context: next.handle.Ptr(), Protocols: cfg.Protocols, Groups: cfg.Groups, Signatures: cfg.Signatures, LegacyCiphers: cfg.LegacyCiphers, TLS13Ciphers: cfg.TLS13Ciphers}, nil
	}
	cb.Cleanup = func() {
		for _, c := range selected {
			_ = c.Close()
		}
	}
	if !native.X_SSL_attach_callbacks(s.handle.Ptr(), cb) {
		return NewOpError("tls: attach callbacks", native.PopError())
	}
	s.callbacks = cb
	if !native.X_SSL_diagnostics(s.handle.Ptr(), settings.DiagnosticFlags, settings.MaxBytes, settings.CaptureSCT) {
		return ErrTLSUnsupported
	}
	runtime.KeepAlive(ctx)
	return nil
}

// SelectedConfiguration 返回构造时关联的配置标记。
//
// SelectedConfiguration returns the configuration tag associated at construction.
func (s *SSLConn) SelectedConfiguration() any {
	if s == nil || s.callbacks == nil {
		return nil
	}
	s.ioMu.Lock()
	defer s.ioMu.Unlock()
	return s.callbacks.Tag
}

// RestrictCipherSuites 限制两个套件家族，空字符串清空对应家族。
//
// RestrictCipherSuites restricts both suite families; an empty string clears that family.
func (c *TLSContext) RestrictCipherSuites(legacy, tls13 string) error {
	if c == nil || c.handle == nil || c.handle.IsClosed() {
		return errors.New("tls: context closed")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ok := native.SSL_CTX_set_cipher_list(c.handle.Ptr(), legacy)
	if legacy == "" {
		// An intentionally empty legacy list returns zero and queues an error.
		native.ERR_clear_error()
	}
	if !ok && legacy != "" {
		return NewOpError("tls: cipher list", native.PopError())
	}
	if !native.SSL_CTX_set_ciphersuites(c.handle.Ptr(), tls13) {
		return NewOpError("tls: TLS 1.3 suites", native.PopError())
	}
	return nil
}
