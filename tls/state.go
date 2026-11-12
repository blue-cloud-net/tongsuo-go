package tls

import (
	"errors"
	"fmt"
	"net"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
	"github.com/blue-cloud-net/tongsuo-go/x509"
)

// VerificationState 区分未验证、验证通过与验证失败。
//
// VerificationState distinguishes unchecked, passed and failed verification.
type VerificationState uint8

const (
	// VerificationNotPerformed 表示未验证或没有对端证书。
	//
	// VerificationNotPerformed means verification was not performed or no peer certificate exists.
	VerificationNotPerformed VerificationState = iota
	// VerificationPassed 表示信任验证通过。
	//
	// VerificationPassed means trust verification passed.
	VerificationPassed
	// VerificationFailed 表示至少发生一次验证失败，即使允许继续。
	//
	// VerificationFailed means at least one verification failed, even if continuation was allowed.
	VerificationFailed
)

// CertificateVerificationError 保存证书失败码、深度及独立 DER。
//
// CertificateVerificationError holds a certificate failure code, depth and independent DER.
type CertificateVerificationError struct {
	// Code 是铜锁 X509 验证错误码。
	//
	// Code is the Tongsuo X509 verification error code.
	Code int
	// Depth 是验证链深度。
	//
	// Depth is the verification chain depth.
	Depth int
	// Certificate 是失败证书的 DER 副本。
	//
	// Certificate is a DER copy of the failing certificate.
	Certificate []byte
}

// ConnectionState 是不持有原生句柄的独立快照；DER 切片无需 Close。
//
// ConnectionState is an independent snapshot without native handles; DER slices need no Close.
type ConnectionState struct {
	// SecureRenegotiation 为原生 RFC 5746 支持标志，不表示支持主动重协商。
	//
	// SecureRenegotiation is the native RFC 5746 flag, not active renegotiation support.
	SecureRenegotiation bool
	// SignedCertificateTimestamps 为 TLS 扩展 SCT wire 编码的独立副本。
	//
	// SignedCertificateTimestamps holds independent TLS extension SCT wire encodings.
	SignedCertificateTimestamps [][]byte
	// HandshakeComplete 仅在协议握手及自定义验证均成功后为真。
	//
	// HandshakeComplete is true only after protocol and custom verification succeed.
	HandshakeComplete bool
	// Version 为实际协商协议号。
	//
	// Version is the negotiated wire protocol version.
	Version uint16
	// NTLS 标记实际协商的 NTLS 协议。
	//
	// NTLS identifies an actually negotiated NTLS connection.
	NTLS bool
	// CipherSuite 为协商套件的 wire ID。
	//
	// CipherSuite is the negotiated cipher wire ID.
	CipherSuite uint16
	// CipherName 为铜锁套件名称。
	//
	// CipherName is the Tongsuo cipher name.
	CipherName string
	// ServerName 是发送或接收的 SNI。
	//
	// ServerName is the sent or received SNI.
	ServerName string
	// NegotiatedProtocol 是 ALPN 结果，空表示未协商。
	//
	// NegotiatedProtocol is the ALPN result, empty when not negotiated.
	NegotiatedProtocol string
	// NegotiatedGroup 为密钥交换组名称，空表示原生未报告。
	//
	// NegotiatedGroup is the key-exchange group name, empty when unavailable.
	NegotiatedGroup string
	// PeerSignatureAlgorithm 为对端握手签名算法，空表示不可用。
	//
	// PeerSignatureAlgorithm is the peer handshake signature algorithm, empty when unavailable.
	PeerSignatureAlgorithm string
	// PeerCertificates 保留对端叶证书和原始证书链 DER，NTLS 包含双证书。
	//
	// PeerCertificates preserves peer leaf and chain DER, including both NTLS certificates.
	PeerCertificates [][]byte
	// VerifiedChains 保存内建验证通过的链；NTLS 原生仅报告最近一次链。
	//
	// VerifiedChains holds verified chains; NTLS natively reports only its most recent chain.
	VerifiedChains [][][]byte
	// Verification 为明确的验证结果。
	//
	// Verification is the explicit verification result.
	Verification VerificationState
	// VerificationErrors 保留全部原生验证失败。
	//
	// VerificationErrors preserves all native verification failures.
	VerificationErrors []CertificateVerificationError
}

// ConnectionState 返回状态副本，在失败握手或 Close 后仍可读取最后快照。
//
// ConnectionState returns a copied state, retaining the last snapshot after failure or Close.
func (c *Conn) ConnectionState() ConnectionState {
	if c == nil {
		return ConnectionState{}
	}
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	return cloneState(c.state)
}

func cloneDER(in [][]byte) [][]byte {
	if in == nil {
		return nil
	}
	out := make([][]byte, len(in))
	for i := range in {
		out[i] = append([]byte(nil), in[i]...)
	}
	return out
}
func cloneState(in ConnectionState) ConnectionState {
	out := in
	out.SignedCertificateTimestamps = cloneDER(in.SignedCertificateTimestamps)
	out.PeerCertificates = cloneDER(in.PeerCertificates)
	out.VerifiedChains = nil
	for _, chain := range in.VerifiedChains {
		out.VerifiedChains = append(out.VerifiedChains, cloneDER(chain))
	}
	out.VerificationErrors = append([]CertificateVerificationError(nil), in.VerificationErrors...)
	for i := range out.VerificationErrors {
		out.VerificationErrors[i].Certificate = append([]byte(nil), in.VerificationErrors[i].Certificate...)
	}
	return out
}

func (c *Conn) captureState(success bool) error {
	raw, err := c.ssl.State()
	if err != nil {
		return err
	}
	state := ConnectionState{SecureRenegotiation: raw.SecureRenegotiation, SignedCertificateTimestamps: raw.SignedCertificateTimestamps, HandshakeComplete: success, Version: raw.Version, NTLS: raw.Version == NTLSVersion, CipherSuite: raw.CipherSuite, CipherName: raw.CipherName, ServerName: raw.ServerName, NegotiatedProtocol: raw.Protocol, NegotiatedGroup: raw.Group, PeerSignatureAlgorithm: raw.Signature, PeerCertificates: raw.PeerCertificates}
	if raw.VerifyEnabled && raw.VerificationPerformed && len(raw.PeerCertificates) > 0 {
		state.Verification = VerificationPassed
		for _, failure := range raw.Failures {
			state.VerificationErrors = append(state.VerificationErrors, CertificateVerificationError{failure.Code, failure.Depth, failure.Certificate})
		}
		if raw.VerifyCode > 0 && len(state.VerificationErrors) == 0 {
			state.VerificationErrors = append(state.VerificationErrors, CertificateVerificationError{Code: raw.VerifyCode})
		}
		if len(state.VerificationErrors) > 0 {
			state.Verification = VerificationFailed
		} else if success && len(raw.VerifiedChain) > 0 {
			state.VerifiedChains = [][][]byte{raw.VerifiedChain}
		}
	}
	cfg := c.config
	if selected, ok := c.ssl.SelectedConfiguration().(*Config); ok {
		cfg = selected
	}
	if success && cfg != nil {
		if cfg.RFC8998 {
			err = checkRFC8998State(state)
		}
		if err == nil && cfg.VerifyPeerCertificate != nil {
			err = cfg.VerifyPeerCertificate(cloneDER(state.PeerCertificates), cloneState(state).VerifiedChains)
		}
		if err == nil && cfg.VerifyConnection != nil {
			err = cfg.VerifyConnection(cloneState(state))
		}
	}
	if success && cfg != nil && (cfg.VerifyPeerCertificate != nil || cfg.VerifyConnection != nil) {
		if diagnosticErr := c.ssl.ObserveTLSEvent(9, err); diagnosticErr != nil {
			err = errors.Join(err, diagnosticErr)
		}
	}
	if err != nil {
		state.HandshakeComplete = false
		err = &HandshakeError{Op: "verify callback", Kind: HandshakeErrorPeerVerify, Err: err}
	}
	c.stateMu.Lock()
	c.state = state
	c.stateMu.Unlock()
	return err
}

// Client 包装已连接的 TCP socket，不立即握手；成功后由返回连接负责关闭 socket。
//
// Client wraps a connected TCP socket without handshaking; on success the returned connection owns it.
func Client(raw net.Conn, config *Config) (*Conn, error) {
	if raw == nil {
		return nil, errors.New("tls: nil connection")
	}
	return newClient(raw, config, raw.RemoteAddr().String())
}

func newClient(raw net.Conn, config *Config, addr string) (*Conn, error) {
	cfg := config.Clone()
	ctx, err := newContext(cfg, true)
	if err != nil {
		return nil, err
	}
	name := verificationName(cfg, addr)
	sni := cfg.ServerName
	if sni == "" {
		if host, _, err := net.SplitHostPort(addr); err == nil {
			sni = host
		} else {
			sni = addr
		}
	}
	if cfg.DisableSNI || net.ParseIP(sni) != nil {
		sni = ""
	}
	wrapped, err := wrapConnWithHostname(raw, ctx, false, sni, "", true)
	if err != nil {
		_ = ctx.Close()
		return nil, err
	}
	c := wrapped.(*Conn)
	c.config = cfg
	if effectiveVerification(cfg, true) != VerifyNone {
		if err := c.ssl.SetVerifyName(name, cfg.HostnameOptions.Email, cfg.HostnameOptions.Flags); err != nil {
			_ = c.Close()
			return nil, err
		}
	}
	return c, nil
}

// UnderlyingConn 返回底层连接，仅用于地址、期限等管理，不得直接读写加密数据。
//
// UnderlyingConn returns the underlying connection for management; do not read or write encrypted data directly.
func (c *Conn) UnderlyingConn() net.Conn {
	if c == nil {
		return nil
	}
	return c.raw
}

// VerifyHostname 检查已完成握手的对端签名叶证书名称，不替代证书链验证。
//
// VerifyHostname checks the peer signing leaf name after handshake and does not replace chain verification.
func (c *Conn) VerifyHostname(host string) error {
	if c == nil || !c.handshakeDone.Load() {
		return errors.New("tls: handshake not complete")
	}
	cert, err := c.ssl.PeerCertificate()
	if err != nil {
		return err
	}
	if cert == nil {
		return errors.New("tls: no peer certificate")
	}
	defer cert.Close()
	cfg := c.config
	if selected, ok := c.ssl.SelectedConfiguration().(*Config); ok {
		cfg = selected
	}
	var flags uint32
	if cfg != nil {
		flags = cfg.HostnameOptions.Flags
	}
	return cert.CheckName(host, false, flags)
}

// CheckEmail 检查已完成握手的对端签名叶证书邮箱。
//
// CheckEmail checks the peer signing leaf email after handshake.
func (c *Conn) CheckEmail(email string) error {
	state := c.ConnectionState()
	if !state.HandshakeComplete || len(state.PeerCertificates) == 0 {
		return errors.New("tls: peer certificate unavailable")
	}
	cert, err := core.LoadCertificateDER(state.PeerCertificates[0])
	if err != nil {
		return fmt.Errorf("tls: peer certificate: %w", err)
	}
	defer cert.Close()
	return cert.CheckName(email, true, 0)
}

// Error 返回证书验证失败码、深度及铜锁解释。
//
// Error returns the verification code, depth and Tongsuo explanation.
func (e CertificateVerificationError) Error() string {
	return fmt.Sprintf("tls: verify depth %d code %d: %s", e.Depth, e.Code, x509.VerifyErrorMessage(e.Code))
}
