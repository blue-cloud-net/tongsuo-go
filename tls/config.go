package tls

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/internal/core"
	"github.com/blue-cloud-net/tongsuo-go/x509"
)

// ProtocolMode 指定 TLS、NTLS 或服务端混合协议。
//
// ProtocolMode selects TLS, NTLS or server-side mixed negotiation.
type ProtocolMode uint8

const (
	// ProtocolDefault 保留 NTLS 字段的兼容选择。
	//
	// ProtocolDefault preserves the legacy NTLS field selection.
	ProtocolDefault ProtocolMode = iota
	// ProtocolTLS 仅使用 TLS。
	//
	// ProtocolTLS uses TLS only.
	ProtocolTLS
	// ProtocolNTLS 仅使用 NTLS。
	//
	// ProtocolNTLS uses NTLS only.
	ProtocolNTLS
	// ProtocolMixed 允许服务端同端口接受 TLS 与 NTLS。
	//
	// ProtocolMixed allows TLS and NTLS on one server port.
	ProtocolMixed
)

// VerificationPolicy 控制验证是否执行及失败时是否终止。
//
// VerificationPolicy controls verification and whether failures abort the handshake.
type VerificationPolicy uint8

const (
	// VerifyDefault 保留旧客户端行为，服务端由 ClientAuth 决定。
	//
	// VerifyDefault preserves legacy client behavior and follows ClientAuth on servers.
	VerifyDefault VerificationPolicy = iota
	// VerifyNone 不强制信任验证，不绕过协议必需的签名或凭证检查。
	//
	// VerifyNone does not enforce trust validation or bypass mandatory protocol checks.
	VerifyNone
	// VerifyReport 记录验证失败后继续握手，适用于诊断。
	//
	// VerifyReport records verification failures and continues for diagnostics.
	VerifyReport
	// VerifyStrict 遇到验证失败终止握手。
	//
	// VerifyStrict aborts the handshake on verification failure.
	VerifyStrict
)

// ClientAuthType 指定服务端请求客户端证书的方式。
//
// ClientAuthType controls how servers request client certificates.
type ClientAuthType uint8

const (
	// NoClientCert 不主动请求客户端证书。
	//
	// NoClientCert does not request client certificates.
	NoClientCert ClientAuthType = iota
	// RequestClientCert 请求但不要求客户端证书。
	//
	// RequestClientCert requests an optional client certificate.
	RequestClientCert
	// RequireAnyClientCert 要求客户端提供证书。
	//
	// RequireAnyClientCert requires a client certificate.
	RequireAnyClientCert
	// VerifyClientCertIfGiven 对提供的证书强制验证。
	//
	// VerifyClientCertIfGiven enforces verification when a certificate is provided.
	VerifyClientCertIfGiven
	// RequireAndVerifyClientCert 要求并强制验证客户端证书。
	//
	// RequireAndVerifyClientCert requires and verifies a client certificate.
	RequireAndVerifyClientCert
)

// Certificate 表示一套签名凭证，Chain 仅包含 leaf 后的中间证书。
//
// Certificate holds signing credentials; Chain contains intermediates following the leaf.
type Certificate struct {
	// Leaf 是叶证书，调用方仍持有源对象。
	//
	// Leaf is the leaf certificate; the caller retains the source object.
	Leaf *x509.Certificate
	// PrivateKey 是对应私钥。
	//
	// PrivateKey is the matching private key.
	PrivateKey asym.PrivateKey
	// Chain 是按签发顺序排列的中间证书。
	//
	// Chain contains intermediate certificates in issuer order.
	Chain []*x509.Certificate
}

// NTLSCertificate 表示独立签名与加密凭证。
//
// NTLSCertificate holds separate signing and encryption credentials.
type NTLSCertificate struct {
	// Sign 是签名凭证。
	//
	// Sign holds signing credentials.
	Sign Certificate
	// Enc 是加密凭证。
	//
	// Enc holds encryption credentials.
	Enc Certificate
}

// ClientHelloInfo 提供当前连接的 SNI 和实际协议；回调不得重入当前连接。
//
// ClientHelloInfo supplies the SNI and actual protocol; callbacks must not reenter the connection.
type ClientHelloInfo struct {
	// ServerName 是客户端发送的 SNI，可为空。
	//
	// ServerName is the offered SNI and may be empty.
	ServerName string
	// NTLS 表示当前连接正在协商 NTLS。
	//
	// NTLS reports whether the connection is negotiating NTLS.
	NTLS bool
}

// HostnameOptions 提供 DNS 通配符、CN 回退和邮箱验证选项。
//
// HostnameOptions controls DNS wildcards, CN fallback and email verification.
type HostnameOptions struct {
	// Flags 为命名的主机名检查 flags 的组合。
	//
	// Flags combines named hostname-check flags.
	Flags uint32
	// Email 非空时额外验证邮箱。
	//
	// Email requests an additional email check when nonempty.
	Email string
}

const (
	// HostnameAlwaysCheckSubject 即使存在 SAN 也检查 Subject。
	//
	// HostnameAlwaysCheckSubject checks the Subject even when SAN exists.
	HostnameAlwaysCheckSubject uint32 = 1
	// HostnameNoWildcards 禁止通配符。
	//
	// HostnameNoWildcards disables wildcards.
	HostnameNoWildcards uint32 = 2
	// HostnameNoPartialWildcards 禁止标签内部分通配符。
	//
	// HostnameNoPartialWildcards disables partial-label wildcards.
	HostnameNoPartialWildcards uint32 = 4
	// HostnameMultiLabelWildcards 允许跨标签通配符。
	//
	// HostnameMultiLabelWildcards allows multi-label wildcards.
	HostnameMultiLabelWildcards uint32 = 8
	// HostnameSingleLabelSubdomains 限制为单标签子域。
	//
	// HostnameSingleLabelSubdomains restricts matching to single-label subdomains.
	HostnameSingleLabelSubdomains uint32 = 16
	// HostnameNeverCheckSubject 禁止 CN 回退。
	//
	// HostnameNeverCheckSubject disables CN fallback.
	HostnameNeverCheckSubject uint32 = 32
	// OptionNoCompression 禁用 TLS 压缩。
	//
	// OptionNoCompression disables TLS compression.
	OptionNoCompression uint64 = 1 << 17
	// OptionCipherServerPreference 使用服务端套件优先级。
	//
	// OptionCipherServerPreference uses server cipher preference.
	OptionCipherServerPreference uint64 = 1 << 22
	// OptionNoRenegotiation 禁止重协商。
	//
	// OptionNoRenegotiation disables renegotiation.
	OptionNoRenegotiation uint64 = 1 << 30
	// ModeEnablePartialWrite 允许原生部分写入。
	//
	// ModeEnablePartialWrite permits native partial writes.
	ModeEnablePartialWrite int64 = 1
	// ModeAcceptMovingWriteBuffer 允许重试时缓冲地址改变。
	//
	// ModeAcceptMovingWriteBuffer permits moving buffers on retries.
	ModeAcceptMovingWriteBuffer int64 = 2
)

func protocolMode(cfg *Config, client bool) (ProtocolMode, error) {
	mode := cfg.Protocol
	if mode > ProtocolMixed {
		return mode, errors.New("tls: invalid protocol mode")
	}
	if mode == ProtocolDefault {
		mode = ProtocolTLS
		if cfg.NTLS {
			mode = ProtocolNTLS
		}
	}
	if cfg.NTLS && mode != ProtocolNTLS {
		return mode, errors.New("tls: conflicting NTLS and Protocol settings")
	}
	if client && mode == ProtocolMixed {
		return mode, errors.New("tls: mixed protocol is server-only")
	}
	return mode, nil
}

func effectiveVerification(cfg *Config, client bool) VerificationPolicy {
	if cfg.Verification != VerifyDefault {
		return cfg.Verification
	}
	if client {
		if shouldSkipVerify(cfg) {
			return VerifyNone
		}
		return VerifyStrict
	}
	if cfg.ClientAuth == VerifyClientCertIfGiven || cfg.ClientAuth == RequireAndVerifyClientCert {
		return VerifyStrict
	}
	return VerifyNone
}

func validateConfig(cfg *Config, client bool) error {
	cfg = cfg.Clone()
	if err := normalizeRFC8998(cfg); err != nil {
		return err
	}
	if cfg.Diagnostics != nil && (cfg.Diagnostics.MaxEvents < 0 || cfg.Diagnostics.MaxBytes < 0 || cfg.Diagnostics.MaxBytes > 1<<31-1) {
		return errors.New("tls: invalid diagnostic limits")
	}
	if cfg == nil {
		return nil
	}
	mode, err := protocolMode(cfg, client)
	if err != nil {
		return err
	}
	if mode == ProtocolNTLS && (cfg.MinVersion != 0 && cfg.MinVersion != NTLSVersion || cfg.MaxVersion != 0 && cfg.MaxVersion != NTLSVersion) {
		return errors.New("tls: NTLS requires NTLSVersion bounds")
	}
	if mode != ProtocolNTLS && (cfg.MinVersion == NTLSVersion || cfg.MaxVersion == NTLSVersion) {
		return errors.New("tls: TLS bounds cannot use NTLSVersion")
	}
	if len(cfg.DHParameters) > 1<<31-1 {
		return errors.New("tls: DH parameters too large")
	}
	for _, list := range [][]string{cfg.CurvePreferences, cfg.SignatureAlgorithms} {
		for _, name := range list {
			if name == "" {
				return errors.New("tls: empty group or signature algorithm")
			}
		}
	}
	if cfg.Verification > VerifyStrict || cfg.ClientAuth > RequireAndVerifyClientCert {
		return errors.New("tls: invalid verification or client authentication mode")
	}
	if cfg.Verification != VerifyDefault && cfg.InsecureSkipVerify {
		return errors.New("tls: explicit verification conflicts with InsecureSkipVerify")
	}
	if !client && (cfg.ClientAuth == VerifyClientCertIfGiven || cfg.ClientAuth == RequireAndVerifyClientCert) && cfg.Verification != VerifyDefault && cfg.Verification != VerifyStrict {
		return errors.New("tls: verified client authentication requires strict verification")
	}
	if cfg.MinVersion != 0 && core.CipherVersionToUint16(cfg.MinVersion) == 0 || cfg.MaxVersion != 0 && core.CipherVersionToUint16(cfg.MaxVersion) == 0 {
		return errors.New("tls: unsupported protocol version")
	}
	if cfg.MinVersion != 0 && cfg.MaxVersion != 0 && cfg.MinVersion > cfg.MaxVersion {
		return errors.New("tls: invalid protocol version range")
	}
	if cfg.Options & ^(OptionNoCompression|OptionCipherServerPreference|OptionNoRenegotiation) != 0 || cfg.Modes & ^(ModeEnablePartialWrite|ModeAcceptMovingWriteBuffer) != 0 {
		return errors.New("tls: unsupported options or modes")
	}
	if cfg.HostnameOptions.Flags & ^uint32(63) != 0 {
		return errors.New("tls: unsupported hostname flags")
	}
	for _, v := range append(append(append([]string{cfg.ServerName, cfg.VerificationName, cfg.HostnameOptions.Email}, cfg.CurvePreferences...), cfg.SignatureAlgorithms...), cfg.CipherSuites...) {
		if strings.ContainsRune(v, 0) {
			return errors.New("tls: configuration contains NUL")
		}
	}
	return nil
}

// Clone 复制配置容器；证书和私钥对象仍由调用方管理，回调可能并发执行。
//
// Clone copies configuration containers; callers retain certificates and keys, and callbacks may run concurrently.
func (cfg *Config) Clone() *Config {
	if cfg == nil {
		return &Config{}
	}
	out := *cfg
	if cfg.Diagnostics != nil {
		d := *cfg.Diagnostics
		out.Diagnostics = &d
	}
	out.CipherSuites = append([]string(nil), cfg.CipherSuites...)
	out.NextProtos = append([]string(nil), cfg.NextProtos...)
	out.CurvePreferences = append([]string(nil), cfg.CurvePreferences...)
	out.SignatureAlgorithms = append([]string(nil), cfg.SignatureAlgorithms...)
	out.DHParameters = append([]byte(nil), cfg.DHParameters...)
	out.RootCAs = append([]*x509.Certificate(nil), cfg.RootCAs...)
	out.ClientCAs = append([]*x509.Certificate(nil), cfg.ClientCAs...)
	out.CertChain = append([]*x509.Certificate(nil), cfg.CertChain...)
	out.SignChain = append([]*x509.Certificate(nil), cfg.SignChain...)
	out.EncChain = append([]*x509.Certificate(nil), cfg.EncChain...)
	return &out
}

func selectServerConfig(base *Config, name string, ntls bool) (*core.TLSContext, error) {
	info := &ClientHelloInfo{ServerName: name, NTLS: ntls}
	cfg := base
	if base.GetConfigForClient != nil {
		next, err := base.GetConfigForClient(info)
		if err != nil {
			return nil, err
		}
		if next != nil {
			cfg = next
		}
	}
	cfg = cfg.Clone()
	cfg.Diagnostics = base.Diagnostics
	cfg.CaptureSCT = base.CaptureSCT
	if base.RFC8998 && !cfg.RFC8998 {
		return nil, errors.New("tls: SNI cannot disable RFC 8998")
	}
	if err := normalizeRFC8998(cfg); err != nil {
		return nil, err
	}
	if len(base.CurvePreferences) > 0 && len(cfg.CurvePreferences) == 0 {
		return nil, errors.New("tls: selected configuration must explicitly set CurvePreferences when the base restricts groups")
	}
	mode, err := protocolMode(cfg, false)
	if err != nil {
		return nil, err
	}
	if ntls && mode == ProtocolTLS || !ntls && mode == ProtocolNTLS {
		return nil, errors.New("tls: selected config rejects negotiated protocol")
	}
	if ntls && cfg.GetNTLSCertificate != nil {
		pair, err := cfg.GetNTLSCertificate(info)
		if err != nil {
			return nil, err
		}
		if pair == nil {
			return nil, errors.New("tls: nil NTLS certificate selection")
		}
		cfg.SignCert, cfg.SignKey, cfg.SignChain = pair.Sign.Leaf, pair.Sign.PrivateKey, pair.Sign.Chain
		cfg.EncCert, cfg.EncKey, cfg.EncChain = pair.Enc.Leaf, pair.Enc.PrivateKey, pair.Enc.Chain
	} else if !ntls && cfg.GetCertificate != nil {
		cert, err := cfg.GetCertificate(info)
		if err != nil {
			return nil, err
		}
		if cert == nil {
			return nil, errors.New("tls: nil certificate selection")
		}
		cfg.Cert, cfg.Key, cfg.CertChain = cert.Leaf, cert.PrivateKey, cert.Chain
	}
	cfg.Protocol = ProtocolTLS
	cfg.NTLS = false
	if ntls {
		if mode == ProtocolMixed {
			// Mixed configurations use TLS bounds for their TLS side only.
			cfg.MinVersion, cfg.MaxVersion = 0, 0
		}
		cfg.Protocol = ProtocolNTLS
		cfg.NTLS = true
	}
	cfg.GetConfigForClient = nil
	cfg.GetCertificate = nil
	cfg.GetNTLSCertificate = nil
	if err := validateServerConfig(cfg); err != nil {
		return nil, err
	}
	return newContext(cfg, false)
}

func verificationName(cfg *Config, addr string) string {
	if cfg.VerificationName != "" {
		return cfg.VerificationName
	}
	if cfg.ServerName != "" {
		return cfg.ServerName
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

type credentialKind uint8

const (
	tlsCredential credentialKind = iota
	signingCredential
	encryptionCredential
)

func addCredential(ctx *core.TLSContext, cert *x509.Certificate, key asym.PrivateKey, chain []*x509.Certificate, kind credentialKind) error {
	if cert == nil && key == nil {
		if len(chain) > 0 {
			return errors.New("tls: chain without leaf")
		}
		return nil
	}
	if cert == nil || key == nil {
		return errors.New("tls: incomplete certificate/private key pair")
	}
	c, err := coreCertOf(cert)
	if err != nil {
		return err
	}
	k, err := corePrivateKeyForTLS(key)
	if err != nil {
		return err
	}
	owned, err := k.Dup()
	if err != nil {
		return fmt.Errorf("tls: duplicate private key: %w", err)
	}
	defer owned.Close()
	switch kind {
	case tlsCredential:
		err = ctx.UseCertificate(c, owned)
	case signingCredential:
		err = ctx.UseSignCertificate(c, owned)
	case encryptionCredential:
		err = ctx.UseEncryptCertificate(c, owned)
	}
	if err != nil {
		return err
	}
	for _, cert := range chain {
		c, err := coreCertOf(cert)
		if err != nil {
			return err
		}
		if err := ctx.AddChainCertificate(c); err != nil {
			return err
		}
	}
	return nil
}

func mergeCertificateChains(chains ...[]*x509.Certificate) ([]*x509.Certificate, error) {
	var combined []*x509.Certificate
	seen := make(map[string]bool)
	for _, chain := range chains {
		for _, cert := range chain {
			c, err := coreCertOf(cert)
			if err != nil {
				return nil, err
			}
			der, err := c.MarshalDER()
			if err != nil {
				return nil, fmt.Errorf("tls: chain certificate: %w", err)
			}
			if !seen[string(der)] {
				seen[string(der)] = true
				combined = append(combined, cert)
			}
		}
	}
	return combined, nil
}
