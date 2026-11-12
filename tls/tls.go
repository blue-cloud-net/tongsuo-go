// Package tls 基于铜锁原生实现提供 TLS 与 NTLS（国密 TLCP）传输层。
// 提供 TLS 客户端（Dial）、服务端（Server + Accept）与 net.Conn 包装（Conn），
// 支持 SM2 单证书（TLS）与双证书（NTLS：签名证书 + 加密证书）。
//
// Package tls provides TLS and NTLS (TLCP) transport-layer connections
// backed by the Tongsuo native library. It exposes a client Dial, a server
// (Server with Accept) and a net.Conn wrapper (Conn). NTLS uses the GM/T
// 0024 TLCP dual-certificate pair (sign certificate + encryption
// certificate); standard TLS uses a single certificate.
package tls

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/internal/certaccess"
	"github.com/blue-cloud-net/tongsuo-go/internal/core"
	"github.com/blue-cloud-net/tongsuo-go/internal/keyaccess"
	"github.com/blue-cloud-net/tongsuo-go/x509"
)

// corePrivateKeyForTLS 经 internal/keyaccess 取出私钥的底层 *core.PKey 句柄。
//
// Config 的 Key / SignKey / EncKey 现在是 asym.PrivateKey（roadmap §3.11），
// 而 `SSL_CTX_use_certificate` / `SSL_CTX_use_PrivateKey` 需要原生句柄。
// 取到的句柄**只借用**（调用期间源密钥一直存活），因此无需 Dup。
//
// corePrivateKeyForTLS extracts the underlying *core.PKey handle of a private key
// through internal/keyaccess.
//
// Config's Key / SignKey / EncKey are asym.PrivateKey now (roadmap §3.11), while
// SSL_CTX_use_certificate / SSL_CTX_use_PrivateKey need the native handle. The
// handle is only borrowed (the source key stays alive for the call), so no Dup is
// required.
func corePrivateKeyForTLS(priv asym.PrivateKey) (*core.PKey, error) {
	if priv == nil {
		return nil, fmt.Errorf("tls: nil private key")
	}
	k, ok := keyaccess.PKey(priv)
	if !ok || k == nil {
		return nil, fmt.Errorf("tls: unsupported private key type %T", priv)
	}
	return k, nil
}

// coreCertOf 经 internal/certaccess 取出证书的底层 *core.Certificate 句柄。
//
// x509 已弃用 Certificate.Core()（roadmap §5 E1-8：公开签名中不得出现 internal/
// 类型），跨包取证书句柄统一走桥接包。取不到时返回错误——在正常路径下不应发生，
// 出现即说明 x509.Certificate 的桥接形状被改动而本包未同步。
//
// coreCertOf extracts the underlying *core.Certificate handle through
// internal/certaccess.
//
// x509 deprecated Certificate.Core() (roadmap §5, E1-8: no public signature may
// mention an internal/ type), so cross-package handle access goes through the
// bridge package. A failure returns an error; it should not happen on a normal
// path and would mean x509.Certificate's bridge shape changed without this
// package being updated.
func coreCertOf(c *x509.Certificate) (*core.Certificate, error) {
	h, ok := certaccess.Certificate(c)
	if !ok || h == nil {
		return nil, fmt.Errorf("tls: certificate handle unavailable")
	}
	return h, nil
}

// Config 表示 TLS / NTLS 配置。
//
// Cert / Key 用于标准 TLS 路径（服务端必填，客户端用于双向认证时可选）；启用 NTLS
// 时由 SignCert / SignKey 与 EncCert / EncKey 提供 GM/T 0024 TLCP 双证书
// （签名证书 + 加密证书）。MinVersion / MaxVersion 与 CipherSuites 非空时覆盖库默认。
//
// 0.9.0 起请优先使用 Verification 显式指定策略。以下 D1 描述是历史说明；
// 零值实际行为是 RootCAs 非空或 ServerName 非空且未跳过时启用验证。
// VerifyReport 与 VerifyStrict 在未配置根时使用铜锁默认信任路径。
// 配置构造后不可修改；选择回调可能并发执行，不得重入同一连接。
//
// 客户端对端验证（D1，方案 A，默认不验证）：
//
//   - RootCAs 为 nil 或 InsecureSkipVerify 为 true：客户端不验证对端证书，
//     与 crypto/tls 默认行为的语义不同（crypto/tls 默认开启）；本库出于对国密
//     生态（私有 CA、自签双证书为主）的适配默认关闭，**强烈建议生产环境显式
//     配置 RootCAs**——OpenSSL 在 PEER 模式下未提供 CA 时会立即握手失败。
//
//   - RootCAs 非 nil 且 InsecureSkipVerify == false：客户端开启 PEER 验证
//     并注入信任根；ServerName 非空时同时启用主机名校验。
//
//   - ServerName 空时 Dial 会从 network/addr  推导 host 部分。
//
// **NTLS 警告**：本库对 NTLS/TLCP 的对端验证接线遵循与 TLS 完全相同的策略；
// 但 Tongsuo NTLS 路径是否执行标准 X509_STORE 链/主机名校验依赖 Tongsuo
// 版本，生产部署前请先实测握手行为。
//
// Config represents a TLS or NTLS configuration shared by Dial and Server.
//
// Since 0.9.0, prefer an explicit Verification policy. The following D1
// description is historical; the zero policy actually verifies when RootCAs
// is nonempty or ServerName is set, unless verification is skipped.
// VerifyReport and VerifyStrict use Tongsuo default trust paths when roots
// are absent. Do not mutate configurations after construction; selection
// callbacks may run concurrently and must not reenter the same connection.
//
// See the package-level "客户端对端验证" Chinese comment above for the
// D1 default-verify policy (方案 A: VERIFY_NONE by default; PEER enabled
// only when RootCAs is set AND InsecureSkipVerify is false).
type Config struct {
	// RFC8998 限定 TLS 1.3、SM4 套件、curveSM2、sm2sig_sm3 与单证书；冲突报错。
	//
	// RFC8998 restricts TLS 1.3 to SM4 suites, curveSM2, sm2sig_sm3 and single credentials; conflicts fail.
	RFC8998 bool
	// CaptureSCT 采集 TLS 扩展 SCT，不执行 CT 策略校验；默认关闭。
	//
	// CaptureSCT collects TLS extension SCTs without CT policy validation; disabled by default.
	CaptureSCT bool
	// Diagnostics 配置同步诊断；nil 关闭，输出错误中断连接。
	//
	// Diagnostics configures synchronous diagnostics; nil disables it and output errors abort connections.
	Diagnostics *DiagnosticsConfig
	// Protocol 显式选择协议；混合模式仅用于服务端。
	//
	// Protocol explicitly selects the protocol; mixed mode is server-only.
	Protocol ProtocolMode

	// Verification 控制验证与失败处理，零值保留旧行为。
	//
	// Verification controls validation and failure handling; zero preserves legacy behavior.
	Verification VerificationPolicy

	// ClientAuth 控制客户端证书请求策略。
	//
	// ClientAuth controls client certificate requests.
	ClientAuth ClientAuthType

	// ClientCAs 是服务端验证客户端的信任根及 CA 名称。
	//
	// ClientCAs contains trust roots and CA names for client authentication.
	ClientCAs []*x509.Certificate

	// CertChain 为 TLS 中间证书链。
	//
	// CertChain contains TLS intermediates.
	CertChain []*x509.Certificate

	// SignChain 为 NTLS 签名中间证书链。
	//
	// SignChain contains NTLS signing intermediates.
	SignChain []*x509.Certificate

	// EncChain 为 NTLS 加密中间证书链。
	//
	// EncChain contains NTLS encryption intermediates.
	EncChain []*x509.Certificate

	// NextProtos 是 ALPN 列表，服务端按本列表优先级选择。
	//
	// NextProtos lists ALPN protocols in server preference order.
	NextProtos []string

	// CurvePreferences 配置命名组，按铜锁名称与顺序设置。
	//
	// CurvePreferences configures named groups in Tongsuo name and preference order.
	CurvePreferences []string

	// SignatureAlgorithms 配置签名算法列表。
	//
	// SignatureAlgorithms configures signature algorithms.
	SignatureAlgorithms []string

	// DHParameters 是 PEM 编码的 DH 参数。
	//
	// DHParameters contains PEM-encoded DH parameters.
	DHParameters []byte

	// Options 为本包 Option 常量的组合。
	//
	// Options combines the package Option constants.
	Options uint64

	// Modes 为本包 Mode 常量的组合。
	//
	// Modes combines the package Mode constants.
	Modes int64

	// StrictConfig 拒绝无效套件并精确限制已指定的套件集合。
	//
	// StrictConfig rejects invalid suites and precisely restricts the specified suite set.
	StrictConfig bool

	// VerificationName 独立指定验证名称，可为 IP。
	//
	// VerificationName independently specifies the verification name and may be an IP.
	VerificationName string

	// DisableSNI 禁止发送 SNI，不影响名称验证。
	//
	// DisableSNI disables SNI without changing name verification.
	DisableSNI bool

	// HostnameOptions 配置 DNS 与邮箱验证。
	//
	// HostnameOptions configures DNS and email verification.
	HostnameOptions HostnameOptions

	// GetConfigForClient 在服务端选择完整配置；nil 结果沿用当前配置。
	//
	// GetConfigForClient selects a server configuration; a nil result retains the current configuration.
	GetConfigForClient func(*ClientHelloInfo) (*Config, error)

	// GetCertificate 选择 TLS 签名凭证，回调不得重入连接。
	//
	// GetCertificate selects TLS signing credentials; callbacks must not reenter the connection.
	GetCertificate func(*ClientHelloInfo) (*Certificate, error)

	// GetNTLSCertificate 选择完整 NTLS 双证书凭证。
	//
	// GetNTLSCertificate selects complete NTLS dual-certificate credentials.
	GetNTLSCertificate func(*ClientHelloInfo) (*NTLSCertificate, error)

	// VerifyPeerCertificate 检查独立 DER 副本，返回错误始终终止。
	//
	// VerifyPeerCertificate checks independent DER copies; any returned error aborts.
	VerifyPeerCertificate func([][]byte, [][][]byte) error

	// VerifyConnection 在内建验证后检查状态，返回错误始终终止。
	//
	// VerifyConnection checks state after built-in validation; any returned error aborts.
	VerifyConnection func(ConnectionState) error

	// Cert 与 Key 为 TLS 证书与私钥（服务端必填；客户端用作客户端证书时可选）。
	//
	// Cert is the TLS leaf certificate, required on static servers and optional on clients.
	Cert *x509.Certificate
	// Key 是 TLS 证书对应的私钥。
	//
	// Key is the private key matching Cert.
	Key asym.PrivateKey

	// NTLS 启用国密双证书（须同时提供签名证书与加密证书）。
	//
	// NTLS enables legacy dual-certificate selection; prefer explicit Protocol.
	NTLS bool
	// SignCert 是 NTLS 签名叶证书。
	//
	// SignCert is the NTLS signing leaf certificate.
	SignCert *x509.Certificate
	// SignKey 是 SignCert 对应私钥。
	//
	// SignKey is the private key matching SignCert.
	SignKey asym.PrivateKey
	// EncCert 是 NTLS 加密叶证书。
	//
	// EncCert is the NTLS encryption leaf certificate.
	EncCert *x509.Certificate
	// EncKey 是 EncCert 对应私钥。
	//
	// EncKey is the private key matching EncCert.
	EncKey asym.PrivateKey

	// MinVersion / MaxVersion 为协议版本范围（0 表示不限制）。
	//
	// MinVersion is the lower protocol bound; in mixed mode it applies to TLS only.
	MinVersion uint16
	// MaxVersion 是最高协议版本，混合模式仅限制 TLS 一侧。
	//
	// MaxVersion is the upper protocol bound; in mixed mode it applies to TLS only.
	MaxVersion uint16

	// CipherSuites 为可用密码套件（空表示使用默认）。
	//
	// CipherSuites lists allowed suites; empty preserves native defaults.
	CipherSuites []string

	// RootCAs 为客户端用于信证书池（nil 表示不进行对端验证）；
	// InsecureSkipVerify 为 true 时强制跳过验证（覆盖 RootCAs）。
	//
	// RootCAs contains client trust roots. The preceding skip description is
	// historical; explicit policies also permit default Tongsuo trust paths.
	RootCAs []*x509.Certificate
	// InsecureSkipVerify 为旧策略强制关闭验证；与显式 Verification 冲突。
	//
	// InsecureSkipVerify disables legacy verification and conflicts with explicit policies.
	InsecureSkipVerify bool
	// ServerName 为对端主机名校验的预期值（空时 Dial 从 addr 推导 host）。
	//
	// ServerName is sent as SNI and supplies a verification name unless overridden.
	ServerName string
}

// Dial 与指定地址建立 TLS 连接（含握手）；成功时返回包装底层 socket 的 *Conn 并已完成握手，失败时返回错误并关闭已部分初始化的资源。
//
// 客户端对端验证（D1 方案 A 默认行为）：
//   - config.InsecureSkipVerify 为 true：跳过验证；
//   - 否则若 config.RootCAs 非 nil 或 config.ServerName 非空：开启 PEER
//     验证 + 注入根 + 主机名校验；
//   - 否则保持 VERIFY_NONE（与 crypto/tls 默认行为不同）。
//
// 握手完成后若开启了 PEER 验证，额外调用 SSL_get_verify_result 检查错误码；
// 验证失败关闭连接并返回 *x509.VerifyError 风格的错误。
//
// Dial connects to the given network address using a TLS or NTLS client
// handshake. On success it returns a *Conn wrapping the underlying socket
// after the handshake completes; on failure it returns an error and closes
// any partially initialised resources.
// DialContext 与指定地址建立 TLS 连接。ctx 同时控制 TCP 拨号超时/取消与握手超时/取消。
//
// 握手完成后若开启了 PEER 验证，额外调用 SSL_get_verify_result 检查错误码；
// 验证失败关闭连接并返回 *HandshakeError{Kind:HandshakeErrorPeerVerify}。
//
// 取消/超时：ctx 取消/超时经 net.Dialer.DialContext 传播为底层 error；
// 握手阶段的取消由 *Conn.HandshakeContext 负责。
//
// **Linux 平台限制**：握手阶段使用 syscall.Select 等待 fd 可读，该调用
// 在 Linux 上不可从 Go 侧直接打断；握手循环以 waitFDTimeout 为切片
// 等待，并在每片超时后重新检查 ctx / deadline，使 ctx 取消的实际
// 响应延迟不超过一个切片（当前 250ms）。完整 epoll/poll(2) 改造计划
// 在 v0.1.3+。
//
// DialContext dials network/addr under ctx and completes a TLS or NTLS
// handshake. Cancellation of ctx aborts the TCP dial (via net.Dialer)
// and the TLS handshake (via *Conn.HandshakeContext); the returned
// error is the raw ctx.Err() (context.Canceled or context.DeadlineExceeded).
//
// On peer-verification failure (when PEER mode is enabled) the returned
// error is a *HandshakeError{Kind:HandshakeErrorPeerVerify} wrapping
// the Tongsuo X509 verification result text.
func DialContext(ctx context.Context, network, addr string, config *Config) (net.Conn, error) {
	if ctx == nil {
		return nil, errors.New("tls: nil context")
	}
	if err := validateConfig(config, true); err != nil {
		return nil, err
	}
	raw, err := (&net.Dialer{}).DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	c, err := newClient(raw, config, addr)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	if err := c.HandshakeContext(ctx); err != nil {
		_ = c.Close()
		return nil, err
	}
	return c, nil
}

// Dial 以 context.Background() 包装 DialContext，向后兼容现有调用点。
//
// Dial is a context.Background() wrapper around DialContext, kept for
// backward compatibility with callers that cannot pass a context.
func Dial(network, addr string, config *Config) (net.Conn, error) {
	return DialContext(context.Background(), network, addr, config)
}

// shouldSkipVerify 按 D1 方案 A 判定客户端是否跳过对端验证。
//
// shouldSkipVerify implements the D1 方案 A policy: VERIFY_NONE by
// default; PEER enabled only when RootCAs is non-empty AND
// InsecureSkipVerify is false.
func shouldSkipVerify(config *Config) bool {
	if config == nil {
		return true
	}
	if config.InsecureSkipVerify {
		return true
	}
	if len(config.RootCAs) == 0 && config.ServerName == "" {
		return true
	}
	return false
}

// Server 表示一个 TLS / NTLS 服务端。
//
// Server represents a TLS or NTLS server that performs handshakes on top
// of already-accepted raw connections.
type Server struct {
	ctx *core.TLSContext
}

// NewServer 创建 TLS 服务端；失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// NewServer creates a TLS or NTLS server from the given configuration.
// On failure it returns an error wrapping an OpError that describes the
// underlying operation.
func NewServer(config *Config) (*Server, error) {
	ctx, err := newContext(config, false)
	if err != nil {
		return nil, err
	}
	return &Server{ctx: ctx}, nil
}

// Accept 将已接受的原始连接包装为 TLS 连接（**惰性握手**：仅创建底层 SSL 句柄，
// 不执行服务端 Accept()）；调用方须随后调用返回 *Conn 的 Handshake /
// HandshakeContext 以驱动握手。
//
// Accept wraps an already-accepted raw connection and prepares the
// underlying SSL handle without performing the server-side handshake.
// Callers must invoke *Conn.Handshake / HandshakeContext on the
// returned *Conn to actually drive the handshake.
func (s *Server) Accept(raw net.Conn) (net.Conn, error) {
	// 服务端不设置 SNI / 校验主机名（由客户端在 ClientHello 中提供）。
	return wrapConnWithHostname(raw, s.ctx, true, "", "", false)
}

// Close 释放服务端上下文（重复调用安全，幂等）。
//
// Close releases the server-side TLS context. Close is safe to call
// repeatedly (idempotent).
func (s *Server) Close() error {
	return s.ctx.Close()
}

// Conn 是一个 TLS / NTLS 连接（net.Conn），基于底层 socket fd 上的 SSL。
//
// Read 与 Write 通过内部互斥锁序列化；多 goroutine 并发调用安全但不能并行。
// Close 通过 sync.Once 保证幂等：先停止 SSL 层并 shutdown 底层 socket（唤醒在途阻塞
// 的 SSL_read / SSL_write / select 调用），再释放 SSL 句柄（含其持有的 dup socket
// 副本）；之后 Read/Write 立即返回 `io.EOF`/错误而非传 nil 进 cgo。
//
// 0.9.0 起以下读写串行化描述为历史行为：读取与写入分别串行，原生单步互斥，等待就绪时允许另一方向推进。
//
// Conn is a net.Conn implementation that performs TLS or NTLS I/O on top
// of an underlying socket file descriptor.
//
// Read and Write are serialized with an internal mutex; concurrent calls
// from multiple goroutines are safe but not parallel. Close uses a
// sync.Once to remain idempotent: it stops the SSL layer and shuts the socket
// down (waking any in-progress SSL_read / SSL_write / select call) and then
// releases the SSL handle, including the dup'ed socket duplicate it owns.
// Subsequent Read/Write calls return io.EOF / an error rather than passing nil
// across the cgo boundary.
//
// Since 0.9.0, the serialization description below is historical: reads and writes progress independently, with serialized native steps and unlocked readiness waits.
type Conn struct {
	config    *Config
	stateMu   sync.RWMutex
	state     ConnectionState
	ssl       *core.SSLConn
	raw       net.Conn
	mu        sync.Mutex // serializes readers
	writeMu   sync.Mutex // serializes writers independently
	closeErr  error
	closeOnce sync.Once   // 保证 Close 只执行一次（幂等）
	closed    atomic.Bool // Close 完成后置位，Read/Write 入口短路

	// ownsCtx 为真时 Conn 拥有底层 *core.TLSContext，Close 时释放；
	// 服务端 Accept 路径中 sharesCtx=false，关闭 ctx 由 Server.Close 负责。
	ownsCtx bool
	ctx     *core.TLSContext

	// isServer / ntls 记录握手方向与协议类型，PeerCertificates / Close 路径需要。
	isServer bool
	ntls     bool

	// handshakeOnce 与 handshakeErr 保证 Handshake / HandshakeContext 幂等。
	handshakeOnce sync.Once
	handshakeErr  error
	handshakeDone atomic.Bool
}

// wrapConnWithHostname 创建底层 SSL 句柄并构造 *Conn，但不执行握手。
// ownsCtx 为 true 时 Conn 拥有 ctx（仅 DialContext 路径为 true）；
// 服务端 Accept 路径共享 s.ctx，由 Server.Close 释放。
//
// wrapConnWithHostname creates the underlying SSL handle and returns a
// *Conn without performing the handshake. When ownsCtx is true, the
// returned *Conn owns ctx (only the DialContext path sets this); the
// server Accept path shares ctx with the Server and the Server is
// wrapConnWithHostname 创建 SSL 连接并（分别）设置 SNI 与校验用主机名。
//
// sniHost 非空时写入 ClientHello 的 server_name 扩展（路由信息，与验证无关）；
// verifyHost 非空时设置 SSL_set1_host（证书主机名校验）。两者可为不同值，也可
// 各自为空。均必须在 Connect 之前设置。
//
// wrapConnWithHostname creates the SSL connection and, independently, applies
// the SNI (server_name) extension and the verification hostname. Both must be
// set before Connect.
func wrapConnWithHostname(raw net.Conn, ctx *core.TLSContext, server bool, sniHost, verifyHost string, ownsCtx bool) (net.Conn, error) {
	fd, err := connFD(raw)
	if err != nil {
		return nil, err
	}
	ssl, err := core.NewSSLConn(ctx, fd)
	if err != nil {
		return nil, err
	}
	if !server {
		if sniHost != "" {
			if err := ssl.SetServerName(sniHost); err != nil {
				_ = ssl.Close()
				return nil, err
			}
		}
		if verifyHost != "" {
			// 主机名验证必须在 Connect 之前设置；空字符串表示跳过。
			if err := ssl.SetHostname(verifyHost); err != nil {
				_ = ssl.Close()
				return nil, err
			}
		}
	}
	return &Conn{
		ssl:      ssl,
		raw:      raw,
		ownsCtx:  ownsCtx,
		ctx:      ctx,
		isServer: server,
		ntls:     ctx.IsNTLS(),
	}, nil
}

// Handshake 驱动 TLS / NTLS 握手。是 HandshakeContext(context.Background()) 的别名。
//
// Handshake performs the TLS / NTLS handshake; it is a shortcut for
// HandshakeContext(context.Background()). Handshake is idempotent: the
// handshake is driven exactly once per *Conn, and the result is cached.
// Returns the cached error on subsequent calls.
//
// **API 注意**：Server.Accept 当前是惰性的；服务端连接在 Accept 后必须调
// 用 Handshake / HandshakeContext 才会真正完成握手。
func (c *Conn) Handshake() error {
	return c.HandshakeContext(context.Background())
}

// HandshakeContext 在 ctx 的控制下驱动 TLS / NTLS 握手。握手在后台 goroutine
// 中执行；ctx 取消时立即关闭底层 socket 使 select 唤醒、握手退出，等待
// goroutine 收敛后返回 ctx.Err()。握手完成后必须 Close 才能彻底释放。
//
// 返回的错误可能为：
//   - context.Canceled / context.DeadlineExceeded：ctx 取消/超时；
//   - *HandshakeError：握手本身失败（版本/套件/对端验证等）；
//   - core.OpError：底层 Tongsuo 错误未分类。
//
// HandshakeContext drives the TLS / NTLS handshake under ctx. The
// handshake runs on a helper goroutine; ctx cancellation closes the
// underlying socket to wake up the poll-based retry loop, then waits
// for the helper goroutine to converge before returning ctx.Err().
//
// The handshake is executed exactly once per *Conn; subsequent calls
// return the cached error (or nil if the first call succeeded).
func (c *Conn) HandshakeContext(ctx context.Context) error {
	if c == nil {
		return errors.New("tls: nil Conn")
	}
	c.handshakeOnce.Do(func() {
		// 校验 ctx：HandshakeContext 拒绝 nil；DialContext 已早一步传
		// Background() 进来，因此只针对外部直接调用此方法的场景。
		if ctx == nil {
			c.handshakeErr = errors.New("tls: HandshakeContext requires non-nil ctx")
			return
		}
		if c.handshakeDone.Load() {
			return
		}
		// 句柄已关闭：直接报错（Close 后不可再 Handshake）。
		if c.ssl == nil {
			c.handshakeErr = errors.New("tls: SSL closed")
			return
		}
		if err := c.ssl.ObserveTLSEvent(0, nil); err != nil {
			c.handshakeErr = err
			_ = c.captureState(false)
			return
		}
		errCh := make(chan error, 1)
		go func() {
			var hsErr error
			if c.isServer {
				hsErr = c.ssl.Accept()
			} else {
				hsErr = c.ssl.Connect()
			}
			errCh <- hsErr
		}()
		select {
		case hsErr := <-errCh:
			// 竞态：ctx 到期/取消与后台握手 goroutine 因 deadline 退出可能
			// 同时就绪，select 随机择一。为保持 crypto/tls 语义（调用方按
			// errors.Is(err, context.DeadlineExceeded / context.Canceled)
			// 判断），ctx 已结束时一律以 ctx.Err() 为准。
			if cErr := ctx.Err(); cErr != nil {
				c.handshakeErr = cErr
			} else {
				c.handshakeErr = hsErr
			}
		case <-ctx.Done():
			// 唤醒握手中的 SSL_read/SSL_write 等待。
			//
			// 仅关 raw socket 在 Linux 上不一定能立刻打断 syscall.Select
			// （fd 仍存在但无数据），所以同时把 SSLConn 的 deadline 设为
			// 「现在」让后续 waitFD 立即返回 timeout；二者联合保证后台
			// goroutine 能在毫秒级退出。
			_ = c.ssl.SetDeadline(time.Now())
			_ = c.raw.Close()
			// 等后台 goroutine 退出后再返回 ctx.Err，避免泄漏。
			<-errCh
			c.handshakeErr = ctx.Err()
		}
		if cbErr := c.ssl.CallbackError(); cbErr != nil && c.handshakeErr != nil && ctx.Err() == nil {
			c.handshakeErr = cbErr
		}
		if stateErr := c.captureState(c.handshakeErr == nil); c.handshakeErr == nil {
			c.handshakeErr = stateErr
		}
		if c.handshakeErr == nil && ctx.Err() != nil {
			c.handshakeErr = ctx.Err()
			c.stateMu.Lock()
			c.state.HandshakeComplete = false
			c.stateMu.Unlock()
		}
		if err := c.ssl.ObserveTLSEvent(1, c.handshakeErr); err != nil {
			c.handshakeErr = errors.Join(c.handshakeErr, err)
			_ = c.captureState(false)
		}
		if c.handshakeErr == nil {
			c.handshakeDone.Store(true)
		}
	})
	if c.handshakeErr == nil {
		return nil
	}
	// 包装握手错误为 HandshakeError（保留 context 取消/超时原样）。
	if errors.Is(c.handshakeErr, context.Canceled) || errors.Is(c.handshakeErr, context.DeadlineExceeded) {
		return c.handshakeErr
	}
	return classifyHandshakeErr("HandshakeContext", c.handshakeErr)
}

// classifyHandshakeErr 将底层错误包装为 *HandshakeError（仅握手阶段）。
// 取消/超时已在调用方拦截；其余错误按最近的 Tongsuo 错误码分类。
//
// classifyHandshakeErr wraps a non-context error from the handshake path
// as a *HandshakeError, using the most recent Tongsuo error code on the
// thread's error queue as the classification signal.
func classifyHandshakeErr(op string, err error) error {
	if err == nil {
		return nil
	}
	var existing *HandshakeError
	if errors.As(err, &existing) {
		return err
	}
	kind := HandshakeErrorOther
	var nativeErr *core.SSLOperationError
	if errors.As(err, &nativeErr) {
		if nativeErr.SSLCode == SSLErrorSyscall {
			kind = HandshakeErrorNetwork
		}
		if nativeErr.VerifyCode > 0 {
			kind = HandshakeErrorPeerVerify
		}
		for _, code := range nativeErr.Codes {
			candidate := classifyOpenSSLError(core.ClassifySSLError(code))
			if candidate != HandshakeErrorNetwork && candidate != HandshakeErrorOther {
				kind = candidate
				break
			}
		}
	} else if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		kind = HandshakeErrorNetwork
	}
	result := &HandshakeError{Op: op, Kind: kind, Err: err}
	if nativeErr != nil {
		result.SSLCode = nativeErr.SSLCode
		result.VerifyCode = nativeErr.VerifyCode
		result.NativeErrors = append([]uint64(nil), nativeErr.Codes...)
	}
	return result
}

// Read 读取解密后的应用层数据。
//
// 与同一 Conn 上的并发 Write 调用互斥序列化。连接已关闭时返回 io.EOF；
// 短读返回 n > 0 与 nil（与 io.Reader 契约一致）。
//
// Read reads decrypted application data from the TLS or NTLS connection
// into b.
//
// 0.9.0 起以下与 Write 互斥的描述为历史行为：读取仅与其他读取串行，首次 I/O 自动握手。
//
// Read is serialized with concurrent Write calls on the same Conn.
// Returns io.EOF after Close. Returns (n, nil) for partial reads
// (matching the io.Reader contract).
//
// Since 0.9.0, the Write-exclusion description below is historical: reads serialize only with other reads, and first I/O triggers a handshake.
func (c *Conn) Read(b []byte) (int, error) {
	if err := c.Handshake(); err != nil {
		return 0, err
	}
	if c.closed.Load() {
		return 0, io.EOF
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed.Load() {
		return 0, io.EOF
	}
	n, err := c.ssl.Read(b)
	if err != nil && c.closed.Load() {
		// 关闭后读返回 io.EOF，便于 io.Copy 等感知对端正常关闭。
		return n, io.EOF
	}
	if err != nil && isCleanShutdownErr(err) {
		// 对端发来 close_notify：标准库返回 io.EOF 0,nil；本库保持 n,nil。
		return n, io.EOF
	}
	return n, err
}

// Write 加密并发送应用层数据。
//
// 0.9.0 起下述读写互斥为历史行为：写入仅与其他写入串行；
// 原生写入开始后的超时或错误会使后续写入保持失败，须关闭连接。
//
// 与同一 Conn 上的并发 Read 调用互斥序列化。连接已关闭时返回 ErrClosed。
//
// Write encrypts and sends application data b over the TLS or NTLS
// connection.
//
// Since 0.9.0, the read/write exclusion below is historical: writes serialize
// only with other writes. A timeout or error after native writing begins
// permanently fails subsequent writes; close the connection.
//
// Write is serialized with concurrent Read calls on the same Conn.
// Returns ErrClosed after Close.
func (c *Conn) Write(b []byte) (int, error) {
	if err := c.Handshake(); err != nil {
		return 0, err
	}
	if c.closed.Load() {
		return 0, ErrClosed
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.closed.Load() {
		return 0, ErrClosed
	}
	written := 0
	for written < len(b) {
		n, err := c.ssl.Write(b[written:])
		written += n
		if err != nil {
			return written, err
		}
		if n == 0 {
			return written, io.ErrShortWrite
		}
	}
	return written, nil
}

// ErrClosed 表示对 tls.Conn 的 I/O 操作因连接已关闭而失败。
//
// ErrClosed is returned by Write (and similar methods) when the
// underlying tls.Conn has already been closed.
var ErrClosed = errors.New("tls: connection closed")

// isCleanShutdownErr 判定 ssl.Read 返回的 "tls: connection closed" 是否
// 表示对端 close_notify（OpenSSL 的 SSL_ERROR_ZERO_RETURN）。
func isCleanShutdownErr(err error) bool {
	return err != nil && err.Error() == "tls: connection closed"
}

// Close 关闭 TLS 连接与底层连接。幂等（多次调用安全）。顺序为：停止 SSL 层并
// shutdown 底层 socket（唤醒在途阻塞的 SSL_read / SSL_write / select，并让对端立刻
// 看到 FIN）→ 关闭 raw socket → 释放 SSL 句柄与它持有的 socket 副本 →（DialContext
// 路径）释放 *core.TLSContext。
//
// 给 SSL 的是 dup 得到的 socket 副本（见 connFD 与 docs/issues/2026-09-24/P1011）：
// 这样 SSL 用的 fd 号在本连接生命周期内不会被内核回收给别人，避免跨连接数据串扰。
//
// Close shuts down the TLS or NTLS session and closes the underlying socket. The
// order is: stop the SSL layer and shutdown(2) the socket (waking in-flight
// SSL_read / SSL_write / select and letting the peer observe a FIN immediately) →
// close the raw socket → release the SSL handle together with the socket duplicate
// it owns → (DialContext path only) release the *core.TLSContext.
//
// The SSL handle is bound to a dup'ed socket duplicate (see connFD and
// docs/issues/2026-09-24/P1011), so its fd number cannot be recycled to another
// connection for the lifetime of this Conn — which is what caused cross-connection
// crosstalk.
//
// The call is idempotent — multiple invocations return the same error as the first.
func (c *Conn) Close() error {
	if c == nil {
		return nil
	}
	var firstErr error
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		// 0) 先停 SSL 并 shutdown 底层 socket：唤醒在途 select/recv，并让对端立刻看到
		//    FIN —— 本库给 SSL 的是 dup 出来的副本，单靠关 raw 既不会关闭套接字，
		//    也唤不醒在途等待（P1011）。
		if c.ssl != nil {
			c.ssl.Stop()
		}
		// 1) 关 raw socket：释放 Go 侧资源；SSL 侧仍持有副本，随后由 ssl.Close 关闭。
		if c.raw != nil {
			if err := c.raw.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		// 2) 释放 SSL 句柄并关闭 socket 副本：ssl.Close 会先等在途调用归零，再
		//    SSL_free 并 close(dup)，因此完成后不会泄漏描述符。
		if c.ssl != nil {
			if err := c.ssl.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		// 3) DialContext 路径上 Conn 拥有 ctx，必须释放（避免 leak）。
		//    Accept 路径 ownsCtx=false，跳过（Server.Close 负责）。
		if c.ownsCtx && c.ctx != nil {
			if err := c.ctx.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		c.closeErr = firstErr
	})
	return c.closeErr
}

// LocalAddr 返回本地地址。
//
// LocalAddr returns the local network address of the underlying socket.
func (c *Conn) LocalAddr() net.Addr { return c.raw.LocalAddr() }

// RemoteAddr 返回远端地址。
//
// RemoteAddr returns the remote network address of the underlying socket.
func (c *Conn) RemoteAddr() net.Addr { return c.raw.RemoteAddr() }

// SetDeadline 设置 handshake 与后续 Read/Write 的累计 deadline（影响 SSL 层的
// waitFD 等待）；同时转给 raw socket 影响 TCP 层。
//
// SetDeadline sets the cumulative handshake + Read/Write deadline
// (propagated to SSL's waitFD retry loop) and also to the underlying
// socket.
func (c *Conn) SetDeadline(t time.Time) error {
	if c == nil || c.ssl == nil {
		return errors.New("tls: SSL closed")
	}
	if err := c.ssl.SetDeadline(t); err != nil {
		return err
	}
	return c.raw.SetDeadline(t)
}

// SetReadDeadline 设置读取期限（仅 SSL 层；raw socket 层同时设置）。
// 同时清空 raw socket 的写入 deadline，避免用户后续 Write 因旧写入
// deadline 而意外超时。
//
// 0.9.0 起以下清空写入期限的描述为历史行为：读取期限独立设置，保留写入期限。
//
// SetReadDeadline sets the read deadline on both the SSL and the
// underlying socket; the raw socket's write deadline is also cleared to
// zero so that subsequent Write calls are not impacted by a stale write
// timeout.
//
// Since 0.9.0, clearing the write deadline as described below is historical: read and write deadlines remain independent.
func (c *Conn) SetReadDeadline(t time.Time) error {
	if c == nil || c.ssl == nil {
		return errors.New("tls: SSL closed")
	}
	if err := c.ssl.SetReadDeadline(t); err != nil {
		return err
	}
	return c.raw.SetReadDeadline(t)
}

// SetWriteDeadline 设置写入期限（仅 SSL 层；raw socket 层同时设置）。
// 同时清空 raw socket 的读取 deadline，避免用户后续 Read 因旧读取
// deadline 而意外超时。
//
// 0.9.0 起上述清空读取期限的描述为历史行为；写入期限独立设置，保留读取期限。
//
// SetWriteDeadline sets the write deadline on both the SSL and the
// underlying socket; the raw socket's read deadline is also cleared to
// zero so that subsequent Read calls are not impacted by a stale read
// timeout.
//
// Since 0.9.0, the read-deadline clearing described above is historical; write deadlines preserve read deadlines.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	if c == nil || c.ssl == nil {
		return errors.New("tls: SSL closed")
	}
	if err := c.ssl.SetWriteDeadline(t); err != nil {
		return err
	}
	return c.raw.SetWriteDeadline(t)
}

// Version 返回协商后的协议版本。
//
// Version returns the negotiated protocol version string (for example "TLSv1.2" or "NTLS").
func (c *Conn) Version() string { return c.ssl.Version() }

// CipherName 返回协商后的密码套件。
//
// CipherName returns the name of the negotiated cipher suite.
func (c *Conn) CipherName() string { return c.ssl.CipherName() }

// PeerCertificates 返回对端证书链（leaf→root，已按签发者顺序重排）。
// 返回的每张 *x509.Certificate 为 owned（X509_dup 副本），调用方须在用毕
// 后调用 Close 释放。
//
// 普通 TLS 与 NTLS 行为略有差异：
//
//   - 客户端：peer_chain 已是「签名叶 + 后续链」；按签发者重构。
//   - 服务端：peer_chain 不含叶；另用 peer_certificate 取叶再重构。
//   - 无对端证书（非 mTLS 服务端路径）：返回 (nil, nil)。
//
// PeerCertificates returns the peer's certificate chain rebuilt in
// leaf→root order (issuer walk). Each returned *x509.Certificate is an
// owned copy (X509_dup); the caller should Close it. Returns (nil, nil)
// when the peer did not present any certificate.
func (c *Conn) PeerCertificates() ([]*x509.Certificate, error) {
	if c == nil {
		return nil, errors.New("tls: nil Conn")
	}
	if !c.handshakeDone.Load() {
		return nil, errors.New("tls: PeerCertificates before handshake")
	}
	pool, err := c.ssl.PeerCertificates()
	if err != nil {
		return nil, err
	}
	defer func() {
		for _, cert := range pool {
			_ = cert.Close()
		}
	}()
	leafCore, err := c.ssl.PeerCertificate()
	if err != nil {
		return nil, err
	}
	if leafCore != nil {
		defer leafCore.Close()
	}
	return c.peerCertificateChain(leafCore, pool)
}

// PeerEncCertificates 返回对端 NTLS 加密证书链（仅在 NTLS 下有意义；
// 普通 TLS 始终返回 nil, nil）。
//
// Tongsuo NTLS 下对端证书链布局（来源：ssl/statem_ntls/ntls_statem_clnt.c
// 与 ntls_statem_srvr.c 的代码注释）：
//
//   - 客户端：peer_chain[0] = 对端签名证书；peer_chain[1] = 对端加密证书；
//     其后为额外链证书。peer == peer_chain[0]（签名叶）。
//   - 服务端：peer = 客户端签名证书；peer_chain[0] = 客户端加密证书。
//
// 本方法按角色定位加密叶并按签发者重构 leaf→root。依赖 Tongsuo 内部栈
// 布局，代码注释已标注。
//
// PeerEncCertificates returns the NTLS encryption certificate chain
// rebuilt leaf→root. Returns (nil, nil) for non-NTLS connections or when
// no encryption certificate is present. Depends on Tongsuo's internal
// peer_chain layout.
func (c *Conn) PeerEncCertificates() ([]*x509.Certificate, error) {
	if c == nil {
		return nil, errors.New("tls: nil Conn")
	}
	if !c.handshakeDone.Load() {
		return nil, errors.New("tls: PeerEncCertificates before handshake")
	}
	if !c.ConnectionState().NTLS {
		return nil, nil
	}
	pool, err := c.ssl.PeerCertificates()
	if err != nil {
		return nil, err
	}
	defer func() {
		for _, cert := range pool {
			_ = cert.Close()
		}
	}()
	if len(pool) == 0 {
		return nil, nil
	}
	// 按角色定位加密叶起点。
	switch c.isServer {
	case true:
		// 服务端：加密叶 = peer_chain[0]；栈只此一张。
		return c.peerCertificateChain(pool[0], pool[1:])
	default:
		// 客户端：加密叶 = peer_chain[1]；后续为链证书。
		if len(pool) < 2 {
			return nil, nil
		}
		return c.peerCertificateChain(pool[1], pool[2:])
	}
}

// newContext 根据配置创建客户端/服务端上下文并加载证书。
//
// newContext builds the underlying Tongsuo TLS context (NTLS, client, or
// server) from config and loads the configured certificates / keys onto it.
func newContext(config *Config, client bool) (*core.TLSContext, error) {
	// Configuration failures must read the same native thread's error queue.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	cfg := config.Clone()
	if err := normalizeRFC8998(cfg); err != nil {
		return nil, err
	}
	if cfg.Diagnostics != nil && (cfg.Diagnostics.MaxEvents < 0 || cfg.Diagnostics.MaxBytes < 0 || cfg.Diagnostics.MaxBytes > 1<<31-1) {
		return nil, errors.New("tls: invalid diagnostic limits")
	}
	if err := validateConfig(cfg, client); err != nil {
		return nil, err
	}
	mode, err := protocolMode(cfg, client)
	if err != nil {
		return nil, err
	}
	var ctx *core.TLSContext
	if mode == ProtocolNTLS {
		ctx, err = core.NewNTLSContext()
	} else if client {
		ctx, err = core.NewClientTLSContext()
	} else {
		ctx, err = core.NewServerTLSContext()
	}
	if err != nil {
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			_ = ctx.Close()
		}
	}()
	if mode == ProtocolMixed {
		if err := ctx.EnableMixedNTLS(); err != nil {
			return nil, err
		}
	}
	if cfg.RFC8998 && !client && cfg.Cert == nil && cfg.GetCertificate == nil && cfg.GetConfigForClient == nil {
		return nil, errors.New("tls: RFC 8998 server requires signing credentials")
	}
	if mode != ProtocolNTLS {
		if err := addCredential(ctx, cfg.Cert, cfg.Key, cfg.CertChain, tlsCredential); err != nil {
			return nil, err
		}
	}
	if mode != ProtocolTLS {
		// NTLS sends one shared intermediate pool after its two leaves.
		chain, err := mergeCertificateChains(cfg.SignChain, cfg.EncChain)
		if err != nil {
			return nil, err
		}
		if err := addCredential(ctx, cfg.SignCert, cfg.SignKey, chain, signingCredential); err != nil {
			return nil, err
		}
		if err := addCredential(ctx, cfg.EncCert, cfg.EncKey, cfg.EncChain, encryptionCredential); err != nil {
			return nil, err
		}
	}
	if cfg.MinVersion != 0 {
		if err := ctx.SetMinProtoVersion(cfg.MinVersion); err != nil {
			return nil, err
		}
	}
	if cfg.MaxVersion != 0 {
		if err := ctx.SetMaxProtoVersion(cfg.MaxVersion); err != nil {
			return nil, err
		}
	}
	legacy, tls13, err := configureCiphers(ctx, cfg.CipherSuites, cfg.StrictConfig)
	if err != nil {
		return nil, err
	}
	// Capture effective suite lists so SNI replacement also resets omitted families.
	legacyNames, tls13Names := []string{}, []string{}
	for _, suite := range ctx.CipherList() {
		if strings.HasPrefix(suite.Name, "TLS_") {
			tls13Names = append(tls13Names, suite.Name)
		} else {
			legacyNames = append(legacyNames, suite.Name)
		}
	}
	legacy, tls13 = strings.Join(legacyNames, ":"), strings.Join(tls13Names, ":")
	policy := effectiveVerification(cfg, client)
	verifyMode := 0
	if client && policy != VerifyNone {
		verifyMode = 1
	}
	if !client && cfg.ClientAuth != NoClientCert {
		verifyMode = 1
		if cfg.ClientAuth == RequireAnyClientCert || cfg.ClientAuth == RequireAndVerifyClientCert {
			verifyMode |= 2
		}
	}
	if err := ctx.SetVerifyMode(verifyMode); err != nil {
		return nil, err
	}
	if err := ctx.SetVerifyDepth(defaultVerifyDepth); err != nil {
		return nil, err
	}
	roots := cfg.RootCAs
	if !client {
		roots = cfg.ClientCAs
	}
	if len(roots) > 0 {
		certs := make([]*core.Certificate, 0, len(roots))
		for _, root := range roots {
			c, err := coreCertOf(root)
			if err != nil {
				return nil, err
			}
			certs = append(certs, c)
			if !client {
				if err := ctx.AddClientCA(c); err != nil {
					return nil, err
				}
			}
		}
		if err := ctx.AddVerifyRoots(certs); err != nil {
			return nil, err
		}
	} else if policy != VerifyNone && cfg.Verification != VerifyDefault {
		if err := ctx.SetDefaultVerifyPaths(); err != nil {
			return nil, err
		}
	}
	settings := core.TLSSettings{RFC8998: cfg.RFC8998, CaptureSCT: cfg.CaptureSCT, Tag: cfg, Protocols: cfg.NextProtos, Groups: strings.Join(cfg.CurvePreferences, ":"), Signatures: strings.Join(cfg.SignatureAlgorithms, ":"), DHParameters: cfg.DHParameters, Options: cfg.Options, Modes: cfg.Modes, Continue: policy == VerifyNone || policy == VerifyReport, VerifyEnabled: policy != VerifyNone, LegacyCiphers: legacy, TLS13Ciphers: tls13}
	if cfg.Diagnostics != nil {
		d := *cfg.Diagnostics
		settings.MaxEvents, settings.MaxBytes = d.MaxEvents, d.MaxBytes
		if settings.MaxEvents == 0 {
			settings.MaxEvents = defaultDiagnosticMaxEvents
		}
		if settings.MaxBytes == 0 {
			settings.MaxBytes = defaultDiagnosticMaxBytes
		}
		if d.OnEvent != nil {
			settings.DiagnosticFlags |= 1
		}
		if d.TraceWriter != nil {
			settings.DiagnosticFlags |= 2
		}
		if d.KeyLogWriter != nil {
			settings.DiagnosticFlags |= 4
		}
		if settings.DiagnosticFlags != 0 {
			settings.Dispatch = func() core.TLSAcknowledge { delivery := &diagnosticDelivery{config: d}; return delivery.observe }
		}
	}
	if !client && (mode == ProtocolMixed || cfg.GetConfigForClient != nil || cfg.GetCertificate != nil || cfg.GetNTLSCertificate != nil) {
		settings.SelectContext = func(name string, ntls bool) (*core.TLSContext, error) { return selectServerConfig(cfg, name, ntls) }
	}
	if err := ctx.ConfigureTLS(settings); err != nil {
		return nil, err
	}
	success = true
	return ctx, nil
}

// defaultVerifyDepth 为对端证书链验证默认深度上限（100，覆盖常规 CA 路径长度）。
const defaultVerifyDepth = 100

// connFD 复制 net.Conn 底层的 socket fd，返回**由调用方持有**的副本。
//
// 必须复制（而不是直接把 fd 号交给 OpenSSL）：`net.Conn` 关闭后该号码会被内核回收
// 并可能分配给新连接，而 SSL 的 BIO 仍记着它 —— 之后的 SSL_read / SSL_write 会
// 读写**别的连接**的 socket（跨连接串扰、握手随机失败）。
// 见 docs/issues/2026-09-24/P1011。
//
// 复制在 `SyscallConn().Control` 回调**内部**完成：该契约要求不得在回调外持有底层
// fd，而 dup 出来的副本属于我们自己，可以安全长期持有。返回的 fd 由 tls.Conn 持有，
// 最终由 `(*core.SSLConn).Close` 关闭。
//
// connFD duplicates the socket fd behind conn and returns the duplicate owned by
// the caller.
//
// Duplicating (rather than handing the bare fd number to OpenSSL) is essential:
// once the net.Conn is closed the kernel may recycle that number for a new
// connection while the SSL BIO still remembers it, after which SSL_read /
// SSL_write touch another connection's socket — cross-connection crosstalk and
// intermittent handshake failures. See docs/issues/2026-09-24/P1011.
//
// The duplication happens inside the SyscallConn().Control callback, whose
// contract forbids retaining the underlying fd outside it; the duplicate is ours
// and may be retained. The returned fd is owned by tls.Conn and finally released
// by (*core.SSLConn).Close.
//
// It returns an error for any net.Conn that is not a *net.TCPConn.
func connFD(conn net.Conn) (int, error) {
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return -1, fmt.Errorf("tls: unsupported connection type %T", conn)
	}
	raw, err := tcp.SyscallConn()
	if err != nil {
		return -1, err
	}
	var (
		dup  = -1
		derr error
	)
	if err := raw.Control(func(f uintptr) {
		dup, derr = core.DupFD(int(f))
	}); err != nil {
		return -1, err
	}
	if derr != nil {
		return -1, derr
	}
	return dup, nil
}

// 暴露协议版本常量，便于用户配置 MinVersion / MaxVersion。
//
// ProtocolVersion exposes TLS protocol version constants suitable for Config.MinVersion and Config.MaxVersion.
//
// Wire-format IANA TLS protocol version values (RFC 5246 / RFC 8446); also
// consumed by core.TLSContext.SetMinProtoVersion / SetMaxProtoVersion.
const (
	TLS1Version   uint16 = 0x0301
	TLS1_1Version uint16 = 0x0302
	TLS1_2Version uint16 = 0x0303
	TLS1_3Version uint16 = 0x0304
)
