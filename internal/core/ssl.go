package core

import (
	"fmt"
	"runtime"
	"time"
	"unsafe"

	"github.com/blue-cloud-net/tongsuo-go/internal/native"
)

// waitFDTimeout 为 fd 轮询等待超时。
//
// waitFDTimeout is the deadline for waiting on fd readiness during the
// poll-based retry loop driven by Connect / Accept / Read / Write.
const waitFDTimeout = 30 * time.Second

// TLSContext 表示一个 TLS / NTLS 上下文（SSL_CTX 的包装）。
//
// 使用完毕必须调用 Close 释放底层句柄。
//
// TLSContext is the Go wrapper around an OpenSSL SSL_CTX for either TLS
// or NTLS (TLCP, GM/T 0024).
//
// The type owns the underlying SSL_CTX handle through an internal Handle
// value; callers must invoke Close to release it once they are done with
// the context.
type TLSContext struct {
	handle *Handle
}

// NewClientTLSContext 创建 TLS 客户端上下文。
//
// NewClientTLSContext creates a TLS client SSL_CTX via TLS_client_method.
//
// 返回的 *TLSContext 拥有底层句柄，使用完毕须调用 Close 释放。
// SSL_CTX_new 本身是线程安全的，故本方法可并发调用。
//
// The returned *TLSContext owns the underlying handle and the caller is
// responsible for calling Close to release it. The method is safe to
// invoke concurrently because SSL_CTX_new is thread-safe.
func NewClientTLSContext() (*TLSContext, error) {
	return newTLSContext(native.TLS_client_method(), false)
}

// NewServerTLSContext 创建 TLS 服务端上下文。
//
// NewServerTLSContext creates a TLS server SSL_CTX via TLS_server_method.
//
// 返回的 *TLSContext 拥有底层句柄，使用完毕须调用 Close 释放。
// SSL_CTX_new 本身是线程安全的，故本方法可并发调用。
//
// The returned *TLSContext owns the underlying handle and the caller is
// responsible for calling Close to release it. The method is safe to
// invoke concurrently because SSL_CTX_new is thread-safe.
func NewServerTLSContext() (*TLSContext, error) {
	return newTLSContext(native.TLS_server_method(), false)
}

// NewNTLSContext 创建 NTLS（国密 TLCP）上下文，启用双证书。
//
// NewNTLSContext creates an NTLS (TLCP, GM/T 0024) SSL_CTX with the
// dual-certificate extension enabled.
//
// 上下文在握手前需通过 UseSignCertificate 设置签名证书 / 私钥对，
// 并通过 UseEncryptCertificate 设置加密证书 / 私钥对。
// 返回的 *TLSContext 拥有底层句柄，使用完毕须调用 Close 释放。
//
// The context expects a signing certificate / key pair set via
// UseSignCertificate and an encryption certificate / key pair set via
// UseEncryptCertificate before any handshake. The returned *TLSContext
// owns the underlying handle and the caller is responsible for calling
// Close to release it.
func NewNTLSContext() (*TLSContext, error) {
	return newTLSContext(native.NTLS_method(), true)
}

// newTLSContext 按 method 创建 SSL_CTX 并初始化终结器。
//
// newTLSContext creates an SSL_CTX from the supplied method (TLS
// client / TLS server / NTLS method) and registers a finalizer for
// automatic SSL_CTX_free. When ntls is true, NTLS is enabled on the
// resulting context.
func newTLSContext(method unsafe.Pointer, ntls bool) (*TLSContext, error) {
	ctx := native.SSL_CTX_new(method)
	if ctx == nil {
		return nil, NewOpError("tls: SSL_CTX_new", native.PopError())
	}
	h := NewHandle(ctx, true, native.SSL_CTX_free)
	if ntls {
		native.SSL_CTX_enable_ntls(ctx)
	}
	return &TLSContext{handle: h}, nil
}

// UseCertificate 设置 TLS 证书与私钥（单证书模式）。
//
// UseCertificate installs the certificate and private key on the context
// in single-certificate (TLS) mode.
//
// The consistency between cert and key is verified via
// SSL_CTX_check_private_key; any failure is wrapped as OpError. For
// NTLS dual-certificate contexts use UseSignCertificate and
// UseEncryptCertificate instead.
func (c *TLSContext) UseCertificate(cert *Certificate, key *PKey) error {
	if !native.SSL_CTX_use_certificate(c.handle.Ptr(), cert.handle.Ptr()) {
		return NewOpError("tls: SSL_CTX_use_certificate", native.PopError())
	}
	if !native.SSL_CTX_use_PrivateKey(c.handle.Ptr(), key.handle.Ptr()) {
		return NewOpError("tls: SSL_CTX_use_PrivateKey", native.PopError())
	}
	if !native.SSL_CTX_check_private_key(c.handle.Ptr()) {
		return NewOpError("tls: SSL_CTX_check_private_key", native.PopError())
	}
	return nil
}

// UseSignCertificate 设置 NTLS 签名证书与私钥。
//
// UseSignCertificate installs the signing certificate and private key on
// the context for NTLS (TLCP) handshakes.
//
// Must be invoked on an NTLS context (NewNTLSContext); errors from the
// underlying Tongsuo calls are wrapped as OpError.
func (c *TLSContext) UseSignCertificate(cert *Certificate, key *PKey) error {
	if !native.SSL_CTX_use_sign_certificate(c.handle.Ptr(), cert.handle.Ptr()) {
		return NewOpError("tls: SSL_CTX_use_sign_certificate", native.PopError())
	}
	if !native.SSL_CTX_use_sign_PrivateKey(c.handle.Ptr(), key.handle.Ptr()) {
		return NewOpError("tls: SSL_CTX_use_sign_PrivateKey", native.PopError())
	}
	return nil
}

// UseEncryptCertificate 设置 NTLS 加密证书与私钥。
//
// UseEncryptCertificate installs the encryption certificate and private
// key on the context for NTLS (TLCP) handshakes.
//
// Must be invoked on an NTLS context (NewNTLSContext); errors from the
// underlying Tongsuo calls are wrapped as OpError.
func (c *TLSContext) UseEncryptCertificate(cert *Certificate, key *PKey) error {
	if !native.SSL_CTX_use_enc_certificate(c.handle.Ptr(), cert.handle.Ptr()) {
		return NewOpError("tls: SSL_CTX_use_enc_certificate", native.PopError())
	}
	if !native.SSL_CTX_use_enc_PrivateKey(c.handle.Ptr(), key.handle.Ptr()) {
		return NewOpError("tls: SSL_CTX_use_enc_PrivateKey", native.PopError())
	}
	return nil
}

// SetCipherList 设置可用密码套件（冒号分隔）。
//
// SetCipherList installs the colon-separated cipher list accepted by
// subsequent handshakes.
//
// The format matches the OpenSSL "cipher list" string (for example
// "ECDHE-ECDSA-SM2-WITH-SM4-SM3:ECDHE-SM2-WITH-SM4-SM3" for NTLS).
// Returns a wrapped OpError when the cipher list is rejected.
func (c *TLSContext) SetCipherList(list string) error {
	if !native.SSL_CTX_set_cipher_list(c.handle.Ptr(), list) {
		return NewOpError("tls: SSL_CTX_set_cipher_list", native.PopError())
	}
	return nil
}

// SetMinProtoVersion 设置最低协议版本（如 native.TLS1_2Version）。
//
// SetMinProtoVersion sets the minimum accepted protocol version.
//
// Pass one of the native.TLS*_VERSION constants (for example
// native.TLS1_2Version). Errors from the underlying OpenSSL call are
// wrapped as OpError.
func (c *TLSContext) SetMinProtoVersion(v uint16) error {
	if !native.SSL_CTX_set_min_proto_version(c.handle.Ptr(), int(v)) {
		return NewOpError("tls: SSL_CTX_set_min_proto_version", native.PopError())
	}
	return nil
}

// SetMaxProtoVersion 设置最高协议版本。
//
// SetMaxProtoVersion sets the maximum accepted protocol version.
//
// Pass one of the native.TLS*_VERSION constants (for example
// native.TLS1_3Version). Errors from the underlying OpenSSL call are
// wrapped as OpError.
func (c *TLSContext) SetMaxProtoVersion(v uint16) error {
	if !native.SSL_CTX_set_max_proto_version(c.handle.Ptr(), int(v)) {
		return NewOpError("tls: SSL_CTX_set_max_proto_version", native.PopError())
	}
	return nil
}

// Close 释放底层上下文。幂等。
//
// Close releases the underlying SSL_CTX handle.
//
// The call is idempotent: invoking it on a nil receiver or on a context
// that has already been closed returns nil without further side
// effects. After Close returns, any other method on the same
// *TLSContext returns a wrapped OpError, so the caller must guarantee
// that no SSLConn built from this context is still in use.
func (c *TLSContext) Close() error {
	if c == nil {
		return nil
	}
	return c.handle.Close()
}

// SSLConn 表示一个 TLS 连接（SSL 的包装）。
// 使用完毕必须调用 Close 释放底层句柄。
//
// SSLConn is the Go wrapper around an OpenSSL SSL connection bound to a
// raw socket file descriptor.
//
// 类型通过内部 Handle 拥有底层 SSL 句柄，使用完毕须调用 Close 释放连接。
// 持有的 ctx 与 fd 不属于 *SSLConn：关闭上下文或底层 socket 由调用方负责。
//
// The type owns the underlying SSL handle through an internal Handle
// value; callers must invoke Close to release the connection once they
// are done with it. The retained ctx and fd are not owned by *SSLConn;
// closing the context or the underlying socket is the caller's
// responsibility.
type SSLConn struct {
	handle *Handle
	ctx    *TLSContext
	fd     int
}

// NewSSLConn 基于套接字 fd 创建 TLS 连接并绑定。
//
// NewSSLConn creates an SSL connection bound to the socket fd via
// SSL_set_fd.
//
// ctx 必须有效；fd 应为非阻塞 socket，
// 因为 Connect / Accept / Read / Write 使用基于 poll 的重试机制
// 处理 SSL_ERROR_WANT_READ / SSL_ERROR_WANT_WRITE。
// 返回的 *SSLConn 拥有底层 SSL 句柄，使用完毕须调用 Close 释放。
//
// The ctx must be live; fd is expected to be a non-blocking socket
// because Connect/Accept/Read/Write use poll-based retries on
// SSL_ERROR_WANT_READ / SSL_ERROR_WANT_WRITE. The returned *SSLConn
// owns the underlying SSL handle and the caller must invoke Close to
// release it.
func NewSSLConn(ctx *TLSContext, fd int) (*SSLConn, error) {
	ssl := native.SSL_new(ctx.handle.Ptr())
	if ssl == nil {
		return nil, NewOpError("tls: SSL_new", native.PopError())
	}
	h := NewHandle(ssl, true, native.SSL_free)
	if !native.SSL_set_fd(ssl, fd) {
		_ = h.Close()
		return nil, NewOpError("tls: SSL_set_fd", native.PopError())
	}
	return &SSLConn{handle: h, ctx: ctx, fd: fd}, nil
}

// Connect 执行客户端握手。Go 的 socket 为非阻塞，按 WANT_READ/WANT_WRITE 轮询重试。
//
// Connect performs the TLS client handshake.
//
// The method locks the current OS thread and drives SSL_connect in a
// retry loop: SSL_ERROR_WANT_READ / SSL_ERROR_WANT_WRITE are answered by
// waiting for fd readiness via select with a waitFDTimeout deadline, after
// which the handshake resumes. Returns nil once the handshake completes;
// any other SSL error is wrapped as OpError.
func (s *SSLConn) Connect() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	for {
		ret := native.SSL_connect(s.handle.Ptr())
		if ret == 1 {
			return nil
		}
		if err := s.retry("SSL_connect", ret); err != nil {
			return err
		}
	}
}

// Accept 执行服务端握手。
//
// Accept performs the TLS server handshake.
//
// The method locks the current OS thread and drives SSL_accept in the
// same WANT_READ / WANT_WRITE retry loop described in Connect. Returns
// nil once the handshake completes; any other SSL error is wrapped as
// OpError.
func (s *SSLConn) Accept() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	for {
		ret := native.SSL_accept(s.handle.Ptr())
		if ret == 1 {
			return nil
		}
		if err := s.retry("SSL_accept", ret); err != nil {
			return err
		}
	}
}

// Read 读取解密后的数据，返回 n 与错误。
//
// Read reads decrypted application data into buf.
//
// The method locks the current OS thread and retries on
// SSL_ERROR_WANT_READ / SSL_ERROR_WANT_WRITE using select with the
// waitFDTimeout deadline. A return value of (0, error) indicates EOF or
// a fatal SSL error (the error string distinguishes "tls: connection
// closed" from a wrapped OpError).
func (s *SSLConn) Read(buf []byte) (int, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	for {
		ret := native.SSL_read(s.handle.Ptr(), buf)
		if ret > 0 {
			return ret, nil
		}
		if ret == 0 {
			return 0, fmt.Errorf("tls: connection closed")
		}
		if err := s.retry("SSL_read", ret); err != nil {
			return 0, err
		}
	}
}

// Write 写入数据，返回写入字节数与错误。
//
// Write encrypts and sends application data from buf.
//
// The method locks the current OS thread and retries on
// SSL_ERROR_WANT_READ / SSL_ERROR_WANT_WRITE using select with the
// waitFDTimeout deadline. A return value of (0, error) indicates a fatal
// SSL error (wrapped as OpError).
func (s *SSLConn) Write(buf []byte) (int, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	for {
		ret := native.SSL_write(s.handle.Ptr(), buf)
		if ret > 0 {
			return ret, nil
		}
		if err := s.retry("SSL_write", ret); err != nil {
			return 0, err
		}
	}
}

// retry 处理 WANT_READ/WANT_WRITE：等待 fd 就绪并返回 nil 以便重试；其他错误返回 error。
//
// retry maps SSL_ERROR_WANT_READ / SSL_ERROR_WANT_WRITE to waitFD and
// returns nil so the caller can retry; any other SSL_get_error value is
// converted to a wrapped error via opError.
func (s *SSLConn) retry(op string, ret int) error {
	switch native.SSL_get_error(s.handle.Ptr(), ret) {
	case native.SSLErrorWantRead:
		return waitFD(s.fd, false)
	case native.SSLErrorWantWrite:
		return waitFD(s.fd, true)
	default:
		return s.opError(op, ret)
	}
}

// waitFD 在内部平台实现文件里定义（waitfd_linux.go / waitfd_darwin.go）。
//
// waitFD is implemented in the per-OS build files
// waitfd_linux.go and waitfd_darwin.go because syscall.Timeval field
// types and syscall.Select return shape differ between Linux and
// macOS. Keeping a single implementation per OS avoids runtime
// branching while preserving cross-platform correctness.

// Close 发送关闭通知并释放底层句柄。幂等。
//
// Close sends the TLS close_notify alert (via SSL_shutdown) and then
// releases the underlying SSL handle.
//
// The call is idempotent: invoking it on a nil receiver or on a
// connection that has already been closed returns nil without further
// side effects and does NOT invoke SSL_shutdown again. The underlying
// socket fd is NOT closed by this method; the caller is responsible for
// closing it.
func (s *SSLConn) Close() error {
	if s == nil {
		return nil
	}
	// 幂等：closed 时直接返回；避免二次 Close 时 SSL_shutdown(NULL) 崩溃。
	if s.handle == nil || s.handle.IsClosed() {
		return nil
	}
	native.SSL_shutdown(s.handle.Ptr())
	return s.handle.Close()
}

// Version 返回协商后的协议版本字符串。
//
// 对 nil 接收者或已关闭的连接返回空字符串。
//
// Version returns the negotiated protocol version as a human-readable
// string (for example "TLSv1.2" or "NTLSv1.1"). Returns the empty
// string for a nil or closed connection.
func (s *SSLConn) Version() string {
	if s == nil || s.handle == nil || s.handle.IsClosed() {
		return ""
	}
	return native.SSL_get_version(s.handle.Ptr())
}

// CipherName 返回协商后的密码套件名。
//
// 对 nil 接收者或已关闭的连接返回空字符串。
//
// CipherName returns the name of the negotiated cipher suite
// (for example "ECDHE-ECDSA-SM2-WITH-SM4-SM3"). Returns the empty
// string for a nil or closed connection.
func (s *SSLConn) CipherName() string {
	if s == nil || s.handle == nil || s.handle.IsClosed() {
		return ""
	}
	return native.SSL_get_current_cipher_name(s.handle.Ptr())
}

// opError 将 SSL 返回值转为错误。
//
// opError translates an SSL_get_error value into a Go error tagged with
// op; SYS_CALL failures wrap the OpenSSL error queue via OpError.
func (s *SSLConn) opError(op string, ret int) error {
	switch native.SSL_get_error(s.handle.Ptr(), ret) {
	case native.SSLErrorWantRead:
		return fmt.Errorf("tls: %s: want read (retry needed)", op)
	case native.SSLErrorWantWrite:
		return fmt.Errorf("tls: %s: want write (retry needed)", op)
	case native.SSLErrorZeroReturn:
		return fmt.Errorf("tls: %s: connection closed", op)
	case native.SSLErrorSyscall:
		return NewOpError("tls: "+op+" (syscall)", native.PopError())
	}
	return NewOpError("tls: "+op, native.PopError())
}
