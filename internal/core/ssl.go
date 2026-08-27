package core

import (
	"fmt"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"github.com/blue-cloud-net/tongsuo-go/internal/native"
)

// waitFDTimeout 为 fd 轮询等待超时。
const waitFDTimeout = 30 * time.Second

// TLSContext 表示一个 TLS / NTLS 上下文（SSL_CTX 的包装）。
// 使用完毕必须调用 Close 释放底层句柄。
type TLSContext struct {
	handle *Handle
}

// NewClientTLSContext 创建 TLS 客户端上下文。
func NewClientTLSContext() (*TLSContext, error) {
	return newTLSContext(native.TLS_client_method(), false)
}

// NewServerTLSContext 创建 TLS 服务端上下文。
func NewServerTLSContext() (*TLSContext, error) {
	return newTLSContext(native.TLS_server_method(), false)
}

// NewNTLSContext 创建 NTLS（国密 TLCP）上下文，启用双证书。
func NewNTLSContext() (*TLSContext, error) {
	return newTLSContext(native.NTLS_method(), true)
}

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
func (c *TLSContext) SetCipherList(list string) error {
	if !native.SSL_CTX_set_cipher_list(c.handle.Ptr(), list) {
		return NewOpError("tls: SSL_CTX_set_cipher_list", native.PopError())
	}
	return nil
}

// SetMinProtoVersion 设置最低协议版本（如 native.TLS1_2Version）。
func (c *TLSContext) SetMinProtoVersion(v uint16) error {
	if !native.SSL_CTX_set_min_proto_version(c.handle.Ptr(), int(v)) {
		return NewOpError("tls: SSL_CTX_set_min_proto_version", native.PopError())
	}
	return nil
}

// SetMaxProtoVersion 设置最高协议版本。
func (c *TLSContext) SetMaxProtoVersion(v uint16) error {
	if !native.SSL_CTX_set_max_proto_version(c.handle.Ptr(), int(v)) {
		return NewOpError("tls: SSL_CTX_set_max_proto_version", native.PopError())
	}
	return nil
}

// Close 释放底层上下文。幂等。
func (c *TLSContext) Close() error {
	if c == nil {
		return nil
	}
	return c.handle.Close()
}

// SSLConn 表示一个 TLS 连接（SSL 的包装）。
// 使用完毕必须调用 Close 释放底层句柄。
type SSLConn struct {
	handle *Handle
	ctx    *TLSContext
	fd     int
}

// NewSSLConn 基于套接字 fd 创建 TLS 连接并绑定。
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

// waitFD 等待 fd 可读（write=false）或可写（write=true）。
func waitFD(fd int, write bool) error {
	var rfds, wfds syscall.FdSet
	if write {
		wfds.Bits[fd/64] |= 1 << (uint(fd) % 64)
	} else {
		rfds.Bits[fd/64] |= 1 << (uint(fd) % 64)
	}
	timeout := &syscall.Timeval{
		Sec:  int64(waitFDTimeout / time.Second),
		Usec: int64((waitFDTimeout % time.Second) / time.Microsecond),
	}
	n, err := func() (int, error) {
		if write {
			return syscall.Select(fd+1, nil, &wfds, nil, timeout)
		}
		return syscall.Select(fd+1, &rfds, nil, nil, timeout)
	}()
	if err != nil {
		return fmt.Errorf("tls: wait fd: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("tls: wait fd timeout")
	}
	return nil
}

// Close 发送关闭通知并释放底层句柄。幂等。
func (s *SSLConn) Close() error {
	if s == nil {
		return nil
	}
	native.SSL_shutdown(s.handle.Ptr())
	return s.handle.Close()
}

// Version 返回协商后的协议版本字符串。
func (s *SSLConn) Version() string {
	return native.SSL_get_version(s.handle.Ptr())
}

// CipherName 返回协商后的密码套件名。
func (s *SSLConn) CipherName() string {
	return native.SSL_get_current_cipher_name(s.handle.Ptr())
}

// opError 将 SSL 返回值转为错误。
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
