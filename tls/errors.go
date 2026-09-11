// Package tls 提供基于铜锁原生实现的 TLS / NTLS 传输层握手错误分类。
//
// 握手失败、证书验证失败、网络取消、超时等情形经本文件中的哨兵 error 与
// HandshakeError 类型向调用方暴露。语义：
//
//   - 哨兵 error（ErrVersionNotSupported / ErrNoSharedCipher / ErrPeerVerification）
//     供 errors.Is 判定具体失败原因；
//   - HandshakeError{Kind, Op, Err} 类型在握手/读写过程中作为包装器使用，
//     供 errors.As 取出详细字段；HandshakeError.Unwrap() 同时指向 Err
//     与上述哨兵之一（哨兵值由 ErrKindHint 决定）。
//
// 取消/超时：ctx.Err() 直接透传，不包 HandshakeError（与 net/http 习惯一致）。
//
// tls handshake error classification.
//
// Handshake failures, peer-verification failures, network cancellation, and
// timeouts surface through the sentinel errors and the HandshakeError type
// defined in this file. Use errors.Is to discriminate the failure kind
// and errors.As to extract the rich HandshakeError value. HandshakeError
// also wraps the underlying error (e.g. core.OpError or a net.Error) via
// Unwrap so callers can still recover lower-level detail.
//
// Cancellation / timeouts propagate as the raw ctx.Err() (context.Canceled
// or context.DeadlineExceeded) without an extra HandshakeError wrapper,
// matching net/http conventions.

package tls

import (
	"errors"
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/internal/native"
)

// 握手失败原因的语义分类。
//
// HandshakeErrorKind enumerates the kinds of failures that HandshakeError
// can report; each value corresponds to one sentinel error above.
type HandshakeErrorKind int

const (
	// HandshakeErrorOther: 其它/未分类错误（默认兜底）。
	//
	// HandshakeErrorOther is the catch-all for errors that do not map to
	// any of the named kinds below.
	HandshakeErrorOther HandshakeErrorKind = iota

	// HandshakeErrorVersion: 协议版本协商失败（如 MinVersion 过高）。
	//
	// HandshakeErrorVersion signals that the peer does not support any of
	// the protocol versions allowed by the configured range; errors.Is(err,
	// ErrVersionNotSupported) is true.
	HandshakeErrorVersion

	// HandshakeErrorCipher: 无共同密码套件。
	//
	// HandshakeErrorCipher signals that the local cipher list and the
	// peer's offered cipher list have no overlap; errors.Is(err,
	// ErrNoSharedCipher) is true.
	HandshakeErrorCipher

	// HandshakeErrorPeerVerify: 对端证书验证失败。
	//
	// HandshakeErrorPeerVerify signals that the peer certificate chain
	// failed verification (expired, unknown CA, hostname mismatch, ...);
	// errors.Is(err, ErrPeerVerification) is true.
	HandshakeErrorPeerVerify

	// HandshakeErrorNetwork: 底层网络/系统故障（拨号失败、EOF 等）。
	//
	// HandshakeErrorNetwork wraps a non-classified transport-level error
	// (e.g. ECONNRESET, EOF). Use errors.Is(err, ErrNetwork) to detect.
	HandshakeErrorNetwork
)

// 哨兵 error 集，供 errors.Is 使用。
//
// Sentinel errors for the common handshake failure categories; prefer
// errors.Is over string comparison.
var (
	// ErrVersionNotSupported: 协议版本不支持（MinVersion 过高 / 对端过低）。
	//
	// ErrVersionNotSupported signals that the peer did not offer any
	// protocol version inside the locally-configured range.
	ErrVersionNotSupported = errors.New("tls: protocol version not supported")

	// ErrNoSharedCipher: 客户端与对端无共同密码套件。
	//
	// ErrNoSharedCipher signals that no cipher in the locally configured
	// cipher list is also offered by the peer.
	ErrNoSharedCipher = errors.New("tls: no shared cipher")

	// ErrPeerVerification: 对端证书验证失败（OpenSSL X509_V_ERR_*）。
	//
	// ErrPeerVerification signals that peer certificate chain validation
	// failed; details can be recovered via errors.As(*HandshakeError) and
	// the contained core.VerifyErrorMessage-equivalent text.
	ErrPeerVerification = errors.New("tls: peer verification failed")

	// ErrNetwork: 底层网络故障。
	//
	// ErrNetwork wraps a transport-level error from net.Dial, Read, Write,
	// or the SSL syscall adapter that was not classified into the categories
	// above. The underlying error is reachable via errors.Unwrap.
	ErrNetwork = errors.New("tls: network error")
)

// HandshakeError 将握手期间的失败包装为可分类的 error。
//
// HandshakeError wraps a handshake failure with a semantic Kind and the
// failing operation name; Unwrap exposes both the original error and the
// matching sentinel (so errors.Is works for both).
//
// Unwrap 返回首个非 nil 的 err / sentinel；errors.Is 优先匹配 err（先 LIFO
// 后回退到 sentinel）。
//
// Unwrap returns the first non-nil of Err / sentinel so that errors.Is
// matches the most specific error available.
type HandshakeError struct {
	// Op 是触发失败的操作（如 "DialContext"、"HandshakeContext"、"Read"）。
	//
	// Op names the failing operation (for example "DialContext" or
	// "HandshakeContext" or "Read").
	Op string

	// Kind 是失败的语义类别。
	//
	// Kind classifies the failure semantically.
	Kind HandshakeErrorKind

	// Err 是底层错误（可能是 core.OpError、net.Error 等）；可能为 nil。
	//
	// Err is the underlying error (e.g. core.OpError, net.Error); may be nil.
	Err error
}

// Error 实现 error 接口。
//
// Error implements error by combining Op, the kind name and the underlying
// error's Error() string.
func (e *HandshakeError) Error() string {
	if e == nil {
		return "<nil>"
	}
	kindName := e.kindName()
	if e.Err == nil {
		return fmt.Sprintf("tls: %s: %s", e.Op, kindName)
	}
	return fmt.Sprintf("tls: %s: %s: %s", e.Op, kindName, e.Err.Error())
}

// kindName 返回 Kind 的可读名。
func (e *HandshakeError) kindName() string {
	switch e.Kind {
	case HandshakeErrorVersion:
		return "protocol version not supported"
	case HandshakeErrorCipher:
		return "no shared cipher"
	case HandshakeErrorPeerVerify:
		return "peer verification failed"
	case HandshakeErrorNetwork:
		return "network error"
	default:
		return "handshake error"
	}
}

// Unwrap 实现 errors.Unwrap；优先返回底层 Err，再回退到匹配的哨兵。
//
// Unwrap first returns the wrapped Err (so errors.Is can match concrete
// error types) and then falls back to the matching sentinel for errors.Is
// callers that ask for ErrVersionNotSupported / ErrNoSharedCipher /
// ErrPeerVerification / ErrNetwork.
//
// 这是一次性展开（不是 errors.Is 支持链）；调用方多次 errors.Is 调用时
// Go 会自动重入 Is() 验证底层 Err / sentinel。
func (e *HandshakeError) Unwrap() error {
	if e == nil {
		return nil
	}
	if e.Err != nil {
		return e.Err
	}
	return e.sentinel()
}

// sentinel 返回与 Kind 对应的哨兵 error。
func (e *HandshakeError) sentinel() error {
	switch e.Kind {
	case HandshakeErrorVersion:
		return ErrVersionNotSupported
	case HandshakeErrorCipher:
		return ErrNoSharedCipher
	case HandshakeErrorPeerVerify:
		return ErrPeerVerification
	case HandshakeErrorNetwork:
		return ErrNetwork
	}
	return nil
}

// Is 支持 errors.Is 同时匹配 Err 与 sentinel。
//
// Is lets errors.Is match the underlying Err OR the matching sentinel;
// without this, errors.Is(err, ErrNoSharedCipher) would not work.
func (e *HandshakeError) Is(target error) bool {
	if e == nil || target == nil {
		return false
	}
	if e.Err != nil && errors.Is(e.Err, target) {
		return true
	}
	return errors.Is(e.sentinel(), target)
}

// classifyOpenSSLError 根据最近一次 Tongsuo 错误码（reason 部分）决定
// HandshakeErrorKind。
//
// 备注：Tongsuo 在 X509_V_ERR_* / SSL_R_* 错误之间共用 ERR_R_* reason
// 编号；此处仅依据 reason 推断版本/套件/验证三大类。其余归 Network。
//
// classifyOpenSSLError maps a Tongsuo error code (taken from
// ERR_GET_REASON) to a HandshakeErrorKind. The mapping is a best-effort
// heuristic that uses the reason portion of the last error code; it
// focuses on the three categories that Tongsuo flags distinctly (version
// negotiation, cipher negotiation, peer verification). Everything else
// falls into HandshakeErrorNetwork.
func classifyOpenSSLError(code uint64) HandshakeErrorKind {
	if code == 0 {
		return HandshakeErrorOther
	}
	lib := native.ErrGetLib(code)
	reason := native.ErrGetReason(code)
	switch lib {
	case native.ErrLibSSL:
		switch reason {
		case native.SSL_R_NO_SHARED_CIPHER, native.SSL_R_NO_CIPHERS_AVAILABLE:
			return HandshakeErrorCipher
		case native.SSL_R_UNSUPPORTED_PROTOCOL, native.SSL_R_VERSION_TOO_LOW,
			native.SSL_R_WRONG_SSL_VERSION, native.SSL_R_BAD_LEGACY_VERSION:
			return HandshakeErrorVersion
		}
	case native.ErrLibX509:
		switch reason {
		case native.X509_R_CERT_VERIFY_FAILED:
			return HandshakeErrorPeerVerify
		}
	}
	// X509_V_ERR_* 直接的 OpenSSL 验证错误（非通过 ERR_R_* 路径）会出
	// 现在 ssl_get_verify_result 中；此分类器处理不到，由调用方
	// VerifyResult 直接归类为 HandshakeErrorPeerVerify。
	return HandshakeErrorNetwork
}