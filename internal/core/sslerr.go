package core

import (
	"github.com/blue-cloud-net/tongsuo-go/internal/native"
)

// SSLErrorClass 是 TLS / 证书错误码的语义分类。
//
// 本枚举只表达「失败的种类」，不出现任何 OpenSSL 符号名；公开层（`tls` 包）
// 把它映射为自己的 `HandshakeErrorKind`。之所以放在核心层：区分 `SSL_R_*` /
// `X509_R_*` reason 码需要 `internal/native`，而 API 层不得直接 import 绑定层
// （AGENTS.md §3.3）。
//
// SSLErrorClass classifies a TLS / certificate error code semantically.
//
// The enum names no OpenSSL symbols; the public layer (package tls) maps it to
// its own HandshakeErrorKind. It lives in the core layer because discriminating
// SSL_R_* / X509_R_* reason codes requires internal/native, which API-layer
// packages must not import directly (AGENTS.md §3.3).
type SSLErrorClass int

const (
	// SSLErrorClassOther 表示无法分类：错误码为 0（队列为空）或未识别的组合。
	//
	// SSLErrorClassOther means "unclassifiable": the code was 0 (empty queue)
	// or an unrecognized lib/reason combination.
	SSLErrorClassOther SSLErrorClass = iota

	// SSLErrorClassVersion 表示协议版本协商失败（本地版本范围与对端无不重叠）。
	//
	// SSLErrorClassVersion means protocol version negotiation failed (the
	// locally allowed version range and the peer's overlap is empty).
	SSLErrorClassVersion

	// SSLErrorClassCipher 表示无共同密码套件。
	//
	// SSLErrorClassCipher means no shared cipher suite.
	SSLErrorClassCipher

	// SSLErrorClassPeerVerify 表示对端证书链验证失败。
	//
	// SSLErrorClassPeerVerify means peer certificate chain validation failed.
	SSLErrorClassPeerVerify

	// SSLErrorClassNetwork 表示其余情况（底层传输故障等），由本分类器兜底。
	//
	// SSLErrorClassNetwork is the catch-all for everything else (transport
	// failures and the like).
	SSLErrorClassNetwork
)

// DrainErrors 弹出当前线程错误队列中的全部错误码，返回最后一次弹出的码。
//
// 返回 0 表示队列为空。之所以一次性清空：队列里往往残留前序操作入队的错误，
// 只有把旧的弹干净、取「最后一条」，才是本次失败真正对应的码。
//
// DrainErrors pops every code from the current thread's OpenSSL error queue and
// returns the last one popped.
//
// 0 means the queue was empty. The queue is drained in full because stale codes
// enqueued by earlier operations would otherwise mask the one that actually
// corresponds to the current failure.
func DrainErrors() uint64 {
	var last uint64
	for {
		code := native.PopError()
		if code == 0 {
			return last
		}
		last = code
	}
}

// ErrorString 返回铜锁错误码对应的文本描述（包装 `ERR_error_string_n`）。
//
// 等价 `tongsuo errstr <code>`；与 `VerifyErrorMessage`（只认 `X509_V_ERR_*`
// 链验证码）不同，本函数接受任意 `ERR_get_error()` 形态的错误码，未识别的码由
// 铜锁自行给出 "<库>:<reason>:" 形式或 "<HEX>:" 占位文本，不会 panic。
//
// ErrorString returns the textual description of a Tongsuo error code
// (wrapping ERR_error_string_n).
//
// It matches `tongsuo errstr <code>`. Unlike VerifyErrorMessage, which only
// understands X509_V_ERR_* chain-validation codes, this function accepts any
// ERR_get_error-style code; unrecognized codes yield the library's own
// "<lib>:<reason>:" form or a "<HEX>:" placeholder rather than panicking.
func ErrorString(code uint64) string {
	return native.ErrorString(code)
}

// ClassifySSLError 依据错误码的 lib / reason 两部分给出语义分类。
//
// ⚠️ 本函数是**尽力而为的启发式**：`SSL_R_*` 与 `X509_R_*` 共用 reason 编号空间，
// 而链验证失败常常只体现在 `SSL_get_verify_result`（`X509_V_ERR_*`）而非错误
// 队列上——后者由调用方直接判为 `SSLErrorClassPeerVerify`，不经过本函数。
// 未识别的组合一律归 `SSLErrorClassNetwork`（兜底，绝不返回 nil 语义）。
//
// code 为 0 时返回 SSLErrorClassOther。
//
// ClassifySSLError maps a code's lib and reason parts to a semantic class.
//
// ⚠️ This is a best-effort heuristic: SSL_R_* and X509_R_* share the reason
// number space, and chain-validation failures often surface only through
// SSL_get_verify_result (X509_V_ERR_*) rather than the error queue — callers
// classify that path as SSLErrorClassPeerVerify directly, bypassing this
// function. Unrecognized combinations fall back to SSLErrorClassNetwork.
//
// A code of 0 yields SSLErrorClassOther.
func ClassifySSLError(code uint64) SSLErrorClass {
	if code == 0 {
		return SSLErrorClassOther
	}
	switch native.ErrGetLib(code) {
	case native.ErrLibSSL:
		switch native.ErrGetReason(code) {
		case native.SSL_R_NO_SHARED_CIPHER, native.SSL_R_NO_CIPHERS_AVAILABLE:
			return SSLErrorClassCipher
		case native.SSL_R_UNSUPPORTED_PROTOCOL, native.SSL_R_VERSION_TOO_LOW,
			native.SSL_R_WRONG_SSL_VERSION, native.SSL_R_BAD_LEGACY_VERSION:
			return SSLErrorClassVersion
		}
	case native.ErrLibX509:
		if native.ErrGetReason(code) == native.X509_R_CERT_VERIFY_FAILED {
			return SSLErrorClassPeerVerify
		}
	}
	return SSLErrorClassNetwork
}
