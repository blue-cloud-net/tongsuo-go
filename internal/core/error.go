package core

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/internal/native"
)

// OpError 表示一次铜锁操作失败，携带原生错误码（ERR_get_error 的返回值）。
// 对应 C# 参考项目中的 OpenSSLCryptoException。
//
// 类型被本包中所有包装器统一用于暴露绑定层失败；底层 OpenSSL 错误码通过 Code 字段暴露，
// 便于调用方与原生诊断信息关联。
//
// OpError reports a failed Tongsuo operation and carries the native error
// code returned by ERR_get_error. It is the Go analogue of the C#
// reference project's OpenSSLCryptoException.
//
// The type is used uniformly by every wrapper in this package to surface
// failures from the binding layer; the underlying OpenSSL code is exposed
// through Code so callers can correlate failures with native diagnostics.
type OpError struct {
	Op   string // 操作描述，如 "sm4: EVP_EncryptUpdate"
	Code uint64 // 铜锁错误码
	Msg  string // 错误描述（来自 ERR_error_string_n）
	Err  error  // 底层错误（可为 nil）
}

// NewOpError 构造 OpError：从绑定层捕获错误码与错误描述。
// op 字符串保留为可读的操作名（例如 "sm4: EVP_EncryptUpdate"），
// Msg 通过 native.ErrorString（内部封装 ERR_error_string_n）由 code 生成。
//
// NewOpError constructs an OpError by capturing the error code and
// message from the binding layer. The op string is preserved as the
// human-readable operation name (for example "sm4: EVP_EncryptUpdate"),
// and Msg is generated from code via native.ErrorString (which wraps
// ERR_error_string_n).
func NewOpError(op string, code uint64) *OpError {
	return &OpError{Op: op, Code: code, Msg: native.ErrorString(code)}
}

// Error 实现 error 接口。
// 当 Msg 非空时格式化为 "<op>: tongsuo error 0x<code> (<message>)"，否则回退为 "<op>: tongsuo error 0x<code>"。
// 仅在通过标准 error 机制调用时对 nil 接收者安全（调用方不应直接对类型化 nil 指针调用）。
//
// Error formats the failure as "<op>: tongsuo error 0x<code> (<message>)"
// when Msg is non-empty, falling back to "<op>: tongsuo error 0x<code>"
// otherwise. Implements the standard error interface and is safe to call
// on a nil receiver only via the standard error machinery (callers should
// not invoke it directly on a typed nil pointer).
func (e *OpError) Error() string {
	if e.Msg != "" {
		return fmt.Sprintf("%s: tongsuo error 0x%x (%s)", e.Op, e.Code, e.Msg)
	}
	return fmt.Sprintf("%s: tongsuo error 0x%x", e.Op, e.Code)
}

// Unwrap 返回底层错误，支持 errors.Is / errors.As。
// 当 e.Err 为 nil 时，错误链终止于 OpError。
//
// Unwrap returns the wrapped underlying error (e.Err), enabling
// errors.Is and errors.As to traverse the error chain. When e.Err is
// nil the chain terminates at OpError.
func (e *OpError) Unwrap() error { return e.Err }
