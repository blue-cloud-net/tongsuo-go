package core

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/internal/native"
)

// OpError 表示一次铜锁操作失败，携带原生错误码（ERR_get_error 的返回值）。
// 对应 C# 参考项目中的 OpenSSLCryptoException。
type OpError struct {
	Op   string // 操作描述，如 "sm4: EVP_EncryptUpdate"
	Code uint64 // 铜锁错误码
	Msg  string // 错误描述（来自 ERR_error_string_n）
	Err  error  // 底层错误（可为 nil）
}

// NewOpError 构造 OpError：从绑定层捕获错误码与错误描述。
func NewOpError(op string, code uint64) *OpError {
	return &OpError{Op: op, Code: code, Msg: native.ErrorString(code)}
}

// Error 实现 error 接口。
func (e *OpError) Error() string {
	if e.Msg != "" {
		return fmt.Sprintf("%s: tongsuo error 0x%x (%s)", e.Op, e.Code, e.Msg)
	}
	return fmt.Sprintf("%s: tongsuo error 0x%x", e.Op, e.Code)
}

// Unwrap 返回底层错误，支持 errors.Is / errors.As。
func (e *OpError) Unwrap() error { return e.Err }
