// Package core 的随机数薄包装层。
//
// 文件提供加密安全随机数的核心层抽象：将 internal/native 的 RAND_bytes 调用
// 与错误码获取封装为 core.RandomBytes，使公开层 crypto/rand 不必直接依赖
// internal/native，从而维护三层（API → core → native）的依赖方向。
//
// The random bytes thin wrapper for the core layer.
//
// The file exposes RandomBytes as the core-layer abstraction over
// internal/native.RAND_bytes + PopError, so the public crypto/rand
// package does not need to import internal/native. This preserves the
// documented three-layer dependency direction (API → core → native).
package core

import (
	"github.com/blue-cloud-net/tongsuo-go/internal/native"
)

// RandomBytes 使用铜锁 RAND_bytes 将加密安全随机字节填充到 b。
//
// 成功时返回 nil；CSPRNG 失败时返回包装 ERR_get_error 错误码的 *OpError。
// 该函数为内部 core 层对外暴露的随机数原语，crypto/rand 公开包
// 不应直接调用 internal/native，统一经由本函数获取随机源。
//
// RandomBytes fills b with cryptographically secure random bytes sourced
// from Tongsuo RAND_bytes.
//
// Returns nil on success, or a *OpError wrapping the ERR_get_error code
// when the underlying CSPRNG fails. This is the core-layer primitive
// exposed to the public crypto/rand package so that the latter does not
// need to import internal/native.
func RandomBytes(b []byte) error {
	if !native.RAND_bytes(b) {
		return NewOpError("rand: RAND_bytes", native.PopError())
	}
	return nil
}
