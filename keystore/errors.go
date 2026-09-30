package keystore

import "errors"

// 本包定义的哨兵错误。
//
// Package-level sentinel errors.
var (
	// ErrNotFound 表示存储中不存在指定 ID 的条目。
	//
	// ErrNotFound reports that no entry with the given ID exists in the store.
	ErrNotFound = errors.New("keystore: not found")
	// ErrClosed 表示密钥句柄关闭后仍被使用。
	//
	// 本包的 Handle.Close 是幂等的，不会返回该错误；它供调用方在自有的
	// 生命周期实现中复用同一哨兵，与迁移前的 key.ErrClosed 对齐。
	//
	// ErrClosed reports use of a key handle after it has been closed.
	//
	// Handle.Close in this package is idempotent and never returns this
	// error; it exists so callers implementing their own lifecycle can
	// reuse the same sentinel, matching the pre-migration key.ErrClosed.
	ErrClosed = errors.New("keystore: key closed")
	// ErrUnsupported 表示该密钥类型不支持所请求的操作（如导出为 PEM）。
	//
	// ErrUnsupported reports that the key type does not support the
	// requested operation, such as exporting to PEM.
	ErrUnsupported = errors.New("keystore: unsupported key type")
	// ErrNoDecoder 表示未配置 PEM 解码器，无法从 JSON 还原密钥对象。
	//
	// 本包不 import asym / sym，无法自行把 PEM 还原为具体密钥类型；
	// 请先经 (*Handle).SetDecoder 注入，或改用 UnmarshalHandle。
	//
	// ErrNoDecoder reports that no PEM decoder is configured, so the key
	// object cannot be restored from JSON.
	//
	// This package does not import asym or sym and therefore cannot turn
	// PEM back into a concrete key type on its own: inject a decoder with
	// (*Handle).SetDecoder first, or use UnmarshalHandle.
	ErrNoDecoder = errors.New("keystore: no PEM decoder configured")
)
