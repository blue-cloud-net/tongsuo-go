package native

/*
#include "ssl_handshake.h"
#include "shim.h"
*/
import "C"

import (
	"errors"
	"runtime/cgo"
	"unsafe"
)

// ErrTLSUnsupported 表示所请求的原生 TLS 能力不可用。
//
// ErrTLSUnsupported indicates an unavailable native TLS capability.
var ErrTLSUnsupported = errors.New("tls: native capability unsupported")

// ErrTLSLimit 表示诊断缓冲超过限额。
//
// ErrTLSLimit indicates a diagnostic buffer limit was exceeded.
var ErrTLSLimit = errors.New("tls: diagnostic limit exceeded")

// TLSEvent 保存一次原生诊断观察的副本。
//
// TLSEvent contains a copy of a native diagnostic observation.
type TLSEvent struct {
	// Err 为生命周期或自定义验证错误。
	//
	// Err is a lifecycle or custom verification error.
	Err error
	// Kind 标记事件类别。
	//
	// Kind identifies the event category.
	Kind int
	// Write 标记发送方向。
	//
	// Write identifies outgoing observations.
	Write bool
	// Version 是原生协议版本。
	//
	// Version is the native protocol version.
	Version int
	// Type 是原生内容类型或状态标志。
	//
	// Type is the native content type or state flags.
	Type int
	// Code 是原生返回值或验证结果。
	//
	// Code is the native result or verification code.
	Code int
	// Depth 是证书验证深度。
	//
	// Depth is the certificate verification depth.
	Depth int
	// Data 保存独立字节副本。
	//
	// Data holds independent copied bytes.
	Data []byte
}

func (cb *TLSCallbacks) observe(kind, write, version, typ, code, depth int, ptr unsafe.Pointer, size uint64) {
	if cb.DiagnosticErr != nil {
		return
	}
	if kind == 8 || len(cb.Events) >= cb.MaxEvents || size > uint64(cb.MaxBytes-cb.EventBytes) || size > 1<<31-1 {
		cb.DiagnosticErr = ErrTLSLimit
		return
	}
	data := C.GoBytes(ptr, C.int(size))
	cb.Events = append(cb.Events, TLSEvent{Kind: kind, Write: write != 0, Version: version, Type: typ, Code: code, Depth: depth, Data: data})
	cb.EventBytes += int(size)
}

// CgoTLSObserve 在原生回调期间采集有界数据，不调用用户函数。
// CgoTLSObserve collects bounded data without invoking user functions.
//
//export CgoTLSObserve
func CgoTLSObserve(id C.uintptr_t, kind, write, version, typ, code C.int, ptr unsafe.Pointer, size C.size_t) {
	cb := cgo.Handle(id).Value().(*TLSCallbacks)
	cb.observe(int(kind), int(write), int(version), int(typ), int(code), 0, ptr, uint64(size))
}

// X_SSL_CTX_rfc8998 启用原生 RFC 8998 严格模式。
//
// X_SSL_CTX_rfc8998 enables native RFC 8998 strict mode.
func X_SSL_CTX_rfc8998(ctx unsafe.Pointer) bool { return C.X_SSL_CTX_rfc8998((*C.SSL_CTX)(ctx)) == 1 }

// X_SSL_diagnostics 安装连接诊断及可选 SCT 采集。
//
// X_SSL_diagnostics installs connection diagnostics and optional SCT capture.
func X_SSL_diagnostics(ssl unsafe.Pointer, flags, limit int, sct bool) bool {
	if sct && C.X_SSL_capture_sct((*C.SSL)(ssl)) != 1 {
		return false
	}
	return C.X_SSL_diagnostics((*C.SSL)(ssl), C.int(flags), C.size_t(limit)) == 1
}

// X_SSL_extra_state 复制安全重协商标志及 TLS 扩展 SCT。
//
// X_SSL_extra_state copies secure renegotiation support and TLS extension SCTs.
func X_SSL_extra_state(ssl unsafe.Pointer, capture bool) (bool, [][]byte, error) {
	s := (*C.SSL)(ssl)
	secure := C.X_SSL_secure_renegotiation(s) == 1
	var out [][]byte
	if capture {
		for i, n := 0, int(C.X_SSL_sct_count(s)); i < n; i++ {
			var data *C.uchar
			size := C.X_SSL_sct_copy(s, C.int(i), &data)
			if size < 0 {
				return secure, nil, errors.New("tls: encode SCT")
			}
			if size > 0 {
				out = append(out, C.GoBytes(unsafe.Pointer(data), size))
				C.X_OPENSSL_free(unsafe.Pointer(data))
			}
		}
	}
	return secure, out, nil
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

// CgoTLSTraceBudget 返回分配 trace 前允许暂存的剩余字节数。
// CgoTLSTraceBudget returns remaining bytes before allocating trace data.
//
//export CgoTLSTraceBudget
func CgoTLSTraceBudget(id C.uintptr_t) C.size_t {
	cb := cgo.Handle(id).Value().(*TLSCallbacks)
	if cb.DiagnosticErr != nil {
		return 0
	}
	if len(cb.Events) >= cb.MaxEvents {
		cb.DiagnosticErr = ErrTLSLimit
		return 0
	}
	return C.size_t(cb.MaxBytes - cb.EventBytes)
}

// X_SSL_CTX_keylog 按显式配置安装或禁用 keylog 回调。
//
// X_SSL_CTX_keylog installs or disables keylog according to explicit configuration.
func X_SSL_CTX_keylog(ctx unsafe.Pointer, enabled bool) {
	C.X_SSL_CTX_keylog((*C.SSL_CTX)(ctx), C.int(boolInt(enabled)))
}
