package native

/*
#include "ssl_handshake.h"
#include <stdlib.h>
#include <openssl/err.h>
*/
import "C"

import (
	"bytes"
	"runtime/cgo"
	"unsafe"
)

// SSLSessionInfo 保存不含密钥的会话元数据。
// SSLSessionInfo holds session metadata without key material.
type SSLSessionInfo struct {
	// Peer 为会话原生对端叶证书副本。
	// Peer is a copy of the native session peer leaf certificate.
	Peer []byte

	// Version 为协议版本。
	// Version is the protocol version.
	Version uint16
	// Created 为创建时间戳。
	// Created is the creation timestamp.
	Created int64
	// Timeout 为有效秒数。
	// Timeout is the lifetime in seconds.
	Timeout int64
	// HasTicket 标记存在票据。
	// HasTicket reports whether a ticket is present.
	HasTicket bool
	// Resumable 标记原生可恢复状态。
	// Resumable reports native resumability.
	Resumable bool
	// ID 为会话标识副本。
	// ID is a copied session identifier.
	ID []byte
}

func sessionDER(s *C.SSL_SESSION) []byte {
	var out *C.uchar
	n := C.i2d_SSL_SESSION(s, &out)
	if n <= 0 {
		return nil
	}
	defer C.CRYPTO_free(unsafe.Pointer(out), nil, 0)
	return C.GoBytes(unsafe.Pointer(out), n)
}
func decodeSession(data []byte) *C.SSL_SESSION {
	if len(data) == 0 || len(data) > 1<<20 {
		return nil
	}
	mem := C.CBytes(data)
	defer C.free(mem)
	ptr := (*C.uchar)(mem)
	s := C.d2i_SSL_SESSION(nil, &ptr, C.long(len(data)))
	if s != nil && uintptr(unsafe.Pointer(ptr))-uintptr(mem) != uintptr(len(data)) {
		C.SSL_SESSION_free(s)
		return nil
	}
	return s
}

// SSL_SESSION_decode 校验完整 DER，返回元数据与规范化副本。
// SSL_SESSION_decode validates complete DER and returns metadata and a canonical copy.
func SSL_SESSION_decode(data []byte) (SSLSessionInfo, []byte) {
	s := decodeSession(data)
	if s == nil {
		return SSLSessionInfo{}, nil
	}
	defer C.SSL_SESSION_free(s)
	var n C.uint
	id := C.SSL_SESSION_get_id(s, &n)
	return SSLSessionInfo{certificateDER(C.SSL_SESSION_get0_peer(s)), uint16(C.SSL_SESSION_get_protocol_version(s)), int64(C.SSL_SESSION_get_time(s)), int64(C.SSL_SESSION_get_timeout(s)), C.SSL_SESSION_has_ticket(s) != 0, C.SSL_SESSION_is_resumable(s) != 0, C.GoBytes(unsafe.Pointer(id), C.int(n))}, sessionDER(s)
}

// SSL_set_session 将独立解码的会话设置到连接。
// SSL_set_session sets an independently decoded session on a connection.
func SSL_set_session(ssl unsafe.Pointer, data []byte) bool {
	s := decodeSession(data)
	if s == nil {
		return false
	}
	defer C.SSL_SESSION_free(s)
	return C.SSL_set_session((*C.SSL)(ssl), s) == 1
}

// SSL_session_reused 返回实际恢复状态。
// SSL_session_reused reports actual session resumption.
func SSL_session_reused(ssl unsafe.Pointer) bool { return C.SSL_session_reused((*C.SSL)(ssl)) == 1 }

// X_SSL_CTX_sessions 配置缓存、票据与隔离域。
// X_SSL_CTX_sessions configures caching, tickets and the isolation domain.
func X_SSL_CTX_sessions(ctx unsafe.Pointer, server, disabled bool, tickets int, domain []byte) bool {
	if len(domain) != 32 {
		return false
	}
	p := C.CBytes(domain)
	defer C.free(p)
	return C.X_SSL_CTX_sessions((*C.SSL_CTX)(ctx), C.int(boolInt(server)), C.int(boolInt(disabled)), C.int(tickets), (*C.uchar)(p)) == 1
}

// X_SSL_reverify 对恢复会话重新执行当前原生验证。
// X_SSL_reverify reruns current native verification on a resumed session.
func X_SSL_reverify(ssl unsafe.Pointer, chain []byte) bool {
	p := C.CBytes(append([]byte{}, chain...))
	defer C.free(p)
	return C.X_SSL_reverify((*C.SSL)(ssl), (*C.uchar)(p), C.size_t(len(chain))) == 1
}

// CgoTLSNewSession 保存新建会话副本。
// CgoTLSNewSession saves a copy of a new session.
//
//export CgoTLSNewSession
func CgoTLSNewSession(id C.uintptr_t, session *C.SSL_SESSION) {
	cb := cgo.Handle(id).Value().(*TLSCallbacks)
	cb.Session = sessionDER(session)
	if cb.SessionPut != nil && len(cb.Session) > 0 {
		var n C.uint
		key := C.SSL_SESSION_get_id(session, &n)
		cb.SessionPut(append(append([]byte(nil), cb.SessionName...), C.GoBytes(unsafe.Pointer(key), C.int(n))...), cb.Session)
	}
}

// CgoTLSGetSession 返回独立拥有的缓存会话。
// CgoTLSGetSession returns an independently owned cached session.
//
//export CgoTLSGetSession
func CgoTLSGetSession(id C.uintptr_t, key *C.uchar, n C.int) *C.SSL_SESSION {
	cb := cgo.Handle(id).Value().(*TLSCallbacks)
	if cb.SessionGet == nil {
		return nil
	}
	return decodeSession(cb.SessionGet(append(append([]byte(nil), cb.SessionName...), C.GoBytes(unsafe.Pointer(key), n)...)))
}

// CgoTLSTicketKey 复制选定的票据密钥到原生缓冲区。
// CgoTLSTicketKey copies the selected ticket key into a native buffer.
//
//export CgoTLSTicketKey
func CgoTLSTicketKey(id C.uintptr_t, name, out *C.uchar, enc C.int) C.int {
	cb := cgo.Handle(id).Value().(*TLSCallbacks)
	if cb.TicketKey == nil {
		return -1
	}
	key, status := cb.TicketKey(C.GoBytes(unsafe.Pointer(name), 16), enc != 0)
	if status <= 0 || len(key) != 64 {
		return C.int(status)
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(out)), 64), key)
	return C.int(status)
}

// CgoTLSReverified 保存重新验证后的独立证书链。
// CgoTLSReverified saves the independently copied reverified certificate chain.
//
//export CgoTLSReverified
func CgoTLSReverified(id C.uintptr_t, chain *C.struct_stack_st_X509) {
	cb := cgo.Handle(id).Value().(*TLSCallbacks)
	cb.ReverifiedChain = nil
	for i := 0; i < int(C.X_TLS_chain_num(chain)); i++ {
		cb.ReverifiedChain = append(cb.ReverifiedChain, certificateDER(C.X_TLS_chain_value(chain, C.int(i))))
	}
}

// CgoTLSResumedPeers 保存以原生叶证书为首的独立身份材料。
// CgoTLSResumedPeers saves copied identity material headed by the native peer leaf.
//
//export CgoTLSResumedPeers
func CgoTLSResumedPeers(id C.uintptr_t, leaf *C.X509, chain *C.struct_stack_st_X509) {
	cb := cgo.Handle(id).Value().(*TLSCallbacks)
	cb.ResumedPeers = [][]byte{certificateDER(leaf)}
	for i := 0; i < int(C.X_TLS_chain_num(chain)); i++ {
		der := certificateDER(C.X_TLS_chain_value(chain, C.int(i)))
		duplicate := false
		for _, prior := range cb.ResumedPeers {
			if bytes.Equal(prior, der) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			cb.ResumedPeers = append(cb.ResumedPeers, der)
		}
	}
}
