package native

/*
#include "ssl_handshake.h"
#include "shim.h"
#include <openssl/x509v3.h>
#include <openssl/objects.h>
#include <stdlib.h>
*/
import "C"

import (
	"errors"
	"fmt"
	"runtime/cgo"
	"unsafe"
)

// TLSSelection 保存连接独享的 SNI 配置选择。
// TLSSelection holds a connection-specific SNI configuration selection.
type TLSSelection struct {
	// Context 在配置切换期间借用的 SSL_CTX 指针。
	// Context is an SSL_CTX pointer borrowed during configuration selection.
	Context unsafe.Pointer
	// Protocols 按服务端优先级排列的 ALPN 列表。
	// Protocols lists ALPN protocols in server preference order.
	Protocols []string
	// Groups 传给原生层的冒号分隔命名组。
	// Groups contains colon-separated native named groups.
	Groups string
	// Signatures 传给原生层的冒号分隔签名算法。
	// Signatures contains colon-separated native signature algorithms.
	Signatures string
	// LegacyCiphers TLS 1.2 及 NTLS 的有效套件列表。
	// LegacyCiphers contains effective TLS 1.2 and NTLS cipher suites.
	LegacyCiphers string
	// TLS13Ciphers TLS 1.3 的有效套件列表。
	// TLS13Ciphers contains effective TLS 1.3 cipher suites.
	TLS13Ciphers string
}

// TLSVerifyFailure 保存原生验证失败的副本。
// TLSVerifyFailure holds a copy of a native verification failure.
type TLSVerifyFailure struct {
	// Code 原生 X509 验证错误码。
	// Code is the native X509 verification error code.
	Code int
	// Depth 失败证书的验证链深度。
	// Depth is the failing certificate depth.
	Depth int
	// Certificate 失败证书的独立 DER 副本。
	// Certificate is independent DER of the failing certificate.
	Certificate []byte
}

// TLSCallbacks 管理一个 SSL 对象的回调及失败信息。
// TLSCallbacks manages callbacks and failure details for one SSL object.
type TLSCallbacks struct {
	// VerifyEnabled 指定是否将原生验证结果作为信任验证。
	// VerifyEnabled reports whether native checks count as trust verification.
	VerifyEnabled bool
	// VerificationPerformed 标记内建验证回调实际执行过。
	// VerificationPerformed reports whether the built-in verification callback actually ran.
	VerificationPerformed bool
	// Tag 关联 API 配置的不透明标记。
	// Tag is an opaque tag associating the API configuration.
	Tag any
	// Select 处理当前连接的 ClientHello 配置选择。
	// Select selects the configuration for this connection ClientHello.
	Select func(string, bool) (*TLSSelection, error)
	// Protocols 按服务端优先级排列的 ALPN 列表。
	// Protocols lists ALPN protocols in server preference order.
	Protocols []string
	// Continue 指定原生验证失败后是否继续。
	// Continue controls continuation after native verification failure.
	Continue bool
	// Failures 按发生顺序保存原生验证失败副本。
	// Failures preserves native verification failures in occurrence order.
	Failures []TLSVerifyFailure
	// Err 保存需要终止握手的回调错误。
	// Err holds a callback error that aborts the handshake.
	Err error
	// Cleanup 随 SSL_free 释放附属资源。
	// Cleanup releases associated resources during SSL_free.
	Cleanup func()
}

// X_SSL_attach_callbacks 注册整数句柄，随 SSL_free 释放。
// X_SSL_attach_callbacks registers an integer handle released by SSL_free.
func X_SSL_attach_callbacks(ssl unsafe.Pointer, callbacks *TLSCallbacks) bool {
	h := cgo.NewHandle(callbacks)
	if C.X_SSL_attach((*C.SSL)(ssl), C.uintptr_t(h)) != 1 {
		h.Delete()
		return false
	}
	return true
}

// CgoTLSRelease 释放 SSL 持有的 Go 回调句柄。
// CgoTLSRelease releases the Go callback handle owned by SSL.
//
//export CgoTLSRelease
func CgoTLSRelease(id C.uintptr_t) {
	h := cgo.Handle(id)
	cb := h.Value().(*TLSCallbacks)
	if cb.Cleanup != nil {
		cb.Cleanup()
	}
	h.Delete()
}

// CgoTLSSelect 应用当前连接的 SNI 配置。
// CgoTLSSelect applies the SNI configuration for the current connection.
//
//export CgoTLSSelect
func CgoTLSSelect(id C.uintptr_t, ssl *C.SSL, name *C.char, ntls C.int) C.int {
	cb := cgo.Handle(id).Value().(*TLSCallbacks)
	if cb.Select == nil {
		return 1
	}
	selection, err := cb.Select(C.GoString(name), ntls != 0)
	if err == nil && selection != nil {
		cb.Protocols = selection.Protocols
		if C.X_SSL_switch_context(ssl, (*C.SSL_CTX)(selection.Context)) != 1 {
			err = errors.New("tls: switch SNI context")
		}
		const (
			groups = iota
			signatures
			legacyCiphers
			tls13Ciphers
		)
		settings := []struct {
			value string
			kind  int
		}{{selection.Groups, groups}, {selection.Signatures, signatures}, {selection.LegacyCiphers, legacyCiphers}, {selection.TLS13Ciphers, tls13Ciphers}}
		for _, setting := range settings {
			if err != nil || (setting.value == "" && setting.kind < legacyCiphers) {
				continue
			}
			str := C.CString(setting.value)
			var ok C.int
			switch setting.kind {
			case groups:
				ok = C.X_SSL_groups(ssl, str)
			case signatures:
				ok = C.X_SSL_sigalgs(ssl, str)
			case legacyCiphers:
				ok = C.SSL_set_cipher_list(ssl, str)
			case tls13Ciphers:
				ok = C.SSL_set_ciphersuites(ssl, str)
			}
			C.free(unsafe.Pointer(str))
			if setting.kind == legacyCiphers && setting.value == "" {
				C.ERR_clear_error()
			}
			if ok != 1 && !(setting.kind == legacyCiphers && setting.value == "") {
				err = errors.New("tls: SNI handshake parameters")
			}
		}
	}
	if err != nil {
		cb.Err = err
		return 0
	}
	return 1
}

// CgoTLSVerify 捕获每层证书失败，按显式策略决定是否继续。
// CgoTLSVerify captures certificate failures and applies the explicit continuation policy.
//
//export CgoTLSVerify
func CgoTLSVerify(id C.uintptr_t, ok, code, depth C.int, cert *C.X509) C.int {
	cb := cgo.Handle(id).Value().(*TLSCallbacks)
	if cb.VerifyEnabled {
		cb.VerificationPerformed = true
	}
	if ok == 0 && cb.VerifyEnabled {
		cb.Failures = append(cb.Failures, TLSVerifyFailure{int(code), int(depth), certificateDER(cert)})
	}
	if ok != 0 || cb.Continue {
		return 1
	}
	return 0
}

// CgoTLSALPN 按服务端优先级选择客户端协议。
// CgoTLSALPN selects an offered protocol using server preference.
//
//export CgoTLSALPN
func CgoTLSALPN(id C.uintptr_t, wire *C.uchar, size C.uint) C.int {
	cb := cgo.Handle(id).Value().(*TLSCallbacks)
	if len(cb.Protocols) == 0 {
		return -1
	}
	offered := C.GoBytes(unsafe.Pointer(wire), C.int(size))
	for _, want := range cb.Protocols {
		for i := 0; i < len(offered); {
			n := int(offered[i])
			if n == 0 || i+1+n > len(offered) {
				return -2
			}
			if string(offered[i+1:i+1+n]) == want {
				return C.int(i)
			}
			i += 1 + n
		}
	}
	return -2
}

func certificateDER(cert *C.X509) []byte {
	if cert == nil {
		return nil
	}
	var out *C.uchar
	n := C.i2d_X509(cert, &out)
	if n <= 0 {
		return nil
	}
	defer C.X_OPENSSL_free(unsafe.Pointer(out))
	return C.GoBytes(unsafe.Pointer(out), n)
}

// X_SSL_CTX_callbacks 安装每连接回调分发器。
// X_SSL_CTX_callbacks installs per-connection callback dispatchers.
func X_SSL_CTX_callbacks(ctx unsafe.Pointer) { C.X_SSL_CTX_callbacks((*C.SSL_CTX)(ctx)) }

// X_SSL_CTX_parameters 设置组、签名算法、DH 参数及选项。
// X_SSL_CTX_parameters sets groups, signatures, DH parameters and options.
func X_SSL_CTX_parameters(ctx unsafe.Pointer, groups, sigs string, dh []byte, options uint64, modes int64) bool {
	g, s := C.CString(groups), C.CString(sigs)
	defer C.free(unsafe.Pointer(g))
	defer C.free(unsafe.Pointer(s))
	var p unsafe.Pointer
	if len(dh) > 0 {
		p = C.CBytes(dh)
		defer C.free(p)
	}
	return C.X_SSL_CTX_parameters((*C.SSL_CTX)(ctx), g, s, (*C.uchar)(p), C.size_t(len(dh)), C.uint64_t(options), C.long(modes)) == 1
}

// X_SSL_CTX_add_chain 为当前凭证复制中间证书引用。
// X_SSL_CTX_add_chain copies an intermediate certificate reference for the current credential.
func X_SSL_CTX_add_chain(ctx, cert unsafe.Pointer) bool {
	return C.X_SSL_CTX_add_chain((*C.SSL_CTX)(ctx), (*C.X509)(cert)) == 1
}

// X_SSL_CTX_add_client_ca 添加客户端 CA 名称。
// X_SSL_CTX_add_client_ca adds a client CA name.
func X_SSL_CTX_add_client_ca(ctx, cert unsafe.Pointer) bool {
	return C.X_SSL_CTX_add_client_ca((*C.SSL_CTX)(ctx), (*C.X509)(cert)) == 1
}

// X509_check_private_key 校验证书与私钥配对。
// X509_check_private_key checks the certificate and private key pair.
func X509_check_private_key(cert, key unsafe.Pointer) bool {
	return C.X509_check_private_key((*C.X509)(cert), (*C.EVP_PKEY)(key)) == 1
}

// SSL_CTX_set_alpn_protos 设置客户端 ALPN 列表。
// SSL_CTX_set_alpn_protos sets the client ALPN list.
func SSL_CTX_set_alpn_protos(ctx unsafe.Pointer, wire []byte) bool {
	if len(wire) == 0 {
		return true
	}
	return C.SSL_CTX_set_alpn_protos((*C.SSL_CTX)(ctx), (*C.uchar)(unsafe.Pointer(&wire[0])), C.uint(len(wire))) == 0
}

// X_SSL_set_verify_name 分别设置 DNS/IP 与邮箱验证参数。
// X_SSL_set_verify_name sets DNS/IP and email verification parameters.
func X_SSL_set_verify_name(ssl unsafe.Pointer, host string, ip bool, flags uint32, email string) bool {
	h, e := C.CString(host), C.CString(email)
	defer C.free(unsafe.Pointer(h))
	defer C.free(unsafe.Pointer(e))
	i := 0
	if ip {
		i = 1
	}
	return C.X_SSL_set_verify_name((*C.SSL)(ssl), h, C.int(i), C.uint(flags), e) == 1
}

// X_SSL_name_check 校验 DNS、IP 或邮箱，不改变证书。
// X_SSL_name_check checks DNS, IP or email without modifying the certificate.
func X_SSL_name_check(cert unsafe.Pointer, name string, kind int, flags uint32) bool {
	n := C.CString(name)
	defer C.free(unsafe.Pointer(n))
	return C.X_SSL_name_check((*C.X509)(cert), n, C.int(kind), C.uint(flags)) == 1
}

// TLSSnapshot 保存无原生资源的连接状态。
// TLSSnapshot holds connection state without native resources.
type TLSSnapshot struct {
	// Version 实际协商的协议版本号。
	// Version is the actually negotiated wire version.
	Version uint16
	// CipherSuite 协商套件的 wire ID。
	// CipherSuite is the negotiated cipher wire ID.
	CipherSuite uint16
	// CipherName 协商套件的铜锁名称。
	// CipherName is the Tongsuo name of the negotiated suite.
	CipherName string
	// ServerName 当前连接发送或接收的 SNI。
	// ServerName is the SNI sent or received by this connection.
	ServerName string
	// Protocol 协商的 ALPN 协议，未协商时为空。
	// Protocol is the negotiated ALPN protocol, empty if absent.
	Protocol string
	// Group 协商组的原生名称，不可用时为空。
	// Group is the native negotiated group name, empty if unavailable.
	Group string
	// Signature 原生报告的对端签名算法名称。
	// Signature is the peer signature algorithm name reported natively.
	Signature string
	// VerifyCode 原生最近一次验证结果。
	// VerifyCode is the most recent native verification result.
	VerifyCode int
	// PeerCertificates 对端叶证书与链的独立 DER。
	// PeerCertificates contains independent peer leaf and chain DER.
	PeerCertificates [][]byte
	// VerifiedChain 原生最近一次验证通过的链 DER。
	// VerifiedChain contains DER of the most recently verified native chain.
	VerifiedChain [][]byte
}

// X_SSL_snapshot 复制协商状态及证书 DER。
// X_SSL_snapshot copies negotiated state and certificate DER.
func X_SSL_snapshot(ptr unsafe.Pointer) TLSSnapshot {
	ssl := (*C.SSL)(ptr)
	state := TLSSnapshot{Version: uint16(C.SSL_version(ssl)), ServerName: C.GoString(C.SSL_get_servername(ssl, C.TLSEXT_NAMETYPE_host_name)), VerifyCode: int(C.SSL_get_verify_result(ssl))}
	cipher := C.SSL_get_current_cipher(ssl)
	if cipher != nil {
		state.CipherSuite = uint16(C.SSL_CIPHER_get_protocol_id(cipher))
		state.CipherName = C.GoString(C.SSL_CIPHER_get_name(cipher))
	}
	var proto *C.uchar
	var n C.uint
	C.SSL_get0_alpn_selected(ssl, &proto, &n)
	if n > 0 {
		state.Protocol = C.GoStringN((*C.char)(unsafe.Pointer(proto)), C.int(n))
	}
	group := C.int(0)
	if C.SSL_is_init_finished(ssl) == 1 {
		group = C.X_SSL_group(ssl)
	}
	if group > 0 {
		name := C.SSL_group_to_name(ssl, C.int(group))
		if name != nil {
			state.Group = C.GoString(name)
		} else {
			state.Group = fmt.Sprint(group)
		}
	}
	var sig C.int
	if C.SSL_is_init_finished(ssl) == 1 && C.X_SSL_peer_sig(ssl, &sig) == 1 {
		state.Signature = C.GoString(C.OBJ_nid2sn(sig))
	}
	leaf := C.SSL_get1_peer_certificate(ssl)
	if leaf != nil {
		state.PeerCertificates = append(state.PeerCertificates, certificateDER(leaf))
		C.X509_free(leaf)
	}
	chain := C.SSL_get_peer_cert_chain(ssl)
	for i := 0; i < int(C.X_TLS_chain_num(chain)); i++ {
		cert := C.X_TLS_chain_value(chain, C.int(i))
		der := certificateDER(cert)
		if len(state.PeerCertificates) > 0 && string(der) == string(state.PeerCertificates[0]) {
			continue
		}
		state.PeerCertificates = append(state.PeerCertificates, der)
	}
	chain = C.SSL_get0_verified_chain(ssl)
	for i := 0; i < int(C.X_TLS_chain_num(chain)); i++ {
		state.VerifiedChain = append(state.VerifiedChain, certificateDER(C.X_TLS_chain_value(chain, C.int(i))))
	}
	return state
}

// X_SSL_send_close_notify 尝试非阻塞发送关闭通知，不等待对端。
// X_SSL_send_close_notify attempts a nonblocking close notification without waiting for the peer.
func X_SSL_send_close_notify(ssl unsafe.Pointer) { C.X_SSL_send_close_notify((*C.SSL)(ssl)) }

// X_SSL_operation 在 SSL 操作返回时同时捕获 errno，供 SSL_ERROR_SYSCALL 使用。
// X_SSL_operation captures errno together with the SSL result for SSL_ERROR_SYSCALL.
func X_SSL_operation(ssl unsafe.Pointer, op string, data []byte) (int, error) {
	var ret C.int
	var err error
	var buf unsafe.Pointer
	if len(data) > 0 {
		buf = unsafe.Pointer(&data[0])
	}
	switch op {
	case "SSL_connect":
		ret, err = C.SSL_connect((*C.SSL)(ssl))
	case "SSL_accept":
		ret, err = C.SSL_accept((*C.SSL)(ssl))
	case "SSL_read":
		ret, err = C.SSL_read((*C.SSL)(ssl), buf, C.int(len(data)))
	case "SSL_write":
		ret, err = C.X_SSL_write_owned((*C.SSL)(ssl), buf, C.int(len(data)))
	default:
		return -1, errors.New("tls: unknown SSL operation")
	}
	return int(ret), err
}
