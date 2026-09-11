// Package tls 提供密码套件枚举与 Config.CipherSuites 混合语义。
//
// CipherSuites(version) 返回指定版本下 ctx 启用的全部套件（Name/ID/
// MinVersion/MaxVersion）；实现走「临时 ctx 探测」+ min_tls 字符串解析
// 派生 MinVersion 与 MaxVersion（详见 core.CipherList 与本文件的实现
// 注）。
//
// Config.CipherSuites 支持混合名单（OpenSSL 标准名如 "TLS_AES_128_GCM_SHA256"
// 走 set_ciphersuites 路径；OpenSSL 经典名如 "ECDHE-RSA-AES256-GCM-SHA384"
// 走 set_cipher_list 路径）；逐名探测，部分匹配不致命，全不匹配才返回
// ErrNoSharedCipher。
//
// Cipher suite enumeration and the mixed Config.CipherSuites semantics.
//
// CipherSuites(version) enumerates every cipher enabled at the supplied
// protocol version (Name/ID/MinVersion/MaxVersion). Implementation uses
// a probe scratch ctx (since OpenSSL does not version-filter
// SSL_CTX_get_ciphers); MinVersion / MaxVersion are derived from the
// cipher's min_tls string.
//
// Config.CipherSuites accepts a mix of OpenSSL standard names (TLS1.3,
// set_ciphersuites path) and OpenSSL legacy names (pre-TLS1.3,
// set_cipher_list path). Names are probed individually so partial
// matches are not fatal; only when no name matches does the configuration
// fail with ErrNoSharedCipher.

package tls

import (
	"errors"
	"strings"
	"unsafe"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
	"github.com/blue-cloud-net/tongsuo-go/internal/native"
)

// NTLSVersion 是铜锁 NTLS（TLCP）协议版本常量，对应 internal/native
// 的 NTLSVersion，便于在 CipherSuites / Config.MinVersion / Config.MaxVersion
// 等公开 API 中使用同一组数字标识。
//
// NTLSVersion is the Tongsuo NTLS (TLCP) protocol version constant; pass
// it to CipherSuites / Config.MinVersion / Config.MaxVersion as the
// canonical wire-version identifier.
const NTLSVersion uint16 = native.NTLSVersion

// CipherSuiteInfo 描述一个 TLS / NTLS 密码套件。
//
// CipherSuiteInfo describes a single cipher suite as exposed by the
// enumeration API. All fields are value copies; the struct holds no
// native resources and is safe to retain.
type CipherSuiteInfo struct {
	// Name 是套件的 OpenSSL 名称（如 "ECDHE-SM2-SM4-GCM-SM3" 或
	// "TLS_AES_128_GCM_SHA256"）。同一 ID 在不同版本下可能有不同名，
	// 此处保留探测到的版本对应的名。
	//
	// Name is the OpenSSL name of the cipher as reported for the probed
	// version.
	Name string

	// ID 是 16 位 IANA wire ID；NTLS 套件为铜锁私有编码（如 0x0300E051）。
	//
	// ID is the 16-bit IANA cipher wire ID; NTLS ciphers carry Tongsuo
	// private codes such as 0x0300E051.
	ID uint16

	// MinVersion 是套件适用的最低协议版本（uint16，与 Config.MinVersion
	// 等同型号）。TLS1.0-1.3 由 OpenSSL min_tls 字符串解析；NTLS 套件
	// 固定为 NTLSVersion。
	//
	// MinVersion is the minimum protocol version the cipher is allowed
	// for. Parsed from the OpenSSL c->min_tls string.
	MinVersion uint16

	// MaxVersion 是套件适用的最高协议版本。本库采用「MinVersion ==
	// MaxVersion」语义（OpenSSL 表内 ciphers 的 min/max 通常相同；TLS1.3
	// 套件 max 固定为 TLS1_3Version）；NTLS 套件固定为 NTLSVersion。
	//
	// MaxVersion is the maximum protocol version the cipher is allowed
	// for. Set equal to MinVersion per OpenSSL convention (cipher
	// tables typically have min == max; TLS1.3 ciphers cap at
	// TLS1_3Version). NTLS ciphers cap at NTLSVersion.
	MaxVersion uint16
}

// CipherSuites 返回指定协议版本下铜锁原生支持的密码套件集合。
//
// version 取 TLS1Version / TLS1_1Version / TLS1_2Version / TLS1_3Version /
// NTLSVersion；未识别返回 nil。
//
// 实现走「临时 ctx 探测」：创建一个用对应 method 的 ctx（version==NTLSVersion
// 时用 NTLS_method + SSL_CTX_enable_ntls），限定 min=max=version，设
// set_cipher_list("ALL:eNULL") 加载全量，遍历 SSL_CTX_get_ciphers 取
// Name/ID 与 min_tls 字符串派生 MinVersion；MaxVersion 默认 = MinVersion。
//
// 同一 ID 在不同版本下的表现可能不同（OpenSSL 表内 ciphers 通常
// min==max）；这里返回的是「在指定版本下确实存在的所有套件」全量，
// MinVersion 由解析得到。注意：CipherSuites(TLS1_3) 与
// CipherSuites(TLS1_2) 的结果可能有重叠（TLS1.3-only 套件不会被旧版
// ctx 报告），调用方按 MinVersion 过滤即可。
//
// CipherSuites returns every cipher the Tongsuo native library supports
// at the given protocol version. Pass one of TLS1Version / TLS1_1Version
// / TLS1_2Version / TLS1_3Version / NTLSVersion (or the equivalent
// native.TLS*_Version constants); unknown values return nil.
//
// Implementation creates a probe ctx (NTLS_method for NTLSVersion) and
// restricts min=max=version, then enumerates SSL_CTX_get_ciphers.
func CipherSuites(version uint16) []CipherSuiteInfo {
	if core.CipherVersionToUint16(version) == 0 {
		return nil
	}
	ctx, err := probeCtx(version)
	if err != nil {
		return nil
	}
	defer ctx.free()

	if !native.SSL_CTX_set_min_proto_version(ctx.handle, int(version)) {
		return nil
	}
	if !native.SSL_CTX_set_max_proto_version(ctx.handle, int(version)) {
		return nil
	}
	if !native.SSL_CTX_set_cipher_list(ctx.handle, "ALL:eNULL") {
		return nil
	}
	sk := native.SSL_CTX_get_ciphers(ctx.handle)
	n := native.SSL_CIPHER_sk_num(sk)
	if n == 0 {
		return nil
	}
	out := make([]CipherSuiteInfo, 0, n)
	for i := 0; i < n; i++ {
		cp := native.SSL_CIPHER_sk_value(sk, i)
		if cp == nil {
			continue
		}
		name := native.SSL_CIPHER_get_name(cp)
		id := native.SSL_CIPHER_get_protocol_id(cp)
		minStr := native.SSL_CIPHER_get_version(cp)
		minV := versionForCipher(minStr, version)
		out = append(out, CipherSuiteInfo{
			Name:       name,
			ID:         id,
			MinVersion: minV,
			MaxVersion: minV,
		})
	}
	return out
}

// versionForCipher 从 OpenSSL 返回的 min_tls 字符串派生 uint16 协议版本。
// NTLS 套件因 min_tls="NTLSv1.1" → NTLSVersion；其它情况回退为 version
// （probe ctx 已限定范围）。
//
// versionForCipher derives a uint16 protocol version from the OpenSSL
// min_tls string. NTLS ciphers (min_tls="NTLSv1.1") map to NTLSVersion;
// everything else falls back to the supplied version (the probe ctx has
// already constrained the range).
func versionForCipher(minTLS string, fallback uint16) uint16 {
	if v := core.VersionNameToUint16(minTLS); v != 0 {
		return v
	}
	return fallback
}

// probeCtxPtr 包装一个 SSL_CTX native 指针 + close hook，让 defer 能
// 直接调用 SSL_CTX_free 而不走 core.Handle 包装（避免给一次性临时句柄
// 注册终结器）。
//
// probeCtxPtr wraps an SSL_CTX handle so the deferred release in
// CipherSuites can call SSL_CTX_free directly without going through the
// core.Handle layer (the probe ctx is short-lived and doesn't need a
// finalizer).
type probeCtxPtr struct {
	handle unsafe.Pointer
}

// free 释放底层 SSL_CTX；幂等。
//
// free releases the wrapped SSL_CTX; idempotent.
func (p probeCtxPtr) free() {
	if p.handle != nil {
		native.SSL_CTX_free(p.handle)
		p.handle = nil
	}
}

// probeCtx 创建一个用对应 method 的 probe ctx；version==NTLSVersion 时切
// NTLS_method 并 SSL_CTX_enable_ntls。
//
// probeCtx creates a probe SSL_CTX using the SSL_METHOD matching the
// supplied version; NTLSVersion switches to NTLS_method + enable_ntls.
func probeCtx(version uint16) (probeCtxPtr, error) {
	var method unsafe.Pointer
	switch version {
	case native.NTLSVersion:
		method = native.NTLS_method()
	default:
		method = native.TLS_client_method()
	}
	ph := native.SSL_CTX_new(method)
	if ph == nil {
		return probeCtxPtr{}, errors.New("tls: probe: SSL_CTX_new")
	}
	if version == native.NTLSVersion {
		native.SSL_CTX_enable_ntls(ph)
	}
	return probeCtxPtr{handle: ph}, nil
}

// applyCipherSuites 在 ctx 上按名字集合混合配置 cipher list / ciphersuites。
//
// applyCipherSuites implements the partial-match policy for
// Config.CipherSuites:
//
//   - 每个名字独立探测（legacy 走 SetCipherList；TLS1.3 走 SetCipherSuites）。
//     逐名调用保证：某个名字不识别不会影响其它名字生效。
//   - 全不匹配（即所有探测都失败）才返回 ErrNoSharedCipher。
//
// 探测成功后最终生效的名单等于各成功名字的并集（legacy / tls13 分别合
// 并）。这样调用方可以同时探测如 "ECDHE-RSA-AES128-SHA256:TLS_AES_256_GCM_SHA384"
// 这类跨版本名单。
//
// applyCipherSuites splits the names into TLS1.3 standard names
// ("TLS_AES_..." prefix) and legacy OpenSSL names, then probes each
// name independently. Partial matches are non-fatal: only when every
// single name fails does it return ErrNoSharedCipher. Final effective
// suites are the union of successful names.
func applyCipherSuites(ctx *core.TLSContext, names []string) error {
	var legacy, tls13 []string
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		if strings.HasPrefix(n, "TLS_") {
			tls13 = append(tls13, n)
		} else {
			legacy = append(legacy, n)
		}
	}
	anySucceeded := false
	for _, n := range legacy {
		if err := ctx.SetCipherList(n); err == nil {
			anySucceeded = true
		}
	}
	for _, n := range tls13 {
		if err := ctx.SetCipherSuites(n); err == nil {
			anySucceeded = true
		}
	}
	if !anySucceeded && len(legacy)+len(tls13) > 0 {
		return &HandshakeError{
			Op:   "Config.CipherSuites",
			Kind: HandshakeErrorCipher,
			Err:  errors.New("no cipher matched"),
		}
	}
	return nil
}