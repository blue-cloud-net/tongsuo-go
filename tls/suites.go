// Package tls 提供密码套件枚举、按名查找与 Config.CipherSuites 混合语义。
//
// CipherSuites(version) 返回指定版本下 ctx 启用的全部套件（Name/ID/
// MinVersion/MaxVersion）；CipherSuiteByName(name) 按名称或 16 位 ID 查找单个
// 套件。两者都由 core.ProbeCipherSuites 的「临时 ctx 探测」驱动，MinVersion /
// MaxVersion 由探测结果的 min_tls 字符串解析派生（详见本文件的实现注）。
//
// Config.CipherSuites 支持混合名单（OpenSSL 标准名如 "TLS_AES_128_GCM_SHA256"
// 走 set_ciphersuites 路径；OpenSSL 经典名如 "ECDHE-RSA-AES256-GCM-SHA384"
// 走 set_cipher_list 路径）；逐名探测，部分匹配不致命，全不匹配才返回
// ErrNoSharedCipher。
//
// Cipher suite enumeration, name lookup and the mixed Config.CipherSuites
// semantics.
//
// CipherSuites(version) enumerates every cipher enabled at the supplied
// protocol version (Name/ID/MinVersion/MaxVersion); CipherSuiteByName(name)
// looks up a single suite by name or 16-bit ID. Both are driven by
// core.ProbeCipherSuites (a scratch ctx probe); MinVersion / MaxVersion are
// derived from the probe's min_tls string.
//
// Config.CipherSuites accepts a mix of OpenSSL standard names (TLS1.3,
// set_ciphersuites path) and OpenSSL legacy names (pre-TLS1.3,
// set_cipher_list path). Names are probed individually so partial
// matches are not fatal; only when no name matches does the configuration
// fail with ErrNoSharedCipher.

package tls

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// NTLSVersion 是铜锁 NTLS（TLCP）协议版本常量，与 internal/core 的同名常量同值，
// 便于在 CipherSuites / Config.MinVersion / Config.MaxVersion 等公开 API 中使用同一
// 组数字标识。
//
// NTLSVersion is the Tongsuo NTLS (TLCP) protocol version constant, equal to the
// same-named constant in internal/core; pass it to CipherSuites /
// Config.MinVersion / Config.MaxVersion as the canonical wire-version
// identifier.
const NTLSVersion uint16 = core.NTLSVersion

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
// / TLS1_2Version / TLS1_3Version / NTLSVersion; unknown values return nil.
//
// Implementation delegates to core.ProbeCipherSuites (a scratch ctx with
// min=max=version, NTLS_method for NTLS) and converts each MinVersion from
// OpenSSL's min_tls string to the uint16 wire version.
func CipherSuites(version uint16) []CipherSuiteInfo {
	probed := core.ProbeCipherSuites(version)
	if len(probed) == 0 {
		return nil
	}
	out := make([]CipherSuiteInfo, 0, len(probed))
	for _, c := range probed {
		out = append(out, toCipherSuiteInfo(c, version))
	}
	return out
}

// cipherProbeVersions 是查找套件时依次探测的协议版本（升序）。
//
// 升序的含义：同一名称/ID 若在多个版本下都可用，返回**最低**版本下探测到的那一条
// （其 MinVersion 由 min_tls 字符串决定，通常与探测版本一致）。
//
// cipherProbeVersions lists the protocol versions probed in order (ascending)
// when looking up a cipher suite.
//
// Ascending order means a name/ID available at several versions resolves to the
// entry found under the **lowest** such version (its MinVersion comes from the
// min_tls string and normally equals that version).
var cipherProbeVersions = []uint16{
	TLS1Version, TLS1_1Version, TLS1_2Version, TLS1_3Version, NTLSVersion,
}

// toCipherSuiteInfo 把核心层的探测结果转成公开类型；fallback 用于 min_tls
// 字符串无法解析时的版本回退。
//
// toCipherSuiteInfo converts a core-layer probe result into the public type;
// fallback is the version used when the min_tls string cannot be parsed.
func toCipherSuiteInfo(c core.CipherInfo, fallback uint16) CipherSuiteInfo {
	minV := versionForCipher(c.MinVersion, fallback)
	return CipherSuiteInfo{
		Name:       c.Name,
		ID:         c.ID,
		MinVersion: minV,
		MaxVersion: minV,
	}
}

// CipherSuiteByName 按名称或 16 位 ID 查找单个密码套件。
//
// 入参两种形态：
//
//   - 名称：OpenSSL 套件名，**大小写不敏感**（如 "TLS_AES_128_GCM_SHA256"、
//     "ECDHE-RSA-AES256-GCM-SHA384"、"ECDHE-SM2-SM4-GCM-SM3"）。匹配的是枚举
//     报告的**主名**（`SSL_CIPHER_get_name`），因此 OpenSSL 的旧式别名（如
//     "AES128-SHA256"）不在匹配范围。
//   - ID：16 位 wire ID 的文本形式，十进制（如 "4865"）或带 0x/0X 前缀的十六进制
//     （如 "0x1301"）；不带前缀的十六进制会被当作十进制。
//
// 查找方式是「逐协议版本枚举 + 匹配」：与 `openssl ciphers -V` 列出的一致，
// 命中最低可用版本（见 cipherProbeVersions）。空入参或未命中返回错误（错误串含
// 原始入参，便于排查）。
//
// CipherSuiteByName looks up a single cipher suite by name or 16-bit ID.
//
// Two input forms are accepted:
//
//   - Name: an OpenSSL cipher name, matched **case-insensitively** (for example
//     "TLS_AES_128_GCM_SHA256", "ECDHE-RSA-AES256-GCM-SHA384",
//     "ECDHE-SM2-SM4-GCM-SM3"). Matching is against the primary name reported by
//     SSL_CIPHER_get_name, so OpenSSL's legacy aliases (such as
//     "AES128-SHA256") are not matched.
//   - ID: the 16-bit wire ID in decimal (for example "4865") or with a 0x/0X
//     prefix (for example "0x1301"); unprefixed hex is read as decimal.
//
// The lookup enumerates each protocol version and matches, mirroring
// `openssl ciphers -V`, and resolves to the lowest version that has it (see
// cipherProbeVersions). An empty argument or a miss returns an error whose text
// carries the original argument.
func CipherSuiteByName(name string) (CipherSuiteInfo, error) {
	query := strings.TrimSpace(name)
	if query == "" {
		return CipherSuiteInfo{}, fmt.Errorf("tls: empty cipher suite identifier")
	}
	id, isID := parseCipherSuiteID(query)
	for _, v := range cipherProbeVersions {
		for _, c := range core.ProbeCipherSuites(v) {
			if isID {
				if c.ID != id {
					continue
				}
			} else if !strings.EqualFold(c.Name, query) {
				continue
			}
			return toCipherSuiteInfo(c, v), nil
		}
	}
	return CipherSuiteInfo{}, fmt.Errorf("tls: unknown cipher suite %q", name)
}

// parseCipherSuiteID 尝试把文本解析为 16 位套件 ID。
//
// 接受十进制（"4865"）与带 0x/0X 前缀的十六进制（"0x1301"）；其余形态
// （包括套件名）返回 (0, false)，表示调用方应按名称匹配。
//
// parseCipherSuiteID tries to parse the text as a 16-bit cipher suite ID.
//
// Decimal ("4865") and 0x/0X-prefixed hex ("0x1301") are accepted; anything
// else (including cipher names) yields (0, false), meaning the caller should
// match by name instead.
func parseCipherSuiteID(s string) (uint16, bool) {
	// base 0 同时接受 "0x1301"（十六进制）与 "4865"（十进制），但**不**把
	// 无前缀的 "1301" 当十六进制。
	v, err := strconv.ParseUint(s, 0, 16)
	if err != nil {
		return 0, false
	}
	return uint16(v), true
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
