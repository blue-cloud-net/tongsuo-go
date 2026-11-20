// 本文件提供密码套件枚举、按名查找与 Config.CipherSuites 混合语义。
//
// CipherSuites(version) 返回指定版本下 ctx 启用的全部套件（Name/ID/
// MinVersion/MaxVersion）；CipherSuiteByName(name) 按名称或 16 位 ID 查找单个
// 套件。两者都由 core.ProbeCipherSuites 的「临时 ctx 探测」驱动，MinVersion /
// MaxVersion 由原生套件协议归属和值域派生。
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

	// MaxVersion 是本库支持且该密码套件适用的最高协议版本。
	//
	// MaxVersion is the highest supported protocol version for this cipher suite.
	MaxVersion uint16
}

// CipherSuites 返回指定协议版本下铜锁编译提供的密码套件。
// 握手时可选套件还取决于凭证和安全策略。未知版本返回 nil。
//
// CipherSuites returns the compiled cipher suites for the given protocol
// version. Credentials and security policy can further constrain negotiation.
// An unknown protocol version yields nil.
func CipherSuites(version uint16) []CipherSuiteInfo {
	probed := core.ProbeCipherSuites(version)
	if len(probed) == 0 {
		return nil
	}
	out := make([]CipherSuiteInfo, 0, len(probed))
	for _, c := range probed {
		out = append(out, toCipherSuiteInfo(c))
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

func toCipherSuiteInfo(c core.CipherInfo) CipherSuiteInfo {
	minVersion, maxVersion := core.CipherProtocolRange(c.MinVersion)
	return CipherSuiteInfo{Name: c.Name, ID: c.ID, MinVersion: minVersion, MaxVersion: maxVersion}
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
			return toCipherSuiteInfo(c), nil
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
	base := 10
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		base = 16
		s = s[2:]
	}
	v, err := strconv.ParseUint(s, base, 16)
	if err != nil {
		return 0, false
	}
	return uint16(v), true
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
	_, _, err := configureCiphers(ctx, names, false)
	return err
}

func configureCiphers(ctx *core.TLSContext, names []string, strict bool) (string, string, error) {
	var legacy, tls13 []string
	for _, entry := range names {
		for _, name := range strings.Split(entry, ":") {
			name = strings.TrimSpace(name)
			if name == "" {
				if strict {
					return "", "", fmt.Errorf("tls: empty cipher suite")
				}
				continue
			}
			var err error
			if strings.HasPrefix(name, "TLS_") {
				err = ctx.SetCipherSuites(name)
			} else {
				err = ctx.SetCipherList(name)
			}
			if err != nil {
				if strict {
					return "", "", fmt.Errorf("tls: unsupported cipher %q: %w", name, err)
				}
				continue
			}
			if strings.HasPrefix(name, "TLS_") {
				tls13 = append(tls13, name)
			} else {
				legacy = append(legacy, name)
			}
		}
	}
	l, t := strings.Join(legacy, ":"), strings.Join(tls13, ":")
	if len(names) > 0 && l == "" && t == "" {
		return "", "", ErrNoSharedCipher
	}
	if strict && len(names) > 0 {
		return l, t, ctx.RestrictCipherSuites(l, t)
	}
	if l != "" {
		if err := ctx.SetCipherList(l); err != nil {
			return "", "", err
		}
	}
	if t != "" {
		if err := ctx.SetCipherSuites(t); err != nil {
			return "", "", err
		}
	}
	return l, t, nil
}
