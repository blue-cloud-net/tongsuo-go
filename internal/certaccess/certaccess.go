// Package certaccess 提供跨包获取 X.509 证书底层 *core.Certificate 的桥接机制。
//
// 本包与 internal/keyaccess 同构（roadmap §5.2），只是桥接对象换成证书而非密钥。
//
// 设计动机：
//
//  1. `x509` 已删除公开的 `Core() *core.Certificate`（roadmap §5 E1-8），
//     公开签名中不得再出现 `internal/` 类型；
//  2. `tls` / `pkcs/pkcs7` / `pkcs/pkcs12` 仍需 `*core.Certificate`
//     （用于 `X509_up_ref`、`SSL_CTX_use_certificate`、`PKCS12_add_cert`、
//     `PKCS7_add_certificate`）；
//  3. 这些消费方又不能绕过桥接直接读取 `x509.Certificate` 的非导出字段。
//
// 方案：用结构化接口满足 + 集中断言点。`x509.Certificate` 提供导出方法
// `CoreCertificate() *core.Certificate`（宿主类型已导出，因此该方法会出现在
// `go doc` 中——这是**已接受的残余瑕疵**，理由见 roadmap §5.2：外部包即使断言
// 成功也无法 import `internal/core`，拿到句柄也用不了），本包对该形状做类型断言。
//
// **所有权约定**：与 internal/keyaccess 不同，本包**不要求调用方 Dup**。
// 证书句柄的共享语义由消费方自行处理（`SSL_CTX_use_certificate` 与
// `PKCS12_add_cert` 内部会 up-ref，调用后源证书仍归调用方所有）。之所以与
// keyaccess 不一致，是因为证书不像私钥那样存在「Dup 后独立可用」的需求；
// 若未来某消费方需要长期持有，应显式增加 `(*Certificate).Clone` 之类的入口，
// 而不是在本包里隐式复制。
//
// Package certaccess provides a bridge for retrieving the underlying
// *core.Certificate handle of an X.509 certificate without breaking the
// dependency direction.
//
// It is the certificate counterpart of internal/keyaccess (roadmap §5.2).
//
// Rationale: x509 has removed the public Core() *core.Certificate accessor
// (roadmap §5, E1-8) so that no public signature mentions an internal/ type;
// yet tls, pkcs/pkcs7 and pkcs/pkcs12 still need the underlying handle for
// X509_up_ref, SSL_CTX_use_certificate, PKCS12_add_cert and
// PKCS7_add_certificate, and they cannot reach x509.Certificate's unexported
// field directly.
//
// The mechanism is a structural interface plus a single assertion point:
// x509.Certificate exposes an exported method
// CoreCertificate() *core.Certificate. Because the host type is exported, the
// method does appear in `go doc` — an accepted residual (see roadmap §5.2):
// an external package that satisfies the assertion still cannot import
// internal/core and therefore cannot use the handle. This package performs
// the type assertion on that shape.
//
// **Ownership**: unlike internal/keyaccess, this package does NOT require
// the caller to Dup the handle. Sharing semantics are handled by each
// consumer (SSL_CTX_use_certificate and PKCS12_add_cert up-ref internally,
// leaving the source certificate owned by the caller). The asymmetry with
// keyaccess exists because a certificate, unlike a private key, has no
// "duplicate and use independently" requirement; should a consumer ever
// need long-term ownership, the right fix is an explicit
// (*Certificate).Clone entry point rather than an implicit copy here.
package certaccess

import (
	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// certHolder 是持有一个底层 *core.Certificate 句柄的对象所应满足的两种形状之一。
//
// `x509.Certificate` 提供 `CoreCertificate()`；过渡期若仍有旧式
// `Core() *core.Certificate`，同样接受，待 roadmap commit 19 删除后再收敛。
//
// certHolder is one of the two structural shapes an object holding a
// *core.Certificate may satisfy.
//
// x509.Certificate provides CoreCertificate(); a legacy
// Core() *core.Certificate is also accepted during the migration window and
// will be narrowed once roadmap commit 19 removes it.
type certHolder interface {
	Core() *core.Certificate
}

// coreCertHolder 是 `x509.Certificate` 现行满足的形状。
//
// coreCertHolder is the shape currently satisfied by x509.Certificate.
type coreCertHolder interface {
	CoreCertificate() *core.Certificate
}

// Certificate 从任意证书对象取出底层 *core.Certificate。
//
// 第二个返回值报告断言是否成功：失败时不返回错误而是返回 (nil, false)。
//
// 若 v 本身就是 *core.Certificate，则直接返回 (v, true)。
//
// Certificate extracts the underlying *core.Certificate from any
// certificate object.
//
// The second return value reports assertion success; a failed assertion
// yields (nil, false) rather than an error.
//
// If v is already a *core.Certificate, it is returned as-is.
func Certificate(v any) (*core.Certificate, bool) {
	switch c := v.(type) {
	case *core.Certificate:
		return c, true
	case coreCertHolder:
		return c.CoreCertificate(), true
	case certHolder:
		return c.Core(), true
	}
	return nil, false
}
