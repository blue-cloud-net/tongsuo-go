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
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
	"github.com/blue-cloud-net/tongsuo-go/x509"
)

// coreCertHolder 是 `x509.Certificate` 满足的形状。
//
// 过渡期曾同时接受旧式 `Core() *core.Certificate`；该入口已随 roadmap §5 E1-8
// 删除，故形状收敛为单一。
//
// coreCertHolder is the shape satisfied by x509.Certificate.
//
// A legacy Core() *core.Certificate used to be accepted during the migration
// window; that accessor was removed per roadmap §5 E1-8, so the shape is now
// narrowed to a single one.
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
	}
	return nil, false
}

// Wrap 把底层证书句柄换成 API 层的 *x509.Certificate。
//
// 实现方式是 **DER 往返**：`MarshalDER` → `x509.LoadCertificateDER`。之所以不直接
// 构造：`x509` 原先公开的 `WrapCertificate(c *core.Certificate)` 属于「公开签名中
// 出现 internal/ 类型」的泄漏（roadmap §5 E1 的目标），而把它改为非导出后，包外
// 消费方（tls / pkcs/pkcs7 / pkcs/pkcs12）就只剩本桥接包可用。DER 往返零新增公开
// API、零泄漏，代价是每次调用一次编解码。
//
// **与旧 WrapCertificate 的语义差异（重要）**：返回的对象**拥有自己的句柄**，
// 调用方必须对它调用 Close（而旧入口是共享句柄、Close 会连带释放真正的所有者）。
// 这一点与 tls.peerCertificateChain 已声明的契约（「每个返回的证书是 owned，调用方
// 负责 Close」）一致——本次改动让实现与契约对齐。传入的 c 不受影响。
//
// Wrap turns an underlying certificate handle into an API-layer
// *x509.Certificate.
//
// It performs a DER round trip (MarshalDER → x509.LoadCertificateDER). Building the
// value directly is not possible: x509's former exported
// WrapCertificate(c *core.Certificate) was itself the "internal/ type in a public
// signature" leak roadmap §5 E1 targets, and once it became unexported the
// out-of-package consumers (tls, pkcs/pkcs7, pkcs/pkcs12) had only this bridge left.
// The round trip adds no public API and leaks nothing, at the cost of one
// encode/decode per call.
//
// **Semantic difference from the old WrapCertificate (important)**: the returned
// value **owns its handle**, so the caller must Close it — whereas the old entry
// point shared the handle and closing it released the true owner's object. This
// matches the contract tls.peerCertificateChain already declared ("each returned
// certificate is owned; the caller is responsible for Close"), so this change makes
// the implementation match the contract. The caller-supplied c is unaffected.
func Wrap(c *core.Certificate) (*x509.Certificate, error) {
	if c == nil {
		return nil, fmt.Errorf("certaccess: nil certificate handle")
	}
	der, err := c.MarshalDER()
	if err != nil {
		return nil, err
	}
	return x509.LoadCertificateDER(der)
}
