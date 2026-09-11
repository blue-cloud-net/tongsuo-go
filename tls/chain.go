// Package tls 提供对端证书链的获取与 leaf→root 重排。
//
// Tongsuo 的 SSL_get_peer_cert_chain 在以下两个角色上布局不一致：
//
//   - 客户端：栈按「签名证书、加密证书、…剩余链证书」顺序排列，
//     session->peer == 栈首元素（签名证书）。
//   - 服务端：栈仅含客户端加密证书（NTLS 下）或对端链证书；叶证书
//     （签名证书）须另外用 SSL_get_peer_certificate 取。
//
// 公开 API 在 tls 层按角色重新定位叶 + 按签发者链（IssuerText / SubjectText
// 匹配，AKI / SKI 一致时优先）逐级上溯；无法链接的证书会被丢弃（GoDoc
// 注明）。
//
// On-wire peer certificate chains.
//
// Tongsuo's SSL_get_peer_cert_chain has layout that depends on the local
// role:
//   - Client: the stack contains [signing cert, encryption cert, ...extra
//     chain certs] in on-the-wire order; session->peer aliases the first
//     element (the signing cert).
//   - Server: the stack contains only the client's encryption cert (NTLS)
//     or the chain certs; the leaf (signing cert) must be fetched via
//     SSL_get_peer_certificate.
//
// The public API in this file reconciles those layouts by (a) re-locating
// the leaf according to the role and (b) rebuilding the leaf→root chain
// by walking issuer→subject relations (IssuerText == next SubjectText);
// AKI / SKI matching, when both are present, takes priority. Unlinked
// certificates are dropped — see the per-method docs.

package tls

import (
	"errors"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
	"github.com/blue-cloud-net/tongsuo-go/x509"
)

// rebuildChain 把候选 leaf 与剩余候选证书按 IssuerText / SubjectText
// 关系（优先 AKI / SKI 一致）逐级上溯，返回 leaf→root 切片。未链接上的
// 候选丢弃。内部操作 core 证书；公开 API 在 tls.PeerCertificates /
// PeerEncCertificates 处把它们包成 owned *x509.Certificate。
//
// rebuildChain walks from leaf upward through the candidate pool, picking
// the next cert whose SubjectText matches the current IssuerText; when
// both AKI (AuthorityKeyID) and SKI (SubjectKeyID) are present, AKI must
// equal SKI before the textual match is accepted. Unlinked candidates
// are dropped. Operates on core.Certificate values; public callers wrap
// the returned chain into x509.Certificate at the API boundary.
//
// 复杂度 O(N²)，但本项目对端链一般 < 10 张证书，规模无问题。
func rebuildChain(leaf *core.Certificate, candidates []*core.Certificate) []*core.Certificate {
	if leaf == nil {
		return nil
	}
	out := []*core.Certificate{leaf}
	if len(candidates) == 0 {
		return out
	}
	used := make(map[*core.Certificate]bool, len(candidates))
	used[leaf] = true

	current := leaf
	for {
		// 自签则停止。
		if isSelfSignedCore(current) {
			break
		}
		next := findIssuerCore(current, candidates, used)
		if next == nil {
			break
		}
		out = append(out, next)
		used[next] = true
		current = next
	}
	return out
}

// findIssuerCore 在 candidates 中找一张未被使用、签发 current 的证书。
// 优先 AKI→SKI 精确匹配；否则用 IssuerText==SubjectText 模糊匹配。
func findIssuerCore(current *core.Certificate, candidates []*core.Certificate, used map[*core.Certificate]bool) *core.Certificate {
	wantAKI := current.AuthorityKeyID()
	wantIssuer := current.IssuerText()

	// 第一遍：精确 AKI 匹配。
	if len(wantAKI) > 0 {
		for _, c := range candidates {
			if used[c] {
				continue
			}
			if bytesEqual(c.SubjectKeyID(), wantAKI) {
				return c
			}
		}
	}
	// 第二遍：IssuerText 模糊匹配。
	for _, c := range candidates {
		if used[c] {
			continue
		}
		if c.SubjectText() == wantIssuer {
			return c
		}
	}
	return nil
}

// isSelfSignedCore 判定证书自签（Issuer == Subject 且 AKI == SKI）。
func isSelfSignedCore(c *core.Certificate) bool {
	if c.IssuerText() != c.SubjectText() {
		return false
	}
	aki := c.AuthorityKeyID()
	ski := c.SubjectKeyID()
	if len(aki) == 0 || len(ski) == 0 {
		// 任一缺则只依赖文本；自签名场景常见于测试证书（既无 AKI 也无 SKI）。
		return true
	}
	return bytesEqual(aki, ski)
}

// bytesEqual 字节切片相等比较；nil/空 视为相等（与扩展缺失语义一致）。
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// peerCertificateChain 公共取链入口。返回 leaf→root 的 owned 切片。
// leaves 给出「角色对应的叶证书」候选；pool 是其余候选（栈内容、补充叶
// 等）；调用方根据角色挑选不同的 leaves 与 pool 组合。
//
// peerCertificateChain is the internal entry point: given a leaf (or
// nil to indicate "no leaf was returned by SSL_get_peer_certificate",
// which is the server side under NTLS / non-mTLS) plus the candidate
// pool from SSL_get_peer_cert_chain, it returns the leaf→root chain.
//
// Each returned *x509.Certificate is an owned native X509; the caller is
// responsible for calling Close on each one.
//
// Returns nil, nil when no leaf and no chain are present (typical of
// server side on a non-mTLS handshake).
func (c *Conn) peerCertificateChain(leaf *core.Certificate, pool []*core.Certificate) ([]*x509.Certificate, error) {
	if c == nil || c.ssl == nil {
		return nil, errors.New("tls: peer certificate chain: nil Conn")
	}
	if leaf == nil && len(pool) == 0 {
		return nil, nil
	}
	coreChain := rebuildChain(leaf, pool)
	out := make([]*x509.Certificate, 0, len(coreChain))
	for _, cc := range coreChain {
		out = append(out, x509.WrapCertificate(cc))
	}
	return out, nil
}