package x509

import (
	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// coreKeyPub 为 x509.PublicKey / PrivateKey 鸭子接口提供的 *core.PKey 适配器。
//
// coreKeyPub adapts *core.PKey to the duck-typed x509.PublicKey interface
// (which only requires Key() *core.PKey). It lets Ed25519/Ed448/X25519 keys
// verify certificates through the existing core.Verify path without
// needing a per-algorithm wrapper at the API layer.
type coreKeyPub struct {
	*core.PKey
}

// coreKeyPriv 同 coreKeyPub，但签名时同样只需 Key() *core.PKey。
//
// coreKeyPriv mirrors coreKeyPub for the x509.PrivateKey interface.
type coreKeyPriv struct {
	*core.PKey
}

// Key 返回底层 *core.PKey（实现 x509.PublicKey / PrivateKey 接口）。
//
// Key returns the wrapped *core.PKey.
func (k *coreKeyPub) Key() *core.PKey { return k.PKey }

// Key 返回底层 *core.PKey（实现 x509.PublicKey / PrivateKey 接口）。
//
// Key returns the wrapped *core.PKey.
func (k *coreKeyPriv) Key() *core.PKey { return k.PKey }

// asX509PubKey 把 *core.PKey 包成 x509.PublicKey。
//
// asX509PubKey wraps *core.PKey as x509.PublicKey.
func asX509PubKey(p *core.PKey) PublicKey { return &coreKeyPub{PKey: p} }

// asX509PrivKey 把 *core.PKey 包成 x509.PrivateKey。
//
// asX509PrivKey wraps *core.PKey as x509.PrivateKey.
func asX509PrivKey(p *core.PKey) PrivateKey { return &coreKeyPriv{PKey: p} }