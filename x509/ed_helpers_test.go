package x509

import (
	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// 本文件保留遗留测试使用的两个适配器名，但主体已随 roadmap §5 E1-11 重写：
// 删除 x509.PublicKey / x509.PrivateKey 窄接口后，公开入口直接收 asym 接口，
// 遗留测试里的 `asX509PubKey(priv.Key())` / `asX509PrivKey(priv.Key())` 仍需要
// 「由底层句柄得到可传给 x509 的对象」这一步，于是改走包内 helpers.go 的
// wrapCorePublicKey（PEM 往返）。
//
// This file keeps the two adapter names used by the legacy tests but their bodies
// were rewritten for roadmap §5 E1-11: with the narrow x509.PublicKey /
// x509.PrivateKey interfaces gone, the public entry points take asym interfaces
// directly, yet the legacy `asX509PubKey(priv.Key())` /
// `asX509PrivKey(priv.Key())` call sites still need a step from a raw handle to
// something x509 accepts, so they go through wrapCorePublicKey (a PEM round trip).

// coreKeyPub 由底层句柄构造可直接传给 x509 公钥参数的对象。
//
// coreKeyPub builds, from a raw handle, a value acceptable as an x509 public key
// argument.
type coreKeyPub struct {
	asym.PublicKey
}

// coreKeyPriv 由底层句柄构造可直接传给 x509 私钥参数的对象。
//
// coreKeyPriv builds, from a raw handle, a value acceptable as an x509 private
// key argument.
type coreKeyPriv struct {
	asym.PrivateKey
}

// asX509PubKey 把 *core.PKey 包成 asym.PublicKey（测试助手，失败即 panic）。
//
// 之所以 panic：这些调用点嵌在函数实参位置，没有错误返回通道；失败意味着
// PEM 往返或句柄已失效，属于测试基础设施故障，应立刻响亮地暴露。
//
// asX509PubKey wraps *core.PKey as asym.PublicKey. It panics on failure because the
// call sites sit in argument position with no error channel, and a failure means
// the PEM round trip or the handle is broken — a test-infrastructure fault that
// should fail loudly.
func asX509PubKey(p *core.PKey) asym.PublicKey {
	pub, err := wrapCorePublicKey(p)
	if err != nil {
		panic(err)
	}
	return pub
}

// asX509PrivKey 把 *core.PKey 包成 asym.PrivateKey（测试助手，失败即 panic）。
//
// asX509PrivKey wraps *core.PKey as asym.PrivateKey (test helper; panics on
// failure).
func asX509PrivKey(p *core.PKey) asym.PrivateKey {
	pemBytes, err := p.MarshalPrivateKeyPEM()
	if err != nil {
		panic(err)
	}
	priv, err := asym.LoadPrivateKeyPEM(pemBytes)
	if err != nil {
		panic(err)
	}
	return priv
}
