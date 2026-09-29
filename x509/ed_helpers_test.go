package x509

import (
	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/internal/core"
	"github.com/blue-cloud-net/tongsuo-go/internal/keyaccess"
)

// pkeyOf 取 asym 密钥的底层句柄，供包内测试驱动 internal/core 的入口（如
// core.NewCRL）。
//
// 本文件原本还提供 asX509PubKey / asX509PrivKey（把 *core.PKey 经 PEM 往返包回
// asym 对象）。测试改用 asym 公开接口后，可直接传 `priv.Public()` / `priv`，
// 这两个适配器与它们的包装类型已随本次迁移删除。
//
// pkeyOf returns the underlying handle of an asym key so in-package tests can drive
// internal/core entry points such as core.NewCRL.
//
// This file used to also host asX509PubKey / asX509PrivKey, which round-tripped a
// *core.PKey back into an asym object via PEM. Now that the tests use the public
// asym interfaces directly they can pass `priv.Public()` / `priv`, so both adapters
// and their wrapper types are gone.
func pkeyOf(k asym.Key) *core.PKey {
	h, ok := keyaccess.PKey(k)
	if !ok || h == nil {
		panic("x509 test: key exposes no native handle")
	}
	return h
}
