package key_test

import (
	"github.com/blue-cloud-net/tongsuo-go/key"
	"github.com/blue-cloud-net/tongsuo-go/x509"
)

// 零破坏协同验证:key 自有类型可直接作为 x509 现有窄接口
// （interface{ Key() *core.PKey }）的入参,证明统合后的密钥无需改动 x509 即可
// 用于 CreateCertificate 等证书 API。
//
// Zero-breakage synergy assertions: the package's own key types satisfy the
// existing narrow x509 interfaces (interface{ Key() *core.PKey }), proving
// that unified keys work with certificate APIs such as CreateCertificate
// without any change to the x509 package.
var (
	_ x509.PublicKey  = (*key.PublicKey)(nil)
	_ x509.PrivateKey = (*key.PrivateKey)(nil)
)
