package core

import (
	"runtime"
	"unsafe"

	"github.com/blue-cloud-net/tongsuo-go/internal/native"
)

// MarshalPKCS8PEM 使用显式 PBE 版本、PRF 与迭代次数编码私钥。
//
// MarshalPKCS8PEM encodes a private key using explicit PBE version, PRF and iterations.
func (k *PKey) MarshalPKCS8PEM(pass, cipher, prf string, version, iter int, encrypt bool) ([]byte, error) {
	defer runtime.KeepAlive(k)
	return k.marshalPEM("pkey: write PKCS8", func(bio, key unsafe.Pointer) bool {
		return native.X_PKEY_write_pkcs8(bio, key, pass, cipher, prf, version, iter, encrypt)
	})
}

// LoadRSAPublicKeyPKCS1PEM 加载 PKCS#1 公钥，调用方负责 Close。
//
// LoadRSAPublicKeyPKCS1PEM loads a PKCS#1 public key; callers must Close it.
func LoadRSAPublicKeyPKCS1PEM(data []byte) (*PKey, error) {
	return loadPEM("pkey: read RSA public key", native.X_PEM_read_rsa_public, data)
}

// MarshalRSAPublicKeyPKCS1PEM 导出 PKCS#1 公钥。
//
// MarshalRSAPublicKeyPKCS1PEM exports a PKCS#1 public key.
func (k *PKey) MarshalRSAPublicKeyPKCS1PEM() ([]byte, error) {
	defer runtime.KeepAlive(k)
	return k.marshalPEM("pkey: write RSA public key", native.X_PEM_write_rsa_public)
}
