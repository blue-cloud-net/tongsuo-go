package asym

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/meta"
)

// LoadPrivateKeySource 从 src 读取 PEM 私钥（PKCS#8 / PKCS#1 / SEC1）。
// passphrase 为 nil 或空时按未加密私钥解析；否则按该口令解密。
// src 为 nil 等价于标准输入。解析失败返回与 LoadPrivateKeyPEM /
// LoadEncryptedPrivateKeyPEM 相同的包装错误。
// 本函数不负责擦除 passphrase 中的口令字节。
//
// LoadPrivateKeySource reads a PEM private key (PKCS#8 / PKCS#1 / SEC1)
// from src. A nil or empty passphrase means the key is unencrypted;
// otherwise the key is decrypted with that passphrase. A nil src is
// equivalent to standard input. Parse failures return the same wrapped
// errors as LoadPrivateKeyPEM / LoadEncryptedPrivateKeyPEM. The function
// does not wipe the passphrase bytes.
func LoadPrivateKeySource(src *meta.Source, passphrase *meta.Passphrase) (PrivateKey, error) {
	blob, err := src.ReadAll()
	if err != nil {
		return nil, err
	}
	if passphrase.IsEmpty() {
		return LoadPrivateKeyPEM(blob)
	}
	return LoadEncryptedPrivateKeyPEM(blob, string(passphrase.Bytes()))
}

// LoadPublicKeySource 从 src 读取 SPKI PEM 公钥。
// src 为 nil 等价于标准输入；解析失败返回与 LoadPublicKeyPEM 相同的包装错误。
//
// LoadPublicKeySource reads an SPKI PEM public key from src. A nil src is
// equivalent to standard input; parse failures return the same wrapped
// errors as LoadPublicKeyPEM.
func LoadPublicKeySource(src *meta.Source) (PublicKey, error) {
	blob, err := src.ReadAll()
	if err != nil {
		return nil, err
	}
	return LoadPublicKeyPEM(blob)
}

// MarshalPrivateKeyTo 把私钥序列化后按 sink 的编码写出。
// passphrase 为 nil 或空时输出未加密的 PKCS#8 PEM；否则输出加密 PEM
// （默认算法由底层 provider 决定，见 MarshalEncryptedPrivateKeyPEM）。
// sink 为 nil 等价于标准输出；本函数不调用 sink.Close。
//
// MarshalPrivateKeyTo serialises the private key and writes it using
// sink's encoding. A nil or empty passphrase emits an unencrypted PKCS#8
// PEM block; otherwise the output is an encrypted PEM block (the default
// cipher comes from the provider, see MarshalEncryptedPrivateKeyPEM). A
// nil sink means standard output; the function does not close sink.
func MarshalPrivateKeyTo(priv PrivateKey, sink *meta.Sink, passphrase *meta.Passphrase) error {
	if priv == nil {
		return fmt.Errorf("asym: nil private key")
	}
	var (
		blob []byte
		err  error
	)
	if passphrase.IsEmpty() {
		blob, err = priv.MarshalPrivateKeyPEM()
	} else {
		blob, err = MarshalEncryptedPrivateKeyPEM(priv, string(passphrase.Bytes()))
	}
	if err != nil {
		return err
	}
	if _, err := sink.Write(blob); err != nil {
		return fmt.Errorf("asym: write private key: %w", err)
	}
	return nil
}

// MarshalPublicKeyTo 把公钥序列化（SPKI PEM）后按 sink 的编码写出。
// sink 为 nil 等价于标准输出；本函数不调用 sink.Close。
//
// MarshalPublicKeyTo serialises the public key (SPKI PEM) and writes it
// using sink's encoding. A nil sink means standard output; the function
// does not close sink.
func MarshalPublicKeyTo(pub PublicKey, sink *meta.Sink) error {
	if pub == nil {
		return fmt.Errorf("asym: nil public key")
	}
	blob, err := pub.MarshalPublicKeyPEM()
	if err != nil {
		return err
	}
	if _, err := sink.Write(blob); err != nil {
		return fmt.Errorf("asym: write public key: %w", err)
	}
	return nil
}
