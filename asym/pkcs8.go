package asym

import (
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
	"github.com/blue-cloud-net/tongsuo-go/meta"
)

// PKCS8Options 配置 PKCS#8 加密；Version 指 PBE 方案版本而非 ASN.1 私钥版本。
// Encrypt 为 false 时导出明文，不消费加密参数。
//
// PKCS8Options configures PKCS#8 encryption; Version selects the PBE scheme, not the ASN.1 private-key version.
// When Encrypt is false the key is emitted unencrypted and encryption parameters are not used.
type PKCS8Options struct {
	// Encrypt 表示是否加密（包括空口令）。
	//
	// Encrypt selects encryption, including encryption with an empty password.
	Encrypt bool
	// Version 为 1（PBE-SHA1-3DES）或 2（PBES2，默认）。
	//
	// Version is 1 (PBE-SHA1-3DES) or 2 (PBES2, the default).
	Version int
	// Cipher 为 PBES2 的 AES-128/192/256-CBC，默认 AES-256-CBC。
	//
	// Cipher selects PBES2 AES-128/192/256-CBC; default AES-256-CBC.
	Cipher string
	// PRF 为 PBES2 的 hmacWithSHA1/224/256/384/512，默认 hmacWithSHA256。
	//
	// PRF selects PBES2 hmacWithSHA1/224/256/384/512; default hmacWithSHA256.
	PRF string
	// Iterations 为正迭代次数，0 为 2048。
	//
	// Iterations is a positive iteration count; zero means 2048.
	Iterations int
	// Passphrase 为输出口令；调用方负责源口令与密钥切片清零。
	//
	// Passphrase is the output password; callers must wipe source password and key buffers.
	Passphrase string
}

// MarshalPKCS8 使用指定 PBE/PRF 编码 PKCS#8 PEM 或 DER；失败返回错误。
// 调用方负责清零源密钥、口令与返回的私钥切片。
//
// MarshalPKCS8 encodes PKCS#8 PEM or DER using explicit PBE/PRF settings; failures return errors.
// Callers must wipe source keys, passwords and the returned private-key buffer.
func MarshalPKCS8(priv PrivateKey, format meta.Format, opts *PKCS8Options) ([]byte, error) {
	if priv == nil {
		return nil, fmt.Errorf("asym: nil private key")
	}
	o := PKCS8Options{}
	if opts != nil {
		o = *opts
	}
	if o.Version == 0 {
		o.Version = 2
	}
	if o.Iterations == 0 {
		o.Iterations = 2048
	}
	if o.Cipher == "" {
		o.Cipher = "AES-256-CBC"
	}
	if o.PRF == "" {
		o.PRF = "hmacWithSHA256"
	}
	if o.Encrypt {
		if o.Version != 1 && o.Version != 2 {
			return nil, fmt.Errorf("asym: unsupported PBE version")
		}
		if o.Iterations < 1 || int64(o.Iterations) > 2147483647 {
			return nil, fmt.Errorf("asym: invalid iteration count")
		}
		if o.Version == 1 && opts != nil && (opts.Cipher != "" || opts.PRF != "") {
			return nil, fmt.Errorf("asym: PBE v1 has fixed cipher and PRF")
		}
		switch strings.ToUpper(o.Cipher) {
		case "AES-128-CBC", "AES-192-CBC", "AES-256-CBC":
		default:
			return nil, fmt.Errorf("asym: unsupported PKCS8 cipher")
		}
		switch o.PRF {
		case "hmacWithSHA1", "hmacWithSHA224", "hmacWithSHA256", "hmacWithSHA384", "hmacWithSHA512":
		default:
			return nil, fmt.Errorf("asym: unsupported PKCS8 PRF")
		}
	}
	if format != meta.FormatPEM && format != meta.FormatDER {
		return nil, fmt.Errorf("asym: unsupported format %q", format)
	}
	data, err := priv.corePKey().MarshalPKCS8PEM(o.Passphrase, o.Cipher, o.PRF, o.Version, o.Iterations, o.Encrypt)
	if err != nil {
		return nil, err
	}
	if format == meta.FormatPEM {
		return data, nil
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("asym: invalid PKCS8 encoding")
	}
	return block.Bytes, nil
}

// LoadPKCS8 加载 PKCS#8 PEM/DER，encrypted 指示 DER 是否加密，pass 为解密口令。
// 返回密钥须 asym.Close；调用方负责清零源切片；失败返回错误。
//
// LoadPKCS8 loads PKCS#8 PEM/DER; encrypted identifies encrypted DER and pass decrypts the key.
// Call asym.Close on the result and wipe source buffers; failures return errors.
func LoadPKCS8(data []byte, format meta.Format, encrypted bool, pass string) (PrivateKey, error) {
	if format == meta.FormatDER {
		typ := "PRIVATE KEY"
		if encrypted {
			typ = "ENCRYPTED PRIVATE KEY"
		}
		data = pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: data})
	} else if format != meta.FormatPEM {
		return nil, fmt.Errorf("asym: unsupported format %q", format)
	}
	b, rest := pem.Decode(data)
	if b == nil || len(strings.TrimSpace(string(rest))) != 0 || (b.Type != "PRIVATE KEY" && b.Type != "ENCRYPTED PRIVATE KEY") {
		return nil, fmt.Errorf("asym: expected one PKCS8 PEM block")
	}
	if b.Type == "ENCRYPTED PRIVATE KEY" {
		return LoadEncryptedPrivateKeyPEM(data, pass)
	}
	return LoadPrivateKeyPEM(data)
}

// MarshalRSAPublicKeyPKCS1PEM 导出 RSA PKCS#1 公钥；非 RSA 或关闭密钥返回错误。
//
// MarshalRSAPublicKeyPKCS1PEM exports an RSA PKCS#1 public key; non-RSA or closed keys return errors.
func MarshalRSAPublicKeyPKCS1PEM(pub PublicKey) ([]byte, error) {
	if pub == nil || pub.Algorithm() != AlgRSA {
		return nil, fmt.Errorf("asym: RSA public key required")
	}
	return pub.corePKey().MarshalRSAPublicKeyPKCS1PEM()
}

// LoadRSAPublicKeyPKCS1PEM 加载 RSA PKCS#1 公钥，调用方负责 asym.Close。
//
// LoadRSAPublicKeyPKCS1PEM loads an RSA PKCS#1 public key; callers must call asym.Close.
func LoadRSAPublicKeyPKCS1PEM(data []byte) (PublicKey, error) {
	k, err := core.LoadRSAPublicKeyPKCS1PEM(data)
	if err != nil {
		return nil, err
	}
	pub, err := wrapPublicKey(k)
	if err != nil {
		k.Close()
	}
	return pub, err
}
