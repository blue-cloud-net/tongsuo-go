package asym

import (
	"encoding/asn1"
	"encoding/pem"
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/meta"
)

// MarshalSPKI 将公钥编码为 SubjectPublicKeyInfo PEM 或 DER。
//
// MarshalSPKI encodes a public key as SubjectPublicKeyInfo PEM or DER.
func MarshalSPKI(pub PublicKey, format meta.Format) ([]byte, error) {
	if pub == nil {
		return nil, fmt.Errorf("%w: nil public key", ErrInvalidKey)
	}
	if format != meta.FormatPEM && format != meta.FormatDER {
		return nil, fmt.Errorf("asym: invalid SPKI format %q", format)
	}
	data, err := pub.MarshalPublicKeyPEM()
	if err != nil || format == meta.FormatPEM {
		return data, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("asym: invalid SPKI output")
	}
	return block.Bytes, nil
}

// LoadSPKI 从 SubjectPublicKeyInfo PEM 或 DER 加载公钥。调用方负责 Close。
//
// LoadSPKI loads a SubjectPublicKeyInfo public key from PEM or DER. The caller must Close it.
func LoadSPKI(data []byte, format meta.Format) (PublicKey, error) {
	switch format {
	case meta.FormatPEM:
		return LoadPublicKeyPEM(data)
	case meta.FormatDER:
		var sequence asn1.RawValue
		rest, err := asn1.Unmarshal(data, &sequence)
		if err != nil || len(rest) != 0 || sequence.Class != asn1.ClassUniversal ||
			sequence.Tag != asn1.TagSequence || !sequence.IsCompound {
			return nil, fmt.Errorf("asym: invalid SPKI DER")
		}
		return LoadPublicKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: data}))
	default:
		return nil, fmt.Errorf("asym: invalid SPKI format %q", format)
	}
}
