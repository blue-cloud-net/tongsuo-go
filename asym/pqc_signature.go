package asym

import (
	"fmt"
	"strings"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// PQCSignatureOptions 选择签名上下文和原消息的预哈希算法。零值使用纯消息模式。
// Context 最长 255 字节。Prehash 必须满足密钥变体的碰撞安全强度。
//
// PQCSignatureOptions selects the signature context and prehash of the original
// message. The zero value selects pure message mode. Context is limited to
// 255 bytes. The prehash must meet the collision security strength of the key variant.
type PQCSignatureOptions struct {
	// Context 是签名和验签双方使用的上下文。
	//
	// Context is the context shared by the signer and verifier.
	Context []byte

	// Prehash 为预哈希名称，空字符串表示纯消息模式。
	//
	// Prehash names the prehash. An empty string selects pure message mode.
	Prehash string
}

type pqcPrehash struct {
	oid       byte
	strength  int
	digest    func() *core.Digest
	xofLength int
}

var pqcPrehashes = map[string]pqcPrehash{
	"SHA256":     {1, 128, core.SHA256, 0},
	"SHA384":     {2, 192, core.SHA384, 0},
	"SHA512":     {3, 256, core.SHA512, 0},
	"SHA512/256": {6, 128, core.SHA512_256, 0},
	"SHA3256":    {8, 128, core.SHA3_256, 0},
	"SHA3384":    {9, 192, core.SHA3_384, 0},
	"SHA3512":    {10, 256, core.SHA3_512, 0},
	"SHAKE128":   {11, 128, core.SHAKE128, 32},
	"SHAKE256":   {12, 256, core.SHAKE256, 64},
}

func pqcSignatureStrength(alg Algorithm) int {
	switch alg {
	case AlgMLDSA87, AlgSLHDSASHA2256S, AlgSLHDSASHA2256F, AlgSLHDSASHAKE256S, AlgSLHDSASHAKE256F:
		return 256
	case AlgMLDSA65, AlgSLHDSASHA2192S, AlgSLHDSASHA2192F, AlgSLHDSASHAKE192S, AlgSLHDSASHAKE192F:
		return 192
	default:
		return 128
	}
}

func pqcSignatureInput(key Key, message []byte, opts *PQCSignatureOptions) ([]byte, []byte, bool, error) {
	if key == nil || !pqcVariant(key.Algorithm()) || mlkemCiphertextSize(key) != 0 {
		return nil, nil, false, fmt.Errorf("%w: expected ML-DSA or SLH-DSA key", ErrInvalidKey)
	}
	if opts == nil {
		return message, nil, false, nil
	}
	context := opts.Context
	if len(context) > 255 {
		return nil, nil, false, fmt.Errorf("asym: PQC signature context is limited to 255 bytes")
	}
	if opts.Prehash == "" {
		return message, context, false, nil
	}

	hash, ok := pqcPrehashes[strings.ReplaceAll(strings.ToUpper(opts.Prehash), "-", "")]
	if !ok {
		return nil, nil, false, fmt.Errorf("%w: PQC prehash %q", ErrUnsupported, opts.Prehash)
	}
	if hash.strength < pqcSignatureStrength(key.Algorithm()) {
		return nil, nil, false, fmt.Errorf("%w: %s is too weak for %s", ErrUnsupported, opts.Prehash, key.Algorithm())
	}
	md := hash.digest()
	var digest []byte
	var err error
	if hash.xofLength != 0 {
		digest, err = md.XOFOneShot(message, hash.xofLength)
	} else {
		digest, err = md.OneShot(message)
	}
	if err != nil {
		return nil, nil, false, err
	}

	// FIPS 204 and 205 prehash framing: domain, context, DER hash OID, digest.
	encoded := append([]byte{1, byte(len(context))}, context...)
	encoded = append(encoded, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, hash.oid)
	return append(encoded, digest...), nil, true, nil
}

// SignPQC 使用 ML-DSA 或 SLH-DSA 私钥对原消息签名。
//
// SignPQC signs an original message with an ML-DSA or SLH-DSA private key.
func SignPQC(priv PrivateKey, message []byte, opts *PQCSignatureOptions) ([]byte, error) {
	input, context, encoded, err := pqcSignatureInput(priv, message, opts)
	if err != nil {
		return nil, err
	}
	return priv.corePKey().SignPQC(input, context, encoded)
}

// VerifyPQC 验证 ML-DSA 或 SLH-DSA 签名，验签失败返回 ErrSignature 的包装错误。
//
// VerifyPQC verifies an ML-DSA or SLH-DSA signature. Verification failures wrap ErrSignature.
func VerifyPQC(pub PublicKey, message, signature []byte, opts *PQCSignatureOptions) error {
	input, context, encoded, err := pqcSignatureInput(pub, message, opts)
	if err != nil {
		return err
	}
	if err := pub.corePKey().VerifyPQC(input, signature, context, encoded); err != nil {
		return fmt.Errorf("%w: %w", ErrSignature, err)
	}
	return nil
}
