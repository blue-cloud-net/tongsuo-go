package asym

import (
	"errors"
	"fmt"
	"strings"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

const maxEdDSAContextSize = 255

func edDSAKey(key Key, instance string, context []byte) error {
	if key == nil || key.corePKey() == nil {
		return fmt.Errorf("asym: EdDSA: %w", ErrInvalidKey)
	}
	var alg Algorithm
	switch instance {
	case "Ed25519", "Ed25519ctx", "Ed25519ph":
		alg = AlgEd25519
	case "Ed448", "Ed448ph":
		alg = AlgEd448
	default:
		return fmt.Errorf("asym: EdDSA instance %q: %w", instance, ErrUnknownAlgorithm)
	}
	if key.Algorithm() != alg {
		return fmt.Errorf("asym: EdDSA key/instance mismatch: %w", ErrInvalidKey)
	}
	if len(context) > maxEdDSAContextSize || (instance == "Ed25519ctx" && len(context) == 0) || (instance == "Ed25519" && len(context) != 0) {
		return fmt.Errorf("asym: invalid EdDSA context length %d", len(context))
	}
	return nil
}

func edDSAError(err error) error {
	if errors.Is(err, core.ErrAlgorithmUnavailable) {
		return fmt.Errorf("asym: EdDSA: %w: %w", ErrUnsupported, err)
	}
	return err
}

// SupportsEdDSAInstance 探测密钥的签名或验签初始化是否支持指定实例（大小写不敏感）。
// context 与实际调用一致；无效或关闭的密钥返回错误，不支持返回 false。
//
// SupportsEdDSAInstance probes sign/verify initialization for an instance, case-insensitively.
// Context must match the intended call; invalid/closed keys return errors, unsupported instances return false.
func SupportsEdDSAInstance(key Key, instance string, context []byte) (bool, error) {
	names := map[string]string{"ED25519": "Ed25519", "ED25519CTX": "Ed25519ctx", "ED25519PH": "Ed25519ph", "ED448": "Ed448", "ED448PH": "Ed448ph"}
	name, ok := names[strings.ToUpper(instance)]
	if !ok {
		return false, fmt.Errorf("asym: EdDSA instance %q: %w", instance, ErrUnknownAlgorithm)
	}
	if err := edDSAKey(key, name, context); err != nil {
		return false, err
	}
	_, sign := key.(PrivateKey)
	return key.corePKey().SupportsEdDSAInstance(name, context, sign)
}

func signEdDSA(priv PrivateKey, msg, context []byte, instance string) ([]byte, error) {
	if err := edDSAKey(priv, instance, context); err != nil {
		return nil, err
	}
	sig, err := priv.corePKey().SignEdDSAInstance(msg, instance, context)
	return sig, edDSAError(err)
}

func verifyEdDSA(pub PublicKey, msg, sig, context []byte, instance string) error {
	if err := edDSAKey(pub, instance, context); err != nil {
		return err
	}
	if err := pub.corePKey().VerifyEdDSAInstance(msg, sig, instance, context); err != nil {
		if errors.Is(err, core.ErrAlgorithmUnavailable) {
			return edDSAError(err)
		}
		return fmt.Errorf("asym: EdDSA: %w: %w", ErrSignature, err)
	}
	return nil
}

// SignEd25519ctx 使用 Ed25519ctx；context 必须为 1..255 字节 对原消息签名。context 最长 255 字节；不可用返回 ErrUnsupported。
// 调用方不得预哈希 msg；密钥编码与原 EdDSA 密钥相同。
//
// SignEd25519ctx signs a complete message with Ed25519ctx; context must contain 1..255 bytes. Context is at most 255 bytes; unavailable support returns ErrUnsupported.
// Callers must not prehash msg; existing EdDSA key encodings are reused.
func SignEd25519ctx(priv PrivateKey, msg, context []byte) ([]byte, error) {
	return signEdDSA(priv, msg, context, "Ed25519ctx")
}

// VerifyEd25519ctx 验证原消息的 Ed25519ctx；context 必须为 1..255 字节 签名；context 必须与签名一致。
// 无效签名返回 ErrSignature，不支持实例返回 ErrUnsupported；context 最长 255 字节。
//
// VerifyEd25519ctx verifies a complete message with Ed25519ctx; context must contain 1..255 bytes; context must match the signer.
// Invalid signatures return ErrSignature, unavailable instances return ErrUnsupported; context is at most 255 bytes.
func VerifyEd25519ctx(pub PublicKey, msg, sig, context []byte) error {
	return verifyEdDSA(pub, msg, sig, context, "Ed25519ctx")
}

// SignEd25519ph 使用 Ed25519ph；原生层执行 SHA-512 预哈希 对原消息签名。context 最长 255 字节；不可用返回 ErrUnsupported。
// 调用方不得预哈希 msg；密钥编码与原 EdDSA 密钥相同。
//
// SignEd25519ph signs a complete message with Ed25519ph; SHA-512 prehashing occurs in the native provider. Context is at most 255 bytes; unavailable support returns ErrUnsupported.
// Callers must not prehash msg; existing EdDSA key encodings are reused.
func SignEd25519ph(priv PrivateKey, msg, context []byte) ([]byte, error) {
	return signEdDSA(priv, msg, context, "Ed25519ph")
}

// VerifyEd25519ph 验证原消息的 Ed25519ph；原生层执行 SHA-512 预哈希 签名；context 必须与签名一致。
// 无效签名返回 ErrSignature，不支持实例返回 ErrUnsupported；context 最长 255 字节。
//
// VerifyEd25519ph verifies a complete message with Ed25519ph; SHA-512 prehashing occurs in the native provider; context must match the signer.
// Invalid signatures return ErrSignature, unavailable instances return ErrUnsupported; context is at most 255 bytes.
func VerifyEd25519ph(pub PublicKey, msg, sig, context []byte) error {
	return verifyEdDSA(pub, msg, sig, context, "Ed25519ph")
}

// SignEd448ph 使用 Ed448ph；原生层执行 SHAKE256 预哈希 对原消息签名。context 最长 255 字节；不可用返回 ErrUnsupported。
// 调用方不得预哈希 msg；密钥编码与原 EdDSA 密钥相同。
//
// SignEd448ph signs a complete message with Ed448ph; SHAKE256 prehashing occurs in the native provider. Context is at most 255 bytes; unavailable support returns ErrUnsupported.
// Callers must not prehash msg; existing EdDSA key encodings are reused.
func SignEd448ph(priv PrivateKey, msg, context []byte) ([]byte, error) {
	return signEdDSA(priv, msg, context, "Ed448ph")
}

// VerifyEd448ph 验证原消息的 Ed448ph；原生层执行 SHAKE256 预哈希 签名；context 必须与签名一致。
// 无效签名返回 ErrSignature，不支持实例返回 ErrUnsupported；context 最长 255 字节。
//
// VerifyEd448ph verifies a complete message with Ed448ph; SHAKE256 prehashing occurs in the native provider; context must match the signer.
// Invalid signatures return ErrSignature, unavailable instances return ErrUnsupported; context is at most 255 bytes.
func VerifyEd448ph(pub PublicKey, msg, sig, context []byte) error {
	return verifyEdDSA(pub, msg, sig, context, "Ed448ph")
}

// SignEd448WithContext 使用 带上下文的 Ed448 对原消息签名。context 最长 255 字节；不可用返回 ErrUnsupported。
// 调用方不得预哈希 msg；密钥编码与原 EdDSA 密钥相同。
//
// SignEd448WithContext signs a complete message with Ed448 with a context. Context is at most 255 bytes; unavailable support returns ErrUnsupported.
// Callers must not prehash msg; existing EdDSA key encodings are reused.
func SignEd448WithContext(priv PrivateKey, msg, context []byte) ([]byte, error) {
	return signEdDSA(priv, msg, context, "Ed448")
}

// VerifyEd448WithContext 验证原消息的 带上下文的 Ed448 签名；context 必须与签名一致。
// 无效签名返回 ErrSignature，不支持实例返回 ErrUnsupported；context 最长 255 字节。
//
// VerifyEd448WithContext verifies a complete message with Ed448 with a context; context must match the signer.
// Invalid signatures return ErrSignature, unavailable instances return ErrUnsupported; context is at most 255 bytes.
func VerifyEd448WithContext(pub PublicKey, msg, sig, context []byte) error {
	return verifyEdDSA(pub, msg, sig, context, "Ed448")
}
