package core

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/blue-cloud-net/tongsuo-go/internal/native"
)

// GeneratePQCKey 生成指定变体的原生密钥，调用方负责关闭。
//
// GeneratePQCKey generates a native key for the named variant. The caller owns it.
func GeneratePQCKey(name string) (*PKey, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	native.ERR_clear_error()
	ctx := native.EVP_PKEY_CTX_new_from_name(name)
	if ctx == nil {
		err := NewOpError("pkey: fetch "+name, native.PopError())
		native.ERR_clear_error()
		return nil, fmt.Errorf("%w: %w", ErrAlgorithmUnavailable, err)
	}
	defer native.EVP_PKEY_CTX_free(ctx)
	defer native.ERR_clear_error()
	key := native.EVP_PKEY_keygen(ctx)
	if key == nil {
		return nil, NewOpError("pkey: generate "+name, native.PopError())
	}
	return &PKey{handle: NewHandle(key, true, native.EVP_PKEY_free)}, nil
}

func (k *PKey) pqcAlgorithm() string {
	if k == nil || k.handle == nil || k.handle.IsClosed() {
		return ""
	}
	defer runtime.KeepAlive(k)
	name := strings.ToUpper(native.EVP_PKEY_get0_type_name(k.handle.Ptr()))
	switch {
	case strings.HasPrefix(name, "ML-DSA-"), strings.HasPrefix(name, "SLH-DSA-"), strings.HasPrefix(name, "ML-KEM-"):
		return name
	default:
		return ""
	}
}

func (k *PKey) pqcContext() (*Handle, error) {
	if k == nil || k.handle == nil || k.handle.IsClosed() {
		return nil, fmt.Errorf("pkey: key closed")
	}
	ctx := native.EVP_PKEY_CTX_new_from_pkey(k.handle.Ptr())
	if ctx == nil {
		return nil, NewOpError("pkey: create KEM context", native.PopError())
	}
	return NewHandle(ctx, true, native.EVP_PKEY_CTX_free), nil
}

// EncapsulateMLKEM 封装共享秘密，调用方负责清零秘密。
//
// EncapsulateMLKEM encapsulates a shared secret. The caller must wipe the secret.
func (k *PKey) EncapsulateMLKEM(size int) ([]byte, []byte, error) {
	defer runtime.KeepAlive(k)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	native.ERR_clear_error()
	defer native.ERR_clear_error()
	ctx, err := k.pqcContext()
	if err != nil {
		return nil, nil, err
	}
	defer ctx.Close()
	ciphertext, secret := make([]byte, size), make([]byte, 32)
	if !native.EVP_PKEY_encapsulate(ctx.Ptr(), ciphertext, secret) {
		return nil, nil, NewOpError("pkey: encapsulate ML-KEM", native.PopError())
	}
	return ciphertext, secret, nil
}

// DecapsulateMLKEM 解封装共享秘密，调用方负责清零秘密。
//
// DecapsulateMLKEM decapsulates a shared secret. The caller must wipe the secret.
func (k *PKey) DecapsulateMLKEM(ciphertext []byte) ([]byte, error) {
	defer runtime.KeepAlive(k)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	native.ERR_clear_error()
	defer native.ERR_clear_error()
	ctx, err := k.pqcContext()
	if err != nil {
		return nil, err
	}
	defer ctx.Close()
	secret := make([]byte, 32)
	if !native.EVP_PKEY_decapsulate(ctx.Ptr(), ciphertext, secret) {
		return nil, NewOpError("pkey: decapsulate ML-KEM", native.PopError())
	}
	return secret, nil
}

func (k *PKey) pqcSignatureContext(context []byte, encoded, sign bool) (*Handle, error) {
	if k == nil || k.handle == nil || k.handle.IsClosed() {
		return nil, fmt.Errorf("pkey: key closed")
	}
	ctx := native.EVP_MD_CTX_new()
	if ctx == nil {
		return nil, NewOpError("pkey: create PQC signature context", native.PopError())
	}
	if !native.X_EVP_PQC_signature_init(ctx, k.handle.Ptr(), context, encoded, sign) {
		err := NewOpError("pkey: initialize PQC signature", native.PopError())
		native.EVP_MD_CTX_free(ctx)
		return nil, err
	}
	return NewHandle(ctx, true, native.EVP_MD_CTX_free), nil
}

// SignPQC 对消息或标准预哈希编码签名。
//
// SignPQC signs a message or the standard prehash encoding.
func (k *PKey) SignPQC(message, context []byte, encoded bool) ([]byte, error) {
	defer runtime.KeepAlive(k)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	native.ERR_clear_error()
	defer native.ERR_clear_error()
	ctx, err := k.pqcSignatureContext(context, encoded, true)
	if err != nil {
		return nil, err
	}
	defer ctx.Close()
	size := native.EVP_PKEY_size(k.handle.Ptr())
	if size <= 0 {
		return nil, fmt.Errorf("pkey: invalid PQC signature size")
	}
	signature := make([]byte, size)
	if !native.EVP_DigestSign(ctx.Ptr(), signature, &size, message, len(message)) {
		return nil, NewOpError("pkey: sign PQC message", native.PopError())
	}
	return signature[:size], nil
}

// VerifyPQC 验证消息或标准预哈希编码的签名。
//
// VerifyPQC verifies a signature over a message or the standard prehash encoding.
func (k *PKey) VerifyPQC(message, signature, context []byte, encoded bool) error {
	defer runtime.KeepAlive(k)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	native.ERR_clear_error()
	defer native.ERR_clear_error()
	ctx, err := k.pqcSignatureContext(context, encoded, false)
	if err != nil {
		return err
	}
	defer ctx.Close()
	if !native.EVP_DigestVerify(ctx.Ptr(), signature, len(signature), message, len(message)) {
		return NewOpError("pkey: verify PQC message", native.PopError())
	}
	return nil
}

// PQCKeyAvailable 探测当前 provider 能否创建密钥生成上下文。
//
// PQCKeyAvailable reports whether the current provider can create a key generation context.
func PQCKeyAvailable(name string) bool {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	native.ERR_clear_error()
	defer native.ERR_clear_error()
	ctx := native.EVP_PKEY_CTX_new_from_name(name)
	if ctx == nil {
		return false
	}
	native.EVP_PKEY_CTX_free(ctx)
	return true
}

func (k *PKey) isPQCSigner() bool {
	name := k.pqcAlgorithm()
	return strings.HasPrefix(name, "ML-DSA-") || strings.HasPrefix(name, "SLH-DSA-")
}
