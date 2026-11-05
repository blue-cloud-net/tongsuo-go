package core

import (
	"errors"
	"fmt"
	"runtime"

	"github.com/blue-cloud-net/tongsuo-go/internal/native"
)

const maxSM2DHOutputSize = 1<<31 - 1

// ErrAlgorithmUnavailable 表示当前原生 provider 无法应用请求的算法参数。
//
// ErrAlgorithmUnavailable means the native provider cannot apply the requested algorithm parameters.
var ErrAlgorithmUnavailable = errors.New("core: algorithm parameters unavailable")

func (k *PKey) edDSAContext(instance string, context []byte, sign bool) (*Handle, error) {
	if k == nil || k.handle == nil || k.handle.IsClosed() {
		return nil, fmt.Errorf("pkey: key closed")
	}
	ctx := native.EVP_MD_CTX_new()
	if ctx == nil {
		return nil, NewOpError("pkey: new EdDSA context", native.PopError())
	}
	h := NewHandle(ctx, true, native.EVP_MD_CTX_free)
	rc := native.X_EVP_DigestSignVerifyInit_instance(ctx, k.handle.Ptr(), instance, context, sign)
	if rc != 1 {
		err := NewOpError("pkey: EdDSA instance init", native.PopError())
		h.Close()
		if rc == -2 {
			return nil, fmt.Errorf("%w: %w", ErrAlgorithmUnavailable, err)
		}
		return nil, err
	}
	return h, nil
}

// SupportsEdDSAInstance 探测签名或验签初始化是否真正应用实例和上下文。
//
// SupportsEdDSAInstance probes whether sign/verify initialization applies the instance and context.
func (k *PKey) SupportsEdDSAInstance(instance string, context []byte, sign bool) (bool, error) {
	defer runtime.KeepAlive(k)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	native.ERR_clear_error()
	defer native.ERR_clear_error()
	h, err := k.edDSAContext(instance, context, sign)
	if errors.Is(err, ErrAlgorithmUnavailable) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	h.Close()
	return true, nil
}

// SignEdDSAInstance 对原消息进行指定实例的一次性签名；ph 在原生层预哈希。
//
// SignEdDSAInstance signs a complete message once; ph prehashing occurs in the native provider.
func (k *PKey) SignEdDSAInstance(msg []byte, instance string, context []byte) ([]byte, error) {
	defer runtime.KeepAlive(k)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	h, err := k.edDSAContext(instance, context, true)
	if err != nil {
		return nil, err
	}
	defer h.Close()
	n := native.EVP_PKEY_size(k.handle.Ptr())
	if n <= 0 {
		return nil, fmt.Errorf("pkey: invalid EdDSA signature size")
	}
	sig := make([]byte, n)
	if !native.EVP_DigestSign(h.Ptr(), sig, &n, msg, len(msg)) {
		return nil, NewOpError("pkey: EdDSA sign", native.PopError())
	}
	return sig[:n], nil
}

// VerifyEdDSAInstance 验证指定实例的原消息与签名，失败返回 OpError。
//
// VerifyEdDSAInstance verifies a complete message using the requested instance, returning OpError on failure.
func (k *PKey) VerifyEdDSAInstance(msg, sig []byte, instance string, context []byte) error {
	defer runtime.KeepAlive(k)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	h, err := k.edDSAContext(instance, context, false)
	if err != nil {
		return err
	}
	defer h.Close()
	if !native.EVP_DigestVerify(h.Ptr(), sig, len(sig), msg, len(msg)) {
		return NewOpError("pkey: EdDSA verify", native.PopError())
	}
	return nil
}

// DeriveSM2DH 使用四个独立密钥句柄及 SM3 派生密钥；不生成密钥确认消息。
// 调用方负责清零返回密钥，且不得并发关闭输入句柄。
//
// DeriveSM2DH derives a key using four handles and SM3, without key-confirmation messages.
// Callers must wipe the returned key and must not close input handles concurrently.
func DeriveSM2DH(ephemeral, peerEphemeral, selfStatic, peerStatic *PKey, initiator bool, selfID, peerID []byte, outLen int) ([]byte, error) {
	defer runtime.KeepAlive(ephemeral)
	defer runtime.KeepAlive(peerEphemeral)
	defer runtime.KeepAlive(selfStatic)
	defer runtime.KeepAlive(peerStatic)
	for _, key := range []*PKey{ephemeral, peerEphemeral, selfStatic, peerStatic} {
		if key == nil || key.handle == nil || key.handle.IsClosed() || key.Algorithm() != "SM2" {
			return nil, fmt.Errorf("pkey: invalid or closed SM2 key")
		}
	}
	if outLen <= 0 || uint64(outLen) > uint64(maxSM2DHOutputSize) {
		return nil, fmt.Errorf("pkey: invalid SM2DH output length")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	out := make([]byte, outLen)
	rc := native.X_EVP_PKEY_SM2DH(ephemeral.handle.Ptr(), peerEphemeral.handle.Ptr(),
		selfStatic.handle.Ptr(), peerStatic.handle.Ptr(), initiator, selfID, peerID, out)
	if rc == -2 {
		return nil, ErrAlgorithmUnavailable
	}
	if rc != 1 {
		return nil, NewOpError("pkey: SM2DH derive", native.PopError())
	}
	return out, nil
}
