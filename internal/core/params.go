package core

import (
	"fmt"
	"runtime"

	"github.com/blue-cloud-net/tongsuo-go/internal/native"
)

// MarshalECParameters 编码 EC 参数为 PEM。
//
// MarshalECParameters encodes EC parameters as PEM.
func MarshalECParameters(name string, explicit bool) ([]byte, error) {
	bio := native.BIO_new(native.BIO_s_mem())
	if bio == nil {
		return nil, NewOpError("ec: BIO_new", native.PopError())
	}
	defer native.BIO_free(bio)
	if !native.X_EC_parameters_write(bio, name, explicit) {
		return nil, NewOpError("ec: write parameters", native.PopError())
	}
	return readAllBIO(bio)
}

// LoadECParameters 校验 PEM 参数并返回命名曲线名。
//
// LoadECParameters validates PEM parameters and returns the named curve.
func LoadECParameters(data []byte) (string, error) {
	bio := native.BIO_new(native.BIO_s_mem())
	if bio == nil {
		return "", NewOpError("ec: BIO_new", native.PopError())
	}
	defer native.BIO_free(bio)
	if len(data) > 0 && native.BIO_write(bio, data) != len(data) {
		return "", NewOpError("BIO_write", native.PopError())
	}

	name := native.X_EC_parameters_read(bio)
	if name == "" {
		return "", NewOpError("ec: read parameters", native.PopError())
	}
	return name, nil
}

// Check 校验密钥；public 为 true 时只验证公钥。
//
// Check validates the key; public selects public-key validation only.
func (k *PKey) Check(public bool) error {
	defer runtime.KeepAlive(k)
	if k == nil || k.handle == nil || k.handle.IsClosed() {
		return fmt.Errorf("pkey: key closed")
	}
	if !native.X_EVP_PKEY_check(k.handle.Ptr(), public) {
		return NewOpError("pkey: check", native.PopError())
	}
	return nil
}

// SupportsRSASignatureDigest 探测 RSA provider 是否支持指定签名摘要。
// 不修改密钥；清理本次探测产生的线程错误队列。
//
// SupportsRSASignatureDigest probes whether the RSA provider accepts a signature digest.
// It does not modify the key and clears thread errors from the probe.
func (k *PKey) SupportsRSASignatureDigest(md *Digest) bool {
	defer runtime.KeepAlive(k)
	defer runtime.KeepAlive(md)
	if k == nil || k.handle == nil || k.handle.IsClosed() || md == nil || md.handle == nil || md.handle.IsClosed() {
		return false
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	native.ERR_clear_error()
	defer native.ERR_clear_error()
	ctx := native.EVP_MD_CTX_new()
	if ctx == nil {
		return false
	}
	defer native.EVP_MD_CTX_free(ctx)
	ok, _ := native.EVP_DigestSignInit(ctx, md.handle.Ptr(), nil, k.handle.Ptr())
	return ok
}
