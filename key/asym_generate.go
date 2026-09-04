package key

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// GenerateRSAKey 生成 bits 位的 RSA 密钥对并返回私钥包装。
// bits 必须至少 1024（与 SP 800-131A / FIPS 186-4 最小模数对齐）；调用方
// 使用完毕应经 key.Close 释放底层句柄。
//
// GenerateRSAKey generates an RSA key pair of the given bit size and
// returns the private-key wrapper.
// bits must be at least 1024, aligned with the SP 800-131A and FIPS 186-4
// minimum modulus; callers should release the underlying handle through
// key.Close when done.
func GenerateRSAKey(bits int) (AsymmetricPrivateKey, error) {
	if bits < 1024 {
		return nil, fmt.Errorf("key: RSA key size too small: %d", bits)
	}
	pk, err := core.GenerateRSAKey(bits)
	if err != nil {
		return nil, err
	}
	return newPrivateKey(pk, AlgRSA), nil
}

// GenerateSM2Key 生成新的 SM2 密钥对（GM/T 0003）并返回私钥包装。
// 调用方使用完毕应经 key.Close 释放底层句柄。
//
// GenerateSM2Key generates a fresh SM2 key pair (GM/T 0003) and returns the
// private-key wrapper.
// Callers should release the underlying handle through key.Close when done.
func GenerateSM2Key() (AsymmetricPrivateKey, error) {
	pk, err := core.GenerateSM2Key()
	if err != nil {
		return nil, err
	}
	return newPrivateKey(pk, AlgSM2), nil
}

// GenerateECKey 生成指定曲线的 ECDSA 密钥对并返回私钥包装。
// curve 须非空（如 "prime256v1"、"secp384r1"，亦可为 "sm2" 曲线）。
// 注意：经 EC 密钥生成得到的密钥恒为 EC 类型并报告 AlgECDSA——即使曲线为
// "sm2" 也只是 SM2 曲线上的 ECDSA，并非 GM/T 0003 SM2 方案；生成真正的 SM2
// 密钥请用 GenerateSM2Key。调用方使用完毕应经 key.Close 释放。
//
// GenerateECKey generates an ECDSA key pair on the given curve and returns
// the private-key wrapper.
// curve must be non-empty (for example "prime256v1" or "secp384r1"; the
// "sm2" curve is also accepted). Note that a key produced through EC
// generation is always of EC type and reports AlgECDSA — even on the "sm2"
// curve it is ECDSA over the SM2 curve rather than the GM/T 0003 SM2 scheme;
// use GenerateSM2Key for a genuine SM2 key. Callers should release the
// underlying handle through key.Close when done.
func GenerateECKey(curve string) (AsymmetricPrivateKey, error) {
	if curve == "" {
		return nil, fmt.Errorf("key: empty curve name")
	}
	pk, err := core.GenerateECKey(curve)
	if err != nil {
		return nil, err
	}
	return wrapPrivate(pk)
}

// GenerateEd25519Key 生成 Ed25519 签名密钥对（RFC 8032，AlgED25519）并返回私钥包装。
// 调用方使用完毕应经 key.Close 释放底层句柄。
//
// GenerateEd25519Key generates a fresh Ed25519 signing key pair (RFC 8032,
// AlgED25519) and returns the private-key wrapper.
// Callers should release the underlying handle through key.Close when done.
func GenerateEd25519Key() (AsymmetricPrivateKey, error) {
	pk, err := core.GenerateED25519Key()
	if err != nil {
		return nil, err
	}
	return wrapPrivate(pk)
}

// GenerateEd448Key 生成 Ed448 签名密钥对（RFC 8032，AlgED448）并返回私钥包装。
// 调用方使用完毕应经 key.Close 释放底层句柄。
//
// GenerateEd448Key generates a fresh Ed448 signing key pair (RFC 8032,
// AlgED448) and returns the private-key wrapper.
// Callers should release the underlying handle through key.Close when done.
func GenerateEd448Key() (AsymmetricPrivateKey, error) {
	pk, err := core.GenerateED448Key()
	if err != nil {
		return nil, err
	}
	return wrapPrivate(pk)
}

// GenerateX25519Key 生成 X25519 ECDH 密钥对（RFC 7748，AlgX25519）并返回私钥包装。
// 调用方使用完毕应经 key.Close 释放底层句柄；密钥交换由各 crypto/* 包的 SharedSecret 方法完成。
//
// GenerateX25519Key generates a fresh X25519 ECDH key pair (RFC 7748,
// AlgX25519) and returns the private-key wrapper.
// Callers should release the underlying handle through key.Close when
// done; the actual shared-secret computation lives in the per-package
// SharedSecret method.
func GenerateX25519Key() (AsymmetricPrivateKey, error) {
	pk, err := core.GenerateX25519Key()
	if err != nil {
		return nil, err
	}
	return wrapPrivate(pk)
}
