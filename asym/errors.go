package asym

import "errors"

// 公开错误哨兵（用 errors.Is 判别）。
//
// Public error sentinels (use errors.Is to discriminate).
var (
	// ErrUnknownAlgorithm 算法名不被本包或铜锁识别。
	//
	// ErrUnknownAlgorithm signals that the algorithm name is unknown to
	// this package or to the Tongsuo library.
	ErrUnknownAlgorithm = errors.New("asym: unknown algorithm")

	// ErrInvalidKey 密钥参数非法（长度错误、曲线名未知、类型不匹配）。
	//
	// ErrInvalidKey indicates an invalid key argument (wrong length,
	// unknown curve, mismatched algorithm, etc.).
	ErrInvalidKey = errors.New("asym: invalid key")

	// ErrUnsupported 当前算法不支持请求的操作（如 RSA 上调用 SM2 加解密）。
	//
	// ErrUnsupported indicates that the algorithm does not support the
	// requested operation (e.g. SM2-style encryption on RSA).
	ErrUnsupported = errors.New("asym: unsupported operation")

	// ErrSignature 算法验签未通过。
	//
	// ErrSignature indicates that signature verification failed.
	ErrSignature = errors.New("asym: signature verification failed")

	// ErrInvalidSeedLength 原始私钥种子长度不符合算法规定
	// （Ed25519 = 32 字节，Ed448 = 57 字节，X25519 = 32 字节，X448 = 56 字节）。
	//
	// ErrInvalidSeedLength reports a raw private seed whose length does
	// not match the algorithm's requirement (Ed25519 = 32 bytes,
	// Ed448 = 57 bytes, X25519 = 32 bytes, X448 = 56 bytes).
	ErrInvalidSeedLength = errors.New("asym: invalid seed length")

	// ErrInvalidPublicKeyLength 原始公钥字节长度不符合算法规定
	// （Ed25519 = 32 字节，Ed448 = 57 字节，X25519 = 32 字节，X448 = 56 字节）。
	//
	// ErrInvalidPublicKeyLength reports raw public key bytes whose length
	// does not match the algorithm's requirement (Ed25519 = 32 bytes,
	// Ed448 = 57 bytes, X25519 = 32 bytes, X448 = 56 bytes).
	ErrInvalidPublicKeyLength = errors.New("asym: invalid public key length")
)
