package ecdh

import "errors"

// 公开错误哨兵（用 errors.Is 判别）。
//
// Public error sentinels (use errors.Is to discriminate).
var (
	// ErrUnknownCurve 曲线名不在 Curves() 返回的集合内（且不是可识别的别名）。
	//
	// ErrUnknownCurve signals that a curve name is neither in the set
	// returned by Curves() nor a recognised alias.
	ErrUnknownCurve = errors.New("ecdh: unknown curve")

	// ErrUnsupportedKey 传入的 asym 密钥不是可协商的曲线算法
	// （仅 NIST 曲线 P-256 / P-384 / P-521 / secp256k1 与 OKP 曲线
	// X25519 / X448 可协商；RSA / Ed25519 / Ed448 / SM2 均不支持）。
	//
	// ErrUnsupportedKey signals that the supplied asym key is not an
	// agreement-capable curve algorithm: only the NIST curves
	// (P-256 / P-384 / P-521 / secp256k1) and the OKP curves
	// (X25519 / X448) can agree, while RSA / Ed25519 / Ed448 / SM2 cannot.
	ErrUnsupportedKey = errors.New("ecdh: unsupported key")
)
