package core

import "github.com/blue-cloud-net/tongsuo-go/internal/native"

// PKey 算法类型 ID 镜像（公开 re-export）。
//
// 这些常量与 native.EvpPkey* 完全等价（值相同、含义相同），
// 但作为 core 层的对外 API 镜像存在，使得外部包（crypto/ed25519、
// crypto/ed448、crypto/x25519 等）能够通过 core 间接拿到算法
// 类型 ID 而不必直接 import internal/native，从而维护 §3
// 的三层架构依赖方向（API → core → binding）。
//
// PKey algorithm ID mirrors.
//
// These constants are exact re-exports of native.EvpPkey* (same values,
// same semantics), exposed via the core layer so that consumers
// (such as crypto/ed25519, crypto/ed448, crypto/x25519) can address
// algorithm IDs without importing internal/native, preserving the
// three-layer architecture documented in docs/architecture.md §3.
const (
	PKeyAlgoRSA     = native.EvpPkeyRSA
	PKeyAlgoDSA     = native.EvpPkeyDSA
	PKeyAlgoEC      = native.EvpPkeyEC
	PKeyAlgoX25519  = native.EvpPkeyX25519
	PKeyAlgoX448    = native.EvpPkeyX448
	PKeyAlgoED25519 = native.EvpPkeyED25519
	PKeyAlgoED448   = native.EvpPkeyED448
	PKeyAlgoSM2     = native.EvpPkeySM2
)
