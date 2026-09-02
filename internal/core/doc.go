// Package core 是 tongsuo-go 的核心层：将铜锁原生句柄封装为 Go 对象，
// 管理生命周期与所有权，并提供统一的错误类型与版本查询。
// 本包属于 internal 实现，禁止被库外部导入；对外 API 见 crypto 子包。
//
// Package core is the internal core layer of tongsuo-go: it wraps native
// Tongsuo handles into Go objects, manages their lifecycle and ownership,
// and exposes a unified error type and version queries. The package is an
// internal implementation and must not be imported by code outside this
// module; the public API lives in the crypto subpackages.
package core
