// Package meta 提供铜锁（Tongsuo）运行环境的元信息查询能力。
//
// 本包覆盖铜锁命令行 version / version -a / errstr 三个子命令的 Go 侧
// 等价入口；含运行库版本、构建与运行环境快照、原生错误码解析。
// 本包**只做查询**，不含任何密码学运算，也不持有原生句柄，因此**无需 Close**。
// 本包为公开 API；底层调用由 internal/native 与 internal/core 完成。
//
// Package meta exposes read-only metadata about the Tongsuo runtime:
// the running library version, a build/environment snapshot, and helpers
// for converting native error codes to/from human-readable strings.
//
// The package covers the Go-side equivalents of the Tongsuo CLI's
// version, version -a and errstr subcommands. It performs no
// cryptographic operations and holds no native handles, so none of
// its functions require Close. The package is part of the public API;
// the underlying calls live in internal/native and internal/core.
package meta
