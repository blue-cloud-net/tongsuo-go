// Package meta 提供铜锁（Tongsuo）运行环境的元信息查询能力，
// 以及本库统一的「输入 / 输出」形态词汇。
//
// 本包覆盖铜锁命令行 version / version -a / errstr / list 四个子命令的 Go 侧
// 等价入口；含运行库版本、构建与运行环境快照、原生错误码解析、
// 七族算法枚举、provider 列表与 TLS 组枚举。
//
// 本包还定义跨包复用的形态词汇：
//
//   - Source / Sink —— 统一的输入源与输出汇（字节 / io.Reader / 文件 / 标准流）；
//   - Encoding —— hex / base64 / raw 三种输出编码；
//   - Format —— PEM / DER 两种序列化格式；
//   - Passphrase —— pass: / env: / file: / fd: / stdin 五种口令来源。
//
// 除形态词汇外，本包**只做查询**，不含任何密码学运算，也不持有原生句柄，
// 因此**无需 Close**。
// 本包为公开 API；底层调用由 internal/native 与 internal/core 完成。
//
// Package meta exposes read-only metadata about the Tongsuo runtime and
// the shared input/output vocabulary of this library.
//
// The metadata side covers the Go-side equivalents of the Tongsuo CLI's
// version, version -a, errstr and list subcommands: the running library
// version, a build/environment snapshot, helpers for converting native
// error codes to/from human-readable strings, the enumeration of seven
// algorithm families, the provider list and the TLS group list.
//
// The vocabulary side defines the types reused across packages:
//
//   - Source / Sink — the unified input source and output sink (bytes /
//     io.Reader / file / standard streams);
//   - Encoding — the hex / base64 / raw output encodings;
//   - Format — the PEM / DER serialization formats;
//   - Passphrase — the pass: / env: / file: / fd: / stdin passphrase
//     sources.
//
// Apart from the vocabulary types, the package performs no cryptographic
// operations and holds no native handles, so none of its functions require
// Close. The package is part of the public API; the underlying calls live
// in internal/native and internal/core.
package meta
