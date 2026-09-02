package core

import "github.com/blue-cloud-net/tongsuo-go/internal/native"

// VersionText 返回铜锁版本字符串（如 "Tongsuo 8.5.0-pre1 ..."）。
// 字符串来自 OpenSSL_version，包含完整的 OpenSSL/铜锁构建 banner（编译器与 configure 选项）。
//
// VersionText returns the Tongsuo version string as reported by
// OpenSSL_version (for example "Tongsuo 8.5.0-pre1 ..."). The string
// embeds the full OpenSSL/Tongsuo build banner including compiler and
// configure options.
func VersionText() string { return native.OpenSSLVersionText() }

// VersionNum 返回版本数字（OpenSSL_version_num），类型为 uint64。
// 编码遵循上游约定 <major><minor><fix><patch>（每个字段占一个 nibble），例如 3.0.0 对应 0x030000000。
// 在铜锁构建上该值仍然反映 OpenSSL 谱系。
//
// VersionNum returns the OpenSSL version number (OpenSSL_version_num)
// as a uint64. The encoding follows the upstream convention
// <major><minor><fix><patch> (each nibble), e.g. 0x030000000 for 3.0.0.
// On Tongsuo builds this still reflects the OpenSSL lineage.
func VersionNum() uint64 { return native.OpenSSLVersionNum() }

// TongsuoVersionNum 返回铜锁版本数字（Tongsuo_version_num），类型为 uint64。
// 与 VersionNum 不同，该值反映铜锁分支的发布标识，在铜锁构建上可能不同；在原生 OpenSSL 上通常为 0。
//
// TongsuoVersionNum returns the Tongsuo-specific version number
// (Tongsuo_version_num) as a uint64. Unlike VersionNum this value
// reflects the Tongsuo fork's release identity and may differ on
// Tongsuo builds; on stock OpenSSL it is typically zero.
func TongsuoVersionNum() uint64 { return native.TongsuoVersionNum() }
