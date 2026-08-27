package core

import "github.com/blue-cloud-net/tongsuo-go/internal/native"

// VersionText 返回铜锁版本字符串（如 "Tongsuo 8.5.0-pre1 ..."）。
func VersionText() string { return native.OpenSSLVersionText() }

// VersionNum 返回版本数字（OpenSSL_version_num）。
func VersionNum() uint64 { return native.OpenSSLVersionNum() }

// TongsuoVersionNum 返回铜锁版本数字（Tongsuo_version_num）。
func TongsuoVersionNum() uint64 { return native.TongsuoVersionNum() }
