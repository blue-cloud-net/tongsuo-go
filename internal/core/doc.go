// Package core 是 tongsuo-go 的核心层：将铜锁原生句柄封装为 Go 对象，
// 管理生命周期与所有权，并提供统一的错误类型与版本查询。
//
// 本包属于 internal 实现，禁止被库外部导入；对外 API 见 crypto 子包。
package core
