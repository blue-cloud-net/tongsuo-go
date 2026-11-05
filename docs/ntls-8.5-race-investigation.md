# 铜锁 8.5.0 NTLS 偶发 Broken pipe 调查

## 现象与范围

GitHub Actions 的 Linux amd64 / Tongsuo 8.5.0 在 `go test -count=1 -race ./...`
中出现 `TestNTLSLoopback` 握手成功、应用数据写入报 `Broken pipe`。
8.4.0 及其余矩阵该次运行未失败，不代表其他运行不可能受到线程状态污染。

## 复现与根因

本地铜锁 8.5.0 下，原始 NTLS 回环单独重复 200 次通过，整个 TLS 包重复 30 次也通过。
让客户端握手后等待 20ms 再发送数据，使服务端先进入非阻塞读的 WANT_READ 路径，
100 次回环中出现 21 次失败。客户端读写和服务端读取均观察到了 Broken pipe。

铜锁的原生错误队列属于 OS 线程，并不属于 Go goroutine 或某条 SSL 连接。
`SSL_get_error` 的前置条件是本次 SSL 操作开始前该线程队列为空。
核心层此前锁定了线程，却没有清空前次原生调用留下的错误。
8.5.0 的 NTLS 读取路径会受这些残留错误影响，把正常的 WANT_READ 判为故障。
服务端因读取错误退出并关闭连接，使客户端随后报 Broken pipe。
队列中具体残留错误的来源可能因调度不同而不同；不能仅凭客户端 EPIPE 推断最初的失败操作。

`internal/core/ssl_error_queue_test.go` 构造独立 NTLS 双证书连接，在握手后锁定线程，
用非法 cipher 产生可识别的旧错误，再对没有应用数据的连接读取：

- 修复前：立即报 `SSL_read: ... no cipher match`，证明把无关旧错误当作读取故障。
- 修复后：等待至设置的 deadline 并返回超时，证明正确走 WANT_READ 重试。

相同注入方式的普通 TLS 测试没有复现，说明这条路径上的 NTLS 行为差异值得单独覆盖。

## 修复与回归

Connect / Accept / Read / Write 在锁定的同一 OS 线程上、每次原生操作前调用
`ERR_clear_error`；失败时仍读取该次操作产生的错误，没有忽略真实失败。
保留双向回环断言，增加客户端延迟发送场景和服务端错误诊断。
CI 的 Linux amd64 race 阶段额外重复 NTLS 回环 50 次，8.4/8.5 使用相同命令。
确定性的错误注入测试随默认单元测试、static 和 race 测试执行。

## act 为什么没有发现

此前 act 的 Linux amd64 两个版本确实执行了 race 测试，并非跳过该步骤；
但每组只执行一次 `-count=1`。arm64 按工作流设置不执行 race。
act 容器与 GitHub VM 的调度和负载不同，原始回环通常在服务端读取前就发送了数据，
未触发这个窗口。`-race` 检查 Go 内存访问，不检查铜锁 C 库的线程错误队列语义。
因此不能把 act 一次成功视为偶发时序缺陷不存在的证据。
确定性注入测试让缺陷检测不再依赖碰巧出现的 runner 调度。

## 回收 worktree 后的 act 缓存配置

此次回归还发现，铜锁缓存可包含旧 worktree 的编译时 `OPENSSLDIR`，
导致主目录复用缓存时 CLI 找不到 `openssl.cnf`。CI 显式设置 `OPENSSL_CONF`
指向当前工作区 `.tongsuo-install/ssl/openssl.cnf`，使配置随缓存安装目录定位。
这与 NTLS Broken pipe 是两个独立问题；此前 act 的 race 阶段确实执行成功。

## 修复后验证（2026-11-05）

- 本机铜锁 8.4.0 / 8.5.0：`go vet ./...`、全量 `go test -count=1 -race ./...` 通过。
- 铜锁 8.5.0：放大时序的 NTLS 回环 100 次、错误注入回归 100 次均通过。
- act（Go 1.21.13，Linux amd64）：8.4.0 / 8.5.0 两组完整通过，包含 build/vet、
  单元测试、真实 static 链接测试、全量 race、50 次 NTLS 回环及 CLI 对拍。
- 本轮未重跑 arm64 或 macOS；线上任务结果仍需推送后确认。
