---
description: "Use when discussing the tongsuo-go project overview, architecture, package layout, or need to reference docs. Trigger keywords: tongsuo-go, 项目简介, architecture, package layout."
---

# tongsuo-go 项目简介

`tongsuo-go`（`github.com/blue-cloud-net/tongsuo-go`，Apache-2.0）是基于[铜锁 Tongsuo 8.4.0+](https://www.tongsuo.net/) 的 Go 国密算法封装库，通过 cgo 调用铜锁原生库，提供符合 Go 惯例的接口（`hash.Hash`、`cipher.Block`、`cipher.AEAD`、`(T, error)`），覆盖 SM2/SM3/SM4、AES、HMAC、X.509 与 TLS/NTLS 双证书传输层。采用 API 层 → 核心层 → 绑定层三层分层，依赖单向向下。

## 相关文档

- [architecture.md](../../docs/architecture.md) — 整体架构、目录结构、构建依赖
- [development-guide.md](../../docs/development-guide.md) — 开发规范
- [testing-guide.md](../../docs/testing-guide.md) — 测试规范