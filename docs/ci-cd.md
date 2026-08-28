# CI/CD 指南

本文档说明 `tongsuo-go` 的持续集成与发布流程。架构说明见
[architecture.md](architecture.md)，开发规范见 [development-guide.md](development-guide.md)，
测试规范见 [testing-guide.md](testing-guide.md)。

---

## 1. 流水线总览

| Workflow | 文件 | 触发 | 职责 |
|----------|------|------|------|
| CI | [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) | push / PR 到 `main` / `dev`，手动 | 静态检查 + 测试矩阵（动态/静态链接） |
| Release | [`.github/workflows/release.yml`](../.github/workflows/release.yml) | 推送 `v*` 标签 / 手动输入 tag | 完整测试 + 跨平台构建 + 发版 |

辅助文件：

- [`.github/dependabot.yml`](../.github/dependabot.yml) — GitHub Actions 依赖自动更新
- [`.codecov.yml`](../.codecov.yml) — Codecov 配置（可选）

> ⚠️ **本项目 CI 不强制覆盖率门禁**。覆盖率脚本 [`scripts/check-coverage.sh`](../scripts/check-coverage.sh)
> 保留供本地参考。Phase 14 路线图目标的 ≥80% 覆盖率作为开发者参考标准。

---

## 2. CI 工作流

### 2.1 Job 结构

```
lint ──► test (ubuntu/macos × Go 1.21/1.23)
```

| Job | Runner | 关键步骤 |
|-----|--------|----------|
| `lint` | ubuntu-latest | `go vet ./...` + `golangci-lint-action` |
| `test` | ubuntu-latest × macos-latest × Go 1.21 / 1.23 | 编译 Tongsuo（cache 复用）→ 配置动态链接 → `go build ./...` → `go build -tags static ./...` → `go test -count=1 ./...` |

### 2.2 Tongsuo 编译缓存

CI 中 Tongsuo 从源码编译安装到 `${{ github.workspace }}/.tongsuo-install`：

```bash
git clone --depth 1 --branch ${TONGSUO_REF} \
    https://github.com/${TONGSUO_REPO}.git tongsuo
cd tongsuo
./config --prefix=${TONGSUO_PREFIX} \
         --libdir=${TONGSUO_PREFIX}/lib \
         enable-ntls enable-export-sm4 enable-ssl-trace no-shared
make -j"$(nproc)"
make install_sw
```

- 通过 [actions/cache](https://github.com/actions/cache) 按 `runner.os + Tongsuo 版本
  + workflow hash` 缓存，重复运行通常**秒级命中**
- 关键配置标志（与 [architecture.md §6.2](architecture.md) 对齐）：
  - `enable-ntls` — 国密 NTLS 支持（Phase 6 必需）
  - `enable-export-sm4` — 导出 SM4 算法符号
  - `enable-ssl-trace` — 调试用 trace 回调
  - `no-shared` — 编译静态库，CI 容器内统一管理
- 默认仓库 `OpenTongsuo/Tongsuo`，分支 `master`；需要时改 workflow 顶部的
  `TONGSUO_REPO` / `TONGSUO_REF` 环境变量

### 2.3 CGO 环境变量

```yaml
LD_LIBRARY_PATH: ${TONGSUO_PREFIX}/lib           # Linux
DYLD_LIBRARY_PATH: ${TONGSUO_PREFIX}/lib         # macOS
CGO_CFLAGS: -I${TONGSUO_PREFIX}/include -Wno-deprecated-declarations
CGO_LDFLAGS: -L${TONGSUO_PREFIX}/lib
TONGSUO_HOME: ${TONGSUO_PREFIX}
```

- Linux runner 默认 root，写入 `/etc/ld.so.conf.d/tongsuo.conf` + `ldconfig` 生效
- macOS 通过 `DYLD_LIBRARY_PATH` 让动态链接器找到 Tongsuo

### 2.4 覆盖率（可选）

CI 不强制覆盖率门禁；如需本地检查，请使用
[`scripts/check-coverage.sh`](../scripts/check-coverage.sh)：

```bash
THRESHOLD=80 ./scripts/check-coverage.sh
EXCLUDE="ocsp,jwk" ./scripts/check-coverage.sh
```

默认阈值 60%，可通过 `THRESHOLD` 覆盖；`EXCLUDE` 控制豁免的包后缀（逗号分隔，
默认排除 `ocsp`）。

---

## 3. Release 工作流

### 3.1 触发方式

```bash
# 推送 tag 自动触发
git tag v0.1.0
git push origin v0.1.0

# 或在 GitHub UI 手动触发，输入 tag
```

### 3.2 流程

```
test (ubuntu/macos × Go 1.21/1.23)
   │
   ▼
build (linux/darwin × amd64/arm64) ──► release
                                         ├─ 下载所有 artifacts
                                         ├─ 生成 SHA256SUMS
                                         └─ softprops/action-gh-release@v2
```

- **build** job 默认构建 [examples/sm2](../examples/sm2) 作为最小验证产物
- 产物命名：`sm2-<os>-<arch>`（如 `sm2-linux-amd64`）
- **release** job 仅在 tag 触发时执行；通过 `generate_release_notes: true` 自动
  汇总 PR 与 commit
- macOS 交叉工具链（`osxcross`）依赖较多，当前 `build` job **仅在 ubuntu runner
  上完成 Linux 交叉**；darwin 真实产物由 native macOS runner 产出（`build`
  矩阵中实际只有 `darwin-amd64` / `darwin-arm64` 由对应 runner 直接构建）

### 3.3 调整 release 产物

如需把 `examples/sm2` 换成其他示例，或新增构建目标：

1. 替换 `examples/sm2` 为目标路径
2. 修改 build matrix 的 `include` 列表
3. 增加新平台的交叉工具链安装步骤（如 darwin 需 `nick-fields/setup-osxcross`）

---

## 4. Dependabot

[`.github/dependabot.yml`](../.github/dependabot.yml) 配置：

- **github-actions** — 周一 09:00 (UTC+8) 检测 action 版本更新
- 提交前缀 `ci(<scope>)`，自动打 `dependencies` + `ci` 标签

> 本项目无第三方 Go 运行时包，故不启用 `gomod` ecosystem

---

## 5. 本地等效验证

在没有 GitHub runner 的本地机器上，可用一段脚本复现 CI 的关键步骤：

```bash
#!/usr/bin/env bash
set -euo pipefail

: "${TONGSUO_HOME:=/opt/tongsuo}"
export LD_LIBRARY_PATH="${TONGSUO_HOME}/lib"
export CGO_CFLAGS="-I${TONGSUO_HOME}/include -Wno-deprecated-declarations"
export CGO_LDFLAGS="-L${TONGSUO_HOME}/lib"

echo "==> go vet"
go vet ./...

echo "==> golangci-lint"
golangci-lint run --timeout=5m

echo "==> go build"
go build ./...

echo "==> go build (static)"
go build -tags static ./...

echo "==> go test"
go test -count=1 ./...

# 可选：本地覆盖率检查
# echo "==> coverage gate"
# ./scripts/check-coverage.sh
```

---

## 6. 故障排查

| 症状 | 排查 |
|------|------|
| `ld: library not found for -lssl` | `LD_LIBRARY_PATH` / `DYLD_LIBRARY_PATH` 未生效；确认 `${TONGSUO_PREFIX}/lib` 存在 `libssl.a` / `libcrypto.a` |
| `Tongsuo version mismatch` | 升级 `${TONGSUO_REF}` 到兼容分支（≥ 8.4.0） |
| macOS runner 报签名/权限错 | Tongsuo 安装目录权限问题；`sudo chown -R $(whoami) ${TONGSUO_PREFIX}` |
| Tongsuo 编译时间过长 | 检查 `actions/cache` 是否命中（`Use` 步骤输出 `cache-hit: true`） |

---

## 7. 未来扩展

- [ ] CodeQL 安全扫描（`.github/workflows/codeql.yml`）
- [ ] Docker 镜像构建与推送（`ghcr.io/blue-cloud-net/tongsuo-go`）
- [ ] pkg.go.dev 自动徽章与 API 文档同步
- [ ] 性能回归基准（`go test -bench` 历史追踪）