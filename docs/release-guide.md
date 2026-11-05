# 发版流程（维护者操作手册）

> **定位**：本文是「从准备到 GitHub Release」的**可执行操作手册**。
> 规范条款（提交信息格式、CHANGELOG 规则、层级红线）以 [`AGENTS.md`](../AGENTS.md) §6 为准；
> 本文只回答「按什么顺序做、每条命令看什么结果、出问题怎么退」。
>
> **先例**：`0.4.0`（2026-10-23 发布）按本文流程执行；`0.2.0`–`0.3.0` 的差异见 §11 复盘。

---

## 0. 前置条件

| 项 | 要求 |
|----|------|
| 铜锁 | **8.4.0 / 8.5.0**，CI 两版固定矩阵，头文件/运行库/CLI 同源 |
| Go | 1.21（CI 固定） |
| 推送权限 | `git push origin main` / `git push origin v<ver>`；agent **禁止** push（AGENTS §6.5），由维护者手动执行 |
| 工作区 | `git status --porcelain` 必须为空 |

环境变量（每个新 shell 都要设，注意**库目录可能是 `lib` 或 `lib64`**）：

- 本机 `/opt/tongsuo`（8.5.0-pre*）只有 `lib64/`
- CI 与本地 8.4 临时安装（`--libdir=<prefix>/lib`）用 `lib/`

```bash
export TONGSUO_HOME=/opt/tongsuo            # 或 /tmp/tongsuo-8.4.0-install
export LD_LIBRARY_PATH=$TONGSUO_HOME/lib64  # 8.4 临时安装用 $TONGSUO_HOME/lib
export CGO_CFLAGS="-I$TONGSUO_HOME/include -Wno-deprecated-declarations"
export CGO_LDFLAGS="-L$TONGSUO_HOME/lib64"  # 同上
```

---

## 1. 确定版本号

`CHANGELOG.md` / `CHANGELOG.zh.md` 顶部有两套「未发布」语义，先看清改动属于哪一类：

- `## [Unreleased]` —— **尚未决定归入哪个版本**的暂存区（常为空）
- `## [x.y.z] - TBD` —— **已定目标版本、尚未打 tag**（实际发版内容在这里）

判断口径：

- 该版本**从未发布过**（远端无 tag、无 Release）→ 它就是「未发布版本」，其中的功能修补
  **并入对应的新增条目**，不单列 `Bug 修复`（先例：0.4.0 把原 0.4.1/0.4.2 的内容全部并入 0.4.0）
- 该版本**已经发布**（远端有 tag）→ 后续修补走新的 patch 段

---

## 2. 整理提交（不改写历史）

一个逻辑变更一个 Conventional Commit，中文主题。已存在的提交保持原样，
修补以新增提交表达，不使用 rebase、amend 或 reset 改写历史。功能分支先合并到 dev，
验收通过、干净且已合并后再回收对应 worktree；其他会话的 worktree 保留。

---

## 3. CHANGELOG 定版

两份文件**同改**，段序按版本号降序，新版本段插在最上。

- **不要直接拼接旧段**：按「最终行为」重写。同一个能力先新增、后被修，合并版本里只留一条新增描述，
  不写「先新增、又修复」
- 未发布版本内的修补：并入对应新增条目（见 §1）
- 已发布版本的行为修复：保留在 `Bug 修复` / `Fixed`
- 底部链接定义区必须与标题一一对应；`[Unreleased]` 指向 `compare/v<ver>...HEAD`
- 日期：定版前写 `TBD`，**发版日**再改成 `YYYY-MM-DD`
- 术语保留英文（SM2 / PEM / DER / PKCS#7 / NTLS / RFC xxxx …）

预检（合并前必跑）：

```bash
python3 scripts/extract_release_notes.py <ver>   # 生成 release-notes.md（已 gitignore）
```

要求：**两份都抽得到**（任一缺失 `exit 1`），且正文里不出现上一个未发布版本号。

---

## 4. 基线文档同步

以下文档里的「生成基线 / 本库基线」日期与版本前缀需同步：

| 文件 | 需要同步的内容 |
|------|----------------|
| `docs/api-reference.md` | 生成基线日期、符号前缀图例（`🆕` 0.3.0 / `✨` 0.4.0 / `🧭` 规划中） |
| `docs/api-reference-internal.md` | 生成基线日期 |
| `docs/cli-comparison.md` | 「本库基线」 |
| `docs/official-sdk-comparison.md` | 「本库基线」 |
| `docs/roadmap.md` | 顶部基线与「只写未做的事」口径、§3「已在 `x.y.z` 落地的相关绑定」 |

纯文档改动**不写进 CHANGELOG**（AGENTS §6.3）。

---

## 5. 本地验证（顺序执行，任一步失败即停）

```bash
gofmt -l .                                   # 必须为空
go vet ./...
go build ./...
go test -count=1 ./...
go build -tags static ./...                  # 仅 Linux 接线
go test -count=1 -tags tongsuocli ./...      # 需铜锁 CLI，等价 CI interop
go test -race ./...                          # 涉及并发/生命周期时必跑，见 §10
```

示例模块（各自是独立 module，构建后会留下**未忽略**的二进制，必须清理）：

```bash
for d in examples/*/; do (cd "$d" && go build ./...); done
find examples -maxdepth 2 -type f -perm -u+x ! -name '*.go' ! -name '*.md' ! -name 'go.mod' -print -delete
```

### 5.1 固定双版本验证

分别使用铜锁 8.4.0 与 8.5.0 的头文件、库和 CLI 执行上述检查；不能以系统 OpenSSL
替代，也不能用其中一版通过来证明另一版可用。CI 用 scripts/build-tongsuo-ci.sh
在临时目录从固定 tag 构建 shared 库与静态归档，启用 NTLS/trace；Linux static
标签用 -Bstatic 选择铜锁归档，最终链接测试二进制以验证，不要求整进程静态 libc。

---

## 6. 用 act 本地复跑 CI

```bash
bash scripts/run-act.sh -j all
```

当前 test job 包含 build/vet、单元测试和 Linux static；amd64 另含 race 与 CLI
互通。脚本分别运行 Linux amd64/arm64，两条腿各含铜锁 8.4.0/8.5.0；arm64 在
x86 主机上使用 QEMU 和对应架构的镜像 digest。macOS 必须交给真实 GitHub runner，
不能把 Linux 容器改名为 macOS 视作验证。

每条架构腿的日志与退出码写入 .act-logs/act-test-<arch>-<timestamp>.log/.rc，
退出码必须全为 0。代理通过环境变量传入；容器使用 host 网络，脚本默认限制每个
铜锁构建 8 个并发任务，可用 TONGSUO_BUILD_JOBS 覆盖。旧 -j lint/-j interop
参数作为兼容别名，运行完整 test job。

---

## 7. 合并到 main

```bash
git switch main
git status --porcelain                # 必须为空
git merge --no-ff dev -m "chore(merge): 合并 0.8.0 发布准备到 main"
git rev-list --count main..dev        # 必须为 0
git diff --stat dev main              # 必须为空（树一致）
# 由维护者手动执行：git push origin main
```

main 接受从 dev 的非快进合并；保留已有历史，不 reset 或 rebase。agent 完成本地合并后停止，由维护者推送。

推送后等待双版本 × Linux/macOS × amd64/arm64 矩阵全部通过。
**不要**在 CI 红的基础上打 tag。

---

## 8. 打 tag 并发布

```bash
git tag -a v<ver> -m "v<ver>"         # 历史 tag 全为 annotated
git push origin v<ver>
```

`release.yml` 依次执行：

1. `test` —— `uses: ./.github/workflows/ci.yml`（与 CI 完全同源）
2. `extract-notes` —— 从两份 CHANGELOG 抽取 `## [<ver>]` 段；**任一份缺失即失败**，
   拼接格式「英文 + 3 空行 + 中文」，产物 `release-notes.md`
3. `release` —— Release body = 抽取文本，**不上传任何二进制**

发布后核对（发布物只有文本）：

```bash
curl -sS https://api.github.com/repos/blue-cloud-net/tongsuo-go/releases/tags/v<ver>
```

检查项：`draft=false`；body 同时含 `### Added` 与 `### 新增功能`；含 `### BREAKING`（若有）；
不出现上一个未发布版本号；`assets` 为空列表。

---

## 9. 失败与回退

| 场景 | 处置 |
|------|------|
| CI 红 | 先修再打 tag。修之前**必须先复现**（本机装同版本铜锁，见 §5.1），禁止直接放宽断言 |
| tag 已推送但 Release 失败 | 修复后删远端 tag 重打，或走 `workflow_dispatch` 带 `tag` 输入重跑（不删 tag 优先） |
| tag 打错且**已发布** | 不删已发布 tag；改发下一个 patch 版本 |
| tag 打错且**未推送** | `git tag -d v<ver>` 后重新打 |
| dev 历史需修正 | 使用新增修正提交，不改写历史，不强推 |
| 本地 main 与预期不一致 | 保留提交，先核对差异；不执行 reset --hard |

---

## 10. 历史并发诊断（失败仍阻塞发版）

- `go test -race ./tls/` 约 1/3 概率在 `TestReadReturnsAfterCancel` 报数据竞争
  （`tls.Conn.Close` 与 `internal/core.(*SSLConn).Read` 之间）。
  这是历史诊断记录。0.8.0 的 Linux amd64 CI 已执行 race；任何复现的失败均阻塞发版，不能作为豁免。

---

## 11. 0.4.0 复盘（本流程的来源）

- **首次发布失败**：0.4.0 首次合并后在 CI 上失败，根因是铜锁 8.4 与 8.5 的
  `X509_REQ_add_extensions` 语义不同（8.4 每次调用追加一个新属性，而
  `X509_REQ_get_extensions` 只读第一个）。本地 8.5 全绿掩盖了问题。
  → 结论：**发版前必须用 8.4.0 复跑**（§5.1）
- **未发布版本的修补被拆成 0.4.1 / 0.4.2 两段**，而这两版都没有真正上线
  → 结论：合并为一版，修补并入新增条目（§1、§3）
- **远端 tag 只到 v0.3.0，本地却打了 v0.4.0/v0.4.1 且 main 有未推送的 merge**
  → 结论：发版前先 `git fetch` 并核对 `origin/main`、远端 tag（§7）
- **act 里 clone 铜锁超时**不是 CI 问题，是容器缺代理配置（§6）
