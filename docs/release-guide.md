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
| 铜锁 | **8.4.0+**，CI 固定 `TONGSUO_REF: 8.4.0` |
| Go | 1.21（CI 固定） |
| 推送权限 | `git push origin main` / `git push origin v<ver>`；agent 默认**禁止** push（AGENTS §6.5），需显式授权 |
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

## 2. 整理提交历史（可选但推荐）

目标：一个逻辑变更一个 commit，且不把未发布版本的修补拆成多段。

1. 打安全锚点：`git tag backup/pre-release-<ver>`
2. 重排：`git rebase -i <上一个已发布基线的提交>`
   - 丢弃「临时 CHANGELOG 段」类提交，内容改为在最终一个 CHANGELOG 提交里重写
   - 需要整体重写文件时用 `edit` 停在该提交上
3. **完整性校验**（关键）：

```bash
git diff --stat backup/pre-release-<ver> HEAD          # 应只有 CHANGELOG 等文档
git diff --quiet backup/pre-release-<ver> HEAD -- ':!CHANGELOG.md' ':!CHANGELOG.zh.md' && echo CODE-TREE-IDENTICAL
```

只要代码树不一致就说明重排过程中丢了东西，回到锚点重来。

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

### 5.1 用 CI 同款铜锁 8.4.0 复跑（强烈推荐）

「本地绿 / CI 红」几乎总是 **8.4 与 8.5 的语义差异**，不是 flaky。先例：0.4.0 首次发布
就是 8.4 上 `X509_REQ_add_extensions` 的合并语义不同导致失败。

```bash
cd <tongsuo 源码目录>
git worktree add /tmp/tongsuo-8.4.0 8.4.0
cd /tmp/tongsuo-8.4.0
./config --prefix=/tmp/tongsuo-8.4.0-install --libdir=/tmp/tongsuo-8.4.0-install/lib \
         enable-ntls enable-trace no-shared
make -j"$(nproc)" && make install
```

然后切到 8.4 环境跑 `go build` / `go test` / `go test -tags tongsuocli`。
用完清理：`git worktree remove /tmp/tongsuo-8.4.0 --force && rm -rf /tmp/tongsuo-8.4.0-install`。

---

## 6. 用 act 本地复跑 CI

```bash
scripts/run-act.sh -j all        # lint + 本机可跑的 test 矩阵项
for f in .act-logs/*.rc; do echo "$f: $(cat "$f")"; done   # 全为 0
```

- act 只覆盖 `ci.yml` 的 `lint` / `test`，**不覆盖 `interop`** → 由 §5 的 `-tags tongsuocli` 补齐
- **代理坑**：容器内 git 没有宿主机 `~/.gitconfig` 的代理配置，clone 铜锁会
  `RPC failed; curl 56 Recv failure: Connection timed out`。`run-act.sh` 已透传
  `HTTP_PROXY/HTTPS_PROXY/http_proxy/https_proxy/NO_PROXY/GIT_CONFIG_*`，只需在调用前 export：

```bash
export HTTP_PROXY=http://<proxy>:7890 HTTPS_PROXY=$HTTP_PROXY NO_PROXY=localhost,127.0.0.1,::1
scripts/run-act.sh -j all
```

- 容器用 `--network=host`，宿主机能访问的代理地址容器内同样可访问
- `lint` 与 `test` 的铜锁缓存 key 大小写不同（`tongsuo-v3-Linux-…` vs `…-linux-…`），
  故 lint 可能 miss 而 test 命中；命中后不再 clone，也就不会再超时

---

## 7. 合并到 main

```bash
git switch main
git reset --hard origin/main          # 若本地 main 含未推送的旧 merge（重排后即孤儿）
git merge --no-ff dev -m "merge dev: <ver> 发布准备（要点）"
git rev-list --count main..dev        # 必须为 0
git diff --stat dev main              # 必须为空（树一致）
git push origin main
```

`main` 的历史全部是 `merge dev: ...` 形式的合并提交，**禁止 rebase 已发布历史**。

推送后等 CI：`lint` + `Test (ubuntu/macos × amd64/arm64)` + `Interop` 全绿。
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
| dev 历史需要重写 | 仅限**未发布**的 dev：`git push --force-with-lease origin dev`（需显式授权） |
| 本地 main 含未推送的旧 merge | `git reset --hard origin/main` 后再合并（重排后旧 merge 的提交已成孤儿） |

---

## 10. 已知既有问题（不阻塞发版，但不要误判为本次回归）

- `go test -race ./tls/` 约 1/3 概率在 `TestReadReturnsAfterCancel` 报数据竞争
  （`tls.Conn.Close` 与 `internal/core.(*SSLConn).Read` 之间）。
  CI 不跑 `-race`，普通 `go test` 稳定通过。属既有问题，需单独开 issue 处理。

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
