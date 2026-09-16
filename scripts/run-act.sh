#!/usr/bin/env bash
# scripts/run-act.sh — 在本地用 act 跑 GitHub Actions CI。
#
# 默认镜像 catthehacker/ubuntu:act-latest。
#
# 工作区语义（实测）：act 把仓库 `docker cp` 进一个**命名卷**
# （act-<workflow>-<job>-<runner>-<hash>），而**不是** bind mount；
# 且每次运行都会重建该卷（卷 CreatedAt == 本次启动时刻）。因此：
#   - 宿主仓库里**从不会**出现 .tongsuo-install/ 或 tongsuo/，仓库
#     保持干净；容器内的构建产物也不会跨运行保留
#   - Tongsuo 的复用完全由 actions/cache 负责（key 已含 matrix.arch，
#     按架构隔离）
# 这与 GitHub CI「每个 job 都是全新 runner」的语义一致。
#
# 用法：
#   scripts/run-act.sh                 # 默认：lint + ubuntu-latest/amd64（≈ 6 min）
#   scripts/run-act.sh -j lint         # 仅 lint（≈ 6 min，含 Tongsuo 编译）
#   scripts/run-act.sh -j test         # 本机可跑的 test 矩阵项
#                                      #  - linux host：amd64 + arm64 两路
#                                      #  - darwin host：amd64 + darwin 两路
#   scripts/run-act.sh -j all          # lint + 全部可跑 test 矩阵项
#   scripts/run-act.sh -j test --matrix os:ubuntu-latest,arch:amd64
#                                      # 显式只跑这一个矩阵项（覆盖 host 自省）
#
# 作用域：默认仅作用于 .github/workflows/ci.yml（通过 act --workflows 过滤）。
# release.yml 里有同名 `test` job（uses: ./ci.yml），不限定会触发 CI 内的
# lint 被本地重复执行，前缀出现 `[CI/CI/Lint ...]`。可设 ACT_WORKFLOW_FILE
# 显式覆盖；用 `ACT_WORKFLOW_FILE=`（空）取消过滤、跑仓库内全部 workflow。
#
# 跨 arch 容器：
#   当 ACT_MATRIX_ARCH 与 docker host arch 不同时（典型：x86_64 host 跑
#   arm64 矩阵项），脚本会自动启用 --container-architecture linux/arm64，
#   依赖 Docker server API ≥ 1.41。可用 --arch linux/<arch> 显式覆盖。
#
#   同时脚本会**按目标 arch 锁定镜像 digest**（见 resolve_image_for_arch
#   注释）：act 用 `docker image inspect <ref>` 的 Config.Env 里的 PATH 来
#   拼 `docker exec -e PATH=`，而多架构 tag 的 inspect 只返回宿主架构那层
#   变体，会把 x64 的 node 路径注入 arm64 容器，导致后续所有 exec 报
#   `exec: "node": executable file not found in $PATH`。锁 digest 后 inspect
#   返回目标 arch 变体，PATH 即正确。
#
# 输出：
#   .act-logs/act-<job>-<timestamp>.log 完整 act 日志
#   .act-logs/act-<job>-<timestamp>.rc   该 job 退出码（0 = 成功）
#
# 退出码：以最后一个 act job 的退出码为准。
#
# 已知限制：
#   - act 容器只能用 linux runner image（darwin job 在 linux host 上无法跑）
#   - macOS host 上 act 能跑 darwin matrix 项；linux host 上自动跳过
#   - arm64 linux 在 darwin host 上要 QEMU 跨 arch 模拟，CI 不跑这条
#   - 跨 arch 容器需 Docker server API ≥ 1.41（`docker version` 看 Server）
#   - CI 矩阵里的 ubuntu-24.04-arm 是 GH-hosted 自定义 runner，act 不内
#     置；脚本通过 `-P ubuntu-24.04-arm=<image>` 映射到 catthehacker 镜像
#     （含 go + node + 常见包），arch 由 --container-architecture 走 QEMU
#     跨架构
#   - 解析镜像 digest 需要访问 registry；无网络（如未设 HTTP_PROXY）时回落
#     到 tag 引用并给出告警，此时跨 arch 会出现 node 找不到的问题
#   - Tongsuo 编译产物无法在本地落盘缓存：act 每次运行都重建工作区卷
#     （见上方「工作区语义」），容器内的 tongsuo/ 与 .tongsuo-install/ 不
#     跨次保留；复用 Tongsuo 编译结果靠 actions/cache
#   - `test` job 依赖 `lint`，而 act 的 --container-architecture 是**全局**
#     生效、无法按 job 区分；故跑 arm64 矩阵项时 lint 也在 arm64 容器里跑。
#     lint 的 actions/cache key 在 ci.yml 里硬编码为 amd64，会命中 amd64 的
#     Tongsuo 缓存；`go vet` 只做前端编译/校验、不链接，因此不会失败
#   - act 0.2.x 用 --network=host 默认，能直接 clone Tongsuo；冷启动编译
#     大概 5m45s，热启动（命中本地 .tongsuo-install 复用）≈ 20s
#   - .github/workflows/ci.yml 的 lint job 也构建 Tongsuo（cache miss
#     时），与 test job 共享本地 .tongsuo-install/ 缓存
#
# 见 docs/architecture.md §6.2 与 AGENTS.md §2.1 关于环境变量的说明。

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

ACT_BIN="${ACT_BIN:-act}"
ACT_IMAGE="${ACT_IMAGE:-catthehacker/ubuntu:act-latest}"
ACT_LOGDIR="${ACT_LOGDIR:-$REPO_ROOT/.act-logs}"
ACT_SECRET_FILE="${ACT_SECRET_FILE:-$ACT_LOGDIR/.act-secrets.env}"
# 限定只跑 CI 工作流，避免 release.yml 里同名的 `test` job（uses: ./ci.yml）
# 再次触发 lint/test 导致本地 job 重复执行（详见 AGENTS.md / 注释）。
# 也可用 ACT_WORKFLOW_FILE 覆盖。
ACT_WORKFLOW_FILE="${ACT_WORKFLOW_FILE:-$REPO_ROOT/.github/workflows/ci.yml}"

# act 矩阵参数：默认只跑一个矩阵项保持快速
ACT_MATRIX_OS="${ACT_MATRIX_OS:-ubuntu-latest}"
ACT_MATRIX_ARCH="${ACT_MATRIX_ARCH:-amd64}"
# 如果通过环境变量显式传了矩阵项，标记为 explicit（`-j test` 时只跑这一项，
# 否则按 host 自省跑全部可跑项）。
[ -n "${ACT_MATRIX_OS_OVERRIDE:-}" ] && MATRIX_EXPLICIT=1
[ -n "${ACT_MATRIX_ARCH_OVERRIDE:-}" ] && MATRIX_EXPLICIT=1

JOB="lint"           # lint | test | all
VERBOSE=0
CONTAINER_ARCH=""    # 空=让 act/Docker 用默认（host arch）；显式设了 act --container-architecture 用之

usage() {
    sed -n '2,30p' "$0"
    exit "${1:-0}"
}

while [ $# -gt 0 ]; do
    case "$1" in
        -j|--job)        JOB="$2"; shift 2 ;;
        # 解析格式：os:<runner>,arch:<arch>（act --matrix 也要拆成两条 --matrix 传）
        --matrix)
            _kv="${2// /}"
            _os="${_kv%%,*}"
            _arch="${_kv##*,}"
            # 剥掉可能的 `os:` / `arch:` 前缀
            [ "${_os#os:}" != "$_os" ]   && _os="${_os#os:}"
            [ "${_arch#arch:}" != "$_arch" ] && _arch="${_arch#arch:}"
            ACT_MATRIX_OS="$_os"
            ACT_MATRIX_ARCH="$_arch"
            MATRIX_EXPLICIT=1
            shift 2
            ;;
        --image)         ACT_IMAGE="$2"; shift 2 ;;
        --arch)          CONTAINER_ARCH="$2"; shift 2 ;;   # 例如 linux/arm64
        # --keep-tongsuo：保留参数以兼容既有调用，当前已无效果。本地无工作
        # 区缓存可保（act 每次重建工作区卷）；Tongsuo 复用走 actions/cache。
        --keep-tongsuo)  echo "note: --keep-tongsuo 已无效果（act 每次重建工作区卷；Tongsuo 复用由 actions/cache 负责）" >&2; shift ;;
        -v|--verbose)    VERBOSE=1; shift ;;
        -h|--help)       usage 0 ;;
        *)               echo "unknown arg: $1" >&2; usage 1 ;;
    esac
done

mkdir -p "$ACT_LOGDIR"

# secrets：act checkout@v5 需要 GITHUB_TOKEN；本地无真实 token，dummy 已足够
cat > "$ACT_SECRET_FILE" <<EOF
GITHUB_TOKEN=dummy
GITHUB_REPOSITORY=$(git config --get remote.origin.url | sed -E 's#.*github.com[:/]([^/]+/[^/.]+)(\.git)?#\1#')
GITHUB_REF=refs/heads/$(git branch --show-current)
GITHUB_SHA=$(git rev-parse HEAD)
EOF

# Tongsuo 编译产物：act 每次运行都重建工作区卷（见文件头「工作区语义」），
# 容器内的 .tongsuo-install/ 与 tongsuo/ 不跨次保留，所以本地没有"二次缓存"
# 可用；Tongsuo 的复用完全由 actions/cache 负责（key 含 matrix.arch）。

# 校验前置条件
command -v "$ACT_BIN" >/dev/null 2>&1 || {
    echo "error: '$ACT_BIN' not in PATH；安装：https://nektosact.com/installation/" >&2
    exit 127
}
command -v docker >/dev/null 2>&1 || {
    echo "error: docker 不在 PATH；act 依赖 Docker daemon" >&2
    exit 127
}
docker info >/dev/null 2>&1 || {
    echo "error: docker daemon 不可达" >&2
    exit 127
}

# 预热 act 镜像（避免计时里算上 pull）
if ! docker image inspect "$ACT_IMAGE" >/dev/null 2>&1; then
    echo "==> 拉取 act 镜像 $ACT_IMAGE"
    docker pull "$ACT_IMAGE"
fi

# 当目标 arch 与 docker host arch 不同，需告诉 act 用 QEMU/cross-arch 启动容器。
# Docker server API ≥ 1.41 才支持；act 0.2.x 把这个标志透传给 `docker run --platform`。
# 主机 arch 取法：`docker info --format '{{.Architecture}}'`（不是 uname，避免误判 Apple silicon Rosetta）。
HOST_ARCH="$(docker info --format '{{.Architecture}}' 2>/dev/null || uname -m)"
case "$HOST_ARCH" in
    x86_64|amd64) HOST_ARCH=amd64 ;;
    aarch64|arm64) HOST_ARCH=arm64 ;;
esac
# 给定目标 arch，返回需要的 --container-architecture 值；空表示与 host 同
# arch（无需传）。被 run_act 及多矩阵循环复用。
compute_container_arch() {
    case "$1" in
        arm64) [ "$HOST_ARCH" = "arm64" ] || { echo "linux/arm64"; } ;;
        amd64) [ "$HOST_ARCH" = "amd64" ] || { echo "linux/amd64"; } ;;
    esac
}
# 全局 CONTAINER_ARCH：lint 与单矩阵 --matrix 走 ACT_MATRIX_ARCH；
# 多矩阵（-j test / -j all）由各循环按迭代目标 arch 重新计算，通过
# ACT_CONTAINER_ARCH 临时覆盖，传给 run_act。
if [ -z "$CONTAINER_ARCH" ]; then
    CONTAINER_ARCH="$(compute_container_arch "$ACT_MATRIX_ARCH")"
    [ -n "$CONTAINER_ARCH" ] && \
        echo "[cross-arch] 默认 ACT_MATRIX_ARCH=$ACT_MATRIX_ARCH 但 docker host=$HOST_ARCH；启用 --container-architecture $CONTAINER_ARCH"
fi

ACT_COMMON_ARGS=(
    --action-offline-mode
    --secret-file "$ACT_SECRET_FILE"
)

# resolve_image_for_arch <image> <amd64|arm64> —— 解析该镜像在目标 arch 下的
# digest 引用（形如 <image>@sha256:...）；解析失败输出空串。
#
# 为什么必须锁 digest：`docker image inspect <tag>` 对多架构 tag 只会返回
# **宿主默认架构**那层变体的镜像 Config（本机 amd64 host 上永远拿到 amd64
# 变体）。act 正是用 image inspect 的 Config.Env 里的 PATH 去拼它给
# `docker exec` 传的 `-e PATH=`；跨 arch 时就会把宿主架构的 node 路径
# （/opt/acttoolcache/node/<ver>/x64/bin）注入 arm64 容器，而该路径在 arm64
# 变体镜像里并不存在（arm64 变体只有 .../arm64/bin），于是 act 后续所有
# `docker exec <裸 node>` 都失败：
#     exec: "node": executable file not found in $PATH
# 换成按 arch 锁定的 digest 引用后，image inspect 返回目标 arch 变体，PATH
# 随之与容器一致。
resolve_image_for_arch() {
    local image="$1" want="$2" ref="" key="" cache_file=""
    # 解析结果落盘缓存：registry 查询慢且依赖网络；已解析过且本地仍有该
    # 镜像时直接复用，使后续运行（含无网络场景）不必再查 registry。
    key="$(printf '%s' "$image" | tr '/:@' '___')"
    cache_file="$ACT_LOGDIR/.image-digest-${key}-${want}"
    if [ -f "$cache_file" ]; then
        ref="$(cat "$cache_file" 2>/dev/null || true)"
        if [ -n "$ref" ] && docker image inspect "$ref" >/dev/null 2>&1; then
            printf '%s\n' "$ref"
            return 0
        fi
        ref=""
    fi

    ref="$(docker buildx imagetools inspect "$image" 2>/dev/null | awk -v want="$want" '
        /^  Name:/     { name = $2 }
        /^  Platform:/ { if (index($2, "linux/" want) == 1) { print name; exit } }
    ')"
    if [ -n "$ref" ]; then
        printf '%s\n' "$ref" > "$cache_file" 2>/dev/null || true
        printf '%s\n' "$ref"
    fi
    return 0
}

# image_for_arch <amd64|arm64> —— 返回该 arch 下应使用的 runner 镜像引用。
# 与宿主同架构时直接用 tag（省一次 registry 请求）；跨架构时锁 digest。
# 结果按 arch 缓存，避免重复解析。
IMAGE_FOR_AMD64=""
IMAGE_FOR_ARM64=""
image_for_arch() {
    local arch="$1" cached="" img=""
    case "$arch" in
        amd64) cached="$IMAGE_FOR_AMD64" ;;
        arm64) cached="$IMAGE_FOR_ARM64" ;;
    esac
    if [ -n "$cached" ]; then
        printf '%s\n' "$cached"
        return 0
    fi

    img="$ACT_IMAGE"
    if [ "$arch" != "$HOST_ARCH" ]; then
        local pinned
        pinned="$(resolve_image_for_arch "$ACT_IMAGE" "$arch")"
        if [ -n "$pinned" ]; then
            img="$pinned"
        else
            echo "warning: 无法解析 $ACT_IMAGE 在 $arch 下的 digest（registry 不可达？）" >&2
            echo "         回落到 tag 引用；跨架构时可能出现 exec: \"node\": executable file not found" >&2
        fi
    fi

    case "$arch" in
        amd64) IMAGE_FOR_AMD64="$img" ;;
        arm64) IMAGE_FOR_ARM64="$img" ;;
    esac
    printf '%s\n' "$img"
}

# select_runner_images <amd64|arm64> —— 按目标 arch 刷新全局
# ACT_PLATFORM_ARGS，把 CI 矩阵里的 runner 名映射到对应架构的镜像。
#
# act 内置只有 ubuntu-latest / ubuntu-22.04 / ubuntu-20.04 等标准 runner
# image；CI 的 ubuntu-24.04-arm 是 GH-hosted 自定义 runner，act 不认，
# 统一映射到 catthehacker 镜像（含 go + node + 常见包）。
declare -a ACT_PLATFORM_ARGS=()
select_runner_images() {
    local arch="$1" img
    img="$(image_for_arch "$arch")"
    ACT_PLATFORM_ARGS=()
    for _runner in ubuntu-latest ubuntu-24.04-arm; do
        ACT_PLATFORM_ARGS+=(-P "$_runner=$img")
    done
    # macos-* 在 linux host 上跑不到，留作 darwin host 自省时附加（暂不预设）
}

# 把 act 进度也实时打到 stderr，便于交互式观察
run_act() {
    local job="$1"; shift
    local ts; ts="$(date +%Y%m%d-%H%M%S)"
    local logfile="$ACT_LOGDIR/act-${job}-${ts}.log"
    local rcfile="$ACT_LOGDIR/act-${job}-${ts}.rc"
    echo "================================================================"
    echo "  job: $job"
    echo "  log: $logfile"
    echo "================================================================"

    # shellcheck disable=SC2086
    set +e
    # 把 --container-architecture 放在 ACT_COMMON_ARGS 之前，便于覆盖；非空才传
    # 容器 env 透传：act 默认只透传它"认识"的少数变量；用户变量(HTTP_PROXY 等)
    # 必须通过 --container-options 强行 -e 注入
    declare -a ACT_ENV_ARGS=()
    for _v in HTTP_PROXY HTTPS_PROXY http_proxy https_proxy NO_PROXY no_proxy \
             GIT_CONFIG_COUNT GIT_CONFIG_KEY_0 GIT_CONFIG_VALUE_0; do
        if [ -n "${!_v:-}" ]; then
            ACT_ENV_ARGS+=(--env "$_v=${!_v}")
        fi
    done
    # 多矩阵循环（-j test / -j all 不带 --matrix）会按迭代目标 arch 重算
    # ACT_CONTAINER_ARCH；其他场景（lint、单矩阵 --matrix）回落到全局 CONTAINER_ARCH。
    local _ca="${ACT_CONTAINER_ARCH:-$CONTAINER_ARCH}"
    if [ -n "$_ca" ]; then
        "$ACT_BIN" -j "$job" --container-architecture "$_ca" \
            --workflows "$ACT_WORKFLOW_FILE" \
            "${ACT_COMMON_ARGS[@]}" "${ACT_PLATFORM_ARGS[@]}" \
            "${ACT_ENV_ARGS[@]}" "$@" 2>&1 | tee "$logfile"
    else
        "$ACT_BIN" -j "$job" --workflows "$ACT_WORKFLOW_FILE" \
            "${ACT_COMMON_ARGS[@]}" "${ACT_PLATFORM_ARGS[@]}" \
            "${ACT_ENV_ARGS[@]}" "$@" 2>&1 | tee "$logfile"
    fi
    local rc="${PIPESTATUS[0]}"
    set -e
    echo "$rc" > "$rcfile"

    if [ "$rc" -eq 0 ]; then
        echo "[OK] $job succeeded ($(wc -l <"$logfile") lines)"
    else
        echo "[FAIL] $job exit=$rc；关键错误："
        grep -nE 'SIGSEGV|signal arrived|fatal error|panic:|FAIL: |--- FAIL|Process completed with exit code [0-9]+|Cannot|::error::' "$logfile" | head -20 || true
        echo "完整日志：$logfile"
    fi
    return "$rc"
}

# run_matrix_item <os> <arch> —— 跑一个 test 矩阵项。
#
# 一次矩阵项需要成套地准备两件事，缺一不可：
#   1. --container-architecture：目标 arch 与宿主不同时启用 QEMU 跨架构
#   2. runner 镜像：锁目标 arch 的 digest（否则 act 注入错误架构的 PATH）
# 构建目录无需干预：act 每次运行都会重建工作区卷（见文件头「工作区语义」）。
run_matrix_item() {
    local os="$1" arch="$2" rc=0
    ACT_CONTAINER_ARCH="$(compute_container_arch "$arch")"
    if [ -n "$ACT_CONTAINER_ARCH" ]; then
        echo "[cross-arch] matrix $os/$arch：启用 --container-architecture $ACT_CONTAINER_ARCH"
    fi
    select_runner_images "$arch"

    set +e
    run_act test --matrix "os:$os" --matrix "arch:$arch"
    rc=$?
    set -e

    return "$rc"
}

# 收尾：汇总 + 用最后一个 job 的退出码作为脚本退出码
declare -a RESULTS=()
overall_rc=0

case "$JOB" in
    lint)
        # lint 在 CI 里固定跑 ubuntu-latest（amd64），按 ACT_MATRIX_ARCH 选镜像。
        select_runner_images "$ACT_MATRIX_ARCH"
        run_act lint && RESULTS+=("lint:OK") || { RESULTS+=("lint:FAIL($?)"); overall_rc=1; }
        ;;
    test)
        # 如果用户在命令行显式传了 --matrix，就只跑那一项；否则按 host
        # 自省取可在本机跑的全部矩阵项（与 `-j all` 的逻辑同源，但只跑 test）。
        # act 0.2.x 的 --matrix 必须每个轴单独传（不支持逗号分隔），否则
        # 矩阵为空 job 不跑。
        if [ "${MATRIX_EXPLICIT:-0}" -eq 1 ]; then
            run_matrix_item "$ACT_MATRIX_OS" "$ACT_MATRIX_ARCH" \
                && RESULTS+=("test($ACT_MATRIX_OS/$ACT_MATRIX_ARCH):OK") \
                || { RESULTS+=("test($ACT_MATRIX_OS/$ACT_MATRIX_ARCH):FAIL($?)"); overall_rc=1; }
        else
            # 与 `-j all` 的 host 自省逻辑对齐
            HOST_OS="$(uname -s)"
            case "$HOST_OS" in
                Linux)
                    MATRIX=(ubuntu-latest:amd64 ubuntu-24.04-arm:arm64)
                    echo "[host=Linux] test 跑 linux 两路；darwin 两路需 macOS runner"
                    ;;
                Darwin)
                    MATRIX=(ubuntu-latest:amd64 macos-15-intel:amd64 macos-latest:arm64)
                    echo "[host=Darwin] test 跑 ubuntu/amd64 + darwin 两路"
                    ;;
                *)
                    MATRIX=()
                    echo "[host=$HOST_OS] act 0.2.x 不支持此 host"
                    ;;
            esac
            for combo in "${MATRIX[@]}"; do
                os="${combo%%:*}"; arch="${combo##*:}"
                run_matrix_item "$os" "$arch" \
                    && RESULTS+=("test($os/$arch):OK") \
                    || { RESULTS+=("test($os/$arch):FAIL($?)"); overall_rc=1; }
            done
        fi
        ;;
    all)
        run_act lint \
            && RESULTS+=("lint:OK") \
            || { RESULTS+=("lint:FAIL($?)"); overall_rc=1; }

        # host 自省：决定可跑的 matrix 项目
        #   - linux host：act 容器只能用 linux runner image；arm64 走 cross-arch
        #     （Docker server 需 API ≥ 1.41；见 act --container-architecture 说明）
        #   - darwin host：act 能拉 macos-* image 模拟 GitHub-hosted macOS runner
        #   - 其他 host：windows / freebsd 等——act 0.2.x 仅支持 linux/darwin
        HOST_OS="$(uname -s)"
        case "$HOST_OS" in
            Linux)
                MATRIX=(ubuntu-latest:amd64 ubuntu-24.04-arm:arm64)
                SKIPPED="test(macos-15-intel/amd64) test(macos-latest/arm64)"
                echo "[host=Linux] 跑 linux 两路；跳过 $SKIPPED"
                echo "        要跑 darwin 两路请在 macOS 机器上执行本脚本"
                ;;
            Darwin)
                MATRIX=(ubuntu-latest:amd64 macos-15-intel:amd64 macos-latest:arm64)
                # arm64 linux 在 darwin host 上需要 QEMU 跨 arch 模拟，CI 不跑这条
                SKIPPED="test(ubuntu-24.04-arm/arm64)"
                echo "[host=Darwin] 跑 ubuntu/amd64 + darwin 两路；跳过 $SKIPPED"
                ;;
            *)
                MATRIX=()
                SKIPPED="全部 4 路"
                echo "[host=$HOST_OS] act 0.2.x 不支持此 host；$SKIPPED 都被跳过"
                ;;
        esac

        for combo in "${MATRIX[@]}"; do
            os="${combo%%:*}"; arch="${combo##*:}"
            run_matrix_item "$os" "$arch" \
                && RESULTS+=("test($os/$arch):OK") \
                || { RESULTS+=("test($os/$arch):FAIL($?)"); overall_rc=1; }
        done
        [ -n "$SKIPPED" ] && echo "[skip] $SKIPPED — 此 host 无法跑"
        ;;
    *)
        echo "unknown job '$JOB'；可选：lint | test | all" >&2
        exit 2
        ;;
esac

echo
echo "=== 汇总 ==="
printf '  %s\n' "${RESULTS[@]}"
echo "  日志目录：$ACT_LOGDIR"
echo "  本地 .tongsuo-install/：$([ -d "$REPO_ROOT/.tongsuo-install" ] && echo present || echo absent)"
exit "$overall_rc"