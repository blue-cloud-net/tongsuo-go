#!/usr/bin/env bash
# Local CI: both fixed Tongsuo versions on Linux amd64/arm64.
# Usage: scripts/run-act.sh [-j all|test|lint|interop] [--matrix os:ubuntu-latest,arch:amd64]
# lint/interop are compatibility aliases: each test job now includes these checks.
# macOS needs a real GitHub runner; Linux containers cannot validate macOS.
set -euo pipefail
REPO_ROOT=$(git rev-parse --show-toplevel)
cd "$REPO_ROOT"
ACT_BIN=${ACT_BIN:-act}
ACT_IMAGE=${ACT_IMAGE:-catthehacker/ubuntu:act-latest}
ACT_LOGDIR=${ACT_LOGDIR:-$REPO_ROOT/.act-logs}
ACT_WORKFLOW_FILE=${ACT_WORKFLOW_FILE:-$REPO_ROOT/.github/workflows/ci.yml}
ACT_SECRET_FILE=${ACT_SECRET_FILE:-$ACT_LOGDIR/.act-secrets.env}
JOB=all
MATRIX_EXPLICIT=0
ACT_MATRIX_OS=ubuntu-latest
ACT_MATRIX_ARCH=amd64
CONTAINER_ARCH=""
VERBOSE=0
while [ $# -gt 0 ]; do
 case "$1" in
  -j|--job) JOB=$2; shift 2 ;;
  --matrix)
   pair=${2// /}; ACT_MATRIX_OS=${pair%%,*}; ACT_MATRIX_OS=${ACT_MATRIX_OS#os:}
   ACT_MATRIX_ARCH=${pair##*,}; ACT_MATRIX_ARCH=${ACT_MATRIX_ARCH#arch:}
   MATRIX_EXPLICIT=1; shift 2 ;;
  --image) ACT_IMAGE=$2; shift 2 ;;
  --arch) CONTAINER_ARCH=$2; shift 2 ;;
  -v|--verbose) VERBOSE=1; shift ;;
  --keep-tongsuo) shift ;;
  -h|--help) sed -n '2,5p' "$0"; exit 0 ;;
  *) echo "Unknown argument: $1" >&2; exit 2 ;;
 esac
done
case "$JOB" in all|test|lint|interop) ;; *) echo "Unknown job: $JOB" >&2; exit 2;; esac
mkdir -p "$ACT_LOGDIR"
# A dummy token is sufficient for local checkout; do not read personal tokens.
printf 'GITHUB_TOKEN=dummy\n' > "$ACT_SECRET_FILE"
command -v "$ACT_BIN" >/dev/null
command -v docker >/dev/null
docker info >/dev/null
HOST_ARCH=$(docker info --format '{{.Architecture}}')
case "$HOST_ARCH" in x86_64|amd64) HOST_ARCH=amd64;; aarch64|arm64) HOST_ARCH=arm64;; *) exit 2;; esac
if ! docker image inspect "$ACT_IMAGE" >/dev/null 2>&1; then docker pull "$ACT_IMAGE"; fi
compute_container_arch() {
 if [ "$1" != "$HOST_ARCH" ]; then printf 'linux/%s\n' "$1"; fi
}
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


run_matrix_item() {
 local os=$1 arch=$2 ts logfile rcfile rc=0
 local ca=${CONTAINER_ARCH:-$(compute_container_arch "$arch")}
 case "$os/$arch" in ubuntu-latest/amd64|ubuntu-24.04-arm/arm64) ;; *) echo "Unsupported local matrix: $os/$arch" >&2; return 2;; esac
 select_runner_images "$arch"
 ts=$(date +%Y%m%d-%H%M%S)
 logfile="$ACT_LOGDIR/act-test-${arch}-${ts}.log"
 rcfile="$ACT_LOGDIR/act-test-${arch}-${ts}.rc"
 local -a args=(push -j test --workflows "$ACT_WORKFLOW_FILE" --action-offline-mode --pull=false --secret-file "$ACT_SECRET_FILE" --matrix "os:$os" --matrix "arch:$arch")
 args+=(--env "TONGSUO_BUILD_JOBS=${TONGSUO_BUILD_JOBS:-8}")
 for key in HTTP_PROXY HTTPS_PROXY http_proxy https_proxy NO_PROXY no_proxy GIT_CONFIG_COUNT GIT_CONFIG_KEY_0 GIT_CONFIG_VALUE_0; do
  if [ -n "${!key:-}" ]; then args+=(--env "$key=${!key}"); fi
 done
 [ -z "$ca" ] || args+=(--container-architecture "$ca")
 [ "$VERBOSE" -eq 0 ] || args+=(-v)
 echo "Running Linux $arch, Tongsuo 8.4.0 and 8.5.0; log: $logfile"
 "$ACT_BIN" "${args[@]}" "${ACT_PLATFORM_ARGS[@]}" 2>&1 | tee "$logfile" || rc=${PIPESTATUS[0]}
 printf '%s\n' "$rc" > "$rcfile"
 return "$rc"
}
status=0
if [ "$MATRIX_EXPLICIT" -eq 1 ]; then
 run_matrix_item "$ACT_MATRIX_OS" "$ACT_MATRIX_ARCH" || status=1
else
 run_matrix_item ubuntu-latest amd64 || status=1
 run_matrix_item ubuntu-24.04-arm arm64 || status=1
fi
echo 'macOS amd64/arm64 remain for real GitHub runners.'
exit "$status"
