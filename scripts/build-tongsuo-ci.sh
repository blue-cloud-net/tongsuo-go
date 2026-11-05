#!/usr/bin/env bash
# Build a fixed Tongsuo release for CI; installation stays outside tracked source.
set -euo pipefail
: "${TONGSUO_REF:?set a fixed release tag}"
: "${TONGSUO_HOME:?set the installation directory}"
TONGSUO_REPO=${TONGSUO_REPO:-Tongsuo-Project/Tongsuo}
case "$TONGSUO_REF" in 8.4.0|8.5.0) ;; *) echo "Unsupported CI release: $TONGSUO_REF" >&2; exit 1;; esac
build_root=$(mktemp -d)
trap 'rm -rf "$build_root"' EXIT
git clone --depth 1 --branch "$TONGSUO_REF" "https://github.com/${TONGSUO_REPO}.git" "$build_root/src"
cd "$build_root/src"
# A shared build also produces .a archives for the Linux static-tag checks.
./config --prefix="$TONGSUO_HOME" --libdir="$TONGSUO_HOME/lib" enable-ntls enable-trace shared
jobs=${TONGSUO_BUILD_JOBS:-$(getconf _NPROCESSORS_ONLN)}
make -j"$jobs"
make install
"$TONGSUO_HOME/bin/openssl" version -a
