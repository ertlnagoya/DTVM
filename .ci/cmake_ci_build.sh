#!/bin/bash

set -euo pipefail

if [ "$#" -lt 1 ]; then
    echo "usage: $0 <build-dir> [--] [cmake configure args...]" >&2
    exit 2
fi

BUILD_DIR=$1
shift

if [ "${1:-}" = "--" ]; then
    shift
fi

SOURCE_DIR=${DTVM_CI_SOURCE_DIR:-.}
USE_NINJA=${DTVM_CI_USE_NINJA:-0}
USE_SCCACHE=${DTVM_CI_USE_SCCACHE:-0}
DRY_RUN=${DTVM_CI_DRY_RUN:-0}
BUILD_JOBS=${DTVM_CI_BUILD_JOBS:-16}

GENERATOR_ARGS=()
GENERATOR_NAME=default
if [ "$USE_NINJA" = "1" ]; then
    GENERATOR_ARGS=(-G Ninja)
    GENERATOR_NAME=Ninja
fi

LAUNCHER_ARGS=()
LAUNCHER_NAME=none
if [ "$USE_SCCACHE" = "1" ]; then
    LAUNCHER_ARGS=(
        -DCMAKE_C_COMPILER_LAUNCHER=sccache
        -DCMAKE_CXX_COMPILER_LAUNCHER=sccache
    )
    LAUNCHER_NAME=sccache
fi

CONFIGURE_CMD=(
    cmake
    -S "$SOURCE_DIR"
    -B "$BUILD_DIR"
    "${GENERATOR_ARGS[@]}"
    "${LAUNCHER_ARGS[@]}"
    "$@"
)
BUILD_CMD=(cmake --build "$BUILD_DIR" -j "$BUILD_JOBS")

echo "DTVM CI CMake source dir: ${SOURCE_DIR}"
echo "DTVM CI CMake generator: ${GENERATOR_NAME}"
echo "DTVM CI CMake compiler launcher: ${LAUNCHER_NAME}"

printf '+'
printf ' %q' "${CONFIGURE_CMD[@]}"
printf '\n'

if [ "$DRY_RUN" = "1" ]; then
    printf '+'
    printf ' %q' "${BUILD_CMD[@]}"
    printf '\n'
    exit 0
fi

if [ "$USE_SCCACHE" = "1" ] && ! command -v sccache >/dev/null 2>&1; then
    echo "DTVM_CI_USE_SCCACHE=1 but sccache is not in PATH" >&2
    exit 1
fi

"${CONFIGURE_CMD[@]}"

printf '+'
printf ' %q' "${BUILD_CMD[@]}"
printf '\n'
"${BUILD_CMD[@]}"
