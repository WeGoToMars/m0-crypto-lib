#!/bin/sh
# Build the release library for one profile with the pinned toolchain.
#
# Usage: tools/build_lib.sh speed
#   PROFILE  speed       (the only profile in v0.1)
#            protection  refused: not implemented in this release
#
# Output in build/lib/<profile>/:
#   m0crypto.o       the release unit src/m0crypto.S, relocation-free
#   libm0crypto.a    deterministic archive of m0crypto.o
#   text.bin         the .text bytes (the verified artifact)
#   MANIFEST.txt     profile, toolchain, sha256 of every output and of .text
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
PROFILE=${1:-}
case "$PROFILE" in
    speed) ;;
    protection)
        echo "build_lib: the protection profile is not implemented in this release." >&2
        echo "build_lib: select 'speed' explicitly; it makes no power-analysis or fault claims." >&2
        exit 2 ;;
    *) echo "usage: tools/build_lib.sh speed" >&2; exit 2 ;;
esac

LLVM_BIN=${LLVM_BIN:-/opt/homebrew/opt/llvm/bin}
EXPECT_CLANG=$(sed -n 's/^clang=//p' "$ROOT/tools/versions.txt")
GOT_CLANG=$("$LLVM_BIN/clang" --version | sed -n '1s/.*clang version \([0-9.]*\).*/\1/p')
if [ "$GOT_CLANG" != "$EXPECT_CLANG" ]; then
    echo "toolchain mismatch: clang $GOT_CLANG (want $EXPECT_CLANG)" >&2
    exit 1
fi

OUT="$ROOT/build/lib/$PROFILE"
rm -rf "$OUT"
mkdir -p "$OUT"
"$LLVM_BIN/clang" --target=thumbv6m-none-eabi -mcpu=cortex-m0plus -mthumb \
    -Wall -Werror -ffile-prefix-map="$ROOT"=. -I "$ROOT/src" \
    -c "$ROOT/src/m0crypto.S" -o "$OUT/m0crypto.o"
"$LLVM_BIN/llvm-ar" rcsD "$OUT/libm0crypto.a" "$OUT/m0crypto.o"
"$LLVM_BIN/llvm-objcopy" -O binary --only-section=.text "$OUT/m0crypto.o" "$OUT/text.bin"

# The release unit must be relocation-free, so its .text is the same at any
# 4-byte-aligned link address.
if "$LLVM_BIN/llvm-readelf" -S "$OUT/m0crypto.o" | grep -q ' \.rel'; then
    echo "build_lib: object has relocations" >&2; exit 1
fi

sha() { shasum -a 256 "$1" | cut -d' ' -f1; }
{
    echo "m0-crypto library build"
    echo "profile=$PROFILE"
    echo "source=src/m0crypto.S"
    echo "clang=$GOT_CLANG"
    echo "target=thumbv6m-none-eabi cortex-m0plus"
    echo "text_bytes=$(wc -c < "$OUT/text.bin" | tr -d ' ')"
    echo "text_sha256=$(sha "$OUT/text.bin")"
    echo "object_sha256=$(sha "$OUT/m0crypto.o")"
    echo "archive_sha256=$(sha "$OUT/libm0crypto.a")"
    echo "symbols:"
    "$LLVM_BIN/llvm-nm" --defined-only -S "$OUT/m0crypto.o" | grep ' T ' | sed 's/^/  /'
} > "$OUT/MANIFEST.txt"
cat "$OUT/MANIFEST.txt"
