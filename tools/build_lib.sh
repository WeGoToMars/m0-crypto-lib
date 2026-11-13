#!/bin/sh
# Build the release assets with the pinned toolchain. Each primitive is its own
# independently released asset: one relocation-free unit, verified on its own.
#
# Usage: tools/build_lib.sh [ASSET...]     (default: all assets)
#   ASSET is one of: chacha20poly1305 blake2s x25519
#
# Output in build/lib/ASSET/:
#   m0crypto_ASSET.o       the release unit src/m0crypto_ASSET.S, relocation-free
#   libm0crypto_ASSET.a    deterministic archive of m0crypto_ASSET.o
#   text.bin               the .text bytes (the verified artifact)
#   MANIFEST.txt           toolchain, sha256 of every output and of .text
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
ALL_ASSETS="chacha20poly1305 blake2s x25519"
ASSETS=${*:-$ALL_ASSETS}
for a in $ASSETS; do
    case " $ALL_ASSETS " in
        *" $a "*) ;;
        *) echo "usage: tools/build_lib.sh [$ALL_ASSETS]" >&2; exit 2 ;;
    esac
done

EXPECT_CLANG=$(sed -n 's/^clang=//p' "$ROOT/tools/versions.txt")
GOT_CLANG=$(clang --version | sed -n '1s/.*clang version \([0-9.]*\).*/\1/p')
if [ "$GOT_CLANG" != "$EXPECT_CLANG" ]; then
    echo "toolchain mismatch: clang $GOT_CLANG (want $EXPECT_CLANG)" >&2
    exit 1
fi

sha() { shasum -a 256 "$1" | cut -d' ' -f1; }
for a in $ASSETS; do
    OUT="$ROOT/build/lib/$a"
    U="m0crypto_$a"
    rm -rf "$OUT"
    mkdir -p "$OUT"
    clang --target=thumbv6m-none-eabi -mcpu=cortex-m0plus -mthumb \
        -Wall -Werror -ffile-prefix-map="$ROOT"=. -I "$ROOT/src" \
        -c "$ROOT/src/$U.S" -o "$OUT/$U.o"
    llvm-ar rcsD "$OUT/lib$U.a" "$OUT/$U.o"
    llvm-objcopy -O binary --only-section=.text "$OUT/$U.o" "$OUT/text.bin"

    # A release unit must be relocation-free, so its .text is the same at any
    # 4-byte-aligned link address.
    if llvm-readelf -S "$OUT/$U.o" | grep -q ' \.rel'; then
        echo "build_lib: $U.o has relocations" >&2; exit 1
    fi

    {
        echo "m0-crypto release asset $a"
        echo "source=src/$U.S"
        echo "clang=$GOT_CLANG"
        echo "target=thumbv6m-none-eabi cortex-m0plus"
        echo "text_bytes=$(wc -c < "$OUT/text.bin" | tr -d ' ')"
        echo "text_sha256=$(sha "$OUT/text.bin")"
        echo "object_sha256=$(sha "$OUT/$U.o")"
        echo "archive_sha256=$(sha "$OUT/lib$U.a")"
        echo "symbols:"
        llvm-nm --defined-only -S "$OUT/$U.o" | grep ' T ' | sed 's/^/  /'
    } > "$OUT/MANIFEST.txt"
    cat "$OUT/MANIFEST.txt"
done
