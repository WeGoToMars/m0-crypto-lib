#!/bin/sh
# Build a board image of one released asset.
#   bench/board/build.sh blake2s|x25519 flash|sram
# Output: build/board/ASSET-PLACEMENT/{bench.elf,bench.bin,bench.map,text.bin,IMAGE.txt}.
# The image links the unmodified release object build/lib/ASSET/m0crypto_ASSET.o (from
# tools/build_lib.sh); IMAGE.txt records that the object's .text bytes (sha256 against
# MANIFEST.txt) are present in bench.bin exactly once, and at which flash/SRAM-load offset.
set -eu
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
ASSET=${1:?asset: blake2s or x25519}
PLACE=${2:?placement: flash or sram}
case "$ASSET" in blake2s|x25519) ;; *) echo "unknown asset" >&2; exit 2 ;; esac
case "$PLACE" in flash|sram) ;; *) echo "unknown placement" >&2; exit 2 ;; esac
B=$ROOT/bench/board
FW=$B/firmware
OUT=$ROOT/build/board/$ASSET-$PLACE
"$ROOT/tools/build_lib.sh" "$ASSET" >/dev/null
LIB=$ROOT/build/lib/$ASSET
rm -rf "$OUT"; mkdir -p "$OUT"
BASE="--target=thumbv6m-none-eabi -mcpu=cortex-m0plus -mthumb -fno-unwind-tables -fno-asynchronous-unwind-tables -ffunction-sections -fdata-sections"
FLAGS="$BASE -O2 -ffreestanding -fno-builtin -Wall -Wextra -Werror"
CC=clang
"$CC" $FLAGS -I "$ROOT/include" -I "$B" -c "$B/$ASSET.c" -o "$OUT/main.o"
"$CC" $FLAGS -I "$B" -c "$B/common.c" -o "$OUT/common.o"
"$CC" $FLAGS -c "$FW/bench_uart.c" -o "$OUT/uart.o"
"$CC" $FLAGS -c "$FW/bench_libc.c" -o "$OUT/libc.o"
"$CC" $BASE -c "$FW/support.S" -o "$OUT/support.o"
"$CC" $BASE -DUART_OUT -c "$ROOT/tests/startup.S" -o "$OUT/startup.o"
case "$PLACE" in flash) SECT=$FW/sections-flash.ld ;; sram) SECT=$FW/sections-sram.ld ;; esac
cat "$FW/memory-mspm0l2228-ectf.ld" "$SECT" > "$OUT/link.ld"
ld.lld -T "$OUT/link.ld" --gc-sections --build-id=none -Map "$OUT/bench.map" \
    -o "$OUT/bench.elf" "$OUT/startup.o" "$OUT/main.o" "$OUT/common.o" "$OUT/support.o" \
    "$OUT/libc.o" "$OUT/uart.o" "$LIB/m0crypto_$ASSET.o"
llvm-objcopy -O binary "$OUT/bench.elf" "$OUT/bench.bin"
cp "$LIB/text.bin" "$OUT/text.bin"
llvm-size "$OUT/bench.elf" > "$OUT/size.txt"
llvm-nm -S -n "$OUT/bench.elf" > "$OUT/symbols.txt"
python3 -I - "$OUT" "$LIB" "$ASSET" "$PLACE" <<'PY'
import hashlib, sys
out, lib, asset, place = sys.argv[1:]
img = open(f"{out}/bench.bin", "rb").read()
text = open(f"{lib}/text.bin", "rb").read()
n = img.count(text)
assert n == 1, f"library .text found {n} times in bench.bin"
off = img.index(text)
manifest = dict(l.split("=", 1) for l in open(f"{lib}/MANIFEST.txt") if "=" in l)
sha = hashlib.sha256(text).hexdigest()
assert sha == manifest["text_sha256"].strip(), "text.bin differs from the build manifest"
print(f"asset={asset} placement={place}")
print(f"library_text_bytes={len(text)}")
print(f"library_text_sha256={sha}")
print(f"image_bin_bytes={len(img)}")
print(f"image_bin_sha256={hashlib.sha256(img).hexdigest()}")
print(f"library_text_offset_in_bin=0x{off:x} (image base 0x6000; flash address 0x{0x6000+off:x} "
      f"for flash placement, load address for sram placement)")
PY
