#!/bin/sh
# Build the board comparison image of one primitive.
#   bench/board/build_compare.sh chacha20poly1305|blake2s|x25519
# Output: build/board/compare-PRIMITIVE/{bench.elf,bench.bin,bench.map,cases.h,IMAGE.txt}.
# The image links the object files bench/build.py compiles for the emulator comparison
# (build/bench/PRIMITIVE/, BENCH_OPT as there, default -Os) and the release object, with
# the board start-up, UART and timing code; bench/build.py's runtime.c replaces
# firmware/bench_libc.c. Code executes from flash. IMAGE.txt records the sha256 of
# every linked object and of the emulator ELF built from the same objects.
set -eu
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
P=${1:?primitive: chacha20poly1305, blake2s or x25519}
case "$P" in chacha20poly1305|blake2s|x25519) ;; *) echo "unknown primitive" >&2; exit 2 ;; esac
B=$ROOT/bench/board
FW=$B/firmware
EMU=$ROOT/build/bench/$P
OUT=$ROOT/build/board/compare-$P
python3 -I "$ROOT/bench/build.py" "$P" >/dev/null
rm -rf "$OUT"; mkdir -p "$OUT"
python3 -I "$B/gen_compare.py" "$P" "$OUT/cases.h"
BASE="--target=thumbv6m-none-eabi -mcpu=cortex-m0plus -mthumb -fno-unwind-tables -fno-asynchronous-unwind-tables -ffunction-sections -fdata-sections"
FLAGS="$BASE -O2 -ffreestanding -fno-builtin -Wall -Wextra -Werror"
clang $FLAGS -I "$ROOT/bench" -I "$B" -I "$OUT" -c "$B/compare.c" -o "$OUT/main.o"
clang $FLAGS -I "$B" -c "$B/common.c" -o "$OUT/common.o"
clang $FLAGS -c "$FW/bench_uart.c" -o "$OUT/uart.o"
clang $BASE -c "$FW/support.S" -o "$OUT/support.o"
clang $BASE -DUART_OUT -c "$ROOT/tests/startup.S" -o "$OUT/startup.o"
cat "$FW/memory-mspm0l2228-ectf.ld" "$FW/sections-flash.ld" > "$OUT/link.ld"
LIB=$ROOT/build/lib/$P/m0crypto_$P.o
# The emulator image's objects: build.py numbers them 0-..., N-...
OBJS=$(ls "$EMU"/[0-9]*-*.o)
ld.lld -T "$OUT/link.ld" --gc-sections --build-id=none -Map "$OUT/bench.map" \
    -o "$OUT/bench.elf" "$OUT/startup.o" "$OUT/main.o" "$OUT/common.o" "$OUT/support.o" \
    "$OUT/uart.o" $OBJS "$LIB"
llvm-objcopy -O binary "$OUT/bench.elf" "$OUT/bench.bin"
llvm-size "$OUT/bench.elf" > "$OUT/size.txt"
python3 -I - "$OUT" "$EMU" "$LIB" $OBJS <<'PY'
import hashlib, json, sys
out, emu, lib, *objs = sys.argv[1:]
sha = lambda p: hashlib.sha256(open(p, "rb").read()).hexdigest()
img = open(f"{out}/bench.bin", "rb").read()
text = open(lib.replace(lib.split("/")[-1], "text.bin"), "rb").read()
assert img.count(text) == 1, "release .text not found exactly once in bench.bin"
manifest = json.load(open(f"{emu}/manifest.json"))
assert manifest["elf_sha256"] == sha(f"{emu}/bench.elf"), "emulator ELF differs from its manifest"
with open(f"{out}/IMAGE.txt", "w") as f:
    print(f"image_bin_bytes={len(img)}", file=f)
    print(f"image_bin_sha256={hashlib.sha256(img).hexdigest()}", file=f)
    print(f"release_text_sha256={hashlib.sha256(text).hexdigest()} at bin offset 0x{img.index(text):x}", file=f)
    print(f"emulator_elf_sha256={manifest['elf_sha256']} (same objects, bench/link.ld)", file=f)
    print(f"opt={manifest['opt']}", file=f)
    for p in [lib] + objs:
        print(f"object {sha(p)} {p.split('/build/')[-1]}", file=f)
print(open(f"{out}/IMAGE.txt").read(), end="")
PY
