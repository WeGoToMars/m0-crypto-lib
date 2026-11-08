#!/bin/sh
# Build the on-target test images and run them under QEMU's Cortex-M0 "microbit"
# machine with semihosting. QEMU checks ARMv6-M behaviour, not timing.
#   test_chacha20: m0c_chacha20_xor   test_aead: ChaCha20-Poly1305 and Poly1305
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
LLVM_BIN=${LLVM_BIN:-/opt/homebrew/opt/llvm/bin}
LLD_BIN=${LLD_BIN:-/opt/homebrew/opt/lld/bin}
QEMU=${QEMU:-qemu-system-arm}
OUT="$ROOT/build/test"
rm -rf "$OUT"
mkdir -p "$OUT"
CFLAGS="--target=thumbv6m-none-eabi -mcpu=cortex-m0plus -mthumb -Os -ffreestanding -fno-builtin -fno-unwind-tables -fno-asynchronous-unwind-tables -nostdlib -Wall -Wextra -Werror"
T="$ROOT/tests"
cc() { "$LLVM_BIN/clang" $CFLAGS -I "$ROOT/include" -I "$ROOT/src" -I "$ROOT/tests" -c "$1" -o "$OUT/$(basename "$1").o"; }
# Both images link the release unit src/m0crypto.S (relocation-free).
for src in "$ROOT/src/m0crypto.S" "$T/startup.S" \
           "$T/check_call.S" "$T/check_call8.S" "$T/ref_chacha20.c" \
           "$T/test_chacha20.c" "$T/test_aead.c"; do
    cc "$src"
done
link() {   # link IMAGE OBJ...
    img=$1; shift
    "$LLD_BIN/ld.lld" -T "$T/microbit.ld" --build-id=none -o "$OUT/$img.elf" "$@"
    echo "built $OUT/$img.elf"
}
O=$OUT
link test_chacha20 "$O/startup.S.o" "$O/m0crypto.S.o" "$O/check_call.S.o" \
    "$O/ref_chacha20.c.o" "$O/test_chacha20.c.o"
link test_aead "$O/startup.S.o" "$O/m0crypto.S.o" \
    "$O/check_call8.S.o" "$O/test_aead.c.o"

STATUS_ALL=0
for img in test_chacha20 test_aead; do
    LOG="$OUT/$img.log"
    STATUS=0
    # perl alarm: kill QEMU if the image hangs.
    perl -e 'alarm shift; exec @ARGV' "${TIMEOUT:-300}" \
        "$QEMU" -machine microbit -nographic -monitor none -serial none \
        -semihosting-config enable=on,target=native \
        -kernel "$OUT/$img.elf" > "$LOG" 2>&1 || STATUS=$?
    echo "== $img"
    cat "$LOG"
    if [ "$STATUS" != 0 ] || ! grep -q '^RESULT: PASS' "$LOG"; then
        echo "FAIL: $img: qemu exit status $STATUS" >&2
        STATUS_ALL=1
    fi
done
[ "$STATUS_ALL" = 0 ] || exit 1
echo OK
