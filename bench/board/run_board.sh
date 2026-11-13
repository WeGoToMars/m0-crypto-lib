#!/bin/sh
# Run one board image (bench/board/build.sh output) on the MSPM0L2228 behind the eCTF
# bootloader, through the host that has the board's XDS110 attached.
#   bench/board/run_board.sh IMAGE_DIR LOG
# Same procedure as the dev repo's bench/run_board_ectf.sh (copy bench.bin; update mode by
# holding PB21 low from Pi GPIO23 across an SWD reset; `ectf hw PORT erase | flash | start`;
# open the backchannel UART at 115200 8N1, send one byte, capture until the image's EXIT
# line), with these differences: the ectf tool is the one in the host's venv (no network),
# the remote files live in $REMOTE_DIR, and the log gets ENV lines (tool versions).
# The remote side holds /tmp/m0c-board.lock (flock) so concurrent runs queue. Every remote
# step has a deadline; the whole locked script is capped at 900 s.
#   BOARD_HOST (default ihor@cw-pi)  BOARD_KEY (default ~/.ssh/id_ed25519)
#   BOARD_PORT  REMOTE_DIR (default ~/m0c-board-measure-2026-11-13)
set -eu
IMG=${1:?image dir, e.g. build/board/blake2s-flash}
LOG=${2:?log file}
HOST=${BOARD_HOST:-ihor@cw-pi}
KEY=${BOARD_KEY:-$HOME/.ssh/id_ed25519}
PORT=${BOARD_PORT:-/dev/serial/by-id/usb-Texas_Instruments_XDS110__03.00.00.45__Embed_with_CMSIS-DAP_M4321005-if00}
RDIR=${REMOTE_DIR:-m0c-board-measure-2026-11-13}
SSHOPT="-o BatchMode=yes -o IdentitiesOnly=yes -o ConnectTimeout=10 -o ServerAliveInterval=15 -o ServerAliveCountMax=4"
[ -f "$IMG/bench.bin" ] || { echo "no $IMG/bench.bin" >&2; exit 1; }
SUM=$(shasum -a 256 "$IMG/bench.bin" | cut -d' ' -f1)
ssh $SSHOPT -i "$KEY" "$HOST" "mkdir -p '$RDIR'"
scp -q $SSHOPT -i "$KEY" "$IMG/bench.bin" "$HOST:$RDIR/bench-$SUM.bin"
ssh $SSHOPT -i "$KEY" "$HOST" "PORT='$PORT' RDIR='$RDIR' SUM='$SUM' flock -w 900 /tmp/m0c-board.lock timeout -k 10 900 sh -s" > "$LOG.tmp" 2>&1 <<'REMOTE_EOF' || { cat "$LOG.tmp"; exit 1; }
set -eu
cd "$HOME/$RDIR"
IMG=$HOME/$RDIR/bench-$SUM.bin
E=$HOME/.local/share/ectf-physical-venv/bin/ectf
echo "HOST,$(hostname),$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "ENV,$(uname -sr),$(openocd --version 2>&1 | head -1),ectf $($HOME/.local/share/ectf-physical-venv/bin/pip list 2>/dev/null | sed -n 's/^ectf  *//p'),python $(python3 -V 2>&1)"
echo "IMAGE,$(sha256sum "$IMG" | cut -d' ' -f1),$(stat -c %s "$IMG")"
# Update mode: hold PB21 (S2, pulled up; Pi GPIO23) low across an SWD reset.
timeout -k 5 45 python3 -I - <<'PY'
import gpiod, subprocess, time
from gpiod.line import Direction, Value
cfg = {23: gpiod.LineSettings(direction=Direction.OUTPUT, output_value=Value.INACTIVE)}
with gpiod.request_lines("/dev/gpiochip0", consumer="m0c-bootsel", config=cfg):
    time.sleep(0.1)
    subprocess.run(["timeout", "-k", "5", "30", "openocd", "-f", "board/ti_mspm0_launchpad.cfg",
                    "-c", "init; reset run; shutdown"], check=True, capture_output=True)
    time.sleep(1.0)
PY
timeout -k 10 60 $E hw "$PORT" status
timeout -k 10 60 $E hw "$PORT" erase
timeout -k 10 180 $E hw "$PORT" flash "$IMG" -n m0cbench
timeout -k 10 60 $E hw "$PORT" start
timeout -k 10 700 python3 -I - "$PORT" <<'PY'
import serial, sys, time
s = serial.Serial(sys.argv[1], 115200, timeout=0.5)
time.sleep(0.3)
s.reset_input_buffer()
s.write(b"g")
buf, t0 = b"", time.monotonic()
last = time.monotonic()
while time.monotonic() - t0 < 600:
    chunk = s.read(4096)
    if chunk:
        buf, last = buf + chunk, time.monotonic()
    if b"EXIT 0x" in buf and len(buf.split(b"EXIT 0x", 1)[1]) >= 8:
        break
    if time.monotonic() - last > (5 if not buf else 90):
        break                      # silent board: report instead of hanging
sys.stdout.write(buf.decode("ascii", "replace").replace("\r", ""))
if b"EXIT 0x" not in buf:
    print("\nHOST: no EXIT line within timeout"); sys.exit(1)
PY
REMOTE_EOF
mv "$LOG.tmp" "$LOG"
grep -q '^RESULT: PASS' "$LOG" && grep -q '^EXIT 0x00000000' "$LOG"
