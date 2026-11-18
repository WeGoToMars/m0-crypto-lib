#!/usr/bin/env python3
"""Build the release archive of each library asset.

Usage: tools/release.py [ASSET...]     (default: all; ASSET: chacha20poly1305 blake2s x25519)

For each asset the script:

1. builds it with tools/build_lib.sh (pinned clang) and requires the object to match the proofs
   artifact, proofs/assets/ASSET/artifact/M0Crypto/Artifacts/Release.lean;
2. writes m0crypto_ASSET_text.s, the proved .text as `.inst.n` halfwords (code) and `.byte` data
   (literal pools), with every function symbol at its offset;
3. assembles that file with clang and requires the object to match the same proofs artifact:
   bytes, function offsets, sizes, binding and Thumb bit, code and data ranges
   (proofs/tools/extract_release.py --check); assembles it with GNU as (arm-none-eabi-as, or
   $GNU_AS) and requires the same symbols, mapping symbols and alignment, and a .text that is the
   proved bytes followed only by the padding GNU as adds (see PAD);
4. compiles each of the asset's headers on its own;
5. writes build/release/m0crypto-ASSET-VERSION.tar.gz, after removing the archives and
   SHA256SUMS of any earlier run from build/release:
     LICENSE  MANIFEST.txt  include/m0crypto/*.h  lib/libm0crypto_ASSET.a
     src/m0crypto_ASSET_text.s
   MANIFEST.txt is build_lib.sh's, followed by the library commit and the proofs commit (the
   gitlink of HEAD, which the proofs checkout must match) whose theorems state the claims.

VERSION is the first `## ` heading of CHANGELOG.md. Archive entries carry the time
SOURCE_DATE_EPOCH, or the commit time of HEAD, and no owner, so a rebuild of one commit gives the
same bytes. Prints the sha256 of each archive and writes them to build/release/SHA256SUMS.
"""
import gzip
import hashlib
import io
import os
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROOFS = os.path.join(ROOT, "proofs")
ALL_ASSETS = ["chacha20poly1305", "blake2s", "x25519"]
# The headers of each asset's API; the headers they include are added below.
HEADERS = {"chacha20poly1305": ["chacha20.h", "chacha20poly1305.h"],
           "blake2s": ["blake2s.h"], "x25519": ["x25519.h"]}
STT_FUNC, STB_GLOBAL = 2, 1
# GNU as ends every ARM code section on its alignment, here 4, filling with Thumb NOPs
# (gas/config/tc-arm.h SUB_SEGMENT_ALIGN; -no-pad-sections does not apply to it). The proved
# .text of an asset whose size is 2 mod 4 is followed by one `mov r8, r8` that no call reaches.
PAD = b"\xc0\x46"


def run(*cmd, **kw):
    subprocess.run(cmd, check=True, **kw)


def elf_text(path):
    """The .text bytes, function symbols, mapping symbols and alignment of an ELF32 object, and
    the other sections that would reach a linked image (relocations, allocated contents)."""
    d = open(path, "rb").read()
    (shoff,) = struct.unpack_from("<I", d, 32)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", d, 46)
    secs = [struct.unpack_from("<IIIIIIIIII", d, shoff + i * shentsize) for i in range(shnum)]
    cstr = lambda tab, off: d[tab + off:d.index(b"\0", tab + off)].decode("ascii")
    names = [cstr(secs[shstrndx][4], s[0]) for s in secs]
    ti = names.index(".text")
    code = d[secs[ti][4]:secs[ti][4] + secs[ti][5]]
    extra = [n for n, s in zip(names, secs) if s[1] in (4, 9) or (n != ".text" and s[2] & 2 and s[5])]
    funcs, maps = [], []
    for s in secs:
        if s[1] != 2:  # SHT_SYMTAB
            continue
        for k in range(s[5] // 16):
            st_name, value, size, info, _other, shndx = struct.unpack_from("<IIIBBH", d, s[4] + 16 * k)
            name = cstr(secs[s[6]][4], st_name)
            # The archive and the generated source carry Thumb functions in .text only.
            if info & 0xF == STT_FUNC and (shndx != ti or not value & 1):
                sys.exit(f"{path}: function {name} is not a Thumb function in .text")
            if shndx != ti:
                continue
            if name.split(".")[0] == "$a":
                sys.exit(f"{path}: .text has ARM code at {value:#x}")
            if name.split(".")[0] in ("$t", "$d"):
                maps.append((value, name[:2]))
            elif info & 0xF == STT_FUNC:
                funcs.append((value & ~1, size, name, info >> 4 == STB_GLOBAL))
    return code, sorted(funcs), sorted(maps), secs[ti][8], extra


def text_source(asset, obj, version, clang):
    code, funcs, maps, _, _ = elf_text(obj)
    unit = f"m0crypto_{asset}"
    sha = hashlib.sha256(code).hexdigest()
    out = [
        f"/* m0-crypto {version}, release asset {asset}. SPDX-License-Identifier: MIT",
        " *",
        f" * The .text of {unit}.o as tools/build_lib.sh builds it from src/{unit}.S with",
        f" * clang {clang}: the bytes the Lean proofs cover, {len(code)} bytes, sha256",
        f" * {sha}.",
        " * Instructions are .inst.n halfwords and literal pools are .byte data, so an ARM assembler",
        " * reproduces these bytes, symbols and code/data mapping whatever its instruction selection:",
        " *",
        f" *   clang --target=thumbv6m-none-eabi -c -o {unit}.o {unit}_text.s",
        f" *   arm-none-eabi-as -o {unit}.o {unit}_text.s",
        " *",
        " * GNU as ends .text on a 4-byte boundary: when the size is 2 mod 4 it appends one Thumb NOP",
        " * (c0 46) after the proved bytes. No call reaches it.",
        " *",
        " * Link .text at a 4-byte-aligned address. Generated by tools/release.py; do not edit.",
        " */",
        "\t.syntax unified",
        "\t.cpu cortex-m0plus",
        "\t.thumb",
        "\t.text",
        "\t.p2align 2",
    ]
    out += [f"\t.global {n}" for _, _, n, g in funcs if g]
    cuts = sorted({v for v, _ in maps} | {v for v, *_ in funcs} | {len(code)})
    kind = None
    for a, b in zip(cuts, cuts[1:]):
        kind = dict(maps).get(a, kind)
        for v, _, n, _ in funcs:
            if v == a:
                out += ["", f"\t.type {n}, %function", "\t.thumb_func", f"{n}:"]
        chunk = code[a:b]
        if kind == "$t":
            if len(chunk) % 2:
                sys.exit(f"release: odd-length code range at 0x{a:x} in {obj}")
            hw = [f"0x{h:04x}" for (h,) in struct.iter_unpack("<H", chunk)]
            out += ["\t.inst.n " + ", ".join(hw[i:i + 8]) for i in range(0, len(hw), 8)]
        elif kind == "$d":
            out += ["\t.byte " + ", ".join(f"0x{x:02x}" for x in chunk[i:i + 16])
                    for i in range(0, len(chunk), 16)]
        else:
            sys.exit(f"release: no mapping symbol before offset 0x{a:x} in {obj}")
    out.append("")
    out += [f"\t.size {n}, {s}" for _, s, n, _ in funcs]
    return "\n".join(out) + "\n"


def header_closure(asset):
    todo, seen = list(HEADERS[asset]), []
    while todo:
        h = todo.pop(0)
        if h in seen:
            continue
        seen.append(h)
        src = open(os.path.join(ROOT, "include", "m0crypto", h)).read()
        todo += re.findall(r'#include\s+"m0crypto/([\w.]+)"', src)
    return sorted(seen)


def pack(path, prefix, files, mtime):
    """files: {archive name: (bytes, mode)}. A ustar archive in sorted order, then gzip."""
    dirs = {os.path.dirname(n) for n in files}
    dirs = {"/".join(d.split("/")[:i + 1]) for d in dirs if d for i in range(d.count("/") + 1)}
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for name in sorted([""] + list(dirs) + list(files)):
            info = tarfile.TarInfo(f"{prefix}/{name}".rstrip("/"))
            info.mtime, info.uid, info.gid, info.uname, info.gname = mtime, 0, 0, "", ""
            if name in files:
                data, info.mode = files[name]
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
            else:
                info.type, info.mode = tarfile.DIRTYPE, 0o755
                tar.addfile(info)
    with open(path, "wb") as f, gzip.GzipFile(filename="", mode="wb", fileobj=f, mtime=0,
                                               compresslevel=9) as gz:
        gz.write(buf.getvalue())


def main(argv):
    assets = argv[1:] or ALL_ASSETS
    if any(a not in ALL_ASSETS for a in assets):
        sys.exit(f"usage: tools/release.py [{' '.join(ALL_ASSETS)}]")
    gnu_as = os.environ.get("GNU_AS", "arm-none-eabi-as")
    if not shutil.which(gnu_as):
        sys.exit(f"release: {gnu_as} not found (GNU binutils for arm-none-eabi; set GNU_AS)")
    version = re.search(r"^## (\S+)", open(os.path.join(ROOT, "CHANGELOG.md")).read(), re.M).group(1)
    mtime = int(os.environ.get("SOURCE_DATE_EPOCH") or subprocess.run(
        ["git", "-C", ROOT, "log", "-1", "--format=%ct"], check=True, capture_output=True,
        text=True).stdout)
    clang = re.search(r"^clang=(\S+)", open(os.path.join(ROOT, "tools", "versions.txt")).read(),
                      re.M).group(1)
    git = lambda *a: subprocess.run(["git", *a], check=True, capture_output=True,
                                    text=True).stdout.strip()
    commit, proofs = git("-C", ROOT, "rev-parse", "HEAD"), git("-C", ROOT, "rev-parse", "HEAD:proofs")
    if git("-C", PROOFS, "rev-parse", "HEAD") != proofs:
        sys.exit(f"release: the proofs checkout is not at the gitlink {proofs} of HEAD")
    provenance = (f"library_commit={commit}\nproofs_commit={proofs}\n"
                  f"claims=https://github.com/WeGoToMars/m0-crypto-proofs/tree/{proofs}\n").encode()
    run(os.path.join(ROOT, "tools", "build_lib.sh"), *assets, stdout=subprocess.DEVNULL)
    outdir = os.path.join(ROOT, "build", "release")
    os.makedirs(outdir, exist_ok=True)
    for f in os.listdir(outdir):
        if f == "SHA256SUMS" or (f.startswith("m0crypto-") and f.endswith(".tar.gz")):
            os.remove(os.path.join(outdir, f))
    sums = []
    for a in assets:
        unit = f"m0crypto_{a}"
        lib = os.path.join(ROOT, "build", "lib", a)
        artifact = os.path.join(PROOFS, "assets", a, "artifact", "M0Crypto", "Artifacts", "Release.lean")
        check = lambda obj: run("python3", "-I", os.path.join(PROOFS, "tools", "extract_release.py"),
                                obj, artifact, "--check")
        check(os.path.join(lib, f"{unit}.o"))
        src = text_source(a, os.path.join(lib, f"{unit}.o"), version, clang)
        headers = header_closure(a)
        with tempfile.TemporaryDirectory() as tmp:
            s = os.path.join(tmp, f"{unit}_text.s")
            open(s, "w").write(src)
            obj = os.path.join(tmp, f"{unit}.o")  # extract_release names the unit after the file
            run("clang", "--target=thumbv6m-none-eabi", "-c", s, "-o", obj)
            check(obj)
            run(gnu_as, s, "-o", os.path.join(tmp, "gnu.o"))
            code, funcs, maps, align, extra = elf_text(os.path.join(lib, f"{unit}.o"))
            pad = PAD * (len(code) % 4 // 2)
            if elf_text(os.path.join(tmp, "gnu.o")) != (code + pad, funcs, maps, align, extra):
                sys.exit(f"release: {gnu_as} output of {unit}_text.s differs from {unit}.o")
            print(f"ok {gnu_as}: .text = the {len(code)} proved bytes"
                  + (f" + {pad.hex()} padding" if pad else "") + ", same symbols and mapping", flush=True)
            inc = os.path.join(tmp, "include", "m0crypto")
            os.makedirs(inc)
            for h in headers:
                shutil.copy(os.path.join(ROOT, "include", "m0crypto", h), inc)
            for h in headers:
                run("clang", "--target=thumbv6m-none-eabi", "-ffreestanding", "-fsyntax-only",
                    "-Wall", "-Wextra", "-Werror", "-I", os.path.join(tmp, "include"), "-x", "c",
                    "-", input=f'#include "m0crypto/{h}"\n'.encode())
        read = lambda p: open(p, "rb").read()
        files = {"LICENSE": (read(os.path.join(ROOT, "LICENSE")), 0o644),
                 "MANIFEST.txt": (read(os.path.join(lib, "MANIFEST.txt")) + provenance, 0o644),
                 f"lib/lib{unit}.a": (read(os.path.join(lib, f"lib{unit}.a")), 0o644),
                 f"src/{unit}_text.s": (src.encode(), 0o644)}
        for h in headers:
            files[f"include/m0crypto/{h}"] = (read(os.path.join(ROOT, "include", "m0crypto", h)), 0o644)
        name = f"m0crypto-{a}-{version}"
        path = os.path.join(outdir, f"{name}.tar.gz")
        pack(path, name, files, mtime)
        sums.append(f"{hashlib.sha256(read(path)).hexdigest()}  {name}.tar.gz")
    open(os.path.join(outdir, "SHA256SUMS"), "w").write("\n".join(sums) + "\n")
    print("\n".join(sums))


if __name__ == "__main__":
    main(sys.argv)
