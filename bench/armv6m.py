"""Run a linked Thumb wrapper and apply the Cortex-M0+ instruction-cost model."""

from dataclasses import dataclass
from pathlib import Path
import struct

import capstone
import unicorn
from unicorn import arm_const
from elftools.elf.elffile import ELFFile

FLASH_BASE = 0
FLASH_BYTES = 256 * 1024
RAM_BASE = 0x20200000
RAM_BYTES = 32 * 1024
RETURN_ADDRESS = 0x3FF00
INSTRUCTION_LIMIT = 20_000_000
JOB_FORMAT = struct.Struct("<8Ii")  # Matches Job in harness.c.
STATUS_OFFSET = 32
OUTPUT_SENTINEL = b"\xa5"
GUARD_SENTINEL = b"\x5a"

CONDITIONAL_BRANCHES = {
    "beq",
    "bne",
    "bhs",
    "blo",
    "bmi",
    "bpl",
    "bvs",
    "bvc",
    "bhi",
    "bls",
    "bge",
    "blt",
    "bgt",
    "ble",
}
SINGLE_CYCLE_INSTRUCTIONS = {
    "mov",
    "movs",
    "adds",
    "add",
    "subs",
    "sub",
    "cmp",
    "lsrs",
    "lsls",
    "orrs",
    "ands",
    "eors",
    "rors",
    "mvns",
    "rev",
    "rev16",
    "adcs",
    "sbcs",
    "rsbs",
    "asrs",
    "bics",
    "tst",
    "uxtb",
    "uxth",
    "sxtb",
    "sxth",
    "muls",
    "nop",
    "cmn",
}


@dataclass(frozen=True)
class Buffers:
    job: int = RAM_BASE
    source: int = RAM_BASE + 0x1000
    output: int = RAM_BASE + 0x3000
    key: int = RAM_BASE + 0x5000
    nonce: int = RAM_BASE + 0x5040
    aad: int = RAM_BASE + 0x5080
    tag: int = RAM_BASE + 0x5100
    stack: int = RAM_BASE + RAM_BYTES

    @classmethod
    def for_alignment(cls, alignment: str) -> "Buffers":
        if alignment == "u":
            return cls(source=RAM_BASE + 0x1001, output=RAM_BASE + 0x3003)
        if alignment == "ip":
            return cls(output=RAM_BASE + 0x1000)
        return cls()


@dataclass
class Counts:
    instructions: int = 0
    zero_wait_cycles: int = 0
    store_units: int = 0

    @property
    def sram_store_model_cycles(self) -> int:
        return self.zero_wait_cycles + self.store_units


@dataclass
class CallResult:
    status: int
    output: bytes
    tag: bytes
    counts: Counts


@dataclass(frozen=True)
class Instruction:
    mnemonic: str
    registers: tuple[int, ...]
    operands: str


def branch_taken(mnemonic: str, status_register: int) -> bool:
    negative = bool(status_register & (1 << 31))
    zero = bool(status_register & (1 << 30))
    carry = bool(status_register & (1 << 29))
    overflow = bool(status_register & (1 << 28))
    conditions = {
        "beq": zero,
        "bne": not zero,
        "bhs": carry,
        "blo": not carry,
        "bmi": negative,
        "bpl": not negative,
        "bvs": overflow,
        "bvc": not overflow,
        "bhi": carry and not zero,
        "bls": not carry or zero,
        "bge": negative == overflow,
        "blt": negative != overflow,
        "bgt": not zero and negative == overflow,
        "ble": zero or negative != overflow,
    }
    return conditions[mnemonic]


def instruction_cost(instruction: Instruction, machine: unicorn.Uc) -> tuple[int, int]:
    """Return (zero-wait cycles, store transfers) for supported Cortex-M0+ instructions."""
    mnemonic = instruction.mnemonic
    registers = instruction.registers
    if mnemonic.startswith("ldr"):
        return 2, 0
    if mnemonic.startswith("str"):
        return 2, 1
    if mnemonic in {"ldm", "stm"}:
        # Capstone lists the base register first, followed by transferred registers.
        transfers = len(registers) - 1
        stores = transfers if mnemonic == "stm" else 0
        return 1 + transfers, stores
    if mnemonic in {"push", "pop"}:
        cycles = 1 + len(registers)
        if mnemonic == "pop" and capstone.arm.ARM_REG_PC in registers:
            cycles += 2
        stores = len(registers) if mnemonic == "push" else 0
        return cycles, stores
    if mnemonic in {"b", "bx", "blx"}:
        return 2, 0
    if mnemonic in {"bl", "dmb"}:
        return 3, 0
    if mnemonic in CONDITIONAL_BRANCHES:
        status = machine.reg_read(arm_const.UC_ARM_REG_XPSR)
        return (2 if branch_taken(mnemonic, status) else 1), 0
    if mnemonic in SINGLE_CYCLE_INSTRUCTIONS:
        writes_pc = registers and registers[0] == capstone.arm.ARM_REG_PC
        return (2 if writes_pc else 1), 0
    raise RuntimeError(f"unmodeled instruction: {mnemonic} {instruction.operands}")


class Runner:
    def __init__(self, elf_path: Path):
        with elf_path.open("rb") as stream:
            elf = ELFFile(stream)
            self.segments = []
            for segment in elf.iter_segments():
                if segment["p_type"] != "PT_LOAD":
                    continue
                address = segment["p_vaddr"]
                if address >= RAM_BASE and segment["p_memsz"]:
                    raise RuntimeError("benchmark requires no static RAM sections")
                self.segments.append((address, segment.data()))
            self.symbols = {
                symbol.name: symbol["st_value"]
                for symbol in elf.get_section_by_name(".symtab").iter_symbols()
            }
        self.decoder = capstone.Cs(
            capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB | capstone.CS_MODE_MCLASS
        )
        self.decoder.detail = True
        self.instructions: dict[int, Instruction] = {}

    def decode(self, machine: unicorn.Uc, address: int, size: int) -> Instruction:
        if address not in self.instructions:
            code = bytes(machine.mem_read(address, size))
            decoded = next(self.decoder.disasm(code, address))
            registers = tuple(
                operand.reg
                for operand in decoded.operands
                if operand.type == capstone.arm.ARM_OP_REG
            )
            self.instructions[address] = Instruction(
                decoded.mnemonic, registers, decoded.op_str
            )
        return self.instructions[address]

    def prepare_call(
        self,
        buffers: Buffers,
        key: bytes,
        nonce: bytes,
        aad: bytes,
        message: bytes,
        tag: bytes,
    ) -> tuple[unicorn.Uc, list[int]]:
        machine = unicorn.Uc(
            unicorn.UC_ARCH_ARM, unicorn.UC_MODE_THUMB | unicorn.UC_MODE_MCLASS
        )
        machine.mem_map(FLASH_BASE, FLASH_BYTES)
        machine.mem_map(RAM_BASE, RAM_BYTES)
        for address, data in self.segments:
            machine.mem_write(address, data)

        machine.mem_write(buffers.source, message or b"\0")
        if buffers.source != buffers.output:
            machine.mem_write(buffers.output, OUTPUT_SENTINEL * max(1, len(message)))
        machine.mem_write(buffers.key, key)
        machine.mem_write(buffers.nonce, nonce)
        machine.mem_write(buffers.aad, aad or b"\0")
        machine.mem_write(buffers.tag, tag)
        job = JOB_FORMAT.pack(
            buffers.output,
            buffers.source,
            len(message),
            buffers.key,
            buffers.nonce,
            buffers.aad,
            len(aad),
            buffers.tag,
            99,
        )
        machine.mem_write(buffers.job, job)

        guards = [
            buffers.output - 1,
            buffers.output + len(message),
            buffers.tag - 1,
            buffers.tag + 16,
        ]
        for address in guards:
            machine.mem_write(address, GUARD_SENTINEL)
        machine.reg_write(arm_const.UC_ARM_REG_SP, buffers.stack)
        machine.reg_write(arm_const.UC_ARM_REG_R0, buffers.job)
        machine.reg_write(arm_const.UC_ARM_REG_LR, RETURN_ADDRESS | 1)
        return machine, guards

    def call(
        self,
        implementation: str,
        operation: str,
        key: bytes,
        nonce: bytes,
        aad: bytes,
        message: bytes,
        tag: bytes,
        alignment: str,
    ) -> CallResult:
        buffers = Buffers.for_alignment(alignment)
        machine, guards = self.prepare_call(buffers, key, nonce, aad, message, tag)
        counts = Counts()

        def count_instruction(machine, address, size, _user_data):
            if address == RETURN_ADDRESS:
                machine.emu_stop()
                return
            instruction = self.decode(machine, address, size)
            cycles, stores = instruction_cost(instruction, machine)
            counts.instructions += 1
            counts.zero_wait_cycles += cycles
            counts.store_units += stores

        machine.hook_add(unicorn.UC_HOOK_CODE, count_instruction)
        wrapper = self.symbols[f"run_{implementation}_{operation}"]
        machine.emu_start(wrapper | 1, RETURN_ADDRESS, count=INSTRUCTION_LIMIT)
        if machine.reg_read(arm_const.UC_ARM_REG_PC) != RETURN_ADDRESS:
            raise RuntimeError("call did not return before the instruction limit")
        if machine.reg_read(arm_const.UC_ARM_REG_SP) != buffers.stack:
            raise RuntimeError("call did not restore SP")
        for address in guards:
            if bytes(machine.mem_read(address, 1)) != GUARD_SENTINEL:
                raise RuntimeError(f"guard byte changed at {address:#x}")

        status_bytes = machine.mem_read(buffers.job + STATUS_OFFSET, 4)
        return CallResult(
            status=struct.unpack("<i", status_bytes)[0],
            output=bytes(machine.mem_read(buffers.output, len(message))),
            tag=bytes(machine.mem_read(buffers.tag, 16)),
            counts=counts,
        )
