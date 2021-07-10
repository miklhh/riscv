#!/usr/bin/env python3
from elftools.elf.elffile import ELFFile
import struct
import hexdump
from enum import Enum

# Instructions (40 in total):
#
# Integer Computational Instruction (Section 2.4)
#   Register-Immediate:
#       ADDI                (add immediate)
#       SLTI                (set less than immediate)
#       ANDI, ORI, XORI     (logical AND, OR and XOR)
#       SLLI, SRLI, SRAI    (shift left/right logical/arithmetical immediate)
#       LUI                 (load upper immediate)
#       AUIPC               (add upper immediate to PC)
#   Register-Register:
#       ADD, SUB            (add/subtract)
#       SLT, SLTU           (test less than [unsigned])
#       AND, OR, XOR        (logical, AND, OR and XOR)
#       SLL, SRL, SRA       (shift left/right logical/arithmetical)
#   NOP Instruction:
#       NOP                 (No operation [really it's ADDI x0, x0, 0])
#
# Control Transfer Instructions (Section 2.5)
#   Unconditional Jumps:
#       JAL, JALR           (jump and link [register])
#   Conditional Branches:
#       BEQ, BNE            (branch [not] equal)
#       BLT, BGT            (branch less/greater than)
#
# Load and Store Instructions (Section 2.6)
# Memory Ordering Instruction (Section 2.7)
# Environment Call and Breakpoints (Section 2.8)
# HINT Instructions (Section 2.9)
#

# Instruction formats, found at the top of Table 24.2
class InstFormat(Enum): #  31          25 24     20 19     15 14    12 11          7 6      0
    R = 0               # |    funct7    |   rs2   |   rs1   | funct3 |      rd     | opcode |
    I = 1               # |        imm[11:0]       |   rs1   | funct3 |      rd     | opcode |
    S = 2               # |   imm[11:5]  |   rs2   |   rs1   | funct3 |   imm[4:0]  | opcode |
    B = 3               # | imm[12|10:5] |   rs2   |   rs1   | funct3 | imm[4:1|11] | opcode |
    U = 4               # |                 imm[31:12]                |      rd     | opcode |
    J = 5               # |           imm[20|10:1|11|19:12]           |      rd     | opcode |

# Base opcodes, found in Table 24.1
class BaseOp(Enum):
    LOAD    = 0b0000011
    STORE   = 0b0100011
    BRANCH  = 0b1100011
    JALR    = 0b1100111
    JAL     = 0b1101111
    OP_IMM  = 0b0010011
    OP      = 0b0110011
    SYSTEM  = 0b1110011
    AUIPC   = 0b0010111
    LUI     = 0b0110111

# Instructions, found in Table 24.1
DONT_CARE = -1
class Inst(Enum):
    LUI     = (InstFormat.U, BaseOp.LUI,    DONT_CARE, DONT_CARE)
    AUIPC   = (InstFormat.U, BaseOp.AUIPC,  DONT_CARE, DONT_CARE)
    JAL     = (InstFormat.J, BaseOp.JAL,    DONT_CARE, DONT_CARE)
    JALR    = (InstFormat.I, BaseOp.JALR,   DONT_CARE, DONT_CARE)
    BEQ     = (InstFormat.B, BaseOp.BRANCH, 0b000,     DONT_CARE)
    BNE     = (InstFormat.B, BaseOp.BRANCH, 0b001,     DONT_CARE)
    BLT     = (InstFormat.B, BaseOp.BRANCH, 0b100,     DONT_CARE)
    BGT     = (InstFormat.B, BaseOp.BRANCH, 0b101,     DONT_CARE)

# Register file class. Note especially that register X0 always equals zero.
class Regfile:
    PC=32
    def __init__(self):
        self.regfile = [0xDEADCAFE]*33
        self.regfile[0] = 0
    def __getitem__(self, reg):
        return self.regfile[reg]
    def __setitem__(self, reg, val):
        if reg > 0:
            self.regfile[reg] = val

regfile = Regfile()

PC=32

# 64k memory at 0x80000000
memory = b'\x00'*0x10000
memory_offset = 0

# Control and Status Registers, 4096 (CSR)
csr_memory = b'\x00'*0x1000

def r32(addr):
    addr -= memory_offset
    return struct.unpack("I", memory[addr:addr+4])[0]

def r16(addr):
    addr -= memory_offset
    return struct.unpack("H", memory[addr:addr+2])[0]

def r8(addr):
    addr -= memory_offset
    return memory[addr]

def s32(addr, val32):
    addr -= memory_offset
    memory[addr:addr+4] = struct.pack("I", val32)

def csr_r8(addr):
    return csr_memory[addr]

def csr_w8(addr, val8):
    memory[addr] = val8

def get_bits(n, idx_b, idx_t):
    return (n >> idx_b) & ( (1 << (idx_t-idx_b+1)) - 1 )


def get_rd(inst):
    return get_bits(inst, 7, 11)

def get_rs1(inst):
    return get_bits(inst, 15, 19)

def get_rs2(inst):
    return get_bits(inst, 20, 24)


# For R-type, I-type, S-type and B-type instructions
def get_funct3(inst):
    return get_bits(inst, 12, 14)

# For R-type instructions
def get_funct7(inst):
    return get_bits(inst, 25, 31)

# For SYSTEM.PRIV functions (ECALL, EBREAK)
def get_funct12(inst):
    return get_bits(inst, 20, 31)

# Get immediates from instruction
def get_imm_i_type(inst):
    return get_bits(inst, 20, 31)

def get_imm_s_type(inst):
    return get_bits(inst, 25, 31)

def get_imm_u_type(inst):
    return get_bits(inst, 12, 31)

def get_imm_j_type(inst):
    return get_bits(inst,31,31)<<20 | get_bits(inst,21,30)<<1 | get_bits(inst,20,20)<<11 | get_bits(inst,12,19)<<12

# TODO: i=32 CSR register.

FUNCT3_CSRRW = 0b001
FUNCT3_CSRRS = 0b010
FUNCT3_CSRRC = 0b011
FUNCT3_CSRRWI = 0b101
FUNCT3_CSRRSI = 0b110
FUNCT3_CSRRCI = 0b111

FUNCT3_ADDI = 0b000

def step():
    # Dump registers.
    dump_regs()

    # (1) Instructin fetch
    inst = r32(regfile[PC])

    # (2) Instruction decode
    op = BaseOp(inst & 0x7F)
    if op == BaseOp.JAL:
        # Instruction on J-format
        rd = get_rd(inst)
        imm = get_imm_j_type(inst)
        regfile[PC] += imm
        if rd == 0:
            pass
        else:
            raise NotImplementedError(str(op) + " rd != 0")
    elif op == BaseOp.OP_IMM:
        # Instruction on I-format
        funct3 = get_funct3(inst)
        if funct3 == FUNCT3_ADDI:
            rs1 = get_rs1(inst)
            rd = get_rd(inst)
            imm = get_bits(inst, 20, 31) # TODO: Sign extend imm
            regfile[rd] = regfile[rs1] + imm
        else:
            raise NotImplementedError(str(op) + "/" + str(funct3))
        regfile[PC] += 4
    elif op == BaseOp.SYSTEM:
        funct3 = get_funct3(inst)
        if funct3 == 0b000:
            funct12 = get_funct12(inst)
            if funct12 == 0b000000000000:
                pass # ECALL
            elif funct12 == 0b000000000001:
                pass # EBREAK
        elif funct3 == FUNCT3_CSRRW:
            raise NotImplementedError(str(op) + "/" + "CSRRW")
        elif funct3 == FUNCT3_CSRRS:
            # Atomic Read and Set Bit in CSR
            rd = get_rd(inst)
            rs1 = get_rs1(inst)
            csr = get_bits(inst, 20, 31)
        elif funct3 == FUNCT3_CSRRC:
            raise NotImplementedError(str(op) + "/" + "CSRRC")
        elif funct3 == FUNCT3_CSRWI:
            raise NotImplementedError(str(op) + "/" + "CSRRWI")
        elif funct3 == FUNCT3_CSRRSI:
            raise NotImplementedError(str(op) + "/" + "CSRRSI")
        elif funct3 == FUNCT3_CSRRCI:
            raise NotImplementedError(str(op) + "/" + "CSRRCI")
        else:
            raise NotImplementedError("Invalid instruction: " + str(op) + "funct3=" + str(funct3))
        regfile[PC] += 4
    else:
        raise NotImplementedError(str(op))

    # (3) Instruction execute
    # (4) Access
    # (5) Write back
    return True

def dump_regs():
    base_opcode = BaseOp(r32(regfile[PC]) & 0x7F)
    print("  PC: 0x%08x ins: 0x%08x, base_opcode: %s" % (regfile[PC], r32(regfile[PC]), base_opcode))
    for i in range (4):
        for j in range(8):
            reg = j + i*8
            print(" %3s: 0x%08x" % ("X" + str(reg), regfile[reg]), end="")
        print("")
    print("")

# Load data into the memory at address.
def mem_load(data, addr):
    global memory
    addr -= memory_offset
    memory = memory[:addr] + data + memory[addr+len(data):]

# Super simple ELF loader. Segments are placed contigously into memory, in order,
# starting from address 0x80000000
def load_elf(infile):
    global memory_offset
    TAB = "  "
    print("Loading ELF file: '" + infile + "'")
    with open(infile, 'rb') as f:
        elf = ELFFile(f)
        first_seg = elf.get_segment(0)
        memory_offset = first_seg.header.p_paddr
        print(TAB + "Arch: '" + str(elf.get_machine_arch()), end="', ")
        print("Segments: " + str(elf.num_segments()))
        for seg in elf.iter_segments():
            print(TAB + "Loading segment into address: " + hex(seg.header.p_paddr))
            mem_load(seg.data(), seg.header.p_paddr)
    print("")

if __name__ == '__main__':
    load_elf('riscv-tests/isa/rv32ui-p-add')
    regfile[PC] = memory_offset
    try:
        print("i=0")
        i = 1
        while step() and i < 100:
            print("i=" + str(i))
            i += 1
    except NotImplementedError as e:
        print("Not implemented yet: '" + str(e) + "', exiting.")
    
