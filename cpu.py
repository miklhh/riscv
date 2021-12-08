#!/usr/bin/env python
#
# RISC-V single core RV32I simulator.
# The RV32I ISA is described in detail in 'The RISC-V Instruction Set Manual, Volume I: Unpriviledge ISA' and this
# simulator is based on Document Version 2019-12-13. A copy of this document can be found under
# 'documents/riscv-spec-20191213.pdf'.
#
# Author: Mikael Henriksson
#
from elftools.elf.elffile import ELFFile
import struct
import debug
from enum import Enum, auto


# Instruction formats, found at the top of Table 24.2
class InstFormat(Enum): # |31          25|24     20|19     15|14    12|11          7|6      0|
                        # |--------------|---------|---------|--------|-------------|--------|
    R = auto()          # |    funct7    |   rs2   |   rs1   | funct3 |      rd     | opcode |
    I = auto()          # |         imm[11:0]      |   rs1   | funct3 |      rd     | opcode |
    S = auto()          # |   imm[11:5]  |   rs2   |   rs1   | funct3 |   imm[4:0]  | opcode |
    B = auto()          # | imm[12|10:5] |   rs2   |   rs1   | funct3 | imm[4:1|11] | opcode |
    U = auto()          # |                 imm[31:12]                |      rd     | opcode |
    J = auto()          # |           imm[20|10:1|11|19:12]           |      rd     | opcode |

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
    FENCE   = 0b0001111
    AUIPC   = 0b0010111
    LUI     = 0b0110111

# Get Instruction format from a BaseOp
def to_inst_format(baseop):
    DICTIONARY = {
        BaseOp.LOAD    : InstFormat.I,
        BaseOp.STORE   : InstFormat.S,
        BaseOp.BRANCH  : InstFormat.B,
        BaseOp.JALR    : InstFormat.I,
        BaseOp.JAL     : InstFormat.J,
        BaseOp.OP_IMM  : InstFormat.I,
        BaseOp.OP      : InstFormat.R,
        BaseOp.SYSTEM  : InstFormat.I,
        BaseOp.AUIPC   : InstFormat.U,
        BaseOp.LUI     : InstFormat.U
    }
    return DICTIONARY[baseop]

# Register file of 32+1 registers. Note especially that register X0 always equal zero and that register X32 is the
# program counter (PC) register.
PC = 32
class Regfile:
    def __init__(self):
        self.regfile = [0xDEADCAFE]*33
        self.regfile[0] = 0
    def __getitem__(self, reg):
        return self.regfile[reg]
    def __setitem__(self, reg, val):
        if reg > 0:
            self.regfile[reg] = val

regfile = Regfile()

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

def get_bits(word, idx_b, idx_t):
    return (word >> idx_b) & ( (1 << (idx_t-idx_b+1)) - 1 )

def downto(up, down):
    return (down, up)

#
# Decode the immediate part of an instruction. The immediate is always sign extended with the most significant bit of
# the instruction inst(31).
#
#       |31          25|24     20|19     15|14    12|11          7|6      0|
#       |--------------|---------|---------|--------|-------------|--------|
#    I: |         imm[11:0]      |   rs1   | funct3 |      rd     | opcode |
#    S: |   imm[11:5]  |   rs2   |   rs1   | funct3 |   imm[4:0]  | opcode |
#    B: | imm[12|10:5] |   rs2   |   rs1   | funct3 | imm[4:1|11] | opcode |
#    U: |                 imm[31:12]                |      rd     | opcode |
#    J: |           imm[20|10:1|11|19:12]           |      rd     | opcode |
#
def imm_decode(inst):                   
    opcode = get_bits(inst, *downto(6, 0))    
    baseop = BaseOp(opcode)                   
    inst_format = to_inst_format(baseop)      
    if inst_format == InstFormat.R:           
        return 0                              
    elif inst_format == InstFormat.I:         
        imm = get_bits(inst, *downto(31, 20))
        return (0xFFFFF000 | imm) if ( inst & (1<<31) ) else imm
    elif inst_format == InstFormat.S:
        imm = (    (get_bits(inst, *downto(31, 25)) <<  5)
                 | (get_bits(inst, *downto(11,  7)) <<  0)   )
        return (0xFFFFF000 | imm) if (inst & (1<<31)) else imm
    elif inst_format == InstFormat.B:
        imm = (    (get_bits(inst, *downto(31, 31)) << 12)
                 | (get_bits(inst, *downto(7 ,  7)) << 11)
                 | (get_bits(inst, *downto(30, 25)) <<  5)
                 | (get_bits(inst, *downto(11,  8)) <<  1)   )
        return (0xFFFFE000 | imm) if (inst & (1<<31)) else imm
    elif inst_format == InstFormat.U:
        imm = ( get_bits(inst, *downto(31, 12)) << 12 )
        return imm
    elif inst_format == InstFormat.J:
        imm = (    (get_bits(inst, *downto(31, 31)) << 20)
                 | (get_bits(inst, *downto(19, 12)) << 12)
                 | (get_bits(inst, *downto(20, 20)) << 11)
                 | (get_bits(inst, *downto(30, 21)) <<  1)   )
        return (0xFFF00000 | imm) if (inst & (1<<31)) else imm
    else:
        raise BaseException("Unknown instruction format")

def funct_decode(inst):
    funct3 = get_bits(inst, *downto(14, 12))
    funct7 = get_bits(inst, *downto(31, 25))
    funct12 = get_bits(inst, *downto(31, 20))
    return (funct3, funct7, funct12)

def reg_decode(inst):
    rd  =    get_bits(inst, *downto(11, 7))
    rs1 =    get_bits(inst, *downto(19, 15))
    rs2 =    get_bits(inst, *downto(24, 20))
    return (rd, rs1, rs2)

def step(cnt):
    # Dump registers.
    #print()
    #dump_regs()

    # (1) Instructin fetch

    inst = r32(regfile[PC])

    # (2) Instruction decode
    base_op = BaseOp(get_bits(inst, *downto(6, 0)))
    (rd, rs1, rs2)            = reg_decode(inst)
    (funct3, funct7, funct12) = funct_decode(inst)
    (imm)                     = imm_decode(inst)

    # (3) Instruction execute
    if base_op == BaseOp.LUI:
        debug.print_asm_di("LUI", cnt, regfile[PC], rd, imm)
        regfile[rd] = imm
        regfile[PC] += 4
    elif base_op == BaseOp.AUIPC:
        debug.print_asm_di("AUIPC", cnt, regfile[PC], rd, imm)
        regfile[rd] = regfile[PC] + imm
        regfile[PC] += 4
    elif base_op == BaseOp.JAL:
        debug.print_asm_jal(cnt, regfile[PC], rd, imm)
        if rd == 0: # Plain jump instruction
            pass
        else: # Link to rd register
            regfile[rd] = regfile[PC] + 4
        regfile[PC] += imm
    elif base_op == BaseOp.JALR:
        raise NotImplementedError("JALR")
    elif base_op == BaseOp.BRANCH:
        if funct3 == 0b000:
            debug.print_asm_ssi("BEQ", cnt, regfile[PC], rs1, rs2, imm)
            raise NotImplementedError("BEQ")
        elif funct3 == 0b001: # BNE
            debug.print_asm_ssi("BNE", cnt, regfile[PC], rs1, rs2, imm)
            regfile[PC] += (imm if regfile[rs1] != regfile[rs2] else 4)
        elif funct3 == 0b100: # BLT
            debug.print_asm_ssi("BLT", cnt, regfile[PC], rs1, rs2, imm)
            raise NotImplementedError("BLT")
        elif funct3 == 0b101: # BGE
            debug.print_asm_ssi("BGE", cnt, regfile[PC], rs1, rs2, imm)
            raise NotImplementedError("BGE")
        elif funct3 == 0b110:
            debug.print_asm_ssi("BLTU", cnt, regfile[PC], rs1, rs2, imm)
            raise NotImplementedError("BLTU")
        elif funct3 == 0b111:
            debug.print_asm_ssi("BGEU", cnt, regfile[PC], rs1, rs2, imm)
            raise NotImplementedError("BGEU")
    elif base_op == BaseOp.LOAD:
        if funct3 == 0b000:
            raise NotImplementedError("LB")
        elif funct3 == 0b001:
            raise NotImplementedError("LH")
        elif funct3 == 0b010:
            raise NotImplementedError("LW")
        elif funct3 == 0b100:
            raise NotImplementedError("LBU")
        elif funct3 == 0b101:
            raise NotImplementedError("LHU")
    elif base_op == BaseOp.STORE:
        if funct3 == 0b000:
            raise NotImplementedError("SB")
        elif funct3 == 0b001:
            raise NotImplementedError("SH")
        elif funct3 == 0b010:
            raise NotImplementedError("SW")
    elif base_op == BaseOp.OP_IMM:
        if funct3 == 0b000: # ADDI
            debug.print_asm_addi(cnt, regfile[PC], rd, rs1, imm)
            regfile[rd] = regfile[rs1] + imm
            regfile[PC] += 4
        elif funct3 == 0b010:
            raise NotImplementedError("SLTI")
        elif funct3 == 0b011:
            raise NotImplementedError("SLTIU")
        elif funct3 == 0b111:
            raise NotImplementedError("ANDI")
        elif funct3 == 0b110:
            raise NotImplementedError("ORI")
        elif funct3 == 0b100:
            raise NotImplementedError("XORI")
        elif funct3 == 0b001:
            debug.print_asm_dsi("SLLI", cnt, regfile[PC], rd, rs1, imm)
            regfile[rd] = regfile[rs1] << imm
            regfile[PC] += 4
        elif funct3 == 0b101:
            if funct7 == 0b0000000:
                raise NotImplementedError("SRLI")
            elif funct7 == 0b0100000:
                raise NotImplementedError("SRAI")
    elif base_op == BaseOp.OP:
        if funct3 == 0b000:
            if funct7 == 0b0000000:
                raise NotImplementedError("ADD")
            elif funct7 == 0b0100000:
                raise NotImplementedError("SUB")
        elif funct3 == 0b001:
            raise NotImplementedError("SLL")
        elif funct3 == 0b010:
            raise NotImplementedError("SLT")
        elif funct3 == 0b011:
            raise NotImplementedError("SLTU")
        elif funct3 == 0b100:
            raise NotImplementedError("XOR")
        elif funct3 == 0b101:
            if funct7 == 0b0000000:
                raise NotImplementedError("SRL")
            elif funct7 == 0b0100000:
                raise NotImplementedError("SRA")
        elif funct3 == 0b110:
            raise NotImplementedError("OR")
        elif funct3 == 0b111:
            raise NotImplementedError("AND")
    elif base_op == BaseOp.FENCE:
        raise NotImplementedError("FENCE")
    elif base_op == BaseOp.SYSTEM:
        if funct3 == 0b001:
            debug.print_asm_csr_nop("CSRRW", cnt, regfile[PC], rd, funct12)
        elif funct3 == 0b010:
            debug.print_asm_csr_nop("CSRRS", cnt, regfile[PC], rd, funct12)
        elif funct3 == 0b011:
            debug.print_asm_csr_nop("CSRRC", cnt, regfile[PC], rd, funct12)
        elif funct3 == 0b101:
            debug.print_asm_csr_nop("CSRRWI", cnt, regfile[PC], rd, funct12)
        elif funct3 == 0b110:
            debug.print_asm_csr_nop("CSRRI", cnt, regfile[PC], rd, funct12)
        elif funct3 == 0b111:
            debug.print_asm_csr_nop("CSRRCI", cnt, regfile[PC], rd, funct12)
        else:
            raise NotImplementedError("SYSTEM")
        regfile[PC] += 4

    return True

    # ---- OLD ----
    #if op == BaseOp.JAL:
    #    # Instruction on J-format
    #    rd = get_rd(inst)
    #    imm = get_imm_j_type(inst)
    #    regfile[PC] += imm
    #    if rd == 0:
    #        pass
    #    else:
    #        raise NotImplementedError(str(op) + " rd != 0")
    #elif op == BaseOp.OP_IMM:
    #    # Instruction on I-format
    #    funct3 = get_funct3(inst)
    #    if funct3 == FUNCT3_ADDI:
    #        rs1 = get_rs1(inst)
    #        rd = get_rd(inst)
    #        imm = get_bits(inst, 20, 31) # TODO: Sign extend imm
    #        regfile[rd] = regfile[rs1] + imm
    #    else:
    #        raise NotImplementedError(str(op) + "/" + str(funct3))
    #    regfile[PC] += 4
    #elif op == BaseOp.SYSTEM:
    #    funct3 = get_funct3(inst)
    #    if funct3 == 0b000:
    #        funct12 = get_funct12(inst)
    #        if funct12 == 0b000000000000:
    #            pass # ECALL
    #        elif funct12 == 0b000000000001:
    #            pass # EBREAK
    #    elif funct3 == FUNCT3_CSRRW:
    #        raise NotImplementedError(str(op) + "/" + "CSRRW")
    #    elif funct3 == FUNCT3_CSRRS:
    #        # Atomic Read and Set Bit in CSR
    #        rd = get_rd(inst)
    #        rs1 = get_rs1(inst)
    #        csr = get_bits(inst, 20, 31)
    #    elif funct3 == FUNCT3_CSRRC:
    #        raise NotImplementedError(str(op) + "/" + "CSRRC")
    #    elif funct3 == FUNCT3_CSRWI:
    #        raise NotImplementedError(str(op) + "/" + "CSRRWI")
    #    elif funct3 == FUNCT3_CSRRSI:
    #        raise NotImplementedError(str(op) + "/" + "CSRRSI")
    #    elif funct3 == FUNCT3_CSRRCI:
    #        raise NotImplementedError(str(op) + "/" + "CSRRCI")
    #    else:
    #        raise NotImplementedError("Invalid instruction: " + str(op) + "funct3=" + str(funct3))
    #    regfile[PC] += 4
    #else:
    #    raise NotImplementedError(str(op))

    # (3) Instruction execute
    # (4) Access
    # (5) Write back
    #return True

def dump_regs():
    base_opcode = BaseOp(r32(regfile[PC]) & 0x7F)
    print("  PC: 0x%08x ins: 0x%08x, base_opcode: %s" % (regfile[PC], r32(regfile[PC]), base_opcode))
    for i in range (4):
        for j in range(8):
            reg = j + i*8
            print(" %3s: 0x%08x" % ("X" + str(reg), regfile[reg]), end="")
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
        cnt = 0
        running = True
        while running and step(cnt):
            if cnt > 100:
                running = False
            cnt += 1
    except NotImplementedError as e:
        print("Instruction not implemented yet: '" + str(e) + "', exiting.")
        dump_regs()
