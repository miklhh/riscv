#!/usr/bin/env python
#
# RISC-V single core RV32I simulator (assembly debug scatter printer).
# The RV32I ISA is described in detail in 'The RISC-V Instruction Set Manual, Volume I: Unpriviledge ISA' and this
# simulator is based on Document Version 2019-12-13. A copy of this document can be found under
# 'documents/riscv-spec-20191213.pdf'.
#
# Author: Mikael Henriksson
#


# Convert a immediate to 32-bit two's complement hex string
def _imm_to_hex(x):
    return hex(x)

def print_asm_head(cnt, pc):
    print("i=" + str(cnt).ljust(8) + "|  PC=" + _imm_to_hex(pc) + "  | ", end="")

def reg_str(reg_nr):
    return ("X"+str(reg_nr)).rjust(3)

def print_asm_di(op, cnt, pc, rd, imm):
    print_asm_head(cnt, pc)
    print(op.ljust(7) + reg_str(rd) + ", " + _imm_to_hex(imm))

def print_asm_ds(op, cnt, pc, rd, rs1):
    print_asm_head(cnt, pc)
    print(op.ljust(7) + reg_str(rd) + ", " + reg_str(rs1))

def print_asm_dss(op, cnt, pc, rd, rs1, rs2):
    print_asm_head(cnt, pc)
    print(op.ljust(7) + reg_str(rd) + ", " + reg_str(rs1) + ", " + reg_str(rs2))

def print_asm_dsi(op, cnt, pc, rd, rs1, imm):
    print_asm_head(cnt, pc)
    print(op.ljust(7) + reg_str(rd) + ", " + reg_str(rs1) + ", " + _imm_to_hex(imm))

def print_asm_ssi(op, cnt, pc, rs1, rs2, imm):
    print_asm_head(cnt, pc)
    print(op.ljust(7) + reg_str(rs1) + ", " + reg_str(rs2) + ", " + _imm_to_hex(imm))


def print_asm_dssi(op, cnt, pc, rd, rs1, rs2, imm):
    print_asm_head(cnt, pc)
    print(op.ljust(7) + reg_str(rd) + ", " + reg_str(rs1) + ", " + reg_str(rs2) + ", " + _imm_to_hex(imm))


#
# opcode JAL
#
def print_asm_jal(cnt, pc, rd, imm):
    print_asm_head(cnt, pc)
    print(("J" if rd == 0 else "JAL").ljust(6) + _imm_to_hex(pc + imm))


#
# opcode OP-IMM
#
def print_asm_addi(cnt, pc, rd, rs1, imm):
    print_asm_head(cnt, pc)
    if rs1 == 0:
        print("LI".ljust(7) + reg_str(rd) + ", " + _imm_to_hex(imm))
    elif  imm == 0:
        print("MV".ljust(7) + reg_str(rd) + ", " + reg_str(rs1))
    else:
        print("ADDI".ljust(7) + reg_str(rd) + ", " + reg_str(rs1) + ", " + _imm_to_hex(imm))

#
# opcode SYSTEM
#
def print_asm_csr_nop(op, cnt, pc, rd, funct12):
    print_asm_head(cnt, pc)
    print(op.ljust(7) + reg_str(rd) + ", " + str(funct12) + " [CURRENTLY NOP]")

