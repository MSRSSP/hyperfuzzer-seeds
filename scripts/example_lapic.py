import sys
import random
import struct
import argparse
import os
from vmstate import *

APICBASE = 0xFEE00000

READOFF = (0x20, 0x23, 0x30, 0x80, 0xb0, 0xa0, 0xd0, 0xd3, 0xe0, 0xe3,
           0xf0, 0x100, 0x110, 0x120, 0x130, 0x140, 0x150, 0x160, 0x170,
           0x180, 0x190, 0x1a0, 0x1b0, 0x1c0, 0x1d0, 0x1e0, 0x1f0, 0x200,
           0x210, 0x220, 0x230, 0x240, 0x250, 0x260, 0x270, 0x280, 0x300,
           0x310, 0x320, 0x330, 0x340, 0x350, 0x360, 0x370, 0x380, 0x390,
           0x3e0, 0x2f0)

WRITEOFF = (0x20, 0x80, 0xb0, 0xd0, 0xd3, 0xe0, 0xe3, 0xf0, 0x280, 0x300,
            0x310, 0x320, 0x330, 0x340, 0x350, 0x360, 0x370, 0x380, 0x390,
            0x3e0, 0x3f0, 0x2f0)

rand32 = lambda: random.randint(0, 0xffffffff)

def init_state():
    state = VMState(0x86)
    state.setup_gdt()
    addr = state.memory.allocate(64)
    state.regs.rsp.value = addr + 64
    state.regs.rcx.value = 1 # loop once for string instructions
    return state

def load(state, code):
    code += '\xcc' * 16 # append an INT3 ladder to stop
    addr = state.memory.allocate(len(code))
    state.memory.write(addr, code)
    state.regs.rip.value = addr
    return state

def alu_write(opcode):
    states = []
    for off in WRITEOFF:
        state = init_state()
        state.regs.rax.value = APICBASE + off
        state.regs.rbx.value = rand32()
        states.append(load(state, struct.pack('<BB', opcode, 0x18)))
    return states

def alu_read(opcode):
    states = []
    for off in READOFF:
        state = init_state()
        state.regs.rax.value = APICBASE + off
        states.append(load(state, struct.pack('<BB', opcode, 0)))
    return states

def pushf(opcode):
    states = []
    for off in WRITEOFF:
        state = init_state()
        state.regs.rsp.value = APICBASE + off
        states.append(load(state, struct.pack('<B', opcode)))
    return states

def popf(opcode):
    states = []
    for off in READOFF:
        state = init_state()
        state.regs.rsp.value = APICBASE + off
        states.append(load(state, struct.pack('<B', opcode)))
    return states

def mov_read(opcode):
    states = []
    for off in READOFF:
        state = init_state()
        states.append(load(state, struct.pack('<BI', opcode, APICBASE + off)))
    return states

def mov_write(opcode):
    states = []
    for off in WRITEOFF:
        state = init_state()
        state.regs.rax.value = rand32()
        states.append(load(state, struct.pack('<BI', opcode, APICBASE + off)))
    return states

def movs(opcode):
    states = []
    for roff in READOFF:
        for woff in WRITEOFF:
            state = init_state()
            state.regs.rsi.value = APICBASE + roff
            state.regs.rdi.value = APICBASE + woff
            states.append(load(state, struct.pack('<B', opcode)))
    return states

def cmps(opcode):
    states = []
    for off1 in READOFF:
        for off2 in READOFF:
            state = init_state()
            state.regs.rsi.value = APICBASE + off1
            state.regs.rdi.value = APICBASE + off2
            states.append(load(state, struct.pack('<B', opcode)))
    return states

def stos(opcode):
    states = []
    for off in WRITEOFF:
        state = init_state()
        state.regs.rax.value = rand32()
        state.regs.rdi.value = APICBASE + off
        states.append(load(state, struct.pack('<B', opcode)))
    return states

def loads(opcode):
    states = []
    for off in READOFF:
        state.regs.rsi.value = APICBASE + off
        states.append(load(state, struct.pack('<B', opcode)))
    return states

def scas(opcode):
    states = []
    for off in WRITEOFF:
        state = init_state()
        state.regs.rdi.value = APICBASE + off
        states.append(load(state, struct.pack('<B', opcode)))
    return states

OPCODES = [(0x00, alu_write), # MOV EAX, TARGET; MOV EBX, VALUE; ADD  [EAX], BL
           (0x01, alu_write), # MOV EAX, TARGET; MOV EBX, VALUE; ADD  [EAX], EBX
           (0x08, alu_write), # MOV EAX, TARGET; MOV EBX, VALUE; OR   [EAX], BL
           (0x09, alu_write), # MOV EAX, TARGET; MOV EBX, VALUE; OR   [EAX], EBX
           (0x10, alu_write), # MOV EAX, TARGET; MOV EBX, VALUE; ADC  [EAX], BL
           (0x11, alu_write), # MOV EAX, TARGET; MOV EBX, VALUE; ADC  [EAX], EBX
           (0x18, alu_write), # MOV EAX, TARGET; MOV EBX, VALUE; SBB  [EAX], BL
           (0x19, alu_write), # MOV EAX, TARGET; MOV EBX, VALUE; SBB  [EAX], EBX
           (0x20, alu_write), # MOV EAX, TARGET; MOV EBX, VALUE; AND  [EAX], BL
           (0x21, alu_write), # MOV EAX, TARGET; MOV EBX, VALUE; AND  [EAX], EBX
           (0x28, alu_write), # MOV EAX, TARGET; MOV EBX, VALUE; SUB  [EAX], BL
           (0x29, alu_write), # MOV EAX, TARGET; MOV EBX, VALUE; SUB  [EAX], EBX
           (0x30, alu_write), # MOV EAX, TARGET; MOV EBX, VALUE; XOR  [EAX], BL
           (0x31, alu_write), # MOV EAX, TARGET; MOV EBX, VALUE; XOR  [EAX], EBX
           (0x38, alu_write), # MOV EAX, TARGET; MOV EBX, VALUE; CMP  [EAX], BL
           (0x39, alu_write), # MOV EAX, TARGET; MOV EBX, VALUE; CMP  [EAX], EBX
           (0x86, alu_write), # MOV EAX, TARGET; MOV EBX, VALUE; XCHG [EAX], BL
           (0x87, alu_write), # MOV EAX, TARGET; MOV EBX, VALUE; XCHG [EAX], EBX
           (0x88, alu_write), # MOV EAX, TARGET; MOV EBX, VALUE; MOV  [EAX], BL
           (0x89, alu_write), # MOV EAX, TARGET; MOV EBX, VALUE; MOV  [EAX], EBX
           (0x02, alu_read), # MOV EAX, TARGET; ADD  AL,  [EAX]
           (0x03, alu_read), # MOV EAX, TARGET; ADD  EAX, [EAX]
           (0x0a, alu_read), # MOV EAX, TARGET; OR   AL,  [EAX]
           (0x0b, alu_read), # MOV EAX, TARGET; OR   EAX, [EAX]
           (0x12, alu_read), # MOV EAX, TARGET; ADC  AL,  [EAX]
           (0x13, alu_read), # MOV EAX, TARGET; ADC  EAX, [EAX]
           (0x1a, alu_read), # MOV EAX, TARGET; SBB  AL,  [EAX]
           (0x1b, alu_read), # MOV EAX, TARGET; SBB  EAX, [EAX]
           (0x22, alu_read), # MOV EAX, TARGET; AND  AL,  [EAX]
           (0x23, alu_read), # MOV EAX, TARGET; AND  EAX, [EAX]
           (0x2a, alu_read), # MOV EAX, TARGET; SUB  AL,  [EAX]
           (0x2b, alu_read), # MOV EAX, TARGET; SUB  EAX, [EAX]
           (0x32, alu_read), # MOV EAX, TARGET; XOR  AL,  [EAX]
           (0x33, alu_read), # MOV EAX, TARGET; XOR  EAX, [EAX]
           (0x3a, alu_read), # MOV EAX, TARGET; CMP  AL,  [EAX]
           (0x3b, alu_read), # MOV EAX, TARGET; CMP  EAX, [EAX]
           (0x84, alu_read), # MOV EAX, TARGET; TEST AL,  [EAX]
           (0x85, alu_read), # MOV EAX, TARGET; TEST EAX, [EAX]
           (0x8a, alu_read), # MOV EAX, TARGET; MOV  AL,  [EAX]
           (0x8b, alu_read), # MOV EAX, TARGET; MOV  EAX, [EAX]
           (0x9c, pushf), # MOV ESP, TARGET; PUSHF
           (0x9d, popf), # MOV ESP, TARGET; POPF
           (0xa0, mov_read), # MOV AL,  [TARGET]
           (0xa1, mov_read), # MOV EAX, [TARGET]
           (0xa2, mov_write), # MOV EAX, VALUE; MOV [TARGET], AL
           (0xa3, mov_write), # MOV EAX, VALUE; MOV [TARGET], EAX
           (0xa4, movs), # MOV, ESI, TARGET; MOV EDI, TARGET; MOVSB
           (0xa5, movs), # MOV, ESI, TARGET; MOV EDI, TARGET; MOVSW
           (0xa6, cmps), # MOV, ESI, TARGET; MOV EDI, TARGET; CMPSB
           (0xa7, cmps), # MOV, ESI, TARGET; MOV EDI, TARGET; CMPSW
           (0xaa, stos), # MOV EAX, VALUE; MOV EDI, TARGET; STOSB
           (0xab, stos), # MOV EAX, VALUE; MOV EDI, TARGET; STOSW
           (0xac, loads), # MOV ESI, TARGET; LOADSB
           (0xad, loads), # MOV ESI, TARGET; LOADSW
           (0xae, scas), # MOV EDI, TARGET; SCASB
           (0xaf, scas)] # MOV EDI, TARGET; SCASW

if __name__ == '__main__':
    # parse arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-b', type = lambda b: int(b, 0), dest = 'base', default = 0xFEE00000, help = 'APIC base address')
    parser.add_argument('-o', type = str, dest = 'path', required = True, metavar = '/path/to/seed/folder', help = 'Where to save the seeds')
    args = parser.parse_args()
    # reset APICBASE
    APICBASE = args.base
    # ensure an output directory is provided
    if not os.path.isdir(args.path):
        print '%s must be a directory' % args.path
        sys.exit(0)
    # generate the VM states
    index = 0
    for (opcode, func) in OPCODES:
        for state in func(opcode):
            index += 1
            with open('%s/apic%04d.bin' % (args.path, index), 'wb') as f:
                f.write(state.raw())
