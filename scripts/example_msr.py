import sys
import struct
from vmstate import *
import argparse

def create_state(is_write):
    state = VMState(0x86)
    state.setup_gdt()
    code = '\x0F\x30\xCC' if is_write else '\x0F\x32\xCC'
    addr = state.memory.allocate(len(code))
    state.memory.write(addr, code)
    state.regs.rip.value = addr
    return state

def rdmsr():
    return create_state(False)

def wrmsr():
    return create_state(True)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', required = True, choices = ('rdmsr', 'wrmsr'))
    parser.add_argument('-o', type = argparse.FileType('wb'), metavar = '/path/to/save', help = 'the destination file to save the state')
    args = parser.parse_args()
    state = globals()[args.t]()
    if not args.o:
        state.dump(True, False)
    else:
        args.o.write(state.raw())

