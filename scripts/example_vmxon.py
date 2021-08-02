import argparse
from vmstate import *

def create_state():
    state = VMState(0x86)
    state.setup_paging()
    vmxon_region = state.memory.allocate(PGSIZE, PGSIZE)
    state.memory.write(vmxon_region, '\x01')
    state.setup_gdt()
    addr = state.memory.allocate(8)
    state.memory.write(addr, struct.pack('<Q', vmxon_region))
    code = "\xF3\x0F\xC7\x35" + struct.pack('<I', addr)
    state.regs.cr4.VMXE = 1
    state.regs.cr0.NE = 1
    state.regs.rip.value = state.memory.allocate(len(code))
    state.memory.write(state.regs.rip.value, code)
    return state

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-o', type = argparse.FileType('wb'), metavar = '/path/to/save', help = 'the destination file to save the state')
    args = parser.parse_args()
    state = create_state()
    if not args.o:
        state.dump(True, False)
    else:
        args.o.write(state.raw())