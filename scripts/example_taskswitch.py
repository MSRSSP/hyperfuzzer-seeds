import sys
import struct
import argparse
from vmstate import *

def create_vm():
    state = VMState(0x86)
    state.setup_gdt()
    return state

def setup_idt(state, dst_tss_sel):
    idt = [TaskGateDesc32(dst_tss_sel, 0, 0) if _ != 0x20 else TaskGateDesc32(dst_tss_sel, 0, 1) for _ in range(0x30)]
    raw = ''.join([str(bytearray(gate)) for gate in idt])
    idt_size = len(raw)
    idt_addr = state.memory.allocate(idt_size, 8)
    state.memory.write(idt_addr, raw)
    state.regs.idtr.base = idt_addr
    state.regs.idtr.limit = idt_size - 1

def main(trigger, same_task = False):
    state = create_vm()
    # obtain the source TSS
    src_tss_sel = 0x28
    src_tss_desc = lambda: TssDesc32.from_buffer(state.memory, state.regs.gdtr.base + src_tss_sel)
    src_tss_addr = src_tss_desc().base()
    src_tss = lambda: TSS32.from_buffer(state.memory, src_tss_addr)
    if same_task:
        dst_tss_sel = src_tss_sel
        dst_tss_addr = src_tss_addr
    else:
        # repurpose UT (0x10) for the destination TSS desc
        dst_tss_sel = 0x10
        dst_tss_addr = state.memory.allocate(sizeof(TSS32))
        pointer(TssDesc32.from_buffer(state.memory, state.regs.gdtr.base + 0x10))[0] = TssDesc32(dst_tss_addr, sizeof(TSS32) - 1, 0, 0, 1, 0, 0)
    dst_tss_desc = lambda: TssDesc32.from_buffer(state.memory, state.regs.gdtr.base + dst_tss_sel)
    dst_tss = lambda: TSS32.from_buffer(state.memory, dst_tss_addr)
    # setup the minimal destination TSS
    dst_tss().cs = state.regs.cs.selector
    dst_tss().ss = state.regs.ss.selector
    dst_tss().cr3 = state.regs.cr3.value
    # prepare the rest of the state accordingly
    if trigger == 'iret':
        state.regs.eflags.NT = 1
        src_tss().prev_task_link = dst_tss_sel
        dst_tss_desc().type = 0b1011
        code = '\xcf' # IRET
    elif trigger == 'jmp':
        code ='\xea\x00\x00\x00\x00' + struct.pack('<H', dst_tss_sel)
    elif trigger == 'call':
        code = '\x9a\x00\x00\x00\x00' + struct.pack('<H', dst_tss_sel)
    elif trigger == 'vector':
        setup_idt(state, dst_tss_sel)
        code = '\xcd\x20'
    # write the code bytes and set the EIP
    eip = state.memory.allocate(len(code))
    state.memory.write(eip, code)
    state.regs.rip.value = eip
    # allocate halt instruction
    halt = state.memory.allocate(1)
    state.memory.write(halt, '\xcc')
    dst_tss().eip = halt
    return state

if __name__ == '__main__':
    # parse arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', required = True, choices = ('iret', 'jmp', 'call', 'vector'), help = 'specify how a task switch is triggered')
    parser.add_argument('-s', action = 'store_true', default = False, help = 'whether to use the same TSS for task switch')
    parser.add_argument('-o', type = argparse.FileType('wb'), metavar = '/path/to/save', help = 'the destination file to save the state')
    args = parser.parse_args()
    # construct the state
    state = main(args.t, args.s)
    if not args.o:
        state.dump(True, False)
    else:
        args.o.write(state.raw())
