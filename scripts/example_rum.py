import sys
import struct
from vmstate import *
import argparse

def init_state():
    state = VMState(0x64)
    state.setup_paging() # IA-32e requires paging on
    state.setup_gdt()
    # update the segment registers for user mode
    state.load_seg(state.regs.cs, 0x10 | 3)
    state.load_seg(state.regs.ds, 0x20 | 3)
    state.load_seg(state.regs.es, 0x20 | 3)
    state.load_seg(state.regs.fs, 0x20 | 3)
    state.load_seg(state.regs.gs, 0x20 | 3)
    state.load_seg(state.regs.ss, 0x20 | 3)
    # enable smep
    state.regs.cr4.SMEP = 1
    # make sure GDT is allocated at the end
    assert state.regs.gdtr.base + state.regs.gdtr.limit + 1 == state.memory.allocate(0)
    return state

def setup_stack(state):
    # allocate memory for the stack
    addr = state.memory.allocate(0x100, 8)
    # init user-mode stack pointer
    state.regs.rsp.value = addr + 0x80
    # init kernel-mode stack pointer
    TSS64.from_buffer(state.memory, state.regs.tr.base).rsp0 = addr + 0x80

def callgate():
    state = init_state()
    # append an empty call gate
    callgate_addr = state.memory.allocate(sizeof(CallGateDesc64))
    callgate_selector = callgate_addr - state.regs.gdtr.base
    state.regs.gdtr.limit += sizeof(CallGateDesc64)
    # setup the stack for both user and kernel mode
    setup_stack(state)
    # make user code segment 32-bit (0x10)
    desc = SegDesc32.from_buffer(state.memory, state.regs.gdtr.base + 0x10)
    desc.l = 0 # disable long mode
    desc.db = 1 # enable 32-bit
    state.load_seg(state.regs.cs, 0x10 | 3)
    # inject user-mode far call
    farcall = '\x9a\x00\x00\x00\x00%s' % struct.pack('<H', callgate_selector)
    addr = state.memory.allocate(len(farcall))
    state.memory.write(addr, farcall)
    state.regs.rip.value = addr
    # inject kernel-mode int3 ladder to triple fault
    int3 = '\xcc' * 16
    addr = state.memory.allocate(len(int3))
    state.memory.write(addr, int3)
    # update call gate descriptor
    state.memory.write(callgate_addr, bytearray(CallGateDesc64(addr, 0x8, 0, 3, 1)))
    return state

def sysenter():
    state = init_state()
    # make user code segment 16-bit (0x10)
    desc = SegDesc32.from_buffer(state.memory, state.regs.gdtr.base + 0x10)
    desc.l = 0 # disable long mode
    desc.db = 0 # disable 32-bit
    state.load_seg(state.regs.cs, 0x10 | 3)
    # inject sysenter
    sysenter = '\x0f\x34'
    addr = state.memory.allocate(len(sysenter))
    state.memory.write(addr, sysenter)
    state.regs.rip.value = addr
    # inject int3 ladder to triple fault
    int3 = '\xcc' * 16
    addr = state.memory.allocate(len(int3))
    state.memory.write(addr, int3)
    # update sysenter MSRs
    state.regs.sysentercs.value = 0x8 # kernel CS descriptor
    state.regs.sysentereip.value = addr
    return state

def syscall():
    state = init_state()
    # append a new pair of KT/KD to the GDT
    kt_addr = state.memory.allocate(sizeof(SegDesc32))
    kt_sel = kt_addr - state.regs.gdtr.base
    state.memory.write(kt_addr, bytearray(SegDesc32(0, 0xfffff, 0b1011, 1, 0, 1, 0, 1, 0, 1)))
    kd_addr = state.memory.allocate(sizeof(SegDesc32))
    kd_sel = kd_addr - state.regs.gdtr.base
    state.memory.write(kd_addr, bytearray(SegDesc32(0, 0xfffff, 0b0011, 1, 0, 1, 0, 0, 1, 1)))
    state.regs.gdtr.limit += 2 * sizeof(SegDesc32)
    # setup IA32_STAR
    state.regs.star.value = (kt_sel << 32)
    # inject syscall
    syscall = '\x0F\x05'
    addr = state.memory.allocate(len(syscall))
    state.memory.write(addr, syscall)
    state.regs.rip.value = addr
    # inject int3 ladder in kernel
    int3 = '\xcc' * 16
    addr = state.memory.allocate(len(int3))
    state.memory.write(addr, int3)
    # setup IA32_LSTAR
    state.regs.lstar.value = addr
    return state

def popfs():
    state = init_state()
    # setup the fs segment selector on the stack
    setup_stack(state)
    state.memory.write(state.regs.rsp.value, '\x23\x00\x00\x00')
    # inject "pop fs"
    pop_fs = '\x0F\xA1'
    addr = state.memory.allocate(len(pop_fs))
    state.memory.write(addr, pop_fs)
    state.regs.rip.value = addr
    # inject int3 ladder
    int3 = '\xcc' * 16
    addr = state.memory.allocate(len(int3))
    state.memory.write(addr, int3)
    return state

def popss():
    state = init_state()
    # pop ss can only be executed in 32-bit environment
    desc = SegDesc32.from_buffer(state.memory, state.regs.gdtr.base + 0x10)
    desc.l = 0 # disable long mode
    desc.db = 1 # enable 32-bit
    state.load_seg(state.regs.cs, 0x10 | 3)
    # setup the stack segment selector on the stack
    setup_stack(state)
    state.memory.write(state.regs.rsp.value, '\x23\x00\x00\x00')
    # inject "pop ss"
    pop_ss = '\x17'
    addr = state.memory.allocate(len(pop_ss))
    state.memory.write(addr, pop_ss)
    state.regs.rip.value = addr
    # inject int3 ladder
    int3 = '\xcc' * 16
    addr = state.memory.allocate(len(int3))
    state.memory.write(addr, int3)
    return state

def iret():
    state = init_state()
    # make the user code segment 32-bit
    desc = SegDesc32.from_buffer(state.memory, state.regs.gdtr.base + 0x10)
    desc.l = 0 # disable long mode
    desc.db = 1 # enable 32-bit
    state.load_seg(state.regs.cs, 0x10 | 3)
    # inject iret
    iret = '\xCF'
    addr = state.memory.allocate(len(iret))
    state.memory.write(addr, iret)
    state.regs.rip.value = addr
    # inject int3 as the target of iret
    int3 = '\xcc' * 16
    addr = state.memory.allocate(len(int3))
    state.memory.write(addr, int3)
    # setup the stack for iret
    setup_stack(state)
    state.memory.write(state.regs.rsp.value, '%s\x13\x00\x00\x00\x02\x00\x00\x00' % struct.pack('<I', addr))
    return state

def retf():
    state = init_state()
    # make the user code segment 32-bit
    desc = SegDesc32.from_buffer(state.memory, state.regs.gdtr.base + 0x10)
    desc.l = 0 # disable long mode
    desc.db = 1 # enable 32-bit
    state.load_seg(state.regs.cs, 0x10 | 3)
    # inject iret
    retf = '\xCB'
    addr = state.memory.allocate(len(retf))
    state.memory.write(addr, retf)
    state.regs.rip.value = addr
    # inject int3 as the target of iret
    int3 = '\xcc' * 16
    addr = state.memory.allocate(len(int3))
    state.memory.write(addr, int3)
    # setup the stack for iret
    setup_stack(state)
    state.memory.write(state.regs.rsp.value, '%s\x13\x00\x00\x00' % struct.pack('<I', addr))
    return state

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', required = True, choices = ('sysenter', 'syscall', 'callgate', 'popfs', 'popss', 'iret', 'retf'), help = 'specify how to enter the kernel')
    parser.add_argument('-o', type = argparse.FileType('wb'), metavar = '/path/to/save', help = 'the destination file to save the state')
    args = parser.parse_args()
    state = globals()[args.t]()
    if not args.o:
        state.dump(True, False)
    else:
        args.o.write(state.raw())
