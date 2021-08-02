import os
import sys
import struct
from ctypes import *

PGSIZE = 0x1000

def dumps(struct):
    assert isinstance(struct, Structure)
    ans = ['{']
    for field_info in struct._fields_:
        field = getattr(struct, field_info[0])
        if isinstance(field, Structure):
            ans.append('%s:' % (field_info[0]))
            ans.append(dumps(field))
        else:
            ans.append('%s:%s' % (field_info[0], hex(field)))
    ans.append('}')
    return ' '.join(ans)

class TSS32(Structure):
    _pack_ = 1
    _fields_ = [('prev_task_link', c_uint16),
                ('rsvd0', c_uint16),
                ('esp0', c_uint32),
                ('ss0', c_uint16),
                ('rsvd1', c_uint16),
                ('esp1', c_uint32),
                ('ss1', c_uint16),
                ('rsvd2', c_uint16),
                ('esp2', c_uint32),
                ('ss2', c_uint16),
                ('rsvd3', c_uint16),
                ('cr3', c_uint32),
                ('eip', c_uint32),
                ('eflags', c_uint32),
                ('eax', c_uint32),
                ('ecx', c_uint32),
                ('edx', c_uint32),
                ('ebx', c_uint32),
                ('esp', c_uint32),
                ('ebp', c_uint32),
                ('esi', c_uint32),
                ('edi', c_uint32),
                ('es', c_uint16),
                ('rsvd4', c_uint16),
                ('cs', c_uint16),
                ('rsvd5', c_uint16),
                ('ss', c_uint16),
                ('rsvd6', c_uint16),
                ('ds', c_uint16),
                ('rsvd7', c_uint16),
                ('fs', c_uint16),
                ('rsvd8', c_uint16),
                ('gs', c_uint16),
                ('rsvd9', c_uint16),
                ('ldt_selector', c_uint16),
                ('rsvd10', c_uint16),
                ('T', c_uint16, 1),
                ('rsvd11', c_uint16, 15),
                ('io_map_base', c_uint16)]

assert sizeof(TSS32) == 104

class TSS64(Structure):
    _pack_ = 1
    _fields_ = [('rsvd0', c_uint32),
                ('rsp0', c_uint64),
                ('rsp1', c_uint64),
                ('rsp2', c_uint64),
                ('rsvd1', c_uint64),
                ('ist1', c_uint64),
                ('ist2', c_uint64),
                ('ist3', c_uint64),
                ('ist4', c_uint64),
                ('ist5', c_uint64),
                ('ist6', c_uint64),
                ('ist7', c_uint64),
                ('rsvd2', c_uint64),
                ('rsvd3', c_uint16),
                ('io_map_base', c_uint16)]

assert sizeof(TSS64) == 104

class IntGateDesc32(Structure):
    _pack_ = 1
    _fields_ = [('offset0_15', c_uint16),
                ('selector', c_uint16),
                ('rsvd0', c_uint8),
                ('type', c_uint8, 3),
                ('d', c_uint8, 1),
                ('s', c_uint8, 1),
                ('dpl', c_uint8, 2),
                ('p', c_uint8, 1),
                ('offset16_31', c_uint16)]

    def __init__(self, offset = 0, selector = 0, d = 1, dpl = 0, p = 0):
        self.offset0_15 = offset & 0xffff
        self.offset16_31 = (offset >> 16) & 0xffff
        self.selector = selector
        self.type = 0b110
        self.d = d
        self.s = 0
        self.dpl = dpl
        self.p = p

    def offset(self):
        return self.offset0_15 | (self.offset16_31 << 16)

assert sizeof(IntGateDesc32) == 8

class IntGateDesc64(IntGateDesc32):
    _pack_ = 1
    _fields_ = [('offset32_63', c_uint32),
                ('rsvd', c_uint32)]

    def __init__(self, offset = 0, selector = 0, d = 1, dpl = 0, p = 0):
        self.offset32_63 = (offset >> 32) & 0xffffffff
        IntGateDesc32.__init__(self, offset & 0xffffffff, selector, d, dpl, p)

    def offset(self):
        return IntGateDesc32.offset(self) | (self.offset32_63 << 32)

assert sizeof(IntGateDesc64) == 16

class TrapGateDesc32(IntGateDesc32):
    def __init__(self, offset = 0, selector = 0, d = 1, dpl = 0, p = 0):
        IntGateDesc32.__init__(self, offset, selector, d, dpl, p)
        self.type = 0b111

assert sizeof(TrapGateDesc32) == 8

class TrapGateDesc64(TrapGateDesc32):
    _pack_ = 1
    _fields_ = [('offset32_63', c_uint32),
                ('rsvd', c_uint32)]

    def __init__(self, offset = 0, selector = 0, d = 1, dpl = 0, p = 0):
        self.offset32_63 = (offset >> 32) & 0xffffffff
        TrapGateDesc32.__init__(self, offset & 0xffffffff, selector, d, dpl, p)

    def offset(self):
        return TrapGateDesc32.offset(self) | (self.offset32_63 << 32)

assert sizeof(TrapGateDesc64) == 16

class CallGateDesc32(Structure):
    _pack_ = 1
    _fields_ = [('offset0_15', c_uint16),
                ('selector', c_uint16),
                ('param_count', c_uint8, 5),
                ('rsvd0', c_uint8, 3),
                ('type', c_uint8, 4),
                ('s', c_uint8, 1),
                ('dpl', c_uint8, 2),
                ('p', c_uint8, 1),
                ('offset16_31', c_uint16)]

    def __init__(self, offset = 0, selector = 0, param_count = 0, dpl = 0, p = 0):
        self.offset0_15 = offset & 0xffff
        self.offset16_31 = (offset >> 16) & 0xffff
        self.selector = selector
        self.type = 0b1100
        self.s = 0
        self.param_count = param_count
        self.dpl = dpl
        self.p = p

    def offset(self):
        return self.offset0_15 | (self.offset16_31 << 16)

assert sizeof(CallGateDesc32) == 8

class CallGateDesc64(CallGateDesc32):
    _pack_ = 1
    _fields_ = [('offset32_63', c_uint32),
                ('rsvd', c_uint32)]

    def __init__(self, offset = 0, selector = 0, param_count = 0, dpl = 0, p = 0):
        self.offset32_63 = (offset >> 32) & 0xffffffff
        CallGateDesc32.__init__(self, offset & 0xffffffff, selector, param_count, dpl, p)

    def offset(self):
        return CallGateDesc32.offset(self) | (self.offset32_63 << 32)

assert sizeof(CallGateDesc64) == 16

class TaskGateDesc32(Structure):
    _pack_ = 1
    _fields_ = [('rsvd0', c_uint16),
                ('selector', c_uint16),
                ('rsvd1', c_uint8),
                ('type', c_uint8, 4),
                ('s', c_uint8, 1),
                ('dpl', c_uint8, 2),
                ('p', c_uint8, 1),
                ('rsvd2', c_uint16)]

    def __init__(self, selector = 0, dpl = 0, p = 0):
        self.selector = selector
        self.type = 0b0101
        self.dpl = dpl
        self.p = p

assert sizeof(TaskGateDesc32) == 8

class SegDesc32(Structure):
    _pack_ = 1
    _fields_ = [('limit0_15', c_uint16),
                ('base0_15', c_uint16),
                ('base16_23', c_uint8),
                ('type', c_uint8, 4),
                ('s', c_uint8, 1),
                ('dpl', c_uint8, 2),
                ('p', c_uint8, 1),
                ('limit16_19', c_uint8, 4),
                ('avl', c_uint8, 1),
                ('l', c_uint8, 1),
                ('db', c_uint8, 1),
                ('g', c_uint8, 1),
                ('base24_31', c_uint8)]

    def __init__(self, base = 0, limit = 0, type = 0, s = 0, dpl = 0, p = 0, avl = 0, l = 0, db = 0, g = 0):
        self.base0_15 = base & 0xffff
        self.base16_23 = (base >> 16) & 0xff
        self.base24_31 = (base >> 24) & 0xff
        self.limit0_15 = limit & 0xffff
        self.limit16_19 = (limit >> 16) & 0xf
        self.type = type
        self.s = s
        self.dpl = dpl
        self.p = p
        self.avl = avl
        self.l = l
        self.db = db
        self.g = g

    def base(self):
        return self.base0_15 | (self.base16_23 << 16) | (self.base24_31 << 24)

    def limit(self):
        return self.limit0_15 | (self.limit16_19 << 16)

assert sizeof(SegDesc32) == 8

class TssDesc32(SegDesc32):
    def __init__(self, base = 0, limit = 0, b = 0, dpl = 0, p = 0, avl = 0, g = 0):
        type = 0b1001 | (b << 1)
        SegDesc32.__init__(self, base, limit, type, 0, dpl, p, avl, 0, 0, g)

assert sizeof(TssDesc32) == 8

class TssDesc64(TssDesc32):
    _pack_ = 1
    _fields_ = [('base32_63', c_uint32),
                ('rsvd', c_uint32)]

    def __init__(self, base = 0, limit = 0, b = 0, dpl = 0, p = 0, avl = 0, g = 0):
        self.base32_63 = (base >> 32) & 0xffffffff
        TssDesc32.__init__(self, base & 0xffffffff, limit, b, dpl, p, avl, g)

    def base(self):
        return TssDesc32.base(self) | (self.base32_63 << 32)

assert sizeof(TssDesc64) == 16

class PDE32(Structure):
    _pack_ = 1
    _fields_ = [('p', c_uint32, 1),
                ('w', c_uint32, 1),
                ('u', c_uint32, 1),
                ('pwt', c_uint32, 1),
                ('pcd', c_uint32, 1),
                ('a', c_uint32, 1),
                ('rsvd0', c_uint32, 1),
                ('ps', c_uint32, 1),
                ('rsvd1', c_uint32, 4),
                ('pfn', c_uint32, 20)]

assert sizeof(PDE32) == 4

class PTE32(Structure):
    _pack_ = 1
    _fields_ = [('p', c_uint32, 1),
                ('w', c_uint32, 1),
                ('u', c_uint32, 1),
                ('pwt', c_uint32, 1),
                ('pcd', c_uint32, 1),
                ('a', c_uint32, 1),
                ('d', c_uint32, 1),
                ('pat', c_uint32, 1),
                ('g', c_uint32, 1),
                ('rsvd1', c_uint32, 3),
                ('pfn', c_uint32, 20)]

assert sizeof(PTE32) == 4

class PML4E(Structure):
    _pack_ = 1
    _fields_ = [('p', c_uint64, 1),
                ('w', c_uint64, 1),
                ('u', c_uint64, 1),
                ('pwt', c_uint64, 1),
                ('pcd', c_uint64, 1),
                ('a', c_uint64, 1),
                ('rsvd0', c_uint64, 6),
                ('pfn', c_uint64, 40),
                ('rsvd1', c_uint64, 11),
                ('xd', c_uint64, 1)]

assert sizeof(PML4E) == 8

class PDPTE(Structure):
    _pack_ = 1
    _fields_ = [('p', c_uint64, 1),
                ('w', c_uint64, 1),
                ('u', c_uint64, 1),
                ('pwt', c_uint64, 1),
                ('pcd', c_uint64, 1),
                ('a', c_uint64, 1),
                ('d', c_uint64, 1),
                ('ps', c_uint64, 1),
                ('g', c_uint64, 1),
                ('rsvd0', c_uint64, 3),
                ('pfn', c_uint64, 40),
                ('rsvd1', c_uint64, 11),
                ('xd', c_uint64, 1)]

assert sizeof(PDPTE) == 8

class PDE64(Structure):
    _pack_ = 1
    _fields_ = [('p', c_uint64, 1),
                ('w', c_uint64, 1),
                ('u', c_uint64, 1),
                ('pwt', c_uint64, 1),
                ('pcd', c_uint64, 1),
                ('a', c_uint64, 1),
                ('rsvd0', c_uint64, 1),
                ('ps', c_uint64, 1),
                ('rsvd1', c_uint64, 4),
                ('pfn', c_uint64, 40),
                ('rsvd2', c_uint64, 11),
                ('xd', c_uint64, 1)]

assert sizeof(PDE64) == 8

class PTE64(Structure):
    _pack_ = 1
    _fields_ = [('p', c_uint64, 1),
                ('w', c_uint64, 1),
                ('u', c_uint64, 1),
                ('pwt', c_uint64, 1),
                ('pcd', c_uint64, 1),
                ('a', c_uint64, 1),
                ('d', c_uint64, 1),
                ('pat', c_uint64, 1),
                ('g', c_uint64, 1),
                ('rsvd0', c_uint64, 3),
                ('pfn', c_uint64, 40),
                ('rsvd2', c_uint64, 7),
                ('pkey', c_uint64, 4),
                ('xd', c_uint64, 1)]

assert sizeof(PTE64) == 8

class RegCr0(Structure):
    _pack_ = 1
    _fields_ = [('PE', c_uint32, 1),
                ('MP', c_uint32, 1),
                ('EM', c_uint32, 1),
                ('TS', c_uint32, 1),
                ('ET', c_uint32, 1),
                ('NE', c_uint32, 1),
                ('rsvd0', c_uint32, 10),
                ('WP', c_uint32, 1),
                ('rsvd1', c_uint32, 1),
                ('AM', c_uint32, 1),
                ('rsvd2', c_uint32, 10),
                ('NW', c_uint32, 1),
                ('CD', c_uint32, 1),
                ('PG', c_uint32, 1)]

assert sizeof(RegCr0) == 4

class RegCr4(Structure):
    _pack_ = 1
    _fields_ = [('VME', c_uint32, 1),
                ('PVI', c_uint32, 1),
                ('TSD', c_uint32, 1),
                ('DE', c_uint32, 1),
                ('PSE', c_uint32, 1),
                ('PAE', c_uint32, 1),
                ('MCE', c_uint32, 1),
                ('PGE', c_uint32, 1),
                ('PCE', c_uint32, 1),
                ('OSFXSR', c_uint32, 1),
                ('OSXMMEXCPT', c_uint32, 1),
                ('UMIP', c_uint32, 1),
                ('rsvd0', c_uint32, 1),
                ('VMXE', c_uint32, 1),
                ('SMXE', c_uint32, 1),
                ('rsvd1', c_uint32, 1),
                ('FSGSBASE', c_uint32, 1),
                ('PCIDE', c_uint32, 1),
                ('OSXSAVE', c_uint32, 1),
                ('rsvd2', c_uint32, 1),
                ('SMEP', c_uint32, 1),
                ('SMAP', c_uint32, 1),
                ('PKE', c_uint32, 1),
                ('rsvd3', c_uint32, 9)]

assert sizeof(RegCr4) == 4

class RegEflags(Structure):
    _pack_ = 1
    _fields_ = [('CF', c_uint32, 1),
                ('one', c_uint32, 1),
                ('PF', c_uint32, 1),
                ('rsvd0', c_uint32, 1),
                ('AF', c_uint32, 1),
                ('rsvd1', c_uint32, 1),
                ('ZF', c_uint32, 1),
                ('SF', c_uint32, 1),
                ('TF', c_uint32, 1),
                ('IF', c_uint32, 1),
                ('DF', c_uint32, 1),
                ('OF', c_uint32, 1),
                ('IOPL', c_uint32, 2),
                ('NT', c_uint32, 1),
                ('rsvd2', c_uint32, 1),
                ('RF', c_uint32, 1),
                ('VM', c_uint32, 1),
                ('AC', c_uint32, 1),
                ('VIF', c_uint32, 1),
                ('VIP', c_uint32, 1),
                ('ID', c_uint32, 1),
                ('rsvd3', c_uint32, 10)]

    def __init__(self):
        self.one = 1

assert sizeof(RegEflags) == 4

class RegEfer(Structure):
    _fields_ = [('SCE', c_uint32, 1),
                ('rsvd0', c_uint32, 7),
                ('LME', c_uint32, 1),
                ('rsvd1', c_uint32, 1),
                ('LMA', c_uint32, 1),
                ('NXE', c_uint32, 1),
                ('rsvd2', c_uint32, 20)]

assert sizeof(RegEfer) == 4

class Reg32(Structure):
    _fields_ = [('value', c_uint32)]

assert sizeof(Reg32) == 4

class Reg64(Structure):
    _pack_ = 1
    _fields_ = [('value', c_uint64)]

assert sizeof(Reg64) == 8

class Reg128(Structure):
    _pack_ = 1
    _fields_ = [('low', c_uint64),
                ('high', c_uint64)]

assert sizeof(Reg128) == 16

class RegTable32(Structure):
    _pack_ = 1
    _fields_ = [('base', c_uint32),
                ('limit', c_uint16)]

assert sizeof(RegTable32) == 6

class RegTable64(Structure):
    _pack_ = 1
    _fields_ = [('base', c_uint64),
                ('limit', c_uint16)]

assert sizeof(RegTable64) == 10

class RegSeg32(Structure):
    _pack_ = 1
    _fields_ = [('base', c_uint32),
                ('limit', c_uint32),
                ('selector', c_uint16),
                ('type', c_uint16, 4),
                ('s', c_uint16, 1),
                ('dpl', c_uint16, 2),
                ('p', c_uint16, 1),
                ('rsvd0', c_uint16, 4),
                ('avl', c_uint16, 1),
                ('l', c_uint16, 1),
                ('db', c_uint16, 1),
                ('g', c_uint16, 1)]

assert sizeof(RegSeg32) == 12

class RegSeg64(Structure):
    _pack_ = 1
    _fields_ = [('base', c_uint64),
                ('limit', c_uint32),
                ('selector', c_uint16),
                ('type', c_uint16, 4),
                ('s', c_uint16, 1),
                ('dpl', c_uint16, 2),
                ('p', c_uint16, 1),
                ('rsvd0', c_uint16, 4),
                ('avl', c_uint16, 1),
                ('l', c_uint16, 1),
                ('db', c_uint16, 1),
                ('g', c_uint16, 1)]

assert sizeof(RegSeg64) == 16

class RegFile(Structure):
    _pack_ = 1
    _fields_ = [('rax', Reg64),
                ('rcx', Reg64),
                ('rdx', Reg64),
                ('rbx', Reg64),
                ('rsp', Reg64),
                ('rbp', Reg64),
                ('rsi', Reg64),
                ('rdi', Reg64),
                ('r8', Reg64),
                ('r9', Reg64),
                ('r10', Reg64),
                ('r11', Reg64),
                ('r12', Reg64),
                ('r13', Reg64),
                ('r14', Reg64),
                ('r15', Reg64),
                ('rip', Reg64),
                ('eflags', RegEflags),
                ('es', RegSeg64),
                ('cs', RegSeg64),
                ('ss', RegSeg64),
                ('ds', RegSeg64),
                ('fs', RegSeg64),
                ('gs', RegSeg64),
                ('tr', RegSeg64),
                ('idtr', RegTable64),
                ('gdtr', RegTable64),
                ('cr0', RegCr0),
                ('cr2', Reg64),
                ('cr3', Reg64),
                ('cr4', RegCr4),
                ('dr0', Reg64),
                ('dr1', Reg64),
                ('dr2', Reg64),
                ('dr3', Reg64),
                ('dr6', Reg32),
                ('dr7', Reg32),
                ('sysentercs', Reg32),
                ('sysentereip', Reg64),
                ('sysenteresp', Reg64),
                ('efer', RegEfer),
                ('kernelgsbase', Reg64),
                ('star', Reg64),
                ('lstar', Reg64),
                ('cstar', Reg64),
                ('sfmask', Reg32)]

    def __init__(self):
        for field_info in self._fields_:
            setattr(self, field_info[0], field_info[1]())

class Memory(bytearray):
    def allocate(self, size, alignment = 1):
        addr = (len(self) + alignment - 1) / alignment * alignment
        self.extend('\x00' * (addr + size - len(self)))
        return addr

    def write(self, addr, content):
        assert addr + len(content) <= len(self)
        self[addr:addr + len(content)] = content

    def read(self, addr, size):
        assert addr + size <= len(self)
        return self[addr:addr + size]

class VMState(object):
    def __init__(self, arch = 0x86):
        assert arch in (0x86, 0x64), 'Unsupported architecture: %x' % arch
        self.memory = Memory()
        self.regs = RegFile()
        self.regs.cr0.PE = 1
        if arch == 0x64:
            self.regs.efer.SCE = 1
            self.regs.efer.LME = 1
            self.regs.efer.LMA = 1
            self.regs.efer.NXE = 1

    def setup_real(self):
        '''
        Setup registers for real-mode execution.
        '''
        assert self.regs.efer.LMA == 0
        # setup segment selector registers
        for (reg, s, type) in [(self.regs.cs, 1, 0b1011),
                               (self.regs.ds, 1, 0b0011),
                               (self.regs.es, 1, 0b0011),
                               (self.regs.fs, 1, 0b0011),
                               (self.regs.gs, 1, 0b0011),
                               (self.regs.ss, 1, 0b0011),
                               (self.regs.tr, 0, 0b1011)]:
            reg.limit = 0xffff
            reg.type = type
            reg.s = s
            reg.p = 1
        # setup table registers
        for reg in [self.regs.idtr, self.regs.gdtr]:
            reg.limit = 0xffff
        # disable protected mode
        self.regs.cr0.PE = 0

    def setup_paging(self):
        '''
        Setup an identity mapping (VA == PA) with full accesses.
        '''
        assert self.regs.cr0.PG == 0
        if self.regs.efer.LMA == 0:
            # allocate a page table directory
            pgdiraddr = self.memory.allocate(PGSIZE, PGSIZE)
            # setup identity mapping for [0, 4GB)
            for i in range(PGSIZE / sizeof(PDE32)):
                pde = PDE32.from_buffer(self.memory, pgdiraddr + i * sizeof(PDE32))
                pde.p = 1
                pde.w = 1
                pde.u = 1
                pde.ps = 1 # mark as a 4MB large page
                pde.pfn = (i << 10)
            # setup cr3
            self.regs.cr3.value = pgdiraddr
        else:
            # allocate a PML4 and a PDPT
            pml4addr = self.memory.allocate(PGSIZE, PGSIZE)
            pdptaddr = self.memory.allocate(PGSIZE, PGSIZE)
            # make the first PML4 entry point to the PDPT
            pml4e = PML4E.from_buffer(self.memory, pml4addr)
            pml4e.p = 1
            pml4e.w = 1
            pml4e.u = 1
            pml4e.pfn = (pdptaddr >> 12)
            # setup identity mapping for [0, 512GB)
            for i in range(PGSIZE / sizeof(PDPTE)):
                pdpte = PDPTE.from_buffer(self.memory, pdptaddr + i * sizeof(PDPTE))
                pdpte.p = 1
                pdpte.w = 1
                pdpte.u = 1
                pdpte.ps = 1 # mark as a 1GB large page (requires hardware support)
                pdpte.pfn = (i << 18)
            # PAE is required for 4-level paging
            self.regs.cr4.PAE = 1
            # setup cr3
            self.regs.cr3.value = pml4addr
        # enable large page support
        self.regs.cr4.PSE = 1
        # turn on paging
        self.regs.cr0.PG = 1

    def load_seg(self, reg, selector):
        '''
        Load the segment register and update its cache accordingly.
        '''
        assert (selector & 0b100) == 0, 'LDT is not supported yet'
        assert selector + sizeof(SegDesc32) - 1 <= self.regs.gdtr.limit
        desc_addr = self.regs.gdtr.base + (selector & ~0b111)
        desc = SegDesc32.from_buffer(self.memory, desc_addr)
        if desc.s == 0:
            if desc.type == 0b1100:
                desc = (CallGateDesc64 if self.regs.efer.LMA else CallGateDesc32).from_buffer(self.memory, desc_addr)
            elif desc.type == 0b1011 or desc.type == 0b1001:
                desc = (TssDesc64 if self.regs.efer.LMA else TssDesc32).from_buffer(self.memory, desc_addr)
            else:
                raise NotImplementedError
        reg.base = desc.base()
        reg.limit = desc.limit() if not desc.g else (desc.limit() * PGSIZE + PGSIZE - 1)
        reg.selector = selector
        reg.type = desc.type
        reg.s = desc.s
        reg.dpl = desc.dpl
        reg.p = desc.p
        reg.avl = desc.avl
        reg.l = desc.l
        reg.db = desc.db
        reg.g = desc.g

    def setup_gdt(self):
        '''
        Setup the Global Descriptor Table (GDT) using flat memory model.
        The constructed GDT will be like [NULL, KT, UT, KD, UD, TSS], and
        all the segment registers are initialized to refer to KT/KD.
        If you wish to setup a customized GDT, please do it yourself.
        '''
        assert self.regs.gdtr.base == 0
        assert self.regs.gdtr.limit == 0
        # create a task state segment
        long_mode = self.regs.efer.LMA
        tss_size = sizeof(TSS32) if long_mode else sizeof(TSS64)
        tss_addr = self.memory.allocate(tss_size)
        # GDT always starts with a NULL descriptor
        gdt = [SegDesc32(), # NULL
               SegDesc32(0, 0xfffff, 0b1011, 1, 0, 1, 0, long_mode, 1 - long_mode, 1), # KT
               SegDesc32(0, 0xfffff, 0b1011, 1, 3, 1, 0, long_mode, 1 - long_mode, 1), # UT
               SegDesc32(0, 0xfffff, 0b0011, 1, 0, 1, 0, 0, 1, 1), # KD
               SegDesc32(0, 0xfffff, 0b0011, 1, 3, 1, 0, 0, 1, 1)] # UD
        # add a TSS descriptor to GDT based on the arch
        if long_mode:
            gdt.append(TssDesc64(tss_addr, tss_size - 1, 1, 0, 1, 0, 0))
        else:
            gdt.append(TssDesc32(tss_addr, tss_size - 1, 1, 0, 1, 0, 0))
        # allocate GDT from the memory
        gdt_size = sum([sizeof(desc) for desc in gdt])
        gdt_addr = self.memory.allocate(gdt_size)
        # initialize the GDT layout accordingly
        self.memory.write(gdt_addr, ''.join([str(bytearray(desc)) for desc in gdt]))
        # update gdtr to point to the GDT in memory
        self.regs.gdtr.base = gdt_addr
        self.regs.gdtr.limit = gdt_size - 1
        # update segment registers
        self.load_seg(self.regs.cs, 0x8)
        self.load_seg(self.regs.ds, 0x18)
        self.load_seg(self.regs.es, 0x18)
        self.load_seg(self.regs.ss, 0x18)
        self.load_seg(self.regs.tr, 0x28)

    def setup_idt(self, descs):
        '''
        Setup the Interrupt Descriptor Table given a list of IDT descriptors.
        '''
        # convert the descriptors into raw bytes
        raw = ''.join([str(bytearray(desc)) for desc in descs])
        # allocate IDT and set it up accordingly
        idt_size = len(raw)
        idt_addr = self.memory.allocate(idt_size, 8)
        self.memory.write(idt_addr, raw)
        # update idtr to point to the IDT
        self.regs.idtr.base = idt_addr
        self.regs.idtr.limit = idt_size - 1

    def raw(self):
        '''
        Convert the current VM state to raw bytes.
        '''
        return bytearray(self.regs) + bytearray(self.memory)

    def dump(self, showreg = True, showmem = False):
        '''
        Dump the current register/memory state.
        '''
        if showreg:
            print '==================== REGISTER STATE ====================='
            print
            for field_info in self.regs._fields_:
                print '%s: %s' % (field_info[0], dumps(getattr(self.regs, field_info[0])))
            print
        if showmem:
            print '===================== MEMORY STATE ======================'
            print
            for addr in range(0, len(self.memory), 16):
                remaining = len(self.memory) - addr
                content = self.memory.read(addr, 16 if remaining > 16 else remaining)
                print '%08x: %s' % (addr, ' '.join(map(lambda b: '%02x' % b, content)))
            print

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print 'usage: %s state.bin' % sys.argv[0]
        sys.exit(0)
    raw = bytearray(open(sys.argv[1], 'rb').read())
    state = VMState()
    state.regs = type(state.regs).from_buffer(raw)
    state.memory = Memory(raw[sizeof(state.regs):])
    state.dump(True, True)
