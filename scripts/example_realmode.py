from vmstate import *

CODE = '\x9d\xcc' # POPF; INT3

# init real-mode machine
state = VMState(0x86)
state.setup_real()
# allocate stack
stack = state.memory.allocate(8)
state.regs.rsp.value = stack + 4
# inject POPF
addr = state.memory.allocate(len(CODE))
state.memory.write(addr, CODE) # POPF
state.regs.rip.value = addr
# write the state out
if len(sys.argv) < 2:
    state.dump(True, False)
else:
    open(sys.argv[1], 'wb').write(state.raw())
