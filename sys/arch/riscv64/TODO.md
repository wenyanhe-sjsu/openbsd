check whether necessary to support variable {M,S,U}XLEN in riscvreg.h
check sigcontext struct (stolen from freebsd) in include/signal.h
review if necessary to include FP regs in trapframe in include/frame.h
revisit settings in param.h (FDT / ACPI / U-Area / Clusters / Buffer)

/u/bin/src/OpenBSD/riscv/sys/arch/riscv64/compile/GENERIC/obj/machine/atomic.h:28:19: error: invalid operand for instruction
        __asm __volatile("amoor.w zero, %1, %0"
                         ^
<inline asm>:1:25: note: instantiated into assembly here
        amoor.w zero, 32, 0(a0)
                               ^

