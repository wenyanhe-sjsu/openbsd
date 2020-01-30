freebsd uses two sets of 32 floating point registers in reg.h. Not sure why
check whether necessary to support variable {M,S,U}XLEN in riscvreg.h
check sigcontext struct (stolen from freebsd) in include/signal.h
review if necessary to include FP regs in trapframe in include/frame.h
revisit settings in param.h (FDT / ACPI / U-Area / Clusters / Buffer)


Look into implementing riscv64/cpufunc.c, if necessary

DDB is completely unimplemented. Don't expect it to work.
PMAP is missing quite a few pieces (TLB Flush, etc.)
