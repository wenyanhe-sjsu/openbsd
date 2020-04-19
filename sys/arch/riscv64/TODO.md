# Misc Notes / TODOs
* Registers
    * freebsd uses two sets of 32 floating point registers in reg.h. Not sure why
    * check whether necessary to support variable {M,S,U}XLEN in riscvreg.h
    * review if necessary to include FP regs in trapframe in include/frame.h
* PMAP
    * Physmap vars necessary in bootconfig.h?
* Interrupts
    * check sigcontext struct (stolen from freebsd) in include/signal.h
    * Interrupt diagnostics unimplemented (intr.h > splassert)
* Context Switch
    * switchframe not being initialized on cpu\_fork
    * child\_return logic is best-guess. Consider re-evaluting at later point in time
* System Calls
    * Interrupts not restored during System Call
    * Floating Point Registers not saved during System Call
    * System Call does not signal success / failure
    * Ensure that ERESTART error PC adjustment makes it back to process state
* Misc
    * revisit settings in param.h (FDT / ACPI / U-Area / Clusters / Buffer)
    * Look into implementing riscv64/cpufunc.c, if necessary
