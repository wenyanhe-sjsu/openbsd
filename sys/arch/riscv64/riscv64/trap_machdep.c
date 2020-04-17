/*
 * Copyright (c) 2020 Shivam Waghela <shivamwaghela@gmail.com>
 * Copyright (c) 2020 Brian Bamsch <bbamsch@google.com>
 * Copyright (c) 2020 Mengshi Li <mengshi.li.mars@gmail.com>
 * Copyright (c) 2015 Dale Rahn <drahn@dalerahn.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/user.h>
#include <sys/signalvar.h>
#include <sys/siginfo.h>
#include <sys/syscall.h>
#include <sys/syscall_mi.h>

#include <machine/riscvreg.h>
#include <machine/syscall.h>

/* Called from trap.S */
void do_trap_supervisor(struct trapframe *);
void do_trap_user(struct trapframe *);

static void
dump_regs(struct trapframe *frame)
{
	int n;
	int i;

	n = (sizeof(frame->tf_t) / sizeof(frame->tf_t[0]));
	for (i = 0; i < n; i++)
		printf("t[%d] == 0x%016lx\n", i, frame->tf_t[i]);

	n = (sizeof(frame->tf_s) / sizeof(frame->tf_s[0]));
	for (i = 0; i < n; i++)
		printf("s[%d] == 0x%016lx\n", i, frame->tf_s[i]);

	n = (sizeof(frame->tf_a) / sizeof(frame->tf_a[0]));
	for (i = 0; i < n; i++)
		printf("a[%d] == 0x%016lx\n", i, frame->tf_a[i]);

	printf("sepc == 0x%016lx\n", frame->tf_sepc);
	printf("sstatus == 0x%016lx\n", frame->tf_sstatus);
}

void
do_trap_supervisor(struct trapframe *frame)
{
	uint64_t exception;

	/* Ensure we came from supervisor mode, interrupts disabled */
	KASSERTMSG((csr_read(sstatus) & (SSTATUS_SPP | SSTATUS_SIE)) ==
	    SSTATUS_SPP, "Came from S mode with interrupts enabled");

	if (frame->tf_scause & EXCP_INTR) {
		/* Interrupt */
		riscv_cpu_intr(frame);
		return;
	}

	exception = (frame->tf_scause & EXCP_MASK);
	switch(exception) {
#if 0
	case EXCP_FAULT_LOAD:
	case EXCP_FAULT_STORE:
	case EXCP_FAULT_FETCH:
	case EXCP_STORE_PAGE_FAULT:
	case EXCP_LOAD_PAGE_FAULT:
		data_abort(frame, 0);
		break;
#endif
	case EXCP_BREAKPOINT:
#ifdef DDB
		// kdb_trap(exception, 0, frame);
                db_trapper(frame->tf_sepc,0/*XXX*/, frame, exception);         
#else
		dump_regs(frame);
		panic("No debugger in kernel.\n");
#endif
		break;
	case EXCP_ILLEGAL_INSTRUCTION:
		dump_regs(frame);
		panic("Illegal instruction at 0x%016lx\n", frame->tf_sepc);
		break;
	default:
		dump_regs(frame);
		panic("Unknown kernel exception %x trap value %lx\n",
		    exception, frame->tf_stval);
	}
}

static void
data_abort(struct trapframe *frame, int usermode)
{
	struct vm_map *map;
	uint64_t stval;
	union sigval sv;
	struct pcb *pcb;
	vm_prot_t ftype;
	vaddr_t va;
	struct proc *p;
	int error, sig, code, access_type;

	pcb = curcpu()->ci_curpcb;
	p = curcpu()->ci_curproc;
	stval = frame->tf_stval;

	va = trunc_page(stval);

	//if (va >= VM_MAXUSER_ADDRESS)
	//	curcpu()->ci_flush_bp();

	if ((frame->tf_scause == EXCP_FAULT_STORE) ||
	    (frame->tf_scause == EXCP_STORE_PAGE_FAULT)) {
		access_type = PROT_WRITE;
	} else if (frame->tf_scause == EXCP_INST_PAGE_FAULT) {
		access_type = PROT_EXEC;
	} else {
		access_type = PROT_READ;
	}

	ftype = VM_FAULT_INVALID; // should check for failed permissions.

	if (usermode)
		map = &p->p_vmspace->vm_map;
	else if (stval >= VM_MAX_USER_ADDRESS)
		map = kernel_map;
	else {
		if (pcb->pcb_onfault == 0)
			goto fatal;
		map = &p->p_vmspace->vm_map;
	}

	if (pmap_fault_fixup(map->pmap, va, ftype, usermode))
		goto done;

	KERNEL_LOCK();
	error = uvm_fault(map, va, ftype, access_type);
	KERNEL_UNLOCK();

	if (error != 0) {
		if (usermode) {
			if (error == ENOMEM) {
				sig = SIGKILL;
				code = 0;
			} else if (error == EIO) {
				sig = SIGBUS;
				code = BUS_OBJERR;
			} else if (error == EACCES) {
				sig = SIGSEGV;
				code = SEGV_ACCERR;
			} else {
				sig = SIGSEGV;
				code = SEGV_MAPERR;
			}
			sv.sival_int = stval;
			KERNEL_LOCK();
			trapsignal(p, sig, 0, code, sv);
			KERNEL_UNLOCK();
		} else {
			if (curcpu()->ci_idepth == 0 && pcb->pcb_onfault != 0) {
				frame->tf_a[0] = error;
				frame->tf_sepc = (register_t)pcb->pcb_onfault;
				return;
			}
			goto fatal;
		}
	}

done:
	if (usermode)
		userret(p);
	return;

fatal:
	dump_regs(frame);
	panic("Fatal page fault at %#lx: %#016lx", frame->tf_sepc, sv);
}

void
do_trap_user(struct trapframe *frame)
{
	uint64_t exception;
	//union sigval sv; // XXX
	struct proc *p;
	// struct pcb *pcb; // XXX

	p = curproc;
	p->p_addr->u_pcb.pcb_tf = frame;
	// pcb = td->td_pcb; // XXX

	/* Ensure we came from usermode, interrupts disabled */
	KASSERTMSG((csr_read(sstatus) & (SSTATUS_SPP | SSTATUS_SIE)) == 0,
	    "Came from U mode with interrupts enabled");

	exception = (frame->tf_scause & EXCP_MASK);
	if (frame->tf_scause & EXCP_INTR) {
		/* Interrupt */
		riscv_cpu_intr(frame);
		return;
	}

#if 0	// XXX Debug logging
	CTR3(KTR_TRAP, "do_trap_user: curthread: %p, sepc: %lx, frame: %p",
	    curthread, frame->tf_sepc, frame);
#endif

	switch(exception) {
	case EXCP_FAULT_LOAD:
	case EXCP_FAULT_STORE:
	case EXCP_FAULT_FETCH:
	case EXCP_STORE_PAGE_FAULT:
	case EXCP_LOAD_PAGE_FAULT:
	case EXCP_INST_PAGE_FAULT:
		data_abort(frame, 1);
		break;
	case EXCP_USER_ECALL:
		frame->tf_sepc += 4;	/* Next instruction */
		svc_handler(frame);
		break;
#if 0
	case EXCP_ILLEGAL_INSTRUCTION:
#ifdef FPE
		if ((pcb->pcb_fpflags & PCB_FP_STARTED) == 0) {
			/*
			 * May be a FPE trap. Enable FPE usage
			 * for this thread and try again.
			 */
			fpe_state_clear();
			frame->tf_sstatus &= ~SSTATUS_FS_MASK;
			frame->tf_sstatus |= SSTATUS_FS_CLEAN;
			pcb->pcb_fpflags |= PCB_FP_STARTED;
			break;
		}
#endif
		call_trapsignal(td, SIGILL, ILL_ILLTRP, (void *)frame->tf_sepc);
		userret(td, frame);
		break;
	case EXCP_BREAKPOINT:
		call_trapsignal(td, SIGTRAP, TRAP_BRKPT, (void *)frame->tf_sepc);
		userret(td, frame);
		break;
#endif
	default:
		dump_regs(frame);
		panic("Unknown userland exception %x, trap value %lx\n",
		    exception, frame->tf_stval);
	}
}

#if 0
#include <sys/cdefs.h>

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
//#include <sys/ktr.h>
#include <sys/lock.h>
#include <sys/mutex.h>
//#include <sys/pioctl.h>
//#include <sys/bus.h>
#include <sys/proc.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
//#include <sys/sysent.h>
#ifdef KDB
#include <sys/kdb.h>
#endif

#ifdef FPE
#include <machine/fpe.h>
#endif
#include <machine/frame.h>
#include <machine/pcb.h>
//#include <machine/pmap.h>

//#include <machine/resource.h>
#include <machine/intr.h>

#ifdef KDTRACE_HOOKS
#include <sys/dtrace_bsd.h>
#endif

int (*dtrace_invop_jump_addr)(struct trapframe *);

extern register_t fsu_intr_fault;
#endif

#if 0
static __inline void
call_trapsignal(struct thread *td, int sig, int code, void *addr)
{
	ksiginfo_t ksi;

	ksiginfo_init_trap(&ksi);
	ksi.ksi_signo = sig;
	ksi.ksi_code = code;
	ksi.ksi_addr = addr;
	trapsignal(td, &ksi);
}

int
cpu_fetch_syscall_args(struct thread *td)
{
	struct proc *p;
	register_t *ap;
	struct syscall_args *sa;
	int nap;

	nap = NARGREG;
	p = td->td_proc;
	sa = &td->td_sa;
	ap = &td->td_frame->tf_a[0];

	sa->code = td->td_frame->tf_t[0];

	if (sa->code == SYS_syscall || sa->code == SYS___syscall) {
		sa->code = *ap++;
		nap--;
	}

	if (sa->code >= p->p_sysent->sv_size)
		sa->callp = &p->p_sysent->sv_table[0];
	else
		sa->callp = &p->p_sysent->sv_table[sa->code];

	sa->narg = sa->callp->sy_narg;
	memcpy(sa->args, ap, nap * sizeof(register_t));
	if (sa->narg > nap)
		panic("TODO: Could we have more then %d args?", NARGREG);

	td->td_retval[0] = 0;
	td->td_retval[1] = 0;

	return (0);
}
#endif

