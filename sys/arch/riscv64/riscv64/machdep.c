/*
 * Copyright (c) 2014 Patrick Wildt <patrick@blueri.se>
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
#include <sys/timetc.h>
#include <sys/sched.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <sys/reboot.h>
#include <sys/mount.h>
#include <sys/exec.h>
#include <sys/user.h>
#include <sys/conf.h>
#include <sys/kcore.h>
#include <sys/core.h>
#include <sys/msgbuf.h>
#include <sys/buf.h>
#include <sys/termios.h>
#include <sys/sensors.h>
#include <sys/syscallargs.h>

#include <net/if.h>
#include <uvm/uvm.h>
#include <dev/cons.h>
#include <dev/clock_subr.h>
#include <dev/ofw/fdt.h>
#include <dev/ofw/openfirm.h>
#include <machine/param.h>
#include <machine/bootconfig.h>
#include <machine/bus.h>
#include <machine/riscv64var.h>

#include <machine/db_machdep.h>
#include <ddb/db_extern.h>

#include <dev/acpi/efi.h>

#include "softraid.h"
#if NSOFTRAID > 0
#include <dev/softraidvar.h>
#endif

char *boot_args = NULL;
char *boot_file = "";

uint8_t *bootmac = NULL;

extern uint64_t esym;

int stdout_node;
int stdout_speed;

void (*cpuresetfn)(void);
void (*powerdownfn)(void);

int cold = 1;

struct vm_map *exec_map = NULL;
struct vm_map *phys_map = NULL;

int physmem;

struct consdev *cn_tab;

caddr_t msgbufaddr;
paddr_t msgbufphys;

struct user *proc0paddr;

struct uvm_constraint_range  dma_constraint = { 0x0, (paddr_t)-1 };
struct uvm_constraint_range *uvm_md_constraints[] = { NULL };

/* the following is used externally (sysctl_hw) */
char    machine[] = MACHINE;            /* from <machine/param.h> */
extern todr_chip_handle_t todr_handle;

int safepri = 0;

struct cpu_info cpu_info_primary;
struct cpu_info *cpu_info[MAXCPUS] = { &cpu_info_primary };

//copied from arm64 directly
#if 0
extern void	com_fdt_init_cons(void);
extern void	imxuart_init_cons(void);
extern void	pluart_init_cons(void);
extern void	simplefb_init_cons(bus_space_tag_t);
#endif

void
consinit(void)
{
	static int consinit_called = 0;

	if (consinit_called != 0)
		return;

	consinit_called = 1;

//XXX TODO: need to check how to reference them
#if 0
	com_fdt_init_cons();
	imxuart_init_cons();
	pluart_init_cons();
	simplefb_init_cons(&riscv64_bs_tag);
#endif
}

//XXX TODO: need to populate console for qemu
struct consdev constab[] = {
	{ NULL }
};

void
cpu_idle_enter()
{
}

void
cpu_idle_cycle()
{
	// XXX Enable interrupts?
	// XXX Data Sync Barrier? (Maybe SFENCE???)
	__asm volatile("wfi");
}

void
cpu_idle_leave()
{
}


// XXX what? - not really used
struct trapframe  proc0tf;
void
cpu_startup()
{
	u_int loop;
	paddr_t minaddr;
	paddr_t maxaddr;

	proc0.p_addr = proc0paddr;

	/*
	 * Give pmap a chance to set up a few more things now the vm
	 * is initialised
	 */
	pmap_postinit();

	/*
	 * Initialize error message buffer (at end of core).
	 */

	/* msgbufphys was setup during the secondary boot strap */
	for (loop = 0; loop < atop(MSGBUFSIZE); ++loop)
		pmap_kenter_pa((vaddr_t)msgbufaddr + loop * PAGE_SIZE,
		    msgbufphys + loop * PAGE_SIZE, PROT_READ | PROT_WRITE);
	pmap_update(pmap_kernel());
	initmsgbuf(msgbufaddr, round_page(MSGBUFSIZE));

	/*
	 * Identify ourselves for the msgbuf (everything printed earlier will
	 * not be buffered).
	 */
	printf("%s", version);

	printf("real mem  = %lu (%luMB)\n", ptoa(physmem),
	    ptoa(physmem)/1024/1024);

	/*
	 * Allocate a submap for exec arguments.  This map effectively
	 * limits the number of processes exec'ing at any time.
	 */
	minaddr = vm_map_min(kernel_map);
	exec_map = uvm_km_suballoc(kernel_map, &minaddr, &maxaddr,
				   16*NCARGS, VM_MAP_PAGEABLE, FALSE, NULL);


	/*
	 * Allocate a submap for physio
	 */
	phys_map = uvm_km_suballoc(kernel_map, &minaddr, &maxaddr,
				   VM_PHYS_SIZE, 0, FALSE, NULL);

	/*
	 * Set up buffers, so they can be used to read disk labels.
	 */
	bufinit();

	printf("avail mem = %lu (%luMB)\n", ptoa(uvmexp.free),
	    ptoa(uvmexp.free)/1024/1024);

	curpcb = &proc0.p_addr->u_pcb;
	curpcb->pcb_flags = 0;
	curpcb->pcb_tf = &proc0tf;

	if (boothowto & RB_CONFIG) {
#ifdef BOOT_CONFIG
		user_config();
#else
		printf("kernel does not support -c; continuing..\n");
#endif
	}
}

int
cpu_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp,
    size_t newlen, struct proc *p)
{
	/* all sysctl names at this level are terminal */
	if (namelen != 1)
		return (ENOTDIR);		/* overloaded */

	switch (name[0]) {
		// none supported currently
	default:
		return (EOPNOTSUPP);
	}
	/* NOTREACHED */
}

int	waittime = -1;

__dead void
boot(int howto)
{
	if ((howto & RB_RESET) != 0)
		goto doreset;

	if (cold) {
		if ((howto & RB_USERREQ) == 0)
			howto |= RB_HALT;
		goto haltsys;
	}

	boothowto = howto;
	if ((howto & RB_NOSYNC) == 0 && waittime < 0) {
		waittime = 0;
		vfs_shutdown(curproc);

		if ((howto & RB_TIMEBAD) == 0) {
			resettodr();
		} else {
			printf("WARNING: not updating battery clock\n");
		}
	}
	if_downall();

	uvm_shutdown();
	splhigh();
	cold = 1;

	if ((howto & RB_DUMP) != 0)
		//dumpsys();//XXX no dump so far. CMPE295

haltsys:
	config_suspend_all(DVACT_POWERDOWN);

	if ((howto & RB_HALT) != 0) {
		if ((howto & RB_POWERDOWN) != 0) {
			printf("\nAttempting to power down...\n");
			delay(500000);
			if (powerdownfn)
				(*powerdownfn)();
		}

		printf("\n");
		printf("The operating system has halted.\n");
		printf("Please press any key to reboot.\n\n");
		cngetc();
	}

doreset:
	printf("rebooting...\n");
	delay(500000);
	if (cpuresetfn)
		(*cpuresetfn)();
	printf("reboot failed; spinning\n");
	for (;;)
		continue;
	/* NOTREACHED */
}

//Copied from ARM64, removed some registers. XXX
void
setregs(struct proc *p, struct exec_package *pack, u_long stack,
    register_t *retval)
{
	struct trapframe *tf;

	/* If we were using the FPU, forget about it. */
	if (p->p_addr->u_pcb.pcb_fpcpu != NULL)
		//vfp_discard(p);//XXX ignore fp so far
	p->p_addr->u_pcb.pcb_flags &= ~PCB_FPU;

	tf = p->p_addr->u_pcb.pcb_tf;

	memset (tf,0, sizeof(*tf));
	tf->tf_sp = stack;
	tf->tf_ra = pack->ep_entry;
	tf->tf_gp = pack->ep_entry; //XXX 

	retval[1] = 0;
}

void
need_resched(struct cpu_info *ci)
{
	ci->ci_want_resched = 1;

	/* There's a risk we'll be called before the idle threads start */
	if (ci->ci_curproc) {
		aston(ci->ci_curproc);
		cpu_kick(ci);
	}
}


/// XXX ?
/*
 * Size of memory segments, before any memory is stolen.
 */
phys_ram_seg_t mem_clusters[VM_PHYSSEG_MAX];
int     mem_cluster_cnt;
/// XXX ?
/*
 * cpu_dumpsize: calculate size of machine-dependent kernel core dump headers.
 */
int
cpu_dumpsize(void)
{
	int size;

	size = ALIGN(sizeof(kcore_seg_t)) +
	    ALIGN(mem_cluster_cnt * sizeof(phys_ram_seg_t));
	if (roundup(size, dbtob(1)) != dbtob(1))
		return (-1);

	return (1);
}

u_long
cpu_dump_mempagecnt()
{
	return 0;
}

//Copied from ARM64
/*
 * These variables are needed by /sbin/savecore
 */
u_long	dumpmag = 0x8fca0101;	/* magic number */
int 	dumpsize = 0;		/* pages */
long	dumplo = 0; 		/* blocks */

/*
 * This is called by main to set dumplo and dumpsize.
 * Dumps always skip the first PAGE_SIZE of disk space
 * in case there might be a disk label stored there.
 * If there is extra space, put dump at the end to
 * reduce the chance that swapping trashes it.
 */
void
dumpconf(void)
{
	int nblks, dumpblks;	/* size of dump area */

	if (dumpdev == NODEV ||
	    (nblks = (bdevsw[major(dumpdev)].d_psize)(dumpdev)) == 0)
		return;
	if (nblks <= ctod(1))
		return;

	dumpblks = cpu_dumpsize();
	if (dumpblks < 0)
		return;
	dumpblks += ctod(cpu_dump_mempagecnt());

	/* If dump won't fit (incl. room for possible label), punt. */
	if (dumpblks > (nblks - ctod(1)))
		return;

	/* Put dump at end of partition */
	dumplo = nblks - dumpblks;

	/* dumpsize is in page units, and doesn't include headers. */
	dumpsize = cpu_dump_mempagecnt();
}

//copied from arm64/sys_machdep.h
int
sys_sysarch(struct proc *p, void *v, register_t *retval)
{
	struct sys_sysarch_args /* {
		syscallarg(int) op;
		syscallarg(void *) parms;
	} */ *uap = v;
	int error = 0;

	switch(SCARG(uap, op)) {
	default:
		error = EINVAL;
		break;
	}

	return (error);
}
