/*
 * Copyright (c) 2020, Mars Li <mengshi.li.mars@gmail.com>
 * Copyright (c) 2020, Brian Bamsch <bbamsch@google.com>
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
#include <sys/queue.h>
#include <sys/malloc.h>
#include <sys/device.h>
#include <sys/evcount.h>

#include <machine/bus.h>
#include <machine/fdt.h>
#include <machine/cpu.h>
#include "riscv64/dev/riscv_cpu_intc.h"

#include <dev/ofw/openfirm.h>
#include <dev/ofw/fdt.h>

/*
 * This driver implements a version of the RISC-V PLIC with the actual layout
 * specified in chapter 8 of the SiFive U5 Coreplex Series Manual:
 *
 *     https://static.dev.sifive.com/U54-MC-RVCoreIP.pdf
 *
 * The largest number supported by devices marked as 'sifive,plic-1.0.0', is
 * 1024, of which device 0 is defined as non-existent by the RISC-V Privileged
 * Spec.
 */

#define	PLIC_MAX_IRQS		1024

#define	PLIC_PRIORITY_BASE	0x000000U

#define	PLIC_ENABLE_BASE	0x002000U
#define	PLIC_ENABLE_STRIDE	0x80U

#define	PLIC_CONTEXT_BASE	0x200000U
#define	PLIC_CONTEXT_STRIDE	0x1000U
#define	PLIC_CONTEXT_THRESHOLD	0x0U
#define	PLIC_CONTEXT_CLAIM	0x4U

#define	PLIC_PRIORITY(n)	(PLIC_PRIORITY_BASE + (n) * sizeof(uint32_t))
#define	PLIC_ENABLE(sc, n, h)						\
    (sc->sc_contexts[h].enable_offset + ((n) / 32) * sizeof(uint32_t))
#define	PLIC_THRESHOLD(sc, h)						\
    (sc->sc_contexts[h].context_offset + PLIC_CONTEXT_THRESHOLD)
#define	PLIC_CLAIM(sc, h)						\
    (sc->sc_contexts[h].context_offset + PLIC_CONTEXT_CLAIM)


struct plic_intrhand {
	TAILQ_ENTRY(plic_intrhand) ih_list; /* link on intrq list */
	int (*ih_func)(void *);		/* handler */
	void *ih_arg;			/* arg for handler */
	int ih_ipl;			/* IPL_* */
	int ih_flags;
	int ih_irq;			/* IRQ number */
	struct evcount	ih_count;
	char *ih_name;
};

struct plic_irqsrc {
	TAILQ_HEAD(, plic_intrhand) is_list; /* handler list */
	int 			is_irq;	/* IRQ to mask while handling */
#if 0
	struct device		is_dev;	/* from which device this intr comes */
#endif
};

struct plic_context {
	bus_size_t enable_offset;
	bus_size_t context_offset;
};

struct plic_softc {
	struct device		sc_dev;
	int			sc_node;
	bus_space_tag_t		sc_iot;
	bus_space_handle_t	sc_ioh;
	// XXX Consider switching sc_isrcs to malloc'd memory to reduce waste
	struct plic_irqsrc	sc_isrcs[PLIC_MAX_IRQS];
#if 0	// Masking is done via setting priority threshold?
	u_int32_t 		sc_imask[NIPL];
#endif
	struct plic_context	sc_contexts[MAXCPUS];
	int			sc_ndev;
	struct interrupt_controller 	sc_intc;
};
struct plic_softc *plic;

int	plic_match(struct device *, void *, void *);
void	plic_attach(struct device *, struct device *, void *);
void	plic_splx(int);
int	plic_spllower(int);
int	plic_splraise(int);
void	plic_setipl(int);
void	plic_calc_mask(void);
void	*plic_intr_establish(int, int, int (*)(void *),
		void *, char *);
void	*plic_intr_establish_fdt(void *, int *, int, int (*)(void *),
		void *, char *);
void	plic_intr_disestablish(void *);
int	plic_irq_handler(void *);
void	plic_intr_route(void *, int , struct cpu_info *);


/*
 * OpenBSD saves cpu node info in ci struct, so we can search
 * cpuid by node matching
 */
int
plic_get_cpuid(int intc)
{
	uint32_t hart;
	int parent_node;
	struct cpu_info *ci;
	CPU_INFO_ITERATOR cii;

	/* Check the interrupt controller layout. */
	if (OF_getpropintarray(intc, "#interrupt-cells", &hart,
	    sizeof(hart)) < 0) {
		printf(": could not find #interrupt-cells for phandle %u\n", intc);
		return (-1);
	}

	/*
	 * The parent of the interrupt-controller is the CPU we are
	 * interested in, so search for its OF node index.
	 */
	parent_node = OF_parent(intc);
	CPU_INFO_FOREACH(cii, ci) {
		if(ci->ci_node == parent_node)
			return ci->ci_cpuid;
	}
	return -1;
}

struct cfattach plic_ca = {
	sizeof(struct plic_softc), plic_match, plic_attach,
};

struct cfdriver plic_cd = {
	NULL, "plic", DV_DULL
};

int plic_attached = 0;

int
plic_match(struct device *parent, void *cfdata, void *aux)
{
	struct fdt_attach_args *faa = aux;

	if (plic_attached)
		return 0; // Only expect one instance of PLIC

	return (OF_is_compatible(faa->fa_node, "riscv,plic0") ||
		OF_is_compatible(faa->fa_node, "sifive,plic-1.0.0"));
}

void
plic_attach(struct device *parent, struct device *dev, void *aux)
{
	struct plic_irqsrc *isrcs;
	struct plic_softc *sc;
	struct fdt_attach_args *faa;
	uint32_t *intr;
	uint32_t irq;
	uint32_t cpu;
	int node;
	int len;
	int nintr;
	int context;
	int i;
	struct cpu_info *ci;
	CPU_INFO_ITERATOR cii;

	sc = (struct plic_softc *)dev;
	faa = (struct fdt_attach_args *)aux;

	if (faa->fa_nreg < 1)
		return;

	plic = sc;

	sc->sc_node = node = faa->fa_node;
	sc->sc_iot = faa->fa_iot;

	/* determine number of devices sending intr to this ic */
	sc->sc_ndev = OF_getpropint(faa->fa_node, "riscv,ndev", -1);
	if (sc->sc_ndev < 0) {
		printf(": unable to resolve number of devices\n");
		return;
	}

	if (sc->sc_ndev >= PLIC_MAX_IRQS) {
		printf(": invalid ndev (%d)\n", sc->sc_ndev);
		return;
	}

	/* map interrupt controller to va space */
	if (bus_space_map(sc->sc_iot, faa->fa_reg[0].addr,
	    faa->fa_reg[0].size, 0, &sc->sc_ioh))
		panic("%s: bus_space_map failed!", __func__);

	isrcs = sc->sc_isrcs;
	for (irq = 1; irq <= sc->sc_ndev; irq++) {
		/*
		 * Register Interrupt Source:
		 * actually happens while device is attached, here only need to:
		 * Setup irq;
		 * Initialize Interrupt Handler List
		 */
		isrcs[irq].is_irq = irq;
		TAILQ_INIT(&isrcs[irq].is_list);

		// Mask interrupt
		bus_space_write_4(plic->sc_iot, plic->sc_ioh,
		    PLIC_PRIORITY(irq), 0);

	}

	/*
	 * Calculate the per-cpu enable and context register offsets.
	 *
	 * This is tricky for a few reasons. The PLIC divides the interrupt
	 * enable, threshold, and claim bits by "context", where each context
	 * routes to a Core-Local Interrupt Controller (CLIC).
	 *
	 * The tricky part is that the PLIC spec imposes no restrictions on how
	 * these contexts are laid out. So for example, there is no guarantee
	 * that each CPU will have both a machine mode and supervisor context,
	 * or that different PLIC implementations will organize the context
	 * registers in the same way. On top of this, we must handle the fact
	 * that cpuid != hartid, as they may have been renumbered during boot.
	 * We perform the following steps:
	 *
	 * 1. Examine the PLIC's "interrupts-extended" property and skip any
	 *    entries that are not for supervisor external interrupts.
	 *
	 * 2. Walk up the device tree to find the corresponding CPU, using node
	 *    property to identify the cpuid.
	 *
	 * 3. Calculate the register offsets based on the context number.
	 */
	len = OF_getproplen(node, "interrupts-extended");
	if (len <= 0) {
		printf(": could not find interrupts-extended\n");
		return;
	}

	intr = malloc(len, M_TEMP, M_WAITOK);
	nintr = len / sizeof(*intr);
	if (OF_getpropintarray(node, "interrupts-extended", intr, len) < 0) {
		printf(": failed to read interrupts-extended\n");
		free(intr, M_TEMP, len);
		return;
	}

	for (i = 0, context = 0; i < nintr; i += 2, context++) {
		/* Skip M-mode external interrupts */
		if (intr[i + 1] != IRQ_EXTERNAL_SUPERVISOR)
			continue;

		/* Get the corresponding cpuid. */
		cpu = plic_get_cpuid(OF_getnodebyphandle(intr[i]));
		if (cpu < 0) {
			printf(": invalid hart!\n");
			free(intr, M_TEMP, len);
			return;
		}

		/*
		 * Set the enable and context register offsets for the CPU.
		 *
		 * XXX this calculation formula should be WRONG, as per sifive
		 * plic spec, machine mode and supervisor mode context are
		 * interleaved.
		 * We can not assume we are running inside machine/supervisor
		 * mode.
		 */
		sc->sc_contexts[cpu].enable_offset = PLIC_ENABLE_BASE +
		    context * PLIC_ENABLE_STRIDE;
		sc->sc_contexts[cpu].context_offset = PLIC_CONTEXT_BASE +
		    context * PLIC_CONTEXT_STRIDE;
	}

	free(intr, M_TEMP, len);

#if 0	// XXX Irrelevant ???
	plic_calc_mask();
#endif

	/* Set CPU interrupt priority thresholds to minimum */
	CPU_INFO_FOREACH(cii, ci) {
		bus_space_write_4(plic->sc_iot, plic->sc_ioh,
		    PLIC_THRESHOLD(sc, ci->ci_cpuid), 0);
	}

	plic_attached = 1;

	/*
	 * insert self into the external interrupt handler entry in
	 * global interrupt handler vector
	 */
	riscv_intc_intr_establish(IRQ_EXTERNAL_SUPERVISOR, 0,
			plic_irq_handler, NULL, "plic");

	sc->sc_intc.ic_node = faa->fa_node;
	sc->sc_intc.ic_cookie = sc;
	sc->sc_intc.ic_establish = plic_intr_establish_fdt;
	sc->sc_intc.ic_disestablish = plic_intr_disestablish;
	// sc->sc_intc.ic_enable = XXX;
	// sc->sc_intc.ic_disable = XXX;
	// sc->sc_intc.ic_route = plic_intr_route;
	// sc->sc_intc.ic_cpu_enable = XXX Per-CPU Initialization?

	riscv_intr_register_fdt(&sc->sc_intc);


	plic_setipl(IPL_HIGH);  /* XXX ??? */

	/* enable external interrupt */
	csr_set(sie, SIE_SEIE);

	enable_interrupts();	
	// XXX Clear all pending interrupts?

	return;
}

/*******************************************/

#if 0
void
plic_calc_mask(void)
{
	struct cpu_info *ci = curcpu();
	struct plic_softc *sc = plic;
	int irq;
	struct plic_intrhand *ih;
	int i;

	/* PLIC irq 0 is reserved, thus we start from 1 */
	for (irq = 1; irq < PLIC_MAX_IRQS; irq++) {
		int max = IPL_NONE;
		int min = IPL_HIGH;
		TAILQ_FOREACH(ih, &sc->sc_isrcs[irq].is_list, ih_list) {
			if (ih->ih_ipl > max)
				max = ih->ih_ipl;

			if (ih->ih_ipl < min)
				min = ih->ih_ipl;
		}

		sc->sc_isrcs[irq].iq_irq = max;

		if (max == IPL_NONE)
			min = IPL_NONE;

#if 0 // DEBUG_PLIC
		if (min != IPL_NONE) {
			printf("irq %d to block at %d %d reg %d bit %d\n",
			    irq, max, min, INTC_IRQ_TO_REG(irq),
			    INTC_IRQ_TO_REGi(irq));
		}
#endif
		/* Enable interrupts at lower levels, clear -> enable */
		for (i = 1; i < min; i++)
			plic_imask[i] &= ~(1 << (irq));// XXX
		for (; i <= IPL_HIGH; i++)
			plic_imask[i] |= (1 << (irq));// XXX
	}
	plic_setipl(ci->ci_cpl);
}
#endif

void
plic_splx(int new)
{
#if 0	/* XXX how to do pending external interrupt ? */
	struct cpu_info *ci = curcpu();

	if (ci->ci_ipending & arm_smask[ci->ci_cpl])
		arm_do_pending_intr(ci->ci_cpl);// this seems to be software interrupt
#endif

	plic_setipl(new);
}

int
plic_spllower(int new)
{
	struct cpu_info *ci = curcpu();
	int old = ci->ci_cpl;
	plic_splx(new);
	return (old);
}

int
plic_splraise(int new)
{
	struct cpu_info *ci = curcpu();
	int old;
	old = ci->ci_cpl;

	/*
	 * setipl must always be called because there is a race window
	 * where the variable is updated before the mask is set
	 * an interrupt occurs in that window without the mask always
	 * being set, the hardware might not get updated on the next
	 * splraise completely messing up spl protection.
	 */
	if (old > new)
		new = old;

	plic_setipl(new);

	return (old);
}

void
plic_setipl(int new)
{
	struct cpu_info		*ci = curcpu();
	struct plic_softc	*sc = plic;
	uint64_t sie;

	/* disable here is only to keep hardware in sync with ci->ci_cpl */
	sie = disable_interrupts();
	ci->ci_cpl = new;

	/* higher values are higher priority */
	bus_space_write_4(sc->sc_iot, sc->sc_ioh,
	    PLIC_THRESHOLD(sc, ci->ci_cpuid), (uint32_t)new);
	restore_interrupts(sie);
}

#if 0	// XXX From arm64/omap/intc.c. Necessary?
void
plic_intr_bootstrap(vaddr_t addr)
{
	int i, j;
	extern struct bus_space armv7_bs_tag;
	plic_iot = &armv7_bs_tag;
	plic_ioh = addr;
	for (i = 0; i < INTC_NUM_BANKS; i++)
		for (j = 0; j < NIPL; j++)
			plic_imask[i][j] = 0xffffffff;
}
#endif

int
plic_irq_handler(void *frame)
{
#if 0
	int irq, pri, s;
	struct plic_intrhand *ih;
	void *arg;

	irq = bus_space_read_4(plic_iot, plic_ioh, INTC_SIR_IRQ);
#ifdef DEBUG_INTC
	printf("irq %d fired\n", irq);
#endif

	pri = plic_handler[irq].iq_irq;
	s = plic_splraise(pri);
	TAILQ_FOREACH(ih, &plic_handler[irq].is_list, ih_list) {
		if (ih->ih_arg != 0)
			arg = ih->ih_arg;
		else
			arg = frame;

		if (ih->ih_func(arg))
			ih->ih_count.ec_count++;

	}
	bus_space_write_4(plic_iot, plic_ioh, INTC_CONTROL,
	    INTC_CONTROL_NEWIRQ);

	plic_splx(s);
#else
	panic("plic_irq_handler unimplemented");
	return 0;
#endif
}

void
plic_intr_route(void *cookie, int enable, struct cpu_info *ci)
{
	// XXX TODO
	panic("plic_intr_route unimplemented");
	return;
}

void *
plic_intr_establish(int irqno, int level, int (*func)(void *),
    void *arg, char *name)
{
	struct plic_softc *sc = plic;
	struct plic_intrhand *ih;
	int sie;

	if (irqno < 0 || irqno >= PLIC_MAX_IRQS)
		panic("plic_intr_establish: bogus irqnumber %d: %s",
		     irqno, name);
	sie = disable_interrupts();

	ih = malloc(sizeof *ih, M_DEVBUF, M_WAITOK);
	ih->ih_func = func;
	ih->ih_arg = arg;
	ih->ih_ipl = level & IPL_IRQMASK;
	ih->ih_flags = level & IPL_FLAGMASK;
	ih->ih_irq = irqno;
	ih->ih_name = name;

#if 0	// XXX Identify Core-Local Interrupts?
	if (IS_IRQ_LOCAL(irqno))
		sc->sc_localcoremask[0] |= (1 << IRQ_LOCAL(irqno));
#endif

	TAILQ_INSERT_TAIL(&sc->sc_isrcs[irqno].is_list, ih, ih_list);

	if (name != NULL)
		evcount_attach(&ih->ih_count, name, &ih->ih_irq);

#ifdef DEBUG_INTC
	printf("%s irq %d level %d [%s]\n", __func__, irqno, level,
	    name);
#endif
#if 0	//XXX
	plic_calc_mask();
#endif
	restore_interrupts(sie);
	return (ih);
}

void *
plic_intr_establish_fdt(void *cookie, int *cell, int level,
    int (*func)(void *), void *arg, char *name)
{
	return plic_intr_establish(cell[0], level, func, arg, name);
}

void
plic_intr_disestablish(void *cookie)
{
	struct plic_softc *sc = plic;
	struct plic_intrhand *ih = cookie;
	int irqno = ih->ih_irq;
	int sie;

	sie = disable_interrupts();
	TAILQ_REMOVE(&sc->sc_isrcs[irqno].is_list, ih, ih_list);
	if (ih->ih_name != NULL)
		evcount_detach(&ih->ih_count);
	free(ih, M_DEVBUF, 0);
	restore_interrupts(sie);
}
