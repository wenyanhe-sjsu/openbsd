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

#include <dev/ofw/openfirm.h>
#include <dev/ofw/fdt.h>


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
    (sc->contexts[h].enable_offset + ((n) / 32) * sizeof(uint32_t))
#define	PLIC_THRESHOLD(sc, h)						\
    (sc->contexts[h].context_offset + PLIC_CONTEXT_THRESHOLD)
#define	PLIC_CLAIM(sc, h)						\
    (sc->contexts[h].context_offset + PLIC_CONTEXT_CLAIM)


struct intrhand {
	TAILQ_ENTRY(intrhand) ih_list;	/* link on intrq list */
	int (*ih_func)(void *);		/* handler */
	void *ih_arg;			/* arg for handler */
	int ih_ipl;			/* IPL_* */
	int ih_irq;			/* IRQ number */
	struct evcount	ih_count;
	char *ih_name;
};

struct plic_irqsrc {
	TAILQ_HEAD(, intrhand) is_list;	/* handler list */
	int is_irq;			/* IRQ to mask while handling */
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
void	plic_irq_handler(void *);
void	plic_intr_route(void *, int , struct cpu_info *);

int	riscv_hartid_to_cpu(int);
int	plic_get_hartid(int);

int
riscv_hartid_to_cpu(int hartid)
{
#ifdef MULTIPROCESSOR
	// XXX Figure this out
	int i;

	CPU_FOREACH(i) {
		if (pcpu_find(i)->pc_hart == hartid)
			return (i);
	}
#else
	// XXX Figure this out
	// Just force return CPU 0 for now
	return (0);
#endif

	return (-1);
}

int
plic_get_hartid(int intc)
{
	uint32_t hart;

	/* Check the interrupt controller layout. */
	if (OF_getpropintarray(intc, "#interrupt-cells", &hart,
	    sizeof(hart)) < 0) {
		printf(": could not find #interrupt-cells for phandle %u\n", intc);
		return (-1);
	}

	/*
	 * The parent of the interrupt-controller is the CPU we are
	 * interested in, so search for its hart ID.
	 */
	if (OF_getpropintarray(OF_parent(intc), "reg", (uint32_t *)&hart,
	    sizeof(hart)) < 0) {
		printf(": could not find hartid\n");
		return (-1);
	}

	return (hart);
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
	uint32_t* intr;
	uint32_t irq;
	uint32_t cpu;
	int node;
	int len;
	int nintr;
	int context;
	int i;
	int hart;

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

#if 0
	for (i = 0; i < PLIC_MAX_IRQS; i++) {
		bus_space_write_4(plic->sc_iot, plic->sc_ioh, INTC_ILRn(i),
		    INTC_ILR_PRIs(INTC_MIN_PRI)|INTC_ILR_IRQ);

		TAILQ_INIT(&plic_handler[i].iq_list);
	}
#endif
	isrcs = sc->sc_isrcs;
	for (irq = 1; irq <= sc->sc_ndev; irq++) {
		isrcs[irq].is_irq = irq;

		// Register Interrupt Source
#if 0		// Example (from FreeBSD)
		error = intr_isrc_register(&isrcs[irq].isrc, sc->dev,
		    0, "%s,%u", name, irq);
		if (error != 0)
			return (error);
#endif

		// Mask interrupt
		bus_space_write_4(plic->sc_iot, plic->sc_ioh,
		    PLIC_PRIORITY(irq), 0);
	}

#if 0	// XXX Irrelevant ???
	plic_calc_mask();
#endif

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
	 * 2. Walk up the device tree to find the corresponding CPU, and grab
	 *    it's hart ID.
	 *
	 * 3. Convert the hart to a cpuid, and calculate the register offsets
	 *    based on the context number.
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

		/* Get the hart ID from the CLIC's phandle. */
		hart = plic_get_hartid(OF_getnodebyphandle(intr[i]));
		if (hart < 0) {
			printf(": failed to resolve hart from clic\n");
			free(intr, M_TEMP, len);
			return;
		}

		/* Get the corresponding cpuid. */
		cpu = riscv_hartid_to_cpu(hart);
		if (cpu < 0) {
			printf(": invalid hart!\n");
			free(intr, M_TEMP, len);
			return;
		}

		/* Set the enable and context register offsets for the CPU. */
		sc->sc_contexts[cpu].enable_offset = PLIC_ENABLE_BASE +
		    context * PLIC_ENABLE_STRIDE;
		sc->sc_contexts[cpu].context_offset = PLIC_CONTEXT_BASE +
		    context * PLIC_CONTEXT_STRIDE;
	}

	free(intr, M_TEMP, len);

	plic_attached = 1;

	/*
	 * insert self as external interrupt handler,
	 * might need a different func call
	 *
	riscv_set_intr_handler(plic_splraise, plic_spllower, plic_splx,
		plic_setipl, plic_irq_handler);
	*/

	sc->sc_intc.ic_node = faa->fa_node;
	sc->sc_intc.ic_cookie = sc;
	sc->sc_intc.ic_establish = plic_intr_establish_fdt;
	sc->sc_intc.ic_disestablish = plic_intr_disestablish;
	sc->sc_intc.ic_route = plic_intr_route;

	riscv_intr_register_fdt(&sc->sc_intc);


	plic_setipl(IPL_HIGH);  /* XXX ??? */

	/* enable external interrupt */
	// XXX
	

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
	struct intrhand *ih;
	int i;

	/* PLIC irq 0 is reserved, thus we start from 1 */
	for (irq = 1; irq < PLIC_MAX_IRQS; irq++) {
		int max = IPL_NONE;
		int min = IPL_HIGH;
		TAILQ_FOREACH(ih, &sc->sc_handler[irq].is_list, ih_list) {
			if (ih->ih_ipl > max)
				max = ih->ih_ipl;

			if (ih->ih_ipl < min)
				min = ih->ih_ipl;
		}

		sc->sc_handler[irq].iq_irq = max;

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
#if 0
	struct cpu_info *ci = curcpu();
	int old = ci->ci_cpl;
	plic_splx(new);
	return (old);
#else
	panic("plic_spllower unimplemented");
	return (new);
#endif
}

int
plic_splraise(int new)
{
#if 0
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
#else
	panic("plic_splraise unimplemented");
	return (new);
#endif
}

void
plic_setipl(int new)
{
#if 0
	struct cpu_info		*ci = curcpu();
	//struct plic_softc	*sc = plic;
	int			 psw;

	/* disable here is only to keep hardware in sync with ci->ci_cpl */
	psw = disable_interrupts();
	ci->ci_cpl = new;

	/* low values are higher priority thus IPL_HIGH - pri */
	bus_space_write_4(sc->sc_iot, sc->sc_p_ioh, ICPIPMR,
	    (IPL_HIGH - new) << ICMIPMR_SH);
	restore_interrupts(psw);
#else
	panic("plic_setipl unimplemented");
#endif
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

void
plic_irq_handler(void *frame)
{
#if 0
	int irq, pri, s;
	struct intrhand *ih;
	void *arg;

	irq = bus_space_read_4(plic_iot, plic_ioh, INTC_SIR_IRQ);
#ifdef DEBUG_INTC
	printf("irq %d fired\n", irq);
#endif

	pri = plic_handler[irq].iq_irq;
	s = plic_splraise(pri);
	TAILQ_FOREACH(ih, &plic_handler[irq].iq_list, ih_list) {
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
	panic("plic_intr_establish unimplemented");
	return (0);
#if 0
	struct plic_softc *sc = plic;
	struct intrhand *ih;
	int psw;

	if (irqno < 0 || irqno >= INTC_NIRQ)
		panic("plic_intr_establish: bogus irqnumber %d: %s",
		     irqno, name);
	psw = disable_interrupts();

	ih = malloc(sizeof *ih, M_DEVBUF, M_WAITOK);
	ih->ih_func = func;
	ih->ih_arg = arg;
	ih->ih_ipl = level & IPL_IRQMASK;
	ih->ih_flags = level & IPL_FLAGMASK;//XXX flags for ?
	ih->ih_irq = irqno;
	ih->ih_name = name;

#if 0	// XXX
	if (IS_IRQ_LOCAL(irqno))
		sc->sc_localcoremask[0] |= (1 << IRQ_LOCAL(irqno));
#endif

	TAILQ_INSERT_TAIL(&sc->sc_handler[irqno].is_list, ih, ih_list);

	if (name != NULL)
		evcount_attach(&ih->ih_count, name, &ih->ih_irq);

#ifdef DEBUG_INTC
	printf("%s irq %d level %d [%s]\n", __func__, irqno, level,
	    name);
#endif
#if 0	//XXX
	plic_calc_mask();
#endif
	restore_interrupts(psw);
	return (ih);
#endif
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
	struct intrhand *ih = cookie;
	int irqno = ih->ih_irq;
	int psw;

	psw = disable_interrupts();
	TAILQ_REMOVE(&sc->sc_isrcs[irqno].is_list, ih, ih_list);
	if (ih->ih_name != NULL)
		evcount_detach(&ih->ih_count);
	free(ih, M_DEVBUF, 0);
	restore_interrupts(psw);
}
