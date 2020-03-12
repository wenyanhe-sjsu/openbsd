/*
 * Copyright (c) 2016 Dale Rahn <drahn@dalerahn.com>
 * Copyright (c) 2017 Mark Kettenis <kettenis@openbsd.org>
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
#include <sys/malloc.h>
#include <sys/device.h>
#include <sys/sysctl.h>
#include <sys/task.h>

#include <uvm/uvm.h>

#include <machine/fdt.h>

#include <dev/ofw/openfirm.h>
#include <dev/ofw/ofw_clock.h>
#include <dev/ofw/ofw_regulator.h>
#include <dev/ofw/ofw_thermal.h>
#include <dev/ofw/fdt.h>

#include <machine/cpufunc.h>

#if 0
#include "psci.h"
#if NPSCI > 0
#include <dev/fdt/pscivar.h>
#endif
#endif

/* CPU Identification */
//XXXX TODO
#define CPU_IMPL_SIFIVE		0x00//XXX to be figured out later

struct cpu_cores {
	int	id;
	char	*name;
};

struct cpu_cores cpu_cores_none[] = {
	{ 0, NULL },
};

struct cpu_cores cpu_cores_sifive[] = {
	{ 0, NULL },
};

/* riscv cores makers */
const struct implementers {
	int			id;
	char			*name;
	struct cpu_cores	*corelist;
} cpu_implementers[] = {
	{ CPU_IMPL_SIFIVE, "SiFive", cpu_cores_sifive },
	{ 0, NULL },
};

char cpu_model[64] = "CMPE295";//XXX :)
int cpu_node;

struct cpu_info *cpu_info_list = &cpu_info_primary;

int	cpu_match(struct device *, void *, void *);
void	cpu_attach(struct device *, struct device *, void *);

struct cfattach cpu_ca = {
	sizeof(struct device), cpu_match, cpu_attach
};

struct cfdriver cpu_cd = {
	NULL, "cpu", DV_DULL
};
#if 0 //XXX
void	cpu_flush_bp_psci(void);
#endif

#if 0 // XXX from freebsd
void
identify_cpu(void)
{
	const struct cpu_parts *cpu_partsp;
	uint32_t part_id;
	uint32_t impl_id;
	uint64_t mimpid;
	uint64_t misa;
	u_int cpu;
	size_t i;

	cpu_partsp = NULL;

	/* TODO: can we get mimpid and misa somewhere ? */
	mimpid = 0;
	misa = 0;

	cpu = PCPU_GET(cpuid);

	impl_id	= CPU_IMPL(mimpid);
	for (i = 0; i < nitems(cpu_implementers); i++) {
		if (impl_id == cpu_implementers[i].impl_id ||
		    cpu_implementers[i].impl_id == 0) {
			cpu_desc[cpu].cpu_impl = impl_id;
			cpu_desc[cpu].cpu_impl_name = cpu_implementers[i].impl_name;
			cpu_partsp = cpu_parts_std;
			break;
		}
	}

	part_id = CPU_PART(misa);
	for (i = 0; &cpu_partsp[i] != NULL; i++) {
		if (part_id == cpu_partsp[i].part_id ||
		    cpu_partsp[i].part_id == -1) {
			cpu_desc[cpu].cpu_part_num = part_id;
			cpu_desc[cpu].cpu_part_name = cpu_partsp[i].part_name;
			break;
		}
	}

	/* Print details for boot CPU or if we want verbose output */
	if (cpu == 0 || bootverbose) {
		printf("CPU(%d): %s %s\n", cpu,
		    cpu_desc[cpu].cpu_impl_name,
		    cpu_desc[cpu].cpu_part_name);
	}
}
#endif

void
cpu_identify(struct cpu_info *ci)
{
#if 0
	uint64_t midr, impl, part;
	uint64_t clidr, id_aa64pfr0;
	uint32_t ctr, ccsidr, sets, ways, line;
	const char *impl_name = NULL;
	const char *part_name = NULL;
	const char *il1p_name = NULL;
	const char *sep;
	struct cpu_cores *coreselecter = cpu_cores_none;
	int i;

	midr = READ_SPECIALREG(midr_el1);
	impl = CPU_IMPL(midr);
	part = CPU_PART(midr);

	for (i = 0; cpu_implementers[i].name; i++) {
		if (impl == cpu_implementers[i].id) {
			impl_name = cpu_implementers[i].name;
			coreselecter = cpu_implementers[i].corelist;
			break;
		}
	}

	for (i = 0; coreselecter[i].name; i++) {
		if (part == coreselecter[i].id) {
			part_name = coreselecter[i].name;
			break;
		}
	}

	if (impl_name && part_name) {
		printf(" %s %s r%llup%llu", impl_name, part_name, CPU_VAR(midr),
		    CPU_REV(midr));

		if (CPU_IS_PRIMARY(ci))
			snprintf(cpu_model, sizeof(cpu_model),
			    "%s %s r%llup%llu", impl_name, part_name,
			    CPU_VAR(midr), CPU_REV(midr));
	} else {
		printf(" Unknown, MIDR 0x%llx", midr);

		if (CPU_IS_PRIMARY(ci))
			snprintf(cpu_model, sizeof(cpu_model), "Unknown");
	}

	/* Print cache information. */

	ctr = READ_SPECIALREG(ctr_el0);
	switch (ctr & CTR_IL1P_MASK) {
	case CTR_IL1P_AIVIVT:
		il1p_name = "AIVIVT ";
		break;
	case CTR_IL1P_VIPT:
		il1p_name = "VIPT ";
		break;
	case CTR_IL1P_PIPT:
		il1p_name = "PIPT ";
		break;
	}

	clidr = READ_SPECIALREG(clidr_el1);
	for (i = 0; i < 7; i++) {
		if ((clidr & CLIDR_CTYPE_MASK) == 0)
			break;
		printf("\n%s:", ci->ci_dev->dv_xname);
		sep = "";
		if (clidr & CLIDR_CTYPE_INSN) {
			WRITE_SPECIALREG(csselr_el1,
			    i << CSSELR_LEVEL_SHIFT | CSSELR_IND);
			ccsidr = READ_SPECIALREG(ccsidr_el1);
			sets = CCSIDR_SETS(ccsidr);
			ways = CCSIDR_WAYS(ccsidr);
			line = CCSIDR_LINE_SIZE(ccsidr);
			printf("%s %dKB %db/line %d-way L%d %sI-cache", sep,
			    (sets * ways * line) / 1024, line, ways, (i + 1),
			    il1p_name);
			il1p_name = "";
			sep = ",";
		}
		if (clidr & CLIDR_CTYPE_DATA) {
			WRITE_SPECIALREG(csselr_el1, i << CSSELR_LEVEL_SHIFT);
			ccsidr = READ_SPECIALREG(ccsidr_el1);
			sets = CCSIDR_SETS(ccsidr);
			ways = CCSIDR_WAYS(ccsidr);
			line = CCSIDR_LINE_SIZE(ccsidr);
			printf("%s %dKB %db/line %d-way L%d D-cache", sep,
			    (sets * ways * line) / 1024, line, ways, (i + 1));
			sep = ",";
		}
		if (clidr & CLIDR_CTYPE_UNIFIED) {
			WRITE_SPECIALREG(csselr_el1, i << CSSELR_LEVEL_SHIFT);
			ccsidr = READ_SPECIALREG(ccsidr_el1);
			sets = CCSIDR_SETS(ccsidr);
			ways = CCSIDR_WAYS(ccsidr);
			line = CCSIDR_LINE_SIZE(ccsidr);
			printf("%s %dKB %db/line %d-way L%d cache", sep,
			    (sets * ways * line) / 1024, line, ways, (i + 1));
		}
		clidr >>= 3;
	}
#endif

#if 0 	// ARM specific stuff
	/*
	 * Some ARM processors are vulnerable to branch target
	 * injection attacks (CVE-2017-5715).
	 */
	switch (impl) {
	case CPU_IMPL_ARM:
		switch (part) {
		case CPU_PART_CORTEX_A35:
		case CPU_PART_CORTEX_A53:
		case CPU_PART_CORTEX_A55:
			/* Not vulnerable. */
			ci->ci_flush_bp = cpu_flush_bp_noop;
			break;
		default:
			/*
			 * Potentially vulnerable; call into the
			 * firmware and hope we're running on top of
			 * Arm Trusted Firmware with a fix for
			 * Security Advisory TFV 6.
			 */
			ci->ci_flush_bp = cpu_flush_bp_psci;
			break;
		}
		break;
	default:
		/* Not much we can do for an unknown processor.  */
		ci->ci_flush_bp = cpu_flush_bp_noop;
		break;
	}

	/*
	 * The architecture has been updated to explicitly tell us if
	 * we're not vulnerable.
	 */
	id_aa64pfr0 = READ_SPECIALREG(id_aa64pfr0_el1);
	if (ID_AA64PFR0_CSV2(id_aa64pfr0) == ID_AA64PFR0_CSV2_IMPL ||
	    ID_AA64PFR0_CSV2(id_aa64pfr0) == ID_AA64PFR0_CSV2_SCXT)
		ci->ci_flush_bp = cpu_flush_bp_noop;
#endif 
}

#if 0//XXX
int	cpu_hatch_secondary(struct cpu_info *ci, int, uint64_t);
#endif
int	cpu_clockspeed(int *);

int
cpu_match(struct device *parent, void *cfdata, void *aux)
{
	struct fdt_attach_args *faa = aux;

	char buf[32];

	if (OF_getprop(faa->fa_node, "device_type", buf, sizeof(buf)) <= 0 ||
	    strcmp(buf, "cpu") != 0)
		return 0;

	if (ncpus <= MAXCPUS)	//XXX to force return 1
		return 1;
	return 0;
}

void
cpu_attach(struct device *parent, struct device *dev, void *aux)
{
	struct fdt_attach_args *faa = aux;
	struct cpu_info *ci;

	KASSERT(faa->fa_nreg > 0);

#ifdef MULTIPROCESSOR
	ci = malloc(sizeof(*ci), M_DEVBUF, M_WAITOK | M_ZERO);
	cpu_info[dev->dv_unit] = ci;
	ci->ci_next = cpu_info_list->ci_next;
	cpu_info_list->ci_next = ci;
	ci->ci_flags |= CPUF_AP;
	ncpus++;
#endif

	ci->ci_dev = dev;
	ci->ci_cpuid = dev->dv_unit;
	ci->ci_node = faa->fa_node;
	ci->ci_self = ci;

#ifdef MULTIPROCESSOR // XXX TBD: CMPE
	if (ci->ci_flags & CPUF_AP) {
		char buf[32];
		uint64_t spinup_data = 0;
		int spinup_method = 0;
		int timeout = 10000;
		int len;

		len = OF_getprop(ci->ci_node, "enable-method",
		    buf, sizeof(buf));
		if (strcmp(buf, "psci") == 0) {
			spinup_method = 1;
		} else if (strcmp(buf, "spin-table") == 0) {
			spinup_method = 2;
			spinup_data = OF_getpropint64(ci->ci_node,
			    "cpu-release-addr", 0);
		}

		sched_init_cpu(ci);
		if (cpu_hatch_secondary(ci, spinup_method, spinup_data)) {
			atomic_setbits_int(&ci->ci_flags, CPUF_IDENTIFY);
			__asm volatile("dsb sy; sev");

			while ((ci->ci_flags & CPUF_IDENTIFIED) == 0 &&
			    --timeout)
				delay(1000);
			if (timeout == 0) {
				printf(" failed to identify");
				ci->ci_flags = 0;
			}
		} else {
			printf(" failed to spin up");
			ci->ci_flags = 0;
		}
	} else {
#endif
		cpu_identify(ci);

		if (OF_getproplen(ci->ci_node, "clocks") > 0) {
			cpu_node = ci->ci_node;
			cpu_cpuspeed = cpu_clockspeed;
		}

#if 0// XXX CMPE
		/* Initialize debug registers. */
		WRITE_SPECIALREG(mdscr_el1, DBG_MDSCR_TDCC);
		WRITE_SPECIALREG(oslar_el1, 0);
#endif

#ifdef MULTIPROCESSOR
	}
#endif

	printf("\n");
}

int
cpu_clockspeed(int *freq)
{
	//*freq = clock_get_frequency(cpu_node, NULL) / 1000000;
	//XXX don't care for now
	*freq = 100;
	return 0;
}
