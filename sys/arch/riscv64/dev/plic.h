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

#ifndef _RISCV_PLIC_H_
#define _RISCV_PLIC_H_

#ifndef _LOCORE

#if 0
#include <machine/riscvreg.h>
#include <machine/cpufunc.h>
#include <machine/intr.h>
#include <arm/softintr.h>
#endif

extern volatile int current_spl_level;
extern volatile int softint_pending;
void plic_do_pending(void);

#define SI_TO_IRQBIT(si)  (1U<<(si))
void plic_setipl(int new);
void plic_splx(int new);
int plic_splraise(int ipl);
int plic_spllower(int ipl);
void plic_setsoftintr(int si);

#if 0
/*
 * An useful function for interrupt handlers.
 * XXX: This shouldn't be here.
 */
static __inline int
find_first_bit( uint32_t bits )
{
	int count;

	/* since CLZ is available only on ARMv5, this isn't portable
	 * to all ARM CPUs.  This file is for OMAPINTC processor.
	 */
	asm( "clz %0, %1" : "=r" (count) : "r" (bits) );
	return 31-count;
}
#endif


/*
 * This function *MUST* be called very early on in a port's
 * initriscv() function, before ANY spl*() functions are called.
 *
 * The parameter is the virtual address of the RISC-V Platform Interrupt
 * Controller registers.
 */
void plic_intr_bootstrap(vaddr_t);

void plic_irq_handler(void *);
void *plic_intr_establish(int irqno, int level, int (*func)(void *),
    void *cookie, char *name);
void plic_intr_disestablish(void *cookie);
const char *plic_intr_string(void *cookie);

#endif /* ! _LOCORE */

#endif /* _RISCV_PLIC_H_*/
