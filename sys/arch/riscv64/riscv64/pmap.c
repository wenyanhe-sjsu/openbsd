/*
 * Copyright (c) 2019 Brian Bamsch <bbamsch@google.com>
 * Copyright (c) 2008-2009,2014-2016 Dale Rahn <drahn@dalerahn.com>
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
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/user.h>
#include <sys/systm.h>
#include <sys/pool.h>
#include <sys/atomic.h>

#include <uvm/uvm.h>

#include "machine/vmparam.h"
#include "machine/pmap.h"
// XXX machine/cpufunc.h
// #include "machine/cpufunc.h"
#include "machine/pcb.h"

#include <machine/db_machdep.h>
#include <ddb/db_extern.h>
#include <ddb/db_output.h>

// XXX Get rid of this once PMAP is complete
#define UNIMPLEMENTED()	panic("%s:%s UNIMPLEMENTED", __FILE__, __func__)

struct pmap kernel_pmap_;
struct pmap pmap_tramp;

LIST_HEAD(pted_pv_head, pte_desc);

struct pte_desc {
	LIST_ENTRY(pte_desc) pted_pv_list;
	uint64_t pted_pte;
	pmap_t pted_pmap;
	vaddr_t pted_va;
};

struct pmapvp0 {
	uint64_t l0[VP_IDX0_CNT];
	struct pte_desc *vp[VP_IDX0_CNT];
};

struct pmapvp1 {
	uint64_t l1[VP_IDX1_CNT];
	struct pmapvp0 *vp[VP_IDX1_CNT];
};

struct pmapvp2 {
	uint64_t l2[VP_IDX2_CNT];
	struct pmapvp1 *vp[VP_IDX2_CNT];
};

CTASSERT(sizeof(struct pmapvp0) == sizeof(struct pmapvp1));
CTASSERT(sizeof(struct pmapvp0) == sizeof(struct pmapvp2));

void pmap_kremove_pg(vaddr_t va);

vaddr_t vmmap;
vaddr_t zero_page;
vaddr_t copy_src_page;
vaddr_t copy_dst_page;

/* XXX - panic on pool get failures? */
struct pool pmap_pmap_pool;
struct pool pmap_pted_pool;
struct pool pmap_vp_pool;

vaddr_t virtual_avail, virtual_end;
int	pmap_virtual_space_called = 0;
int pmap_initialized = 0;

// XXX Currently unused, but likely useful when implemented
// static inline void
// pmap_lock(struct pmap *pmap)
// {
// 	if (pmap != pmap_kernel())
// 		mtx_enter(&pmap->pm_mtx);
// }

// static inline void
// pmap_unlock(struct pmap *pmap)
// {
// 	if (pmap != pmap_kernel())
// 		mtx_leave(&pmap->pm_mtx);
// }

// static inline int
// VP_IDX0(vaddr_t va)
// {
// 	return (va >> VP_IDX0_POS) & VP_IDX0_MASK;
// }

// static inline int
// VP_IDX1(vaddr_t va)
// {
// 	return (va >> VP_IDX1_POS) & VP_IDX1_MASK;
// }

// static inline int
// VP_IDX2(vaddr_t va)
// {
// 	return (va >> VP_IDX2_POS) & VP_IDX2_MASK;
// }

struct pte_desc *
pmap_vp_lookup(pmap_t pm, vaddr_t va, uint64_t **pl0entry)
{
	UNIMPLEMENTED();
	return 0;
}

struct pte_desc *
pmap_vp_remove(pmap_t pm, vaddr_t va)
{
	UNIMPLEMENTED();
	return 0;
}

int
pmap_vp_enter(pmap_t pm, vaddr_t va, struct pte_desc *pted, int flags)
{
	UNIMPLEMENTED();
	return 0;
}

void *
pmap_vp_page_alloc(struct pool *pp, int flags, int *slowdown)
{
	UNIMPLEMENTED();
	return 0;
}

void
pmap_vp_page_free(struct pool *pp, void *v)
{
	UNIMPLEMENTED();
}

u_int32_t PTED_MANAGED(struct pte_desc *pted);
u_int32_t PTED_WIRED(struct pte_desc *pted);
u_int32_t PTED_VALID(struct pte_desc *pted);

u_int32_t
PTED_MANAGED(struct pte_desc *pted)
{
	return (pted->pted_va & PTED_VA_MANAGED_M);
}

u_int32_t
PTED_WIRED(struct pte_desc *pted)
{
	return (pted->pted_va & PTED_VA_WIRED_M);
}

u_int32_t
PTED_VALID(struct pte_desc *pted)
{
	return (pted->pted_pte != 0);
}

int
pmap_enter(pmap_t pm, vaddr_t va, paddr_t pa, vm_prot_t prot, int flags)
{
	UNIMPLEMENTED();
	return 0;
}

void
pmap_remove(pmap_t pm, vaddr_t sva, vaddr_t eva)
{
	UNIMPLEMENTED();
}

void
pmap_kenter_pa(vaddr_t va, paddr_t pa, vm_prot_t prot)
{
	UNIMPLEMENTED();
}

void
pmap_kremove(vaddr_t va, vsize_t len)
{
	for (len >>= PAGE_SHIFT; len > 0; len--, va += PAGE_SIZE) {
		pmap_kremove_pg(va);
	}
}

void
pmap_kremove_pg(vaddr_t va)
{
	pmap_t pm = pmap_kernel();
	struct pte_desc *pted;
	int s;

	pmap_vp_lookup(pm, va, NULL);
	if (pted == NULL) {
		return;
	}

	if (!PTED_VALID(pted)) {
		return; /* page is not mapped */
	}

	s = splvm();

	pm->pm_stats.resident_count--;

	/* XXX Need to actually remove the pted */
}

void
pmap_collect(pmap_t pm)
{
	UNIMPLEMENTED();
}

void
pmap_zero_page(struct vm_page *pg)
{
	paddr_t pa = VM_PAGE_TO_PHYS(pg);
	vaddr_t va = zero_page + cpu_number() * PAGE_SIZE;

	pmap_kenter_pa(va, pa, PROT_READ|PROT_WRITE);
	pagezero_cache(va);
	pmap_kremove_pg(va);
}

void
pmap_copy_page(struct vm_page *srcpg, struct vm_page *dstpg)
{
	paddr_t srcpa = VM_PAGE_TO_PHYS(srcpg);
	paddr_t dstpa = VM_PAGE_TO_PHYS(dstpg);
	vaddr_t srcva = copy_src_page + cpu_number() * PAGE_SIZE;
	vaddr_t dstva = copy_dst_page + cpu_number() * PAGE_SIZE;

	pmap_kenter_pa(srcva, srcpa, PROT_READ);
	pmap_kenter_pa(dstva, dstpa, PROT_READ|PROT_WRITE);
	memcpy((void *)dstva, (void *)srcva, PAGE_SIZE);
	pmap_kremove_pg(srcva);
	pmap_kremove_pg(dstva);
}

pmap_t
pmap_create(void)
{
	UNIMPLEMENTED();
	return 0;
}

void
pmap_reference(pmap_t pm)
{
	UNIMPLEMENTED();
}

void
pmap_destroy(pmap_t pm)
{
	UNIMPLEMENTED();
}

void
pmap_release(pmap_t pm)
{
	UNIMPLEMENTED();
}

vaddr_t
pmap_growkernel(vaddr_t maxkvaddr)
{
	UNIMPLEMENTED();
	return 0;
}

/*
 * Initialize pmap setup.
 * ALL of the code which deals with avail needs rewritten as an actual
 * memory allocation.
 */
CTASSERT(sizeof(struct pmapvp0) == 2 * PAGE_SIZE);

vaddr_t
pmap_bootstrap(long kvo, paddr_t lpt1, long kernelstart, long kernelend,
    long ram_start, long ram_end)
{
	UNIMPLEMENTED();
	return 0;
}

void
pmap_activate(struct proc *p)
{
	UNIMPLEMENTED();
}

void
pmap_deactivate(struct proc *p)
{
	UNIMPLEMENTED();
}

boolean_t
pmap_extract(pmap_t pm, vaddr_t va, paddr_t *pa)
{
	UNIMPLEMENTED();
	return 0;
}

void
pmap_page_protect(struct vm_page *pg, vm_prot_t prot)
{
	UNIMPLEMENTED();
}

void
pmap_protect(pmap_t pm, vaddr_t sva, vaddr_t eva, vm_prot_t prot)
{
	UNIMPLEMENTED();
}

void
pmap_init(void)
{
	UNIMPLEMENTED();
}

void
pmap_proc_iflush(struct process *pr, vaddr_t va, vsize_t len)
{
	UNIMPLEMENTED();
}

int
pmap_fault_fixup(pmap_t pm, vaddr_t va, vm_prot_t ftype, int user)
{
	UNIMPLEMENTED();
	return 0;
}

void
pmap_postinit(void)
{
	UNIMPLEMENTED();
}

void
pmap_update(pmap_t pm)
{
	UNIMPLEMENTED();
}

int
pmap_is_referenced(struct vm_page *pg)
{
	return ((pg->pg_flags & PG_PMAP_REF) != 0);
}

int
pmap_is_modified(struct vm_page *pg)
{
	return ((pg->pg_flags & PG_PMAP_MOD) != 0);
}

int
pmap_clear_modify(struct vm_page *pg)
{
	UNIMPLEMENTED();
	return 0;
}

int
pmap_clear_reference(struct vm_page *pg)
{
	UNIMPLEMENTED();
	return 0;
}

void
pmap_copy(pmap_t dst_pmap, pmap_t src_pmap, vaddr_t dst_addr,
	vsize_t len, vaddr_t src_addr)
{
	UNIMPLEMENTED();
}

void
pmap_unwire(pmap_t pm, vaddr_t va)
{
	UNIMPLEMENTED();
}

void
pmap_remove_holes(struct vmspace *vm)
{
	UNIMPLEMENTED();
}

void
pmap_virtual_space(vaddr_t *start, vaddr_t *end)
{
	*start = virtual_avail;
	*end = virtual_end;

	/* Prevent further KVA stealing. */
	pmap_virtual_space_called = 1;
}

void
pmap_avail_fixup(void)
{
	UNIMPLEMENTED();
}

paddr_t
pmap_steal_avail(size_t size, int align, void **kva)
{
	UNIMPLEMENTED();
	return 0;
}

void
pmap_physload_avail(void)
{
	UNIMPLEMENTED();
}

void
pmap_map_early(paddr_t spa, psize_t len)
{
	UNIMPLEMENTED();
}
