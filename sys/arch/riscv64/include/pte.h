/*
 * Copyright (c) 2019 Brian Bamsch <bbamsch@google.com>
 * Copyright (c) 2014 Dale Rahn <drahn@dalerahn.com>
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
#ifndef _RISCV64_PTE_H_
#define _RISCV64_PTE_H_

#include "machine/vmparam.h"

/* Block and Page attributes */
#define ATTR_MASK	(0x3ffUL)
#define ATTR_RSW	(3UL << 8)	/* Supervisor Reserved */
#define ATTR_D		(1UL << 7)	/* Dirty */
#define ATTR_A		(1UL << 6)	/* Accessed */
#define ATTR_G		(1UL << 5)	/* Global */
#define ATTR_U		(1UL << 4)	/* User */
#define ATTR_X		(1UL << 3)	/* Execute */
#define ATTR_W		(1UL << 2)	/* Write */
#define ATTR_R		(1UL << 1)	/* Read */
#define ATTR_V		(1UL << 0)	/* Valid */

/* Level 0 table, 4KiB per entry */
#define		L0_SHIFT	12
#define		L0_SIZE		(1ULL << L0_SHIFT)
#define		L0_OFFSET	(L0_SIZE - 1)

/* Level 1 table, 2MiB per entry */
#define		L1_SHIFT	21
#define		L1_SIZE		(1UL << L1_SHIFT)
#define		L1_OFFSET	(L1_SIZE - 1)

/* Level 2 table, 1GiB per entry */
#define		L2_SHIFT	30
#define		L2_SIZE		(1UL << L2_SHIFT)
#define		L2_OFFSET	(L2_SIZE - 1)

/* page mapping */
#define		Ln_ENTRIES	(1 << 9)
#define		Ln_ADDR_MASK	(Ln_ENTRIES - 1)
#define		Ln_TABLE_MASK	((1 << 12) - 1)

/* physical page number mask */
#define PTE_RPGN (((1ULL << 56) - 1) & ~PAGE_MASK)

#ifndef _LOCORE

typedef uint64_t pd_entry_t;
typedef uint64_t pt_entry_t;

#endif /* !_LOCORE */

#endif /* _RISCV64_PTE_H_ */
