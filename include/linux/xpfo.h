/*
 * Copyright (C) 2017 Docker, Inc.
 * Copyright (C) 2017 Hewlett Packard Enterprise Development, L.P.
 * Copyright (C) 2016 Brown University. All rights reserved.
 *
 * Authors:
 *   Juerg Haefliger <juerg.haefliger@hpe.com>
 *   Vasileios P. Kemerlis <vpk@cs.brown.edu>
 *   Tycho Andersen <tycho@docker.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 */

#ifndef _LINUX_XPFO_H
#define _LINUX_XPFO_H

#ifdef CONFIG_XPFO

#include <linux/dma-mapping.h>

extern struct page_ext_operations page_xpfo_ops;

void set_kpte(void *kaddr, struct page *page, pgprot_t prot);
void xpfo_dma_map_unmap_area(bool map, const void *addr, size_t size,
				    enum dma_data_direction dir);
void xpfo_flush_kernel_tlb(struct page *page, int order);

void xpfo_kmap(void *kaddr, struct page *page);
void xpfo_kunmap(void *kaddr, struct page *page);
void xpfo_alloc_pages(struct page *page, int order, gfp_t gfp);
void xpfo_free_pages(struct page *page, int order);

bool xpfo_page_is_unmapped(struct page *page);

#define XPFO_TEMP_MAP_SIZE(addr, size) \
	(PFN_UP((unsigned long) (addr) + (size)) - \
		PFN_DOWN((unsigned long) (addr)))

void xpfo_temp_map(const void *addr, size_t size, void **mapping,
		   size_t mapping_len);
void xpfo_temp_unmap(const void *addr, size_t size, void **mapping,
		     size_t mapping_len);

bool xpfo_enabled(void);

#else /* !CONFIG_XPFO */

static inline void xpfo_kmap(void *kaddr, struct page *page) { }
static inline void xpfo_kunmap(void *kaddr, struct page *page) { }
static inline void xpfo_alloc_pages(struct page *page, int order, gfp_t gfp) { }
static inline void xpfo_free_pages(struct page *page, int order) { }

static inline bool xpfo_page_is_unmapped(struct page *page) { return false; }

#define XPFO_TEMP_MAP_SIZE(addr, size) 0

static inline void xpfo_temp_map(const void *addr, size_t size, void **mapping,
				 size_t mapping_len)
{
}

static inline void xpfo_temp_unmap(const void *addr, size_t size,
				   void **mapping, size_t mapping_len)
{
}


static inline bool xpfo_enabled(void) { return false; }

#endif /* CONFIG_XPFO */

#endif /* _LINUX_XPFO_H */
