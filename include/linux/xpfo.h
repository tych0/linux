/*
 * Copyright (C) 2017 Hewlett Packard Enterprise Development, L.P.
 * Copyright (C) 2016 Brown University. All rights reserved.
 *
 * Authors:
 *   Juerg Haefliger <juerg.haefliger@hpe.com>
 *   Vasileios P. Kemerlis <vpk@cs.brown.edu>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 */

#ifndef _LINUX_XPFO_H
#define _LINUX_XPFO_H

#ifdef CONFIG_XPFO

extern struct page_ext_operations page_xpfo_ops;

void set_kpte(void *kaddr, struct page *page, pgprot_t prot);

void xpfo_kmap(void *kaddr, struct page *page);
void xpfo_kunmap(void *kaddr, struct page *page);
void xpfo_alloc_pages(struct page *page, int order, gfp_t gfp);
void xpfo_free_pages(struct page *page, int order);

#else /* !CONFIG_XPFO */

static inline void xpfo_kmap(void *kaddr, struct page *page) { }
static inline void xpfo_kunmap(void *kaddr, struct page *page) { }
static inline void xpfo_alloc_pages(struct page *page, int order, gfp_t gfp) { }
static inline void xpfo_free_pages(struct page *page, int order) { }

#endif /* CONFIG_XPFO */

#endif /* _LINUX_XPFO_H */
