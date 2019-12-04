/*
 *  linux/mm/swap.c
 *
 *  Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 */

/*
 * This file contains the default values for the opereation of the
 * Linux VM subsystem. Fine-tuning documentation can be found in
 * linux/Documentation/sysctl/vm.txt.
 * Started 18.12.91
 * Swap aging added 23.2.95, Stephen Tweedie.
 * Buffermem limits added 12.3.98, Rik van Riel.
 */
// active
// lru_cache add/del

#include <linux/mm.h>
#include <linux/kernel_stat.h>
#include <linux/swap.h>
#include <linux/swapctl.h>
#include <linux/pagemap.h>
#include <linux/init.h>

#include <asm/dma.h>
#include <asm/uaccess.h> /* for copy_to/from_user */
#include <asm/pgtable.h>

/* How many pages do we try to swap or page in/out together? */
int page_cluster;	// 换页个数

pager_daemon_t pager_daemon = {
	512,	/* base number for calculating the number of tries */
	SWAP_CLUSTER_MAX,	/* minimum number of tries */
	8,	/* do swap I/O in clusters of this size */
};

/*
 * Move an inactive page to the active list.
 */
// 激活未上锁的页
// ?: 如果 LRU && incativate --> 移除未激活，移入激活
static inline void activate_page_nolock(struct page * page)
{
	if (PageLRU(page) && !PageActive(page)) {
		del_page_from_inactive_list(page);
		add_page_to_active_list(page);
	}
}

void activate_page(struct page * page)
{
	spin_lock(&pagemap_lru_lock);
	activate_page_nolock(page);
	spin_unlock(&pagemap_lru_lock);
}

/**
 * lru_cache_add: add a page to the page lists
 * @page: the page to add
 */
// 加页
// 核心在swap.h里
void lru_cache_add(struct page * page)
{
	if (!TestSetPageLRU(page)) {
		spin_lock(&pagemap_lru_lock);
		add_page_to_inactive_list(page);	// 加页加入未激活表中
		spin_unlock(&pagemap_lru_lock);
	}
}

/**
 * __lru_cache_del: remove a page from the page lists
 * @page: the page to add
 *
 * This function is for when the caller already holds
 * the pagemap_lru_lock.
 */
// 从页列表中删除页
void __lru_cache_del(struct page * page)
{
	if (TestClearPageLRU(page)) {
		if (PageActive(page)) {
			del_page_from_active_list(page);		// 从激活删页
		} else {
			del_page_from_inactive_list(page);		// 从未激活删页
		}
	}
}

/**
 * lru_cache_del: remove a page from the page lists
 * @page: the page to remove
 */
// LRU方式缓存删除页
void lru_cache_del(struct page * page)
{
	spin_lock(&pagemap_lru_lock);
	__lru_cache_del(page);
	spin_unlock(&pagemap_lru_lock);
}

/*
 * Perform any setup for the swap system
 */
// 初始化换页过程
// 不重要，没有用到
void __init swap_setup(void)
{
	// TODO why 20-PAGE_SHIFT? 
	unsigned long megs = num_physpages >> (20 - PAGE_SHIFT);

	/* Use a smaller cluster for small-memory machines */
	if (megs < 16)
		page_cluster = 2;
	else
		page_cluster = 3;
	/*
	 * Right now other parts of the system means that we
	 * _really_ don't want to cluster much more
	 */
}
