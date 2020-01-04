/*
 *  linux/mm/page_alloc.c
 *
 *  Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 *  Swap reorganised 29.12.95, Stephen Tweedie
 *  Support of BIGMEM added by Gerhard Wichert, Siemens AG, July 1999
 *  Reshaped it to be a zoned allocator, Ingo Molnar, Red Hat, 1999
 *  Discontiguous memory support, Kanoj Sarcar, SGI, Nov 1999
 *  Zone balancing, Kanoj Sarcar, SGI, Jan 2000
 */

#include <linux/config.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/swapctl.h>
#include <linux/interrupt.h>
#include <linux/pagemap.h>
#include <linux/bootmem.h>
#include <linux/slab.h>
#include <linux/compiler.h>

int nr_swap_pages;
int nr_active_pages;
int nr_inactive_pages;
struct list_head inactive_list;
struct list_head active_list;
pg_data_t *pgdat_list;

static char *zone_names[MAX_NR_ZONES] = { "DMA", "Normal", "HighMem" };
static int zone_balance_ratio[MAX_NR_ZONES] __initdata = { 128, 128, 128, };
static int zone_balance_min[MAX_NR_ZONES] __initdata = { 20 , 20, 20, };
static int zone_balance_max[MAX_NR_ZONES] __initdata = { 255 , 255, 255, };

/*
 * Free_page() adds the page to the free lists. This is optimized for
 * fast normal cases (no error jumps taken normally).
 *
 * The way to optimize jumps for gcc-2.2.2 is to:
 *  - select the "normal" case and put it inside the if () { XXX }
 *  - no else-statements if you can avoid them
 *
 * With the above two rules, you get a straight-line execution path
 * for the normal case, giving better asm-code.
 */

#define memlist_init(x) INIT_LIST_HEAD(x)
#define memlist_add_head list_add
#define memlist_add_tail list_add_tail
#define memlist_del list_del
#define memlist_entry list_entry
#define memlist_next(x) ((x)->next)
#define memlist_prev(x) ((x)->prev)

/*
 * Temporary debugging check.
 */
#define BAD_RANGE(zone,x) (((zone) != (x)->zone) || (((x)-mem_map) < (zone)->zone_start_mapnr) || (((x)-mem_map) >= (zone)->zone_start_mapnr+(zone)->size))

/*
 * Buddy system. Hairy. You really aren't expected to understand this
 *
 * Hint: -mask = 1+~mask
 */

static void FASTCALL(__free_pages_ok (struct page *page, unsigned int order));
static void __free_pages_ok (struct page *page, unsigned int order)//page指向要释放空间的第一个页面对应的page结构，order释放页面个数的数量级
{
	unsigned long index, page_idx, mask, flags;
	free_area_t *area;
	struct page *base;
	zone_t *zone;

	/* Yes, think what happens when other parts of the kernel take 
	 * a reference to a page in order to pin it for io. -ben
	 */
	if (PageLRU(page))//检查该page是否在page lists中
		lru_cache_del(page);//如果在page lists中,那么调用该函数将其移出

	if (page->buffers)
		BUG();
	if (page->mapping)//检测(page - mem_map)即page是否在有效的范围之内
		BUG();
	if (!VALID_PAGE(page))
		BUG();
	if (PageSwapCache(page))
		BUG();
	if (PageLocked(page))
		BUG();
	if (PageLRU(page))
		BUG();
	if (PageActive(page))
		BUG();
	page->flags &= ~((1<<PG_referenced) | (1<<PG_dirty));//释放page标志位,进而释放该order页

	if (current->flags & PF_FREE_PAGES)
		goto local_freelist;
 back_local_freelist:

	zone = page->zone; //获取zone。在mem_map初始化free_area_init_core>时，就把每个page所指向的zone指定好了

	mask = (~0UL) << order;
	base = zone->zone_mem_map;//base就是zone在mem_map的地址
	page_idx = page - base;//查看page在zone的第几项,即 求page在mem_map内的下标
	if (page_idx & ~mask)//页号必须在页块尺寸边界上对齐
		BUG();
	index = page_idx >> (1 + order); //求在bitmap中的索引

	area = zone->free_area + order;//得到该页块的区域，将zone的空闲页块数加上块大小

	spin_lock_irqsave(&zone->lock, flags);

	zone->free_pages -= mask; //每次调用后会加一，mask=-1，空闲链表加1

	while (mask + (1 << (MAX_ORDER-1))) {//当order大于MAX_ORDER-1时就结束循环
		struct page *buddy1, *buddy2;

		if (area >= zone->free_area + MAX_ORDER)//检查area是否在范围内
			BUG();
		if (!__test_and_change_bit(index, area->map)//判断buddy是否空闲
			/*
			 * the buddy page is still allocated.
			 */
			break;
		/*
		 * Move the buddy up one level.
		 */
		buddy1 = base + (page_idx ^ -mask);//对页块号边界位取反,得到伙伴的起点
		buddy2 = base + page_idx;
		if (BAD_RANGE(zone,buddy1))
			BUG();
		if (BAD_RANGE(zone,buddy2))
			BUG();

		memlist_del(&buddy1->list);//去除不buddy物理块
		mask <<= 1;
		area++;
		index >>= 1;
		page_idx &= mask;
	}//重复循环直到不能再进行合并
	memlist_add_head(&(base + page_idx)->list, &area->free_list);//放到free_list中去
	//将合并后的物理块加入free_list中
	spin_unlock_irqrestore(&zone->lock, flags);
	return;

 local_freelist:
	if (current->nr_local_pages)
		goto back_local_freelist;
	if (in_interrupt())//如果调用时在中断过程中，则转入正常部分
		goto back_local_freelist;		

	list_add(&page->list, &current->local_pages);
	page->index = order;
	current->nr_local_pages++;
}

#define MARK_USED(index, order, area) \
	__change_bit((index) >> (1+(order)), (area)->map)
//将大块一分为二，小块插入链表，直到符合要求大小
static inline struct page * expand (zone_t *zone/*操作所在区*/, struct page *page/*空闲页面块的起始页面指针*/,
	 unsigned long index/*此页面偏移量*/, int low, int high, free_area_t * area/*要插入层的链表表首地址*/)//
{
	unsigned long size = 1 << high;

	while (high > low) {
		if (BAD_RANGE(zone,page))//检测
			BUG();
		area--;
		high--;
		size >>= 1;
		memlist_add_head(&(page)->list, &(area)->free_list);//加入空闲链表
		MARK_USED(index, high, area);//修改bitmap
		index += size;//保留的后半块
		page += size;
	}
	if (BAD_RANGE(zone,page))//检测
		BUG();
	return page;
}

static FASTCALL(struct page * rmqueue(zone_t *zone, unsigned int order));
static struct page * rmqueue(zone_t *zone, unsigned int order)//rmqueue根据buddy法则 分配合适大小的页块，细分过大的页块，将细分后的页块从源链表删除，并整合入新的链表
{//
	free_area_t * area = zone->free_area + order;//free_area[order]就是free_list中含order个空闲页面的数组
	unsigned int curr_order = order;
	struct list_head *head, *curr;
	unsigned long flags;
	struct page *page;

	spin_lock_irqsave(&zone->lock, flags);
	do {
		head = &area->free_list;
		curr = memlist_next(head);//成为挂在area所指的free_area数组项后面的空闲页面链表中的第一个链表项的指针

		if (curr != head) {//order的链表不为空
			unsigned int index;

			page = memlist_entry(curr, struct page, list);//从head的链表中取第1个page返回
			if (BAD_RANGE(zone,page))
				BUG();//检查page指向的页面是否被声明为此zone中的页面，并检查是否超出了范围
			memlist_del(curr);//把curr从空闲链表中移除，即链表中不再管理刚分配的page
			index = page - zone->zone_mem_map;//得到起始页面的偏移量
			if (curr_order != MAX_ORDER-1)
				MARK_USED(index, curr_order, area);//将bitmap中相应的位置置1
			zone->free_pages -= 1UL << order;//zone中含有的free_pages减1

			page = expand(zone, page, index, order, curr_order, area);//调用expand（）将从原来大块中分下来的小块重新合并到链表的新位置
			spin_unlock_irqrestore(&zone->lock, flags);

			set_page_count(page, 1);//初始化引用次数为1
			if (BAD_RANGE(zone,page))
				BUG();
			if (PageLRU(page))
				BUG();
			if (PageActive(page))
				BUG();
			return page;	
		}
		curr_order++;//curr==head说明该order的链表为空，到up-level的order中去找
		area++;
	} while (curr_order < MAX_ORDER);
	spin_unlock_irqrestore(&zone->lock, flags);

	return NULL;
}

#ifndef CONFIG_DISCONTIGMEM
struct page *_alloc_pages(unsigned int gfp_mask, unsigned int order)
{
	return __alloc_pages(gfp_mask, order,
		contig_page_data.node_zonelists+(gfp_mask & GFP_ZONEMASK));
}
#endif

static struct page * FASTCALL(balance_classzone(zone_t *, unsigned int, unsigned int, int *));
static struct page * balance_classzone(zone_t * classzone, unsigned int gfp_mask, unsigned int order, int * freed)
{
	struct page * page = NULL;
	int __freed = 0;

	if (!(gfp_mask & __GFP_WAIT))
		goto out;
	if (in_interrupt())
		BUG();

	current->allocation_order = order;
	current->flags |= PF_MEMALLOC | PF_FREE_PAGES;

	__freed = try_to_free_pages(classzone, gfp_mask, order);

	current->flags &= ~(PF_MEMALLOC | PF_FREE_PAGES);

	if (current->nr_local_pages) {
		struct list_head * entry, * local_pages;
		struct page * tmp;
		int nr_pages;

		local_pages = &current->local_pages;

		if (likely(__freed)) {
			/* pick from the last inserted so we're lifo */
			entry = local_pages->next;
			do {
				tmp = list_entry(entry, struct page, list);
				if (tmp->index == order && memclass(tmp->zone, classzone)) {
					list_del(entry);
					current->nr_local_pages--;
					set_page_count(tmp, 1);
					page = tmp;

					if (page->buffers)
						BUG();
					if (page->mapping)
						BUG();
					if (!VALID_PAGE(page))
						BUG();
					if (PageSwapCache(page))
						BUG();
					if (PageLocked(page))
						BUG();
					if (PageLRU(page))
						BUG();
					if (PageActive(page))
						BUG();
					if (PageDirty(page))
						BUG();

					break;
				}
			} while ((entry = entry->next) != local_pages);
		}

		nr_pages = current->nr_local_pages;
		/* free in reverse order so that the global order will be lifo */
		while ((entry = local_pages->prev) != local_pages) {
			list_del(entry);
			tmp = list_entry(entry, struct page, list);
			__free_pages_ok(tmp, tmp->index);
			if (!nr_pages--)
				BUG();
		}
		current->nr_local_pages = 0;
	}
 out:
	*freed = __freed;
	return page;
}

/*
 * This is the 'heart' of the zoned buddy allocator:
 */
struct page * __alloc_pages(unsigned int gfp_mask, unsigned int order, zonelist_t *zonelist)
{
	unsigned long min;
	zone_t **zone, * classzone;
	struct page * page;
	int freed;

	zone = zonelist->zones;//获取该分配策略队列的管理区数据结构指针数组
	classzone = *zone;
	min = 1UL << order; //分配的最小的页面是一个
	for (;;) { // 遍历zonelist 指向zonelist_t 结构中的zones数组
		zone_t *z = *(zone++);
		if (!z)
			break;
		//查找满足空闲页面多余pages_low的标志的区域
		min += z->pages_low;
		if (z->free_pages > min) { //空闲页面数多于pages_low标志
			page = rmqueue(z, order);//分配需要的空间
			if (page)//如果成功
				return page; // 返回page
		}
	}
//当分配失败时候没任何动作，而是继续循环去寻找下一个管理区。当我们找到第一个合适的管理区，表示这个管理区是按照指定策略适合的管理区，此时若分配失败，则应该退出。但没有退出这个循环，目的是分配失败时候，放宽要求。继续去寻找下一个管理区，看是否适合。
	classzone->need_balance = 1;
	mb();
	if (waitqueue_active(&kswapd_wait))
		wake_up_interruptible(&kswapd_wait);//目前无法从任何区域中分配页面，尝试换出部分页面以获得部分空闲页面
	//进程kswapd用来腾出一些页面，为再次内存分配做准备。
	zone = zonelist->zones;
	min = 1UL << order;
	for (;;) {//在腾出一些页面后，再次分配内存。
		unsigned long local_min;
		zone_t *z = *(zone++);
		if (!z)
			break;

		local_min = z->pages_min;
		if (!(gfp_mask & __GFP_WAIT))
			local_min >>= 2;
		min += local_min;
		if (z->free_pages > min) {
			page = rmqueue(z, order);
			if (page)
				return page;
		}
	}
	
	/* here we're in the low on memory slow path */

rebalance:
	if (current->flags & (PF_MEMALLOC | PF_MEMDIE)) {
		zone = zonelist->zones;
		for (;;) {
			zone_t *z = *(zone++);
			if (!z)
				break;

			page = rmqueue(z, order);
			if (page)
				return page;
		}
		return NULL;
	}

	/* Atomic allocations - we can't balance anything */
	if (!(gfp_mask & __GFP_WAIT))//如果不可等
		return NULL;//返回NULL分配失败

	page = balance_classzone(classzone, gfp_mask, order, &freed);
	if (page)
		return page;

	zone = zonelist->zones;
	min = 1UL << order;
	for (;;) {
		zone_t *z = *(zone++);
		if (!z)
			break;

		min += z->pages_min;
		if (z->free_pages > min) {
			page = rmqueue(z, order);
			if (page)
				return page;
		}
	}

	/* Don't let big-order allocations loop */
	if (order > 3)
		return NULL;

	/* Yield for kswapd, and try again */
	current->policy |= SCHED_YIELD;
	__set_current_state(TASK_RUNNING);
	schedule();
	goto rebalance;
}

/*
 * Common helper functions.
 */
unsigned long __get_free_pages(unsigned int gfp_mask, unsigned int order) //使用mm.h中的——__get_free_pages ()函数分配物理页面
{
	struct page * page;

	page = alloc_pages(gfp_mask, order);//mm.h 先检查是否超过free_area数组中的最大值，之后用__alloc_pages()从空闲链表分配页面
	if (!page)
		return 0;
	return (unsigned long) page_address(page);//将页面mm_struct结构得到其所在的虚拟地址
}//page_address(page)页面mm_struct结构得到其所在的虚拟地址

unsigned long get_zeroed_page(unsigned int gfp_mask)
{
	struct page * page;

	page = alloc_pages(gfp_mask, 0);
	if (page) {
		void *address = page_address(page);
		clear_page(address);
		return (unsigned long) address;
	}
	return 0;
}

void __free_pages(struct page *page, unsigned int order)
{
	if (!PageReserved(page) && put_page_testzero(page))//检查是否为保留
		__free_pages_ok(page, order);
}

void free_pages(unsigned long addr/*addr是内核态的虚拟空间，用‘__pa()’宏先将3G偏移量去掉*/, unsigned int order)
{
	if (addr != 0)
		__free_pages(virt_to_page(addr), order);
}

/*
 * Total amount of free (allocatable) RAM:
 */
unsigned int nr_free_pages (void)
{
	unsigned int sum;
	zone_t *zone;
	pg_data_t *pgdat = pgdat_list;

	sum = 0;
	while (pgdat) {
		for (zone = pgdat->node_zones; zone < pgdat->node_zones + MAX_NR_ZONES; zone++)
			sum += zone->free_pages;
		pgdat = pgdat->node_next;
	}
	return sum;
}

/*
 * Amount of free RAM allocatable as buffer memory:
 */
unsigned int nr_free_buffer_pages (void)
{
	pg_data_t *pgdat = pgdat_list;
	unsigned int sum = 0;

	do {
		zonelist_t *zonelist = pgdat->node_zonelists + (GFP_USER & GFP_ZONEMASK);
		zone_t **zonep = zonelist->zones;
		zone_t *zone;

		for (zone = *zonep++; zone; zone = *zonep++) {
			unsigned long size = zone->size;
			unsigned long high = zone->pages_high;
			if (size > high)
				sum += size - high;
		}

		pgdat = pgdat->node_next;
	} while (pgdat);

	return sum;
}

#if CONFIG_HIGHMEM
unsigned int nr_free_highpages (void)
{
	pg_data_t *pgdat = pgdat_list;
	unsigned int pages = 0;

	while (pgdat) {
		pages += pgdat->node_zones[ZONE_HIGHMEM].free_pages;
		pgdat = pgdat->node_next;
	}
	return pages;
}
#endif

#define K(x) ((x) << (PAGE_SHIFT-10))

/*
 * Show free area list (used inside shift_scroll-lock stuff)
 * We also calculate the percentage fragmentation. We do this by counting the
 * memory on each free list with the exception of the first item on the list.
 */
void show_free_areas_core(pg_data_t *pgdat)
{
 	unsigned int order;
	unsigned type;
	pg_data_t *tmpdat = pgdat;

	printk("Free pages:      %6dkB (%6dkB HighMem)\n",
		K(nr_free_pages()),
		K(nr_free_highpages()));

	while (tmpdat) {
		zone_t *zone;
		for (zone = tmpdat->node_zones;
			       	zone < tmpdat->node_zones + MAX_NR_ZONES; zone++)
			printk("Zone:%s freepages:%6lukB min:%6lukB low:%6lukB " 
				       "high:%6lukB\n", 
					zone->name,
					K(zone->free_pages),
					K(zone->pages_min),
					K(zone->pages_low),
					K(zone->pages_high));
			
		tmpdat = tmpdat->node_next;
	}

	printk("( Active: %d, inactive: %d, free: %d )\n",
	       nr_active_pages,
	       nr_inactive_pages,
	       nr_free_pages());

	for (type = 0; type < MAX_NR_ZONES; type++) {
		struct list_head *head, *curr;
		zone_t *zone = pgdat->node_zones + type;
 		unsigned long nr, total, flags;

		total = 0;
		if (zone->size) {
			spin_lock_irqsave(&zone->lock, flags);
		 	for (order = 0; order < MAX_ORDER; order++) {
				head = &(zone->free_area + order)->free_list;
				curr = head;
				nr = 0;
				for (;;) {
					curr = memlist_next(curr);
					if (curr == head)
						break;
					nr++;
				}
				total += nr * (1 << order);
				printk("%lu*%lukB ", nr, K(1UL) << order);
			}
			spin_unlock_irqrestore(&zone->lock, flags);
		}
		printk("= %lukB)\n", K(total));
	}

#ifdef SWAP_CACHE_INFO
	show_swap_cache_info();
#endif	
}

void show_free_areas(void)
{
	show_free_areas_core(pgdat_list);
}

/*
 * Builds allocation fallback zone lists.
 */
static inline void build_zonelists(pg_data_t *pgdat)
{
	int i, j, k;

	for (i = 0; i <= GFP_ZONEMASK; i++) {
		zonelist_t *zonelist;
		zone_t *zone;

		zonelist = pgdat->node_zonelists + i;
		memset(zonelist, 0, sizeof(*zonelist));

		j = 0;
		k = ZONE_NORMAL;
		if (i & __GFP_HIGHMEM)
			k = ZONE_HIGHMEM;
		if (i & __GFP_DMA)
			k = ZONE_DMA;

		switch (k) {
			default:
				BUG();
			/*
			 * fallthrough:
			 */
			case ZONE_HIGHMEM:
				zone = pgdat->node_zones + ZONE_HIGHMEM;
				if (zone->size) {
#ifndef CONFIG_HIGHMEM
					BUG();
#endif
					zonelist->zones[j++] = zone;
				}
			case ZONE_NORMAL:
				zone = pgdat->node_zones + ZONE_NORMAL;
				if (zone->size)
					zonelist->zones[j++] = zone;
			case ZONE_DMA:
				zone = pgdat->node_zones + ZONE_DMA;
				if (zone->size)
					zonelist->zones[j++] = zone;
		}
		zonelist->zones[j++] = NULL;
	} 
}

#define LONG_ALIGN(x) (((x)+(sizeof(long))-1)&~((sizeof(long))-1))

/*
 * Set up the zone data structures:
 *   - mark all pages reserved
 *   - mark all memory queues empty
 *   - clear the memory bitmaps
 */
void __init free_area_init_core(int nid, pg_data_t *pgdat/*contig_page_data*/, struct page **gmap/*mem_map*/,
	unsigned long *zones_size, unsigned long zone_start_paddr, 
	unsigned long *zholes_size, struct page *lmem_map)
{
	struct page *p;
	unsigned long i, j;
	unsigned long map_size;
	unsigned long totalpages, offset, realtotalpages;
	const unsigned long zone_required_alignment = 1UL << (MAX_ORDER-1);

	if (zone_start_paddr & ~PAGE_MASK)
		BUG();
	//计算DMA+NORMAL+HIGHMEM中所有的页帧数
	totalpages = 0;
	for (i = 0; i < MAX_NR_ZONES; i++) {
		unsigned long size = zones_size[i];
		totalpages += size;
	}
	realtotalpages = totalpages;//去掉total pages中的holes
	if (zholes_size)
		for (i = 0; i < MAX_NR_ZONES; i++)
			realtotalpages -= zholes_size[i];
			
	printk("On node %d totalpages: %lu\n", nid, realtotalpages);

	INIT_LIST_HEAD(&active_list);
	INIT_LIST_HEAD(&inactive_list);
	//初始化active_list&inactive_list

	/*
	 * Some architectures (with lots of mem and discontinous memory
	 * maps) have to search for a good mem_map area:
	 * For discontigmem, the conceptual mem map array starts from 
	 * PAGE_OFFSET, we need to align the actual array onto a mem map 
	 * boundary, so that MAP_NR works.
	 */
	map_size = (totalpages + 1)*sizeof(struct page);//计算map_size的大小
	if (lmem_map == (struct page *)0) {
		lmem_map = (struct page *) alloc_bootmem_node(pgdat, map_size);//给mem_map分配页内存
		lmem_map = (struct page *)(PAGE_OFFSET + 
			MAP_ALIGN((unsigned long)lmem_map - PAGE_OFFSET));//按照page大小对齐
	}
	*gmap = pgdat->node_mem_map = lmem_map;//设定全局指针
	pgdat->node_size = totalpages;
	pgdat->node_start_paddr = zone_start_paddr;
	pgdat->node_start_mapnr = (lmem_map - mem_map);
	pgdat->nr_zones = 0;

	/*
	 * Initially all pages are reserved - free ones are freed
	 * up by free_all_bootmem() once the early boot process is
	 * done.
	 *///初始page链表的结构
	for (p = lmem_map; p < lmem_map + totalpages; p++) {
		set_page_count(p, 0);//初始count=0
		SetPageReserved(p);//fleg=reserved
		init_waitqueue_head(&p->wait);
		memlist_init(&p->list);
	}//把所有物理页初始化为保留，当前无buddy可用的物理页

	offset = lmem_map - mem_map;	//初始时offset为0
	for (j = 0; j < MAX_NR_ZONES; j++) {
		zone_t *zone = pgdat->node_zones + j;//初始化zone中的数据
		unsigned long mask;
		unsigned long size, realsize;

		realsize = size = zones_size[j];
		if (zholes_size)
			realsize -= zholes_size[j];

		printk("zone(%lu): %lu pages.\n", j, size);
		zone->size = size;
		zone->name = zone_names[j];
		zone->lock = SPIN_LOCK_UNLOCKED;
		zone->zone_pgdat = pgdat;
		zone->free_pages = 0;
		zone->need_balance = 0;
		if (!size)
			continue;

		pgdat->nr_zones = j+1;

		mask = (realsize / zone_balance_ratio[j]);
		if (mask < zone_balance_min[j])
			mask = zone_balance_min[j];
		else if (mask > zone_balance_max[j])
			mask = zone_balance_max[j];
		zone->pages_min = mask;
		zone->pages_low = mask*2;
		zone->pages_high = mask*3;

		zone->zone_mem_map = mem_map + offset;
		zone->zone_start_mapnr = offset;
		zone->zone_start_paddr = zone_start_paddr;

		if ((zone_start_paddr >> PAGE_SHIFT) & (zone_required_alignment-1))
			printk("BUG: wrong zone alignment, it will crash\n");
		//初始化mem_map中虚拟地址
		for (i = 0; i < size; i++) {
			struct page *page = mem_map + offset + i;
			page->zone = zone;//让zone中的所有page指向zone，
			if (j != ZONE_HIGHMEM)
				page->virtual = __va(zone_start_paddr);//指向相应的虚拟地址
			zone_start_paddr += PAGE_SIZE;
		}

		offset += size;
		for (i = 0; ; i++) {
			unsigned long bitmap_size;

			memlist_init(&zone->free_area[i].free_list);
			if (i == MAX_ORDER-1) {
				zone->free_area[i].map = NULL;
				break;
			}
			/*
			 * Page buddy system uses "index >> (i+1)",
			 * where "index" is at most "size-1".
			 *nn
			 * The extra "+3" is to round down to byte
			 * size (8 bits per byte assumption). Thus
			 * we get "(size-1) >> (i+4)" as the last byte
			 * we can access.
			 *
			 * The "+1" is because we want to round the
			 * byte allocation up rather than down. So
			 * we should have had a "+7" before we shifted
			 * down by three. Also, we have to add one as
			 * we actually _use_ the last bit (it's [0,n]
			 * inclusive, not [0,n[).
			 *
			 * So we actually had +7+1 before we shift
			 * down by 3. But (n+8) >> 3 == (n >> 3) + 1
			 * (modulo overflows, which we do not have).
			 *
			 * Finally, we LONG_ALIGN because all bitmap
			 * operations are on longs.
			 */
			bitmap_size = (size-1) >> (i+4);
			bitmap_size = LONG_ALIGN(bitmap_size+1);
			zone->free_area[i].map = 
			  (unsigned long *) alloc_bootmem_node(pgdat, bitmap_size);
		}
	}
	build_zonelists(pgdat);
}

void __init free_area_init(unsigned long *zones_size)
{
	free_area_init_core(0, &contig_page_data, &mem_map, zones_size, 0, 0, 0);
}

static int __init setup_mem_frac(char *str)
{
	int j = 0;

	while (get_option(&str, &zone_balance_ratio[j++]) == 2);
	printk("setup_mem_frac: ");
	for (j = 0; j < MAX_NR_ZONES; j++) printk("%d  ", zone_balance_ratio[j]);
	printk("\n");
	return 1;
}

__setup("memfrac=", setup_mem_frac);
