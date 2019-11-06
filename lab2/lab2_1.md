# LAB2
---
## exercise one

### memlayout.h
这个文件定义了操作系统中的内存分配，与内核和用户态相关

一个线性地址定义包括了三个部分(linear address)，其中有page directory(页目录),page table index 和 offset withhin page。

memlayout.h中主要定义了PageInfo 的具体结构，包括了pp_link 指向下一个页（空链中的下一页），pp_ref指出了当前页中所含有的指针数量。

### pmap
#### pmap.h
pmap.h 中定义了相关的地址转换的内容，以及利用PageInfo 的相关信息查看物理地址和内核虚拟地址。

#### pmap.c
包含了大多数的内容

##### boot_alloc
boot_alloc的作用是开辟出n字节空闲空间并返回kva（内核虚拟地址）
因此，需要增加的部分，如注释所说，为:

```c
	if(nextfree+n)>(char *)0xffffffff)
		panic("out of memory!\n");
	char *res;
	res = nextfree;
	if(n>0)
		nextfree = ROUNDUP( nextfree+n,PGSIZE);
	return res;
```

即判断是否out of memory，如果无的话，当n>0的时候分配一个足够大的连续空间地址，否则，则返回下一个空页

##### mem_init
按照要求，这个练习中，只需要分配相应的内容即可。分配一个npages个struct PageInfo的空间大小，返回一个相应的指针，并赋值给pages。
```c
	// Allocate an array of npages 'struct PageInfo's and store it in 'pages'.
	// The kernel uses this array to keep track of physical pages: for
	// each physical page, there is a corresponding struct PageInfo in this
	// array.  'npages' is the number of physical pages in memory.  Use memset
	// to initialize all fields of each struct PageInfo to 0.
	// Your code goes here:
	pages = (struct PageInfo *)boot_alloc(sizeof(struct PageInfo) * npages);
	memset(pages,0,sizeof(struct PageInfo) * npages);
```

##### page_init
+ 第0页不用，留给中断描述符表
+ 第1-159页可以使用，加入空闲链表（npages_basemem为160，即640K以下内存)
+ 640K-1M空间保留给BIOS和显存，不能加入空闲链表
+ 1M以上空间中除去kernel已经占用的页，其他都可以使用

```c
    size_t i;
    for (i = 1; i < npages_basemem; i++) {
        pages[i].pp_ref = 0;
        pages[i].pp_link = page_free_list;
        page_free_list = &pages[i];
    }

    char *nextfree = boot_alloc(0);
    size_t kern_end_page = PGNUM(PADDR(nextfree));
    cprintf("kern end pages:%d\n", kern_end_page);

    for (i = kern_end_page; i < npages; i++) {
        pages[i].pp_ref = 0;
        pages[i].pp_link = page_free_list;
        page_free_list = &pages[i];
    }
```
对于第0页，不作处理，然后处理1-159页，然后找到下一个空闲页，并查看其页地址，利用此，处理后续内容。

##### page_alloc
当存在空闲的内存空间时，找到相应的空间，并移动空闲列表，分配相应地址和内存，否则返回NULL
```c
	if(page_free_list)
	{
		struct PageInfo* pp = page_free_list;
		page_free_list = page_free_list -> pp_link;
		if(alloc_flags & ALLOC_ZERO)
			memset(page2kva(pp),0,PGSIZE);
		return pp;
	}
		
	return NULL;
```

##### page_free
当释放一个空间时，将其加入到page_free_list之中。
```c
	pp->pp_link = page_free_list;
	page_free_list = pp;
```

通过查看mem_init()的调用过程，可以发现整个过程的调用方式。

![mem_init](https://github.com/leliyliu/figure_lib/blob/master/jos/lab1/33.png?raw=true)

## exercise two
80386 将逻辑地址转换为物理地址需要两步：
+ 段转换，将一个逻辑地址转换为一个线性地址
+ 页转换，将一个线性地址转换为一个物理地址

### 段机制
通过描述符将相应的逻辑地址，通过段机制进行转换得到相应的转换的结果（线性地址）。其中，关于描述符，一般通过建立相应的描述符表来实现：包括全局描述符表和本地描述符表。

### 页机制

对于80386而言，线性地址(linear) = 逻辑地址(virtual)+段首地址\
而实际上，`线性地址=逻辑地址+0x00000000`，故实际上，对于该部分，就看虚拟地址=线性地址即可。

+ 首先CPU得到一个地址，看看页的开关开没有（CR0中相应位是否为1，具体见enstry.S），没有可以直接视为物理地址进行访问，否则传给MMU
+ MMU去TLB查找相应的内容，访问
+ 若TLB没有相应内容，利用CPU去从存储器中找到相应的内容。

对于具体的一个地址32位 [31..22]为DIR，[21..12]为page，[11..0]为offset
+ 第一步通过CR3存的地址找到PAGE DIRECTORY
+ 通过DIR作为偏移量，定位到PAGE DIRECTORY 中具体的一项DIR ENTRY
+ 以该项找到PAGE TABLE
+ 通过page作为偏移量，定位到PAGE TABLE的具体一项PAGE Table ENTRY
+ 以该项的值定位到物理页
+ 以offset 定位到该物理页的物理地址

简化的一个相应结构即为：CR3->PAGE TABLE-> PAGE TABLE -> PAGE

## exercise three
使用xshell 调用服务器，进入qemu中查看物理内存的内容：

![info_pg](https://github.com/leliyliu/figure_lib/blob/master/jos/lab1/35.png?raw=true)

### 问题3 的回答：
当JOS内核代码是正确的时候，变量x应该是uintptr_t这一类型，这是因为对于程序而言，只有虚拟内存，没有物理内存的相应概念。

## exercise four

### pgdir_walk
通过相应的注释，我们了解到，我们是要实现一个'pointer to a page directory'，即实际上是一个二级页表，而最终该函数需要返回一个PTE指针(linear address),即根据虚拟地址va找到对应的页表项地址。\\
具体过程如下：

+ 把va分段提取 DIR
+ 根据DIR的内容将其分配到一个具体的ENTRY
+ 如果需要分配地址的且没分配，则进行分配
+ 否则返回地址ENTRY中记录的地址，或者没分配返回NULL

```c
pte_t *
pgdir_walk(pde_t *pgdir, const void *va, int create)
{
	// Fill this function in
	int pde_index = PDX(va);//得到相应的PDE 和 PTE
    int pte_index = PTX(va);
    pde_t *pde = &pgdir[pde_index];
    if (!(*pde & PTE_P)) {
        if (create) {
            struct PageInfo *page = page_alloc(ALLOC_ZERO);//分配空间（地址）
            if (!page) return NULL;//无法进行分配

            page->pp_ref++;
            *pde = page2pa(page) | PTE_P | PTE_U | PTE_W;
        } else {
            return NULL;
        }   
    }   

    pte_t *p = (pte_t *) KADDR(PTE_ADDR(*pde));
    return &p[pte_index];//返回地址ENTRY中记录的地址
}

```

### boot_map_region
映射虚拟地址va到物理地址pa，映射大小为size，所做操作就是找到对应的页表项地址，设置页表项的值为物理地址pa(pa是4KB对齐的，对应该页的首地址)。用到上一个函数pgdir_walk找虚拟地址对应的页表项地址。

```c
static void
boot_map_region(pde_t *pgdir, uintptr_t va, size_t size, physaddr_t pa, int perm)
{
	int pages = PGNUM(size);//查看需要映射到多少个页上
    int i;
	for (i = 0; i < pages; i++) {
        pte_t *pte = pgdir_walk(pgdir, (void *)va, 1);//找到对应页表项
        if (!pte) {//页表项非空，无法映射
            panic("boot_map_region panic: out of memory");
        }
        *pte = pa | perm | PTE_P;
        va += PGSIZE, pa += PGSIZE;//虚拟地址和物理地址都增加
    }
}
```

### page_lookup
查找虚拟地址va对应的页表项，并返回页表项对应的PageInfo结构。其中，提示使用函数pa2page,功能是通过va获取Page *和pte的地址
```c
struct PageInfo *
page_lookup(pde_t *pgdir, void *va, pte_t **pte_store)
{
	pte_t *pte = pgdir_walk(pgdir, va, 0);//查看当前页表项
    if (!pte || !(*pte & PTE_P)) {
        return NULL;
    }

    if (pte_store) {
        *pte_store = pte;
    }

    return pa2page(PTE_ADDR(*pte));//将所得到的物理地址转为页表项
	
}
```
### page_remove
从页表中移除虚拟地址va对应的物理页映射。需要将PageInfo的引用pp_ref减1，并设置对应页表项的值为0，最后调用tlb_invalidate使tlb中该页缓存失效。
```c
void
page_remove(pde_t *pgdir, void *va)
{
	pte_t *pte;
    struct PageInfo *page = page_lookup(pgdir, va, &pte);
    if (!page || !(*pte & PTE_P)) {
        return;
    }
    *pte = 0;
    page_decref(page);//对相应的数目进行删减
    tlb_invalidate(pgdir, va);//进行检查
	
}
```

### page_insert
映射虚拟地址va到pp对应的物理页。如果之前该虚拟地址已经存在映射，则要先移除原来的映射。注意pp_ref++要在page_remove之前执行，不然在page_remove会导致pp_ref减到0从而page_free该页面，该页面后续会被重新分配使用而报错。
```c
int
page_insert(pde_t *pgdir, struct PageInfo *pp, void *va, int perm)
{
	// Fill this function in
	pte_t *pte = pgdir_walk(pgdir, va, 1);//找到当前对应页表项
    if (!pte) {
        return -E_NO_MEM;
    }

    pp->pp_ref++;
    if (*pte & PTE_P) {
        page_remove(pgdir, va);//当存在映射，则进行删除
    }

    *pte = page2pa(pp) | perm | PTE_P;
    return 0;
}
```

## exercise five
根据inc/memlayout.h中所显示的内存空间布局
```c
/*
 * Virtual memory map:                                Permissions
 *                                                    kernel/user
 *
 *    4 Gig -------->  +------------------------------+
 *                     |                              | RW/--
 *                     ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *                     :              .               :
 *                     :              .               :
 *                     :              .               :
 *                     |~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~| RW/--
 *                     |                              | RW/--
 *                     |   Remapped Physical Memory   | RW/--
 *                     |                              | RW/--
 *    KERNBASE, ---->  +------------------------------+ 0xf0000000      --+
 *    KSTACKTOP        |     CPU0's Kernel Stack      | RW/--  KSTKSIZE   |
 *                     | - - - - - - - - - - - - - - -|                   |
 *                     |      Invalid Memory (*)      | --/--  KSTKGAP    |
 *                     +------------------------------+                   |
 *                     |     CPU1's Kernel Stack      | RW/--  KSTKSIZE   |
 *                     | - - - - - - - - - - - - - - -|                 PTSIZE
 *                     |      Invalid Memory (*)      | --/--  KSTKGAP    |
 *                     +------------------------------+                   |
 *                     :              .               :                   |
 *                     :              .               :                   |
 *    MMIOLIM ------>  +------------------------------+ 0xefc00000      --+
 *                     |       Memory-mapped I/O      | RW/--  PTSIZE
 * ULIM, MMIOBASE -->  +------------------------------+ 0xef800000
 *                     |  Cur. Page Table (User R-)   | R-/R-  PTSIZE
 *    UVPT      ---->  +------------------------------+ 0xef400000
 *                     |          RO PAGES            | R-/R-  PTSIZE
 *    UPAGES    ---->  +------------------------------+ 0xef000000
 *                     |           RO ENVS            | R-/R-  PTSIZE
 * UTOP,UENVS ------>  +------------------------------+ 0xeec00000
 * UXSTACKTOP -/       |     User Exception Stack     | RW/RW  PGSIZE
 *                     +------------------------------+ 0xeebff000
 *                     |       Empty Memory (*)       | --/--  PGSIZE
 *    USTACKTOP  --->  +------------------------------+ 0xeebfe000
 *                     |      Normal User Stack       | RW/RW  PGSIZE
 *                     +------------------------------+ 0xeebfd000
 *                     |                              |
 *                     |                              |
 *                     ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *                     .                              .
 *                     .                              .
 *                     .                              .
 *                     |~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|
 *                     |     Program Data & Heap      |
 *    UTEXT -------->  +------------------------------+ 0x00800000
 *    PFTEMP ------->  |       Empty Memory (*)       |        PTSIZE
 *                     |                              |
 *    UTEMP -------->  +------------------------------+ 0x00400000      --+
 *                     |       Empty Memory (*)       |                   |
 *                     | - - - - - - - - - - - - - - -|                   |
 *                     |  User STAB Data (optional)   |                 PTSIZE
 *    USTABDATA ---->  +------------------------------+ 0x00200000        |
 *                     |       Empty Memory (*)       |                   |
 *    0 ------------>  +------------------------------+                 --+
 *
 * (*) Note: The kernel ensures that "Invalid Memory" is *never* mapped.
 *     "Empty Memory" is normally unmapped, but user programs may map pages
 *     there if desired.  JOS user programs map pages temporarily at UTEMP.
 */
```

可以看到，需要在UTOP之上建立地址空间：内核部分的地址空间，实际上主要是对于三部分的内存空间建立相应的地址空间。分别是:\\
+ UPAGES 
+ KSTACKTOP
+ kERNBASE

```c
	//////////////////////////////////////////////////////////////////////
	// Map 'pages' read-only by the user at linear address UPAGES
	// Permissions:
	//    - the new image at UPAGES -- kernel R, user R
	//      (ie. perm = PTE_U | PTE_P)
	//    - pages itself -- kernel RW, user NONE
	// Your code goes here:
	boot_map_region(kern_pgdir,UPAGES,PTSIZE,PADDR(pages),PTE_U);
	//////////////////////////////////////////////////////////////////////
	// Use the physical memory that 'bootstack' refers to as the kernel
	// stack.  The kernel stack grows down from virtual address KSTACKTOP.
	// We consider the entire range from [KSTACKTOP-PTSIZE, KSTACKTOP)
	// to be the kernel stack, but break this into two pieces:
	//     * [KSTACKTOP-KSTKSIZE, KSTACKTOP) -- backed by physical memory
	//     * [KSTACKTOP-PTSIZE, KSTACKTOP-KSTKSIZE) -- not backed; so if
	//       the kernel overflows its stack, it will fault rather than
	//       overwrite memory.  Known as a "guard page".
	//     Permissions: kernel RW, user NONE
	// Your code goes here:
	boot_map_region(kern_pgdir,KSTACKTOP-KSTKSIZE,KSTKSIZE,PADDR(bootstack),PTE_W);
	//////////////////////////////////////////////////////////////////////
	// Map all of physical memory at KERNBASE.
	// Ie.  the VA range [KERNBASE, 2^32) should map to
	//      the PA range [0, 2^32 - KERNBASE)
	// We might not have 2^32 - KERNBASE bytes of physical memory, but
	// we just set up the mapping anyway.
	// Permissions: kernel RW, user NONE
	// Your code goes here:
	boot_map_region(kern_pgdir,KERNBASE,-KERNBASE,0,PTE_W);
```

修改完成之后，进行*make grade*
![finish](https://github.com/leliyliu/figure_lib/blob/master/jos/lab1/39.png?raw=true)

### 问题2 
在exercise five 中，我们进行了一些相应的映射
>UPAGES             : [0xef000000,0xef400000)    ->[pages    -0xf0000000,pages    -0xefc00000) cprintf得到[0x0011a000,0x0015a000)\
 KSTACKTOP-KSTKSIZE : [0xefbf8000,0xefc00000)    ->[bootstack-0xf0000000,bootstack-0xefff8000) cprintf得到[0x0010e000,0x00116000)\
 KERNBASE           : [0xf0000000,0x100000000)   ->[0,0x10000000)

除此之外，还有jos之前手工映射的UVPT[0xef400000,0xef800000)->[kern_pgdir-0xf0000000,kern_pgdir-0xefc00000)
### 问题3
我们将用户和内核环境放在了同一个地址空间，如何保证用户程序不能读取内核的内存？ 内核空间内存的页表项的perm没有设置PTE_U，需要CPL为0-2才可以访问。而用户程序的CPL为3，因为权限不够用户程序读取内核内存时会报错。

### 问题4
2GB，因为 UPAGES 大小最大为4MB，而每个PageInfo大小为8Bytes，所以可以最多可以存储512K个PageInfo结构体，而每个PageInfo对应4KB内存，所以最多 $512K*4K = 2G$内存。
### 问题5
如果有2GB内存，则物理页有512K个，每个PageInfo结构占用8Bytes，则一共是4MB。页目录需要 $512*8=4KB$，而页表包括512K个页表项，每项4字节共需要$512K*4=2MB$存储，所以额外消耗的内存为 6MB + 4KB。
### 问题6
从 kern/entry.S 中的 jmp *%eax语句之后就开始跳转到高地址运行了。因为在entry.S中我们的cr3加载的是entry_pgdir，它将虚拟地址 [0, 4M)和[KERNBASE, KERNBASE+4M)都映射到了物理地址 [0, 4M)，所以能保证正常运行。

而在我们新的kern_pgdir加载后，并没有映射低位的虚拟地址 [0, 4M)，所以这一步跳转是必要的。