# LAB2
---
## exercise 1

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