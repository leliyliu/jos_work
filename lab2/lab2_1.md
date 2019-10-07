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

