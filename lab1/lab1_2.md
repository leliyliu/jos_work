# LAB1
---
## exercise 2
在qemu模拟器中执行相关结果，利用gdb的si指令，查看BIOS执行过程，实际上是从0xffff0的地址跳转到fe05b的位置开始执行。

![gdb_process](https://github.com/leliyliu/figure_lib/blob/master/jos/lab1/1.png?raw=true)

## exercise 3
#### ANSWER:
1. 
- 在boot.S 文件中，通过seta20.1 和seta20.2两个汇编程序段，打开A20数据线，从16位模式切换到32位模式。指令：lgdt gdtdesc 加载了全局描述符表GDT，其中gdtdesc是一个保存了哪些GDT信息需要被存储的信息，格式为[gdt 大小][gdt 地址]。GDT中包括了空段，可执行代码段，可读段，和可写段，地址从0到4G。
- 代码
``` x86asm
  movl    %cr0, %eax
  orl     $CR0_PE_ON, %eax
  movl    %eax, %cr0
```
设置了保护模式开启的flag(实模式工作在16位状态下，保护模式工作在32位状态下)

- 
```x86asm
ljmp    $PROT_MODE_CSEG, $protcseg

movw    $PROT_MODE_DSEG, %ax    # Our data segment selector
movw    %ax, %ds                # -> DS: Data Segment
movw    %ax, %es                # -> ES: Extra Segment
movw    %ax, %fs                # -> FS
movw    %ax, %gs                # -> GS
movw    %ax, %ss                # -> SS: Stack Segment
......
```
加载相应段，将处理器运行在32位中，并且加载地址到相应的代码段，数据段等等......

2. 
- 最后一条是
```x86asm
((void (*)(void)) (ELFHDR->e_entry))();     #main.c中代码  
7d63:	ff 15 18 00 01 00    	call   *0x10018 #反汇编代码
```
可以发现，实际上0x10018的地址即为elfhdr->entry的地址。
```c
struct elfhdr {
  uint magic;  // must equal ELF_MAGIC
  uchar elf[12];
  ushort type;
  ushort machine;
  uint version;
  uint entry;  // 程序入口的虚拟地址
  uint phoff;  // program header 表的位置偏移
  uint shoff;
  uint flags;
  ushort ehsize;
  ushort phentsize;
  ushort phnum; //program header表中的入口数目
  ushort shentsize;
  ushort shnum;
  ushort shstrndx;
};
```
故我们可以采用以下指令，在gdb中找到加载进内核的第一条指令
```bash
(gdb)x/1w 0x10018
(gdb)x/1i 0x0010000c
```
因而，也能找到相应的第三问的结果

3. 
- 内核本身即是一个elf文件，bootloader程序通过解析elf的格式来知道一共有多少个扇区要读。
```c
	ph = (struct Proghdr *) ((uint8_t *) ELFHDR + ELFHDR->e_phoff);
	eph = ph + ELFHDR->e_phnum;
	for (; ph < eph; ph++)
		// p_pa is the load address of this segment (as well
		// as the physical address)
		readseg(ph->p_pa, ph->p_memsz, ph->p_offset);
```
主要是通过elfhdr 中的e_phoff和e_phnum来决定读取的扇区数量

## exercise 4
### pointers.c
```c
#include <stdio.h>
#include <stdlib.h>

void
f(void)
{
    int a[4];
    int *b = malloc(16);//分配了16个字节，实际上一个int是4个字节
    int *c;//定义相关指针
    int i;

    printf("1: a = %p, b = %p, c = %p\n", a, b, c);//打印其相关地址

    c = a;//将a[0]所指向的位置赋值给c
    for (i = 0; i < 4; i++)
	a[i] = 100 + i;//修改了a[0]~a[3]的值
    c[0] = 200;//再次修改a[0]的值
    printf("2: a[0] = %d, a[1] = %d, a[2] = %d, a[3] = %d\n",
	   a[0], a[1], a[2], a[3]);

    c[1] = 300;
    *(c + 2) = 301;
    3[c] = 302;//更改a[1],a[2],a[3]的值
    printf("3: a[0] = %d, a[1] = %d, a[2] = %d, a[3] = %d\n",
	   a[0], a[1], a[2], a[3]);

    c = c + 1;//将地址+1（由于是(int*)型，是+1*sizeof(int)
    *c = 400;//故实际上将a[1]的位置置为4
    printf("4: a[0] = %d, a[1] = %d, a[2] = %d, a[3] = %d\n",
	   a[0], a[1], a[2], a[3]);

    c = (int *) ((char *) c + 1);//将c指针视为(char*)然后跳转，故实际上c+sizeof(char)*1,故实际位置在a[1]和a[2]之间，修改之后，得到的结果
    *c = 500;
    printf("5: a[0] = %d, a[1] = %d, a[2] = %d, a[3] = %d\n",
	   a[0], a[1], a[2], a[3]);

    b = (int *) a + 1;
    c = (int *) ((char *) a + 1);//同理
    printf("6: a = %p, b = %p, c = %p\n", a, b, c);
}

int
main(int ac, char **av)
{
    f();
    return 0;
}


```
相关输出结果:

![pointer.c](https://github.com/leliyliu/figure_lib/blob/master/jos/lab1/2.png?raw=true)

## exercise 5
跳转到7c00之后执行相关指令，看到结果如下

![all](https://github.com/leliyliu/figure_lib/blob/master/jos/lab1/3.png?raw=true)

可以看到，有相关的指令

![ljmp](https://github.com/leliyliu/figure_lib/blob/master/jos/lab1/4.png?raw=true)

同时有Makefrag中的内容为

![7c00](https://github.com/leliyliu/figure_lib/blob/master/jos/lab1/6.png?raw=true)

使用了相关链接跳转指令，因此，可以看到有相应的结果呈现。同时，查看/boot/Makefrag 中的内容，可以看到相应的连接。

修改Makefrag 的内容如下:将地址改为0x7D00

![7d00](https://github.com/leliyliu/figure_lib/blob/master/jos/lab1/10.png?raw=true)

对于执行的结果，在编译后的/obj/boot/boot.asm的内容如下：

![boot_asm](https://github.com/leliyliu/figure_lib/blob/master/jos/lab1/7.png?raw=true)

利用qemu进行模拟和调试，结果即为：
![lgdt](https://github.com/leliyliu/figure_lib/blob/master/jos/lab1/8.png?raw=true)
![ljmp_wrong](https://github.com/leliyliu/figure_lib/blob/master/jos/lab1/9.png?raw=true)

可以看到，由于lgdtw执行的问题，导致后续的连接跳转操作发生错误，无法继续进行

## exercise 6