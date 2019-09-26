# LAB1
---
### ！！！踩坑
我自闭了，终于发现给的上机课的pdf和MIT中要求的有所不同，建议查看英文原版或者助教翻译的另一个版本.......还是决定不要写到一个文档中了，以后分开写，每次做了多少写多少

## bootloader
在所提供的jos操作系统中，Boot Loader的源程序是由一个叫做boot.S(boot/boot.S) 的 AT&T 汇编程序与一个叫做 main.c(boot/main.c) 的 C 程序组成的。

+ 其中 boot.S 主要是将处理器从实模式转换到 32 位的保护模式，这是因为只有在保护模式中我们才能访问到物理内存高于 1MB 的空间。
+ main.c 的主要作用是将内核的可执行代码从硬盘镜像中读入到内存中，具体的方式是运用 x86 专门的 I/O 指令，在这里我们只用了解它的原理，而对 I/O 指令本身我们不用做过多深入的了解。

(关于markdown 引用各种代码，如何高亮，请参考[blog1](https://blog.csdn.net/lusing/article/details/50906898) and [blog2](https://blog.csdn.net/yxys01/article/details/78296526))

(简明[x86汇编教程](https://arthurchiao.github.io/blog/x86-asm-guide-trans-cn-zh/) )
### 代码分析
**boot.S**
```x86asm
#include <inc/mmu.h>

# Start the CPU: switch to 32-bit protected mode, jump into C.
# The BIOS loads this code from the first sector of the hard disk into
# memory at physical address 0x7c00 and starts executing in real mode
# with %cs=0 %ip=7c00.

.set PROT_MODE_CSEG, 0x8         # kernel code segment selector
.set PROT_MODE_DSEG, 0x10        # kernel data segment selector
.set CR0_PE_ON,      0x1         # protected mode enable flag
#设置代码段和数据段，并且设置保护模式的flag

.globl start
start:
  .code16                     # Assemble for 16-bit mode
  cli                         # Disable interrupts
  cld                         # String operations increment
#设置为16位的汇编模式,清中断允许位和方向标志位


  # Set up the important data segment registers (DS, ES, SS).
  xorw    %ax,%ax             # Segment number zero
  movw    %ax,%ds             # -> Data Segment
  movw    %ax,%es             # -> Extra Segment
  movw    %ax,%ss             # -> Stack Segment
#所有均初始化为0

  # Enable A20:
  #   For backwards compatibility with the earliest PCs, physical
  #   address line 20 is tied low, so that addresses higher than
  #   1MB wrap around to zero by default.  This code undoes this.
  # 取消A20
seta20.1:
  inb     $0x64,%al               # Wait for not busy
  testb   $0x2,%al                # wait until the second bit is one on %al
  jnz     seta20.1                #jump not zero

  movb    $0xd1,%al               # 0xd1 -> port 0x64
  outb    %al,$0x64               

seta20.2:
  inb     $0x64,%al               # Wait for not busy
  testb   $0x2,%al                
  jnz     seta20.2

  movb    $0xdf,%al               # 0xdf -> port 0x60
  outb    %al,$0x60


  # Switch from real to protected mode, using a bootstrap GDT
  # and segment translation that makes virtual addresses 
  # identical to their physical addresses, so that the 
  # effective memory map does not change during the switch.
#从实模式切换到保护模式，通过引导程序的GDT（全局描述符表）使得虚拟地址与物理地址相同

  lgdt    gdtdesc
  movl    %cr0, %eax
  orl     $CR0_PE_ON, %eax
  movl    %eax, %cr0          #将%cr0的最后一位置为1

  # Jump to next instruction, but in 32-bit code segment.
  # Switches processor into 32-bit mode.

  ljmp    $PROT_MODE_CSEG, $protcseg # 跳转到相应的段

  .code32                     # Assemble for 32-bit mode
protcseg:
  # Set up the protected-mode data segment registers
  movw    $PROT_MODE_DSEG, %ax    # Our data segment selector
  movw    %ax, %ds                # -> DS: Data Segment
  movw    %ax, %es                # -> ES: Extra Segment
  movw    %ax, %fs                # -> FS
  movw    %ax, %gs                # -> GS
  movw    %ax, %ss                # -> SS: Stack Segment
  
  #初始化代码段，数据段，以及.......

  # Set up the stack pointer and call into C.
  movl    $start, %esp
  call bootmain #调用main.c文件

  # If bootmain returns (it shouldn't), loop.
spin:
  jmp spin

# Bootstrap GDT
.p2align 2                                # force 4 byte alignment
gdt:
  SEG_NULL				# null seg
  SEG(STA_X|STA_R, 0x0, 0xffffffff)	# code seg
  SEG(STA_W, 0x0, 0xffffffff)	        # data seg

gdtdesc:
  .word   0x17                            # sizeof(gdt) - 1
  .long   gdt                             # address gdt
```

**main.c**

```c
#include <inc/x86.h>
#include <inc/elf.h>

/**********************************************************************
 * This a dirt simple boot loader, whose sole job is to boot
 * an ELF kernel image from the first IDE hard disk.
 *
 * DISK LAYOUT
 *  * This program(boot.S and main.c) is the bootloader.  It should
 *    be stored in the first sector of the disk.
 *
 *  * The 2nd sector onward holds the kernel image.
 *
 *  * The kernel image must be in ELF format.
 *
 * BOOT UP STEPS
 *  * when the CPU boots it loads the BIOS into memory and executes it
 *
 *  * the BIOS intializes devices, sets of the interrupt routines, and
 *    reads the first sector of the boot device(e.g., hard-drive)
 *    into memory and jumps to it.
 *
 *  * Assuming this boot loader is stored in the first sector of the
 *    hard-drive, this code takes over...
 *
 *  * control starts in boot.S -- which sets up protected mode,
 *    and a stack so C code then run, then calls bootmain()
 *
 *  * bootmain() in this file takes over, reads in the kernel and jumps to it.
 **********************************************************************/

#define SECTSIZE	512 
//定义磁盘大小为512bytes
#define ELFHDR		((struct Elf *) 0x10000) // scratch space
//定义ELFHDR文件的头标识
void readsect(void*, uint32_t);
void readseg(uint32_t, uint32_t, uint32_t);

void
bootmain(void)
{
	struct Proghdr *ph, *eph;

	// read 1st page off disk 读磁盘的第一扇区（SECTSIZE*8 代表多少bits）
	readseg((uint32_t) ELFHDR, SECTSIZE*8, 0);

	// is this a valid ELF? 判断ELF文件是否有效
	if (ELFHDR->e_magic != ELF_MAGIC)
		goto bad;

	// load each program segment (ignores ph flags) 加载每个程序的程序段
	ph = (struct Proghdr *) ((uint8_t *) ELFHDR + ELFHDR->e_phoff);
	eph = ph + ELFHDR->e_phnum;
	for (; ph < eph; ph++)
		// p_pa is the load address of this segment (as well
		// as the physical address)
		readseg(ph->p_pa, ph->p_memsz, ph->p_offset);//读每个段

	// call the entry point from the ELF header
	// note: does not return!
	((void (*)(void)) (ELFHDR->e_entry))();

bad:
	outw(0x8A00, 0x8A00);
	outw(0x8A00, 0x8E00);
	while (1)
		/* do nothing */;
}

// Read 'count' bytes at 'offset' from kernel into physical address 'pa'.
// Might copy more than asked
void
readseg(uint32_t pa, uint32_t count, uint32_t offset)
{
	uint32_t end_pa;//结束读取标识符

	end_pa = pa + count;

	// round down to sector boundary
	pa &= ~(SECTSIZE - 1);

	// translate from bytes to sectors, and kernel starts at sector 1
	offset = (offset / SECTSIZE) + 1;//查询偏移扇区量

	// If this is too slow, we could read lots of sectors at a time.
	// We'd write more to memory than asked, but it doesn't matter --
	// we load in increasing order.
	while (pa < end_pa) {
		// Since we haven't enabled paging yet and we're using
		// an identity segment mapping (see boot.S), we can
		// use physical addresses directly.  This won't be the
		// case once JOS enables the MMU.
		readsect((uint8_t*) pa, offset);
		pa += SECTSIZE;
		offset++;//读相应扇区后增加
	}
}

void
waitdisk(void)
{
	// wait for disk reaady
	while ((inb(0x1F7) & 0xC0) != 0x40)
		/* do nothing */;
}

void
readsect(void *dst, uint32_t offset)
{
	// wait for disk to be ready
	waitdisk();//等待磁盘可以被读取

	outb(0x1F2, 1);		// count = 1
	outb(0x1F3, offset);
	outb(0x1F4, offset >> 8);
	outb(0x1F5, offset >> 16);
	outb(0x1F6, (offset >> 24) | 0xE0);
	outb(0x1F7, 0x20);	// cmd 0x20 - read sectors

	// wait for disk to be ready
	waitdisk();

	// read a sector
	insl(0x1F0, dst, SECTSIZE/4);
}
```
#### 关于A20总线
当IBM设计IBM PC AT机器时，他们决定采用性能更好但是在实模式下并不完全兼容以前的Intel 8088与Intel 8086系列的Intel 80286微处理器。以前的x86体系微处理器并没有从A20到A23的总线。80286微处理器能够寻址到16MB的系统内存。

在8088及8086下，任何使用x86内存分段方式尝试访问超过最大1MB的内存都会使得溢出的第二十一位无效化。 许多实模式程序利用这一点，使不改变微处理器的段寄存器而去访问最开始的64KB内存成为一个通用的技巧。为了和这些程序保持兼容性，IBM自己在主板上去修复这个问题。在微处理器与系统总线间插入一个逻辑门完成了这个修复。这个逻辑门也因此被命名为A20总线。A20总线能被软件关闭或打开，以此来阻止或允许地址总线收到A20传来的信号。在引导系统时，BIOS先打开A20总线来统计和测试所有的系统内存。而当BIOS准备将计算机的控制权交给操作系统时会先将A20总线关闭。一开始，这个逻辑门连接到Intel 8042的键盘控制器。控制它是相对较慢。

激活A20总线是保护模式在引导阶段的步骤之一，通常在引导程序将控制权交给内核之前完成（例如在Linux下）。


#### 关于ELF文件头
ELF的文件头包含整个执行文件的控制结构，其定义在elf.h中：
```c
struct elfhdr {
uint magic; // must equal ELF_MAGIC
uchar elf[12];
ushort type;
ushort machine;
uint version;
uint entry; // 程序入口的虚拟地址
uint phoff; // program header 表的位置偏移
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

### 练习2
> 使用 GDB 的 debug 功能完成 boot loader 的追踪过程。b 命令设置断点，如 b *0x7c00 表示在 0x7c00 处设置断点；c 命令可执行到下一断点；si 命令是单步执行。
参考文档：清华ucore文档关于gdb的介绍:[gdb on ucore](https://chyyuu.gitbooks.io/ucore_os_docs/content/lab0/lab0_2_3_3_gdb.html)

问题 1 \
Set a breakpoint at address 0x7c00, which is where the boot sector will be loaded. Continue execution until that breakpoint. Trace through the code in boot/boot.S, using the source code and the disassembly file obj/boot/boot.asm to keep track of where you are. Also use the x/i command in GDB to disassemble sequences of instructions in the boot loader, and compare the original boot loader source code with both the disassembly in obj/boot/boot.asm and GDB.\
*在地址0x7c00处设置一个断点，这是boot扇区被加载的地址。执行continue 操作直到断点之前。跟踪在boot/boot.S中的代码执行情况，利用在obj/boot/boot.asm中反汇编的源码来查看当前所在位置。同时，也利用gdb中所提供的x/i命令来反汇编boot loader中的指令序列，并且利用反汇编源码以及boot loader源码与gdb执行情况作比较。*\
Trace into bootmain() in boot/main.c, and then into readsect(). Identify the exact assembly instructions that correspond to each of the statements in readsect(). Trace through the rest of readsect() and back out into bootmain(), and identify the begin and end of the for loop that reads the remaining sectors of the kernel from the disk. Find out what code will run when the loop is finished, set a breakpoint there, and continue to that breakpoint. Then step through the remainder of the boot loader.\
跟踪boot/main.c文件中的bootmain()函数，并且进入到readsect()函数的执行过程。确定在readsect()函数中的相应的汇编指令。跟踪readsect()中剩余的代码以及返回到bootmain()中的代码，明确读取磁盘中剩余扇区的for循环的开头和结尾。弄清楚，当循环结束的时候的具体代码，在那里打一个断点，并且continue(在gdb中)到那个断点位置，然后继续指令到最后。\
确保你能回答以下几个问题：
1. At what point does the processor start executing 32-bit code? What exactly causes the switch from 16- to 32-bit mode?\
在什么位置，处理器开始执行32位的代码，究竟是什么导致从16位模式切换到32位？

2. What is the last instruction of the boot loader executed, and what is the first instruction of the kernel it just loaded?\
boot loader执行的最后一条指令是什么，加载进内核的第一条指令是什么？

3. Where is the first instruction of the kernel?\
内核中第一条指令的位置在哪？

4. How does the boot loader decide how many sectors it must read in order to fetch the entire kernel from disk? Where does it find this information?\
boot loader怎么样决定为了从磁盘中取得完整的内核代码，它有多少个扇区它必须要读？它是从哪里得到这个信息的？

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
#### 操作过程
```bash
cd lab1/src/lab1_1 
make qemu-gdb  
# 打开另一个终端(terminal)
cd lab1/src/lab1_1
gdb #进入gdb模式之后
b *0x7c00
c
si 

```

#### 连接地址与载入地址
使用objdump -h obj/kern/kernel 命令查看elf文件时，要注意VMA和LMA的差别(连接地址与载入地址)

### 练习3
#### 问题：
1. Explain the interface between printf.c and console.c. Specifically, what function does console.c export? How is this function used by printf.c?\
解释printf.c和console.c之间的接口，特别是console.c输出了什么相关函数，这个函数是怎么被printf.c利用的。

2. Explain the following from console.c:
```c
1 if (crt_pos >= CRT_SIZE) {
2 int i;
3 memcpy(crt_buf, crt_buf + CRT_COLS, (CRT_SIZE -CRT_COLS) * sizeof(uint16_t));
4 for (i = CRT_SIZE - CRT_COLS; i < CRT_SIZE; i++)
5 crt_buf[i] = 0x0700 | ' ';
6 crt_pos -= CRT_COLS;
7 }
```
解释console.c中下述代码

3. We have omitted a small fragment of code - the code necessary to print octal numbers using patterns of the form "%o". Find and fill in this code fragment.\
我们已经省略了一小段代码——利用符号"%o"来打印八进制字符的这一段，找出来并且填上去。

#### 关于JOS的虚拟内存控制
映射整个底部的 256MB 物理地址空间,即 0x0000000~0x0fffffff,到虚拟地址空间的 0xf0000000~0xffffffff。这也是为什么 JOS 内核被限制在只能使用 256MB 物理 内存。

#### 函数调用关系
