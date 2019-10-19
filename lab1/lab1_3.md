# LAB1
---
## exercise 7
查看obj/kern/kernel.asm 的内容，看到，在0xf0100025 这一地址中，进行了<font color = red>movl %eax, %cr0</font>这一操作，同时，利用gdb也可以看到相同的结果

![kern.asm](https://github.com/leliyliu/figure_lib/blob/master/jos/lab1/17.png?raw=true)

![gdb_kern](https://github.com/leliyliu/figure_lib/blob/master/jos/lab1/18.png?raw=true)

根据相应的地址查看执行结果:

![process_kern](https://github.com/leliyliu/figure_lib/blob/master/jos/lab1/19.png?raw=true)

可以看到，在跳转到相应地址之后，进行了跳转链接:<font color = red>mov $0xf010002f, %eax</font> 如果注释掉kern/entry.S 中的<font color = red>movl ％eax，％cr0</font>,可以看到结果如下：

![entry.S](https://github.com/leliyliu/figure_lib/blob/master/jos/lab1/20.png?raw=true)

![unlink](https://github.com/leliyliu/figure_lib/blob/master/jos/lab1/21.png?raw=true)

无法进行地址间的链接跳转。

## exercise 8

利用understand 查看函数调用关系:

![]()

并根据<font color = cyan>lib/printfmt.c</font>中的代码，修改<font color=blue>case 'o'</font>的情况，得到相应的修改代码为：

``` c
// unsigned decimal
case 'u':
	num = getuint(&ap, lflag);
	base = 10;
	goto number;

// (unsigned) octal
case 'o':
    // Replace this with your code.
    //putch('0',putdat);//由于八进制的输出结果应该前面有一个'0'，故加上
    num = getuint(&ap,lflag);
    base = 8;
    goto number;

```

serial_putc 子程序的功能是把一个字符输出给串口\
ipt_putc 将内容输出给并口\
cga_putc 将字符输出到cga设备上

关于问题:

+ 解释 printf.c 和 console.c 之间的接口。具体来说，console.c 导出了什么函数？printf.c 是如何使用这些函数的？\
通过对于函数调用关系图的观察可以发现，printf.c中使用了cprintf函数，并且cprintf函数中调用了相关的putch函数，console.c中提供了putch,cputchar等相应的函数来进行相关处理

+ 解释 console.c 的以下内容：
```c
// What is the purpose of this?
if (crt_pos >= CRT_SIZE) {
    int i;

    memmove(crt_buf, crt_buf + CRT_COLS, (CRT_SIZE - CRT_COLS) * sizeof(uint16_t));
    for (i = CRT_SIZE - CRT_COLS; i < CRT_SIZE; i++)
        crt_buf[i] = 0x0700 | ' ';
    crt_pos -= CRT_COLS;
}

```

由于这是控制屏幕的显示的，通过观察console.h 中对于CRT_SIZE的定义可知，实际上这是对于屏幕点阵大小的定义，故，当输出超过屏幕所占宽度时，则需要向下翻滚。

![]()

+ fmt指向格式字串,ap指向除了格式字串以外的

+ 输出He110 World。字符串的编译后的保存形式除了大小端和整数无差别，都是以值的形式保存

+ ics函数的参数传递堆栈知识 取栈上的3的再+4bytes的位置

## challenge

## exercise 9

在kern/entry.S 中，完成了栈的初始化过程，具体指令如下所示：
```x86asm
relocated:

	# Clear the frame pointer register (EBP)
	# so that once we get into debugging C code,
	# stack backtraces will be terminated properly.
	movl	$0x0,%ebp			# nuke frame pointer

	# Set the stack pointer
	movl	$(bootstacktop),%esp

	# now to C code
	call	i386_init
```
查看编译后的结果(obj/kern/kernel.asm):

![stack_init](https://github.com/leliyliu/figure_lib/blob/master/jos/lab1/25.png?raw=true)

初始的精确位置在<font color=cyan>0xf0110000</font>，esp指向当前使用的堆栈的最低地址处（0xf0110000是最大地址，在当前进程下不能高于这个地址），push会使esp-4,pop会使esp+4 (32位模式下)。 x86 栈指针（esp寄存器）指向栈当前正在使用的最低地址位置

## exercise 10
根据所得到的相应结果，看到，在进行完相应的stack初始化之后，进入了init_386的函数调用，实际过程实际上有一个调用test_backtrace(5) 的过程:

因此设置相应的断点，得到执行的过程为：

![gdb_process](https://github.com/leliyliu/figure_lib/blob/master/jos/lab1/27.png?raw=true)

![source_code](https://github.com/leliyliu/figure_lib/blob/master/jos/lab1/26.png?raw=true)

根据相应的源码，可以看到，每一级的递归调用会压入0x14bytes，即5个32位的字，这些内容包括相关的参数和ebp每次调用时的值。


## exercise 11
添加代码如下：
```c
int
mon_backtrace(int argc, char **argv, struct Trapframe *tf)
{
	// Your code here.
	int i;
	uint32_t eip;
	uint32_t* ebp = (uint32_t*)read_ebp();
	cprintf("Stack backtrace:\n");
	while(ebp)
	{
		eip = *(ebp + 1);
		cprintf("  ebp %x  eip %x  args ",ebp,eip);
		uint32_t* args = ebp+2;
		for (i=0; i<5;i++)
		{
			uint32_t arg = args[i];//parameters
			cprintf(" %08x",arg);
		}
		cprintf("\n");
		ebp = (uint32_t*) *ebp;
	}
	return 0;
}
```

## exercise 12
+ 在文件 <font color=red>kern/kernel.ld</font> 中查找 \_\_STAB_*

![_stab](https://github.com/leliyliu/figure_lib/blob/master/jos/lab1/28.png?raw=true)

+ 运行 <font color=red>objdump -h obj/kern/kernel</font>

![objdump](https://github.com/leliyliu/figure_lib/blob/master/jos/lab1/29.png?raw=true)

+ 运行 <font color=red>objdump -G obj/kern/kernel</font>\
-G， --stabs   Display (in raw form) any STABS info in the file

+ 运行 <font color=red>gcc -pipe -nostdinc -O2 -fno-builtin -I. -MD -Wall -Wno-format -DJOS_KERNEL -gstabs -c -S kern/init.c</font>，并查看 init.s

[init.s](https://github.com/leliyliu/jos_work/blob/master/lab1/init.s)的内容可以直接查看到

+ 看看 bootloader 是否在内存中加载了符号表，作为加载内核二进制文件的一部分


inc/stab.h
```c
struct Stab {
	uint32_t n_strx;	// index into string table of name
	uint8_t n_type;         // type of symbol
	uint8_t n_other;        // misc info (usually empty)
	uint16_t n_desc;        // description field
	uintptr_t n_value;	// value of symbol
};
```

对于stabs和stabn的格式，定义如下：
> .stabs "string",type,other,desc,value \
> .stabn type,other,desc,value

查看相关的stab_binsearch函数内容，可以发现，其实际上就是一个查询的作用，找到相应的值

因而，修改相应的程序，如源码所示：
```c
	stab_binsearch(stabs,&lline,&rline,	N_SLINE,addr);
	if(lline<=rline)
	{
		info->eip_line = stabs[rline].n_desc;
	}
	else 
		return -1;
```

```c
int
mon_backtrace(int argc, char **argv, struct Trapframe *tf)
{
	// Your code here.
	int i;
	uint32_t eip;
	uint32_t* ebp = (uint32_t*)read_ebp();
	cprintf("Stack backtrace:\n");
	while(ebp)
	{
		eip = *(ebp + 1);
		cprintf("  ebp %x  eip %x  args ",ebp,eip);
		uint32_t* args = ebp+2;
		for (i=0; i<5;i++)
		{
			uint32_t arg = args[i];//parameters
			cprintf(" %08x",arg);
		}
		cprintf("\n");
		struct Eipdebuginfo debug_info;
		debuginfo_eip(eip,&debug_info);
		cprintf("\t%s:%d: %.*s+%d\n",debug_info.eip_file,debug_info.eip_line,debug_info.eip_fn_namelen,debug_info.eip_fn_name,eip-debug_info.eip_fn_addr);
		ebp = (uint32_t*) *ebp;
	}
	return 0;
}
```

至此，所以lab1的实验作业都已完成

![score](https://github.com/leliyliu/figure_lib/blob/master/jos/lab1/30.png?raw=true)

## challenge
关于最终的挑战，实际上只是修改颜色的话，可以看到在\kern\console.c 的cga_putc函数中，有一行注释为:

![comment](https://github.com/leliyliu/figure_lib/blob/master/jos/lab1/40.png?raw=true)

因此，可以发现，实际上对于颜色的修改就是对于cga_putc函数中的参数c进行相应的修改。一个字符的打印过程为：cprintf→vcprintf
→vprintfmt→putch→cputchar→consputc→cgaputc

在参数c中，高8位是指定打印的颜色，在源代码中，指定为白底黑字，高八位为0x07，其整体架构为：

![table](https://github.com/leliyliu/figure_lib/blob/master/jos/lab1/table.jpg?raw=true)

因而，可以修改相应的函数，实现不同的颜色表示：
```c
// \kern\console.c
static void
cga_putc(int c)
{
	// if no attribute given, then use black on white
	c |= init_color<<8;
	
	if (!(c & ~0xFF))
		c|= 0x0100;
```

```c
// \lib\printfmt.c
#define color_green 0x02;
#define color_blue 0x03;
#define color_red 0x04;
#define color_purple 0x06;
#define color_white 0x07;
#define color_orange 0x0c;

int init_color = color_green;//设置初始化颜色为绿色

//vprintfmt 函数的设置
		case 'm':
			//memmove(selection ,fmt ,sizeof(char ));
			//selection[1] = '\0';
			if(fmt[0] == 'g') 
				init_color = color_green;
			if(fmt[0] == 'b') 
				init_color = color_blue;
			if(fmt[0] == 'r') 
				init_color = color_red;
			if(fmt[0] == 'p') 
				init_color = color_purple;
			if(fmt[0] == 'w') 
				init_color = color_white;
			if(fmt[0] == 'o') 
				init_color = color_orange;
			fmt++;
			break;

```

```c
// \kern\monitor.c
//在monitor函数中增加相应的内容
void
monitor(struct Trapframe *tf)
{
	char *buf;

	cprintf("Welcome to the JOS kernel monitor!\n");
	cprintf("Type 'help' for a list of commands.\n");
	cprintf("%mgCan you see my color?\n");
	cprintf("%mwYes , I can!\n");
	cprintf("%mrSo what is my color?\n");
	cprintf("%mpOh , you are red.\n");
	cprintf("%moI think I am the best.\n");
	cprintf("%mbI think I am better than you. \n");
	
	while (1) {
		buf = readline("K> ");
		if (buf != NULL)
			if (runcmd(buf, tf) < 0)
				break;
	}
}
```

最终打印的结果为:

![final_result](https://github.com/leliyliu/figure_lib/blob/master/jos/lab1/color.png?raw=true)