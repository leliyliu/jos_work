# LAB3
----

新的源代码文件
目录|	文件 |	说明 
| -  | - | - |
inc/|	env.h	| 用户模式进程的公用定义
&nbsp; |trap.h|	陷阱处理的公用定义
&nbsp; |syscall.h|	用户进程向内核发起系统调用的公用定义
&nbsp; |lib.h	|用户模式支持库的公用定义
kern/	|env.h  |用户模式进程的内核私有定义
 &nbsp;|env.c	|用户模式进程的内核代码实现
 &nbsp;|trap.h|	陷阱处理的内核私有定义
&nbsp; | trap.c	|与陷阱处理有关的代码
 &nbsp;|trapentry.S	|汇编语言的陷阱处理函数入口点
&nbsp; |syscall.h	|系统调用处理的内核私有定义
&nbsp; |syscall.c	| 与系统调用实现有关的代码
lib/|	Makefrag|	构建用户模式调用库的 Makefile fragment, obj/lib/libuser.a
&nbsp;|entry.S	|汇编语言的用户进程入口点
&nbsp;|libmain.c	|从 entry.S 进入用户模式的库调用
&nbsp;|syscall.c	|用户模式下的系统调用桩(占位)函数
&nbsp;|console.c	|用户模式下 putchar() 和 getchar() 的实现，提供控制台输入输出
&nbsp;|exit.c	|用户模式下 exit() 的实现
&nbsp;|panic.c	|用户模式下 panic() 的实现
user/|	*	|检查 Lab 3 内核代码的各种测试程序

## PART A
在inc/env.h 中定义了用户进程的一个struct ，其包括了一个*struct Trapframe env_tf;*，也就是中断列表，一个指向下一空闲用户进程的列表*Env *env_link*，一个用户进程id号*env_id*,父进程id号*env_parent_id*,用户进程的标记*env_type*，进程的状态*env_status*和进程运行的时间*env_runs*,页目录的虚拟内存地址*env_pgdir*
```c
struct Env { // 用户进程
	struct Trapframe env_tf;	// Saved registers
	struct Env *env_link;		// Next free Env
	envid_t env_id;			// Unique environment identifier
	envid_t env_parent_id;		// env_id of this env's parent
	enum EnvType env_type;		// Indicates special system environments
	unsigned env_status;		// Status of the environment
	uint32_t env_runs;		// Number of times environment has run

	// Address space
	pde_t *env_pgdir;		// Kernel virtual address of page dir
};
```

### exercise one
修改pamp.c文件，其中主要有两个部分需要增加，即分配空间与进行相应的映射。
```c
	// Make 'envs' point to an array of size 'NENV' of 'struct Env'.
	// LAB 3: Your code here.
	envs = (struct Env *)boot_alloc(sizeof(struct Env) * NENV);//分配相应的空间
	memset(envs,0,sizeof(struct Env)*NENV);

	// Map the 'envs' array read-only by the user at linear address UENVS
	// (ie. perm = PTE_U | PTE_P).
	// Permissions:
	//    - the new image at UENVS  -- kernel R, user R
	//    - envs itself -- kernel RW, user NONE
	// LAB 3: Your code here.
	boot_map_region(kern_pgdir,UENVS,PTSIZE,PADDR(envs),PTE_U);//并为其分配相应的映射，其权限为PTE_U
```

### exercise two

#### env_init() 


#### env_setup_vm()

#### region_alloc()

#### load_icode()

#### env_create()

#### env_run()
