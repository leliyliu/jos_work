# LAB1
---
## [X86汇编与AT&T](http://www.delorie.com/djgpp/doc/brennan/brennan_att_inline_djgpp.html)
+ 寄存器名
寄存器名字加上前缀"%"\
**AT&T**:  %eax\
**Intel**: eax
+ 源地址/目的地址
在AT&T语法中，源地址总是在左边，而目的地址总是在右边\
**AT&T**:  movl %eax, %ebx\
**Intel**: mov ebx, eax
+ 常数/立即数格式\
在常数前加上前缀$\
**AT&T**:  movl $_booga, %eax\
**Intel**: mov eax, _booga\
**AT&T**: movl $0xd00d, %ebx\
**Intel**: mov ebx, d00dh
+ 确定操作数值大小\
用b,w,l来表示**byte**,**word**,**longword**\
**AT&T**: movw %ax, %bx\
**Intel**: mov bx, ax
+ Referencing memory\
对内存地址中数据的查找\
**AT&T**:  immed32(basepointer,indexpointer,indexscale)\
**Intel**: [basepointer + indexpointer*indexscale + immed32]\
各种例子:\
**AT&T**:  _booga\
**Intel**: [_booga]\
\
**AT&T**:  (%eax)\
**Intel**: [eax]\
\
**AT&T**:  _variable(%eax)\
**Intel**: [eax + _variable]\
\
**AT&T**:  _array(,%eax,4)\
**Intel**: [eax*4 + array]\
\
**C code**: *(p+1) where p is a char *\
**AT&T**:  1(%eax) where eax has the value of p\
**Intel**: [eax + 1]

## 作业
关于JOS作业的翻译(LAB1)，可以参考[JOS中文版](http://oslab.mobisys.cc/cn/Lab_1.html),[JOS英文版](http://oslab.mobisys.cc/pdos.csail.mit.edu/6.828/2014/labs/lab1.html)
关于exercise:
