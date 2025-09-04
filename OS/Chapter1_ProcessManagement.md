> 参考：
>
> CSAPP Chapter 8 & 12

A process is an instance of a program in execution. Each program in the system runs in the *context* of some process. The context consists of the state that the program needs to run correctly: program's code and data stored in memory, its stack, the contents of its general-purpose registers, its program counter, environment variables, and the set of open file descriptors.



- hardware context:
  - CPU register values
  - stack pointers
  - CPU status Word Register



## Process Control Blocks

When a process is created, the OS also creates a data structure to maintain information about that process:

- PID: 通常是该PCB 在 process table中的index
- stack pointer: 用来store H/W context of this process
- open files
- pending signals
- CPU usage： 这三个是OS context
- 此外还有 memory context

PCB is stored in a table called a "Process Table": one process table for entire system. One PCB per process.



multitasking types:

- batch processing
- cooperative multitasking
- pre-emptive multitasking
- real-time multitasking

scheduling policies:

- fixed priority





#### **PCB 的作用**

- 保存进程的核心状态，用于在上下文切换时记录和恢复进程状态。
- 包括：
  - 当前程序计数器（PC）。
  - 通用寄存器的值。
  - 栈指针（SP）的位置。
  - 内存映射表。

#### **Stack 的作用**

- 栈保存的是进程执行的局部状态，尤其是函数调用和局部变量。
- 在上下文切换时，栈指针的位置会保存在 PCB 中，切换回进程时通过栈指针恢复栈的内容。
