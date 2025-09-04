> 

An operating system is a collection of specialized software that:

- gives you access to the hardware devices like disk drives, printers, keyboards and monitors.
- controls and allocate system resources like memory and processor time.
- gives you the tools to customize and tune your system.

但OS本身也是一个program --> a sequence of instructions

从结构上看：

- Bootloader: First program run by the system on start-up. Loads remainder of the OS kernel.
- Kernel: the part of the OS that runs almost continuously.
- System Programs



Bootstrapping:  the OS is not present in memory when a system is "cold started". How do we get an operating system into memory? We start first with a bootloader: a tiny program in the first (few) sector(s) of the hard-disk.



Kernels can be monolithic (单体内核) or microkernel (微内核).

- Monolithic kernels: all major parts of the OS - devices drivers, file systems, IPC, etc, running in "kernel space" (即kernel mode, 与之对应的是user mode).
- microkernels: only the "main" part of the kernel is in "kernel space", like scheduler, process management, memory management, etc. The other parts of the kernel operate in "user space", like file systems, USB device drivers, other device drivers. Most famous microkernel OS: MacOS.



System calls: are calls made to the "Application Program Interface" or API of the OS.

## Context Switching

cores: CPU units that can execute processes.

## Scheduling

decide priority & who runs next

