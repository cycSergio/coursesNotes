> 参考：
>
> CSAPP: 6 The Memory Hierarchy
>
> NUS IT5002 Lecture 15: Memory Management
>
> CS61C review slides





Physical memory is:

(存在形式：) The actual matrix of capacitors (DRAM) or flip-flops (SRAM) that stores data and instructions.

(组织形式：) Arranged as an array of bytes. 虽然物理内存是以bit为最小存储单元，但Byte是内存的基本访问单位。每个字节都有一个唯一的地址(memory address)，用于标识它在内存中的位置。反正现在可以这样看：内存是一个很大的字节数组。

## C memory layout

On a 32-bit system, the memory has 32-bit addresses. Each bit can be a 0 or a 1, so you have $2^{32}$ addresses.

Each address refers to one byte, which means you have $2^{32}$ bytes of memory.

```goat
+--------------------------------------------------------------------------------------------------+
|                                                                                                  |
+--------------------------------------------------------------------------------------------------+
^                                                                                                  ^
|                                                                                                  |
address 0x00000000                                                                address 0xFFFFFFFF   
```

One long row of bytes is hard to read for human, so we usually draw memory as a grid of bytes. 

```goat
address 0xFFFFFFFF+---------------------+                          
                  |                     |                                                               
                  |                     |                                                               
                  |                     |
                  |                     |
                  |                     |
                  |                     |
                  |                     |
                  |                     |
                  |                     |
                  |                     |
                  |                     |
                  |                     |
                  |                     |
                  |                     |
address 0x00000000+---------------------+
```

This is only for clarity. The program still sees the long row of bytes on the above.

## Endianness

Physical memory is organized in bytes, but CPUs often transfer data in units of word. 比如 64-bit 机器的字长是 8 bytes， 32-bit 机器的字长是4 bytes. Then how do we map multi-byte words to single-byte memory?

- Big Endian: higher order bytes at lower addresses
- Little Endian: lower order bytes at lower addresses (但是看起来像是backwards)

> [!Note]
>
> `malloc`：C 中用来动态分配内存的函数，比如`malloc(100)`请求OS分配100 bytes的连续内存块，它会返回分配的内存块的起始地址。Any time your code calls `malloc`， space on the heap is allocated. It remains until you call `free`. 



## Physical & Logical Addresses

Physical addresses: addresses that are actually sent to memory to retrieve data or instructions.

Logical addresses: addresses as "seen" by executing processes code.

```goat
+-------+                     +---------+---------+
|  8192 | ------------------> | 24576   |   ...   |
+-------+                     +---------+---------+
| Limit Register              |   ...   |   ...   |
                              +---------+---------+
                              | 16396   |   ...   |
                              +---------+---------+
                              | 16392   |   ...   |
                              +---------+---------+
+-------+                     | 16388   |   ...   |
| 16384 | ------------------> +---------+---------+
+-------+                     | 16384   | JMP 28  |
| Base Register               +---------+---------+
```

- Base register: contains the starting address for the program. All program addresses are computed relative to this register.
- Limit register: contains the length of the memory segment.

只有1个base register和1个limit register (像是废话x)，只是对每个process来说内含的value不同。两个寄存器一起工作，用于在内存管理中实现地址映射和边界检查。前者确保进程的虚拟地址被映射到正确的物理内存位置，后者确保进程的访问范围不会超出OS所分配的内存。

## Contiguous Memory Allocation | Partitioning Strategies

The problem with allocation is that, in order to minimize the meta-data, we allocate memory in blocks of fixed size. As such, in every block, some memory remains unused. This leads to internal fragmentation.

### Fragmentation

There are two forms of fragmentation: *internal fragmentation* and *external fragmentation*.

- Internal fragmentation: Partition is much larger than is needed. Extra space is wasted.
- External fragmentation: Free memory is broken into small chunks by allocated memory. There *is* enough aggregate free memory to satisfy an allocate request, but no single free block is large enough to handle the request.

Internal fragmentation can be reduced by smaller size of allocation blocks. External fragmentation can be reduced by relocating occupied blocks.

### Implementation

- Free block organization: how do we keep track of free blocks?
- Placement: how do we choose an appropriate free block in which to place a newly allocated block?
- Splitting: after we place a newly allocated block in some free block, what do we do with the remainder of the free block?
- Coalescing: what do we do with a block that has just been freed?

#### Placing Allocated Blocks

When an application requests a block of *k* bytes, the allocator searches the free list for a free block that is large enough to hold the requested block.  Some common *placement policy* are first fit, next fit, best fit, and worst fit.



|        | first fit                                                    | next fit                                                     | best fit                                                     | worst fit                                                    |
| ------ | ------------------------------------------------------------ | ------------------------------------------------------------ | ------------------------------------------------------------ | ------------------------------------------------------------ |
| 怎么做 | searches the free list from the **beginning** and chooses the **first** free block that fits | 是对first fit的改进，instead of starting each search at the beginning of the list, it starts each search where the previous search left off | examines **every** free block and chooses the free block with the **smallest** size that fits | finds the largest block of free memory                       |
| 好     | tends to retain large free blocks at the end of the list     | can run significantly faster than first fit, especially if the front of the list becomes littered with many small 碎片 | theoretically should minimize "waste", however can lead to scattered bits of tiny useless holes | theoretically should reduce the number of tiny useless holes |
| 不好   | 分配集中在低地址区，并在此处产生很多small free blocks, which will increase the search time for larger blocks | some studies suggest that next fit suffers from worse memory utilization than first fit | using best fit with simple free list organizations requires an exhaustive search of the heap | 同best fit, 除非free list有序，否则需要遍历整个list          |

> [!Note]
>
> 关于为什么worst fit 产生碎片的几率更小：
>
> 因为在分配内存时，worst fit总是从所有free blocks里选最大的那个，这个最大的块在满足分配需求以后剩下的内存块也因此相对较大，可能能继续满足后续的分配请求，而不是变成非常小的碎片。
>
> 假设有以下内存空闲块：`[2KB, 4KB, 8KB, 16KB]`， 想要请求6KB，
>
> - 使用worst fit: 选择最大块 `16KB`，分配 `6KB` 后剩余 `10KB` 空闲，内存状态：`[2KB, 4KB, 8KB, 10KB]`
> - 使用best fit: 选择最接近需求的块 `8KB`，分配 `6KB` 后剩余 `2KB` 空闲，内存状态：`[2KB, 4KB, 2KB, 16KB]`
>
> 前者产生了一个较大的空闲块（10KB），未来更可能满足其他分配请求；后者产生了两个小碎片（2KB 和 2KB），可能无法用于未来的分配，增加了碎片化。



此外课上还讲了 buddy allocation (aka quick fit), 它是O(logN)的：an efficient way to manage free blocks.

