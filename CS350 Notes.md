# CS350 Notes

Context before process is missing. May be filled in later.

## Process

A process is an **environment** in which an application program runs.

#### Process management command (Unix/Linux)

- `top`: Show current process state
- `ps ax | grep <proc name>`: Find some process
- `kill -9 <pid>`: Kill some process
- `sar`: Similar to `top`



#### A process consists of

- Virtual memory (address space)
- A sequence of threads

- Other recourses such as virtual file system...



#### System calls regarding process

- `fork`: Create a new process (the **child**) that is a clone of the original (the **parent**)
  - The child and the parent have two different address spaces, which means after forking, one is not aware of any change that the other one makes
  - `fork` is called by the parent, however, since the registers, instructions, data are all cloned, `fork` will also return in the child. Parent and child see different return value from fork
- `_exit`: Terminates the process that calls it, and leave a exit status code in the kernel
- `waitpid`: Let a process wait for another to terminate, and retrieve its exit status code

```C
main () {
    rc = fork(); // return 0 to child, pid to parent
    if (rc == 0) {
        // child_code
    } else {
        // parent_code
        p = waitpid(rc, &child_exit, 0);
        // parent_code after child terminates
    }
}
```



> What if we call `waitpid` in multi-thread program?
>
> There are two different implementations, one is to make just the thread that calls `waitpid` to sleep, and the other is to let all the threads of the process fall asleep.



- `execv`: Change the program that the process is running
  - Current address space is destroyed, a new address space is given to the process initialized with the new code and data, and the new program start to execute.

```C
main () {
    int rc = 0;
    char* args[2];
    // init cmd line arguments
    rc = execv("/testbin/argtest", args);
    
    // Should not reach here if execv succeeds
    printf("If you see this, execv failed\n");
    exit(0);
}
```

We can combine `fork` and `execv` to achieve "map reduce": The main process has a bunch of children running different programs.



## System Calls

System calls are the interface between processes and operating system

#### Kernel priviledge

The CPU implements several different levels of **execution privilege**. 

- The kernel code runs at the highest privilege
- Application code runs at a lower privilege
- Programs cannot execute code or instructions belonging to a higher-level of  privilege.

We do this for the sake of security and isolation.

- Security: Application should not modify the page tables the kernel uses to implement virtual memories or halt the CPU
- Isolation: User programs do not need to change on system update

 #### System Call

Since the kernel code cannot be called in the lower privilege mode, how do we do system call?

The answer is through **interrupts/exceptions**

- Interrupts come from hardware while exceptions come from software, they are raised and caught by the kernel
- When an interrupt/exception is caught, the kernel will jump to the **interrupt/exception handler** code and run it (the code is inside the kernel)
- In MIPS, we do system call through `EX_SYS = 8`

- Implementation for each system call interface is like below

  ```C
  fork () {
      li $v0, syscal code // indicate which syscall it is
      li params into a0-a3 // syscall args
      syscall (raises exception of type EX_SYS)
  
  	// Since exception occurs, control transfers to kernel to do actual syscall
       
      $a3 // Success (0) Fail (1)
      $v0 // return value or errorcode
  }
  ```

- Kernel code are omitted...

#### Inter-Process Communication

IPC is a family of methods used to send data between processes

- File
- Shared memory: data is sent via block of shared memory visible to both processes
- Socket: data is sent via network interface
- Pipe: data is sent unidirectionally from one process to another via OS-managed data buffer
- Message Passing/Queue: a queue/data stream provided by the OS to send data between proccesses



## Virtual Memory

#### Why not physical memory?

We do not want to use actual physical address for address space of programs since 

- Security: we do not want the program to access some address outside its address space
- Efficiency: we do not want the ram to be fragmented

####  How virtual memory works

- Each virtual memory is mapped to a different part of physical memory.
- Address translation is performed in hardware, on the **Memory Management Unit (MMU)**, using information provided by the kernel

#### Address translation schemes

- Goals / properties that a valid translation scheme should have:
  - Transparency: the process should never be aware of the translation
  - Efficiency: the translation should be efficient in time and space
  - Protection: it has to provide isolation from the real physical address and other processes
- Some schemes:
  - memory reallocation: MMU simply record a offset and a limit, directly map virtual mem to physical meme
  - Segmentation:  Address space for each process is separated into several segments. MMU records the offset and limit for each segmentation (In fact, it records the address of a segmentation table in the mem and use it to look up for the offset and limit)
  - Paging: Address space for each process is divided into several pages of small fixed size (4kB usually).

- Paging Scheme:
  - Performing translation add at least one MEM operation to each instruction
  - Thus we use TLB cache in CPU
    - 



## IO and Devices

### Device Drivers

- Each device has a small amount of computation power on board shown through device registers
- two ways of interaction:
  - polling: device driver repeatedly asking device to do sth and check status
  - interrupt: device send interrupt when done with sth
- IO
  - port-mapped IO
  - memory-mapped IO
- Large data transfer to/from devices
  - program-controlled IO: CPU is involved
  - Direct memory access (DMA): device could fetch from RAM directly
- Persistant storage devices: store data even without power

### Disk Drivers 

- Magnetic hard disks: a read/write head on each glass platters which are spinning when we are fetching data. Pretty fragile!

  - Moving data to/from a disks involves:
    - seek time: move the read/write heads to the appropriate track
    - rotational latency: wait until the desired sectors spin to  read/write head
    - transfer  time: wait while the desired sectors spin past the read/write head

  - A long transfer is much faster than several small transfers, thus we prefer sequential IO than non-sequential IO

  - Disk Head Scheduling: we want to rearrange a bunch of IO requests to minimize the average seek time while avoiding starvation. 

    - FCFS: first come first served, nothing gets optimized

    - SSTF: shortest seek time first, minimize average seek time, but starvation is possible

    - SCAN: elevator algorithms. First choose a direction to move, and we move in one direction until there are no more request in front of us, and then we turn around. There are many variations above it, and are widely used.

- SSD: no mechanical parts, using integrated circuits for persistant storage
  - reads/write at page level: 1 means empty
  - Going from 0 to 1 needs high voltage, but only on block level (4mb/32mb)
  - To perform overwrite: we could mark to be deleted/overwritten as invalid, and write to an unused page and update translation table. This requires garbage collection. 
  - Each block of an SSD has a limited number of write cycles before it becomes read-only. (about 100,000)  Thus intentional defragmentation is performed to keep all blocks similar level of being written.     
- Persistent RAM: can be used as cache to the secondary storage. An advantage is that the cache wont be cleared even when powering off.



## File System

- File: persistent, named data objects
  - consists of a sequence of numbered bytes
  - has associated meta-data (e.g. type, timestamp, access control)
- File systems: the data structures and algorithms used to store, retrieve, and access filse
  - Logical file system: high-level API, what a user uses
  - Virtual file system: abstraction of lower level file systems 
  - Physical file system: how files are actually stored on physical media

#### Logical File System

- open: takes a string "name" and open file 
  - translate the name to the unique file identifier (or handle or descriptor)
  - tell kernel that one more process will open this file, so the kernel increment the number in the entry
  - return the file identifier to the process so that the process could add a new entry to its file descriptor table
  - other operation (e.g. read, write) require the descriptor as a parameter
- close: kernel tracks which file descriptors are currently valid for each process, and close invalidate a valid file descriptor
- read/write/seek:
  -  in the file descriptor we store the current position in the file, so position is not required
  - seek enables non-sequential reading/writing
- get/set file meta-data: `fstat`, `chmod`, `ls`....
  - `ls -la`: read the metadata of each file and display them
  - `chmod go+w <filename>` : give group and other the write permission
  - `touch -mt <datetime> <filename>`: change the timestamp of a file

- A directory maps a string (file name) to its i-number (unique identifier). Each mapping is called a **hard link**.
  - The directory can be nested, thus a file system tree is formed
  - A directory can be either an internal node or a leaf. A file can only be a leaf in the tree.
  - Directory cannot be modified directly by users.
  - Multiple hard link to a directory is not allowed to avoid cycles.
  - hard links can be removed by unlink: if the last hard link on a file gets removed, the file cannot be opened anymore, however, the data may not be erased!
- Multiple File Systems:
  - Windows uses a 2-part file name `C:/`+`..../blah.txt` . The first part indicates the file system. 
    - A,B: floppy cards
    - C,D....: hard drives
  - Unix uses `mount`, to attach the root of a file system to some point in the root file system.

#### Physical file system

- Things needs to be stored persistently:
  - file data and file meta-data
  - directories and links, file system meta-data
- Use a 256kB disk as an example:
  - Most disks have a sector size of 512 bytes, 512 total sectors on the disk
  - Group every 8 consecutive sectors into a block (4KB to match on-demand paging), 64 total blocks on the disk
  - First few blocks stores system meta-data, blocks following stores data
  - Files does not share blocks!
  - We create an array of i-nodes, where each i-node contains the meta-data for a file. 
  - We use bitmaps to indicate which i-nodes and blocks are used
  - Then the first block is used as the superblock, to store the meta-information about the entire file system

- i-node fields may include: file type, file permissions, file length, number of file blocks, time of last file access, number of hard links to this file, direct data block pointers

