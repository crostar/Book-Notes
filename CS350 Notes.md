# CS350 Notes

Context before process is missing. May be filled in later.

## Process

A process is an **environment** in which an application program runs.

#### Process management command (Unix/Linux)

- `top`: Show current process state
- `ps ax | grep <proc name>`: Find some process
- `kill -9 <pid>`: Kill some process
- `sar`: Similar to `top`



#### A process consists of:

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