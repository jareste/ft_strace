#ifndef FT_STRACE_H
#define FT_STRACE_H


#define MAX_SYSCALL_NAME    32
#define MAX_SYSCALL_NUMBER  512

typedef struct {
    int number;
    char name[MAX_SYSCALL_NAME];
} Syscall;

typedef enum {
    false = 0,
    true = 1
} bool;

extern Syscall syscalls_64[MAX_SYSCALL_NUMBER];
extern Syscall syscalls_32[MAX_SYSCALL_NUMBER];

int trace(int pid);

#endif