#ifndef FT_STRACE_H
#define FT_STRACE_H


#define MAX_SYSCALL_NAME    32
#define MAX_SYSCALL_NUMBER  512

struct user_regs_struct32 {
	int		ebx;
	int		ecx;
	int		edx;
	int		esi;
	int		edi;
	int		ebp;
	int		eax;
	int		xds;
	int		xes;
	int		xfs;
	int		xgs;
	int		orig_eax;
	int		eip;
	int		xcs;
	int		eflags;
	int		esp;
	int		xss;
};

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

int trace(int pid, const char *path);

#endif