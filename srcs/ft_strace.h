#ifndef FT_STRACE_H
#define FT_STRACE_H


#define MAX_SYSCALL_NAME    32
#define MAX_SYSCALL_NUMBER  512

/* TYPES */
# define INT				1
# define LONG				2
# define ULONG				3
# define PTR				4
# define STR				5
# define FLAG_OPEN			6
# define FLAG_OPENAT		7
# define FLAG_PROT			8
# define FLAG_MMAP			9
# define STRUCT_STAT		10
# define STRUCT_POLL		11
# define STRUCT_SIGACT		12
# define STRUCT_SIGSET		13
# define STRUCT_SIGINF		14
# define STRUCT_IOVEC		15
# define STRUCT_FDSET		16
# define STRUCT_TIMEVAL		17
# define STRUCT_TIMEZONE	18
# define STRUCT_TIMESPEC	19
# define STRUCT_SHMID		20
# define STRUCT_SOCKADDR	21
# define STRUCT_MSGHDR		22
# define STRUCT_RUSAGE		23
# define STRUCT_UTSNAME		24
# define STRUCT_SEMBUF		25
# define STRUCT_MSGID		26
# define STRUCT_LINUX_DIR	27
# define STRUCT_RLIMIT		28
# define STRUCT_SYSINFO		29
# define STRUCT_SIGINFO		30
# define STRUCT_TMS			31
# define PIPE				32
# define SV					33
# define KEY				34
# define MODE				35
# define CLOCK				36
# define PTRACE				37
# define ID_T				38
# define DEV				39
# define TIME				40
# define SIGNAL				41
# define ARGV				42
# define ENVP				43

/* TYPES_END */

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

typedef struct {
    char name[MAX_SYSCALL_NAME];
    int arg_count;
    int arg_types[6]; // Array of 6 argument types, max syscall args is 6
    int return_type;
} SyscallInfo;

typedef enum {
    false = 0,
    true = 1
} bool;

extern SyscallInfo syscalls_64[MAX_SYSCALL_NUMBER];
extern SyscallInfo syscalls_32[MAX_SYSCALL_NUMBER];
extern int env_size;

int trace(int pid, const char *path);

#endif