#include <ft_strace.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <errno.h>

Syscall syscalls_64[MAX_SYSCALL_NUMBER];
Syscall syscalls_32[MAX_SYSCALL_NUMBER];

int trace(int pid)
{
    int status;
    /* this only works with 64 calls, with 32 calls it's not working.
        use struct i386_user_regs_struct instead of struct user_regs_struct
        for 32 bits. Review how to handle both cases.
    */
    struct user_regs_struct regs;
    int signal = 0;

    while (1)
    {
        printf("Waiting for Usyscall\n");
		if (ptrace(PTRACE_SYSCALL, pid, NULL, signal) < 0)
        {
            perror("ptrace(PTRACE_SYSCALL)");
            break ;
        }
		if (waitpid(pid, &status, 0) < 0)
        {
            printf("waitpid failed\n");
            break ;
        }

        if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1)
        {
            perror("ptrace(PTRACE_GETREGS)");
            return 1;
        }

        int syscall_number = regs.orig_rax;
        if (syscall_number < MAX_SYSCALL_NUMBER)
        {
            printf("Syscall: %s (%d)\n", syscalls_64[syscall_number].name, syscall_number);
        }
        else
        {
            printf("Unknown syscall: %d\n", syscall_number);
        }

        if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1)
        {
            perror("ptrace(PTRACE_SYSCALL)");
            return 1;
        }
    }

    return 0;
}