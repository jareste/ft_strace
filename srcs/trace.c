#include <ft_strace.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <errno.h>
#include <stdio.h>
#include <elf.h>
#include <fcntl.h>
#include <unistd.h>

Syscall syscalls_64[MAX_SYSCALL_NUMBER];
Syscall syscalls_32[MAX_SYSCALL_NUMBER];


/* could work??? */
int is_64bit_binary(const char *path)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0)
    {
        perror("open");
        return -1;
    }

    unsigned char e_ident[EI_NIDENT];
    if (read(fd, e_ident, EI_NIDENT) != EI_NIDENT)
    {
        perror("read");
        close(fd);
        return -1;
    }
    close(fd);

    switch (e_ident[EI_CLASS])
    {
        case ELFCLASS32:
            return 0;
        case ELFCLASS64:
            return 1;
        default:
            return -1;
    }
}


int trace(int pid, const char *path)
{
    int status;
    /* this only works with 64 calls, with 32 calls it's not working.
        use struct i386_user_regs_struct instead of struct user_regs_struct
        for 32 bits. Review how to handle both cases.
    */
    // union {
        struct user_regs_struct regs;
    //     struct user_regs_struct32 regs32;
    // } regs;

    int signal = 0;
    /* for the moment i'll only handle 64bits ones, if it's not 64 i'll care later. */
    int is_64bit = is_64bit_binary(path);
    
    if (is_64bit == -1 || is_64bit == 0)
    {
        fprintf(stderr, "Unable to determine binary architecture.\n");
        return -1;
    }

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