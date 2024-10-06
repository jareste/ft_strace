#include "ft_strace.h"

#define BUFFER_SIZE 4096
#define MAX_SIGNAME 32

// SyscallInfo syscalls_64[MAX_SYSCALL_NUMBER];
// SyscallInfo syscalls_32[MAX_SYSCALL_NUMBER];
// int	env_size;

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

char *escape(uint8_t *buffer, size_t size)
{
    size_t dest_len = 0;

    for (size_t i = 0; i < size; i++)
    {
        if (buffer[i] == '\n' || buffer[i] == '\t' || buffer[i] == '\r' ||
            buffer[i] == '\v' || buffer[i] == '\f')
        {
            dest_len += 2;
        }
        else if (buffer[i] < 32 || buffer[i] > 126)
        {
            dest_len += 4;
        }
        else
        {
            dest_len++;
        }
    }

    char *dest = calloc(dest_len + 1, sizeof(char));
    if (!buffer)
    {
        fprintf(stderr, "ft_strace: Fatal error on calloc: %s\n", strerror(errno));
        abort();
    }

    size_t l = 0;
    for (size_t i = 0; i < size; i++)
    {
        if (buffer[i] == '\n')
            l += sprintf(dest + l, "\\n");
        else if (buffer[i] == '\t')
            l += sprintf(dest + l, "\\t");
        else if (buffer[i] == '\r')
            l += sprintf(dest + l, "\\r");
        else if (buffer[i] == '\v')
            l += sprintf(dest + l, "\\v");
        else if (buffer[i] == '\f')
            l += sprintf(dest + l, "\\f");
        else if (buffer[i] < 32 || buffer[i] > 126)
            l += sprintf(dest + l, "\\%03o", buffer[i]);
        else
            dest[l++] = buffer[i];
    }

    return dest;
}


void print_string(pid_t pid, void* str)
{
    struct iovec local[1];
    struct iovec remote[1];
    ssize_t nread;

    char *buffer = calloc(BUFFER_SIZE, sizeof(char));
    if (!buffer)
    {
        fprintf(stderr, "ft_strace: Fatal error on calloc: %s\n", strerror(errno));
        abort();
    }

    local[0].iov_base = buffer;
    local[0].iov_len = BUFFER_SIZE;
    remote[0].iov_base = str;
    remote[0].iov_len = BUFFER_SIZE;

    nread = process_vm_readv(pid, local, 1, remote, 1, 0);
    if (nread < 0)
    {
        fprintf(stderr, "%#lx", (long unsigned int)remote[0].iov_base);
    }
    else
    {
        int len = (char *)memchr(buffer, 0, BUFFER_SIZE) - buffer;
        char *escaped = escape((uint8_t *)buffer, len);
        if (!escaped)
        {
            free(buffer);
            return;
        }

        fprintf(stderr, "\"%.32s\"%s", escaped, len > 48 ? "..." : "");
        free(escaped);
    }
    free(buffer);
}

void print_flag_open(int flags)
{
    bool first = true;
    int flag_list[] = {O_APPEND, O_ASYNC, O_CLOEXEC, O_CREAT, O_DIRECT,
                       O_DIRECTORY, O_DSYNC, O_EXCL, O_LARGEFILE, O_NOATIME, O_NOCTTY, O_NOFOLLOW,
                       O_NONBLOCK, O_PATH, O_SYNC, O_TMPFILE, O_TRUNC};
    const char *str[] = {"O_APPEND", "O_ASYNC", "O_CLOEXEC", "O_CREAT", "O_DIRECT",
                         "O_DIRECTORY", "O_DSYNC", "O_EXCL", "O_LARGEFILE", "O_NOATIME", "O_NOCTTY",
                         "O_NOFOLLOW", "O_NONBLOCK", "O_PATH", "O_SYNC", "O_TMPFILE", "O_TRUNC"};

    for (size_t i = 0; i < sizeof(flag_list) / sizeof(int); i++)
    {
        if (flags & flag_list[i])
        {
            fprintf(stderr, "%s%s", first ? "" : "|", str[i]);
            first = false;
        }
    }

    if (flags & O_WRONLY)
        fprintf(stderr, "%sO_WRONLY", first ? "" : "|");
    else if (flags & O_RDWR)
        fprintf(stderr, "%sO_RDWR", first ? "" : "|");
    else
        fprintf(stderr, "%sO_RDONLY", first ? "" : "|");
}

void print_ptr(void *ptr)
{
	if (!ptr)
		fprintf(stderr, "NULL");
	else
		fprintf(stderr, "%#lx", (long unsigned int)ptr);
}

void print_argv(pid_t pid, char **argv_remote)
{
    int i = 0;
    unsigned long addr;

    fprintf(stderr, "[");

    while (1)
    {
        struct iovec local[1], remote[1];
        local[0].iov_base = &addr;
        local[0].iov_len = sizeof(addr);
        remote[0].iov_base = &argv_remote[i];
        remote[0].iov_len = sizeof(addr);

        if (process_vm_readv(pid, local, 1, remote, 1, 0) < 0 || addr == 0)
        {
            break;
        }

        char buffer[BUFFER_SIZE];
        local[0].iov_base = buffer;
        local[0].iov_len = BUFFER_SIZE;
        remote[0].iov_base = (void *)addr;
        remote[0].iov_len = BUFFER_SIZE;

        if (process_vm_readv(pid, local, 1, remote, 1, 0) < 0)
        {
            perror("process_vm_readv");
            return;
        }

        if (i != 0) fprintf(stderr, ", ");
        fprintf(stderr, "\"%s\"", buffer);
        i++;
    }

    fprintf(stderr, "]");
}

const char *get_signal_name(int signal)
{
    if (signal >= MAX_SIGNAME && signal <= SIGRTMAX)
    {
        static char rt_signal_name[20];
        if (signal == MAX_SIGNAME)
            return "SIGRTMIN";
        else
        {
            sprintf(rt_signal_name, "SIGRT_%d", signal - MAX_SIGNAME);
            return rt_signal_name;
        }
    }

    switch (signal)
    {
        case 1: return "SIGHUP";
        case 2: return "SIGINT";
        case 3: return "SIGQUIT";
        case 4: return "SIGILL";
        case 5: return "SIGTRAP";
        case 6: return "SIGABRT";
        case 7: return "SIGBUS";
        case 8: return "SIGFPE";
        case 9: return "SIGKILL";
        case 10: return "SIGUSR1";
        case 11: return "SIGSEGV";
        case 12: return "SIGUSR2";
        case 13: return "SIGPIPE";
        case 14: return "SIGALRM";
        case 15: return "SIGTERM";
        case 16: return "SIGSTKFLT";
        case 17: return "SIGCHLD";
        case 18: return "SIGCONT";
        case 19: return "SIGSTOP";
        case 20: return "SIGTSTP";
        case 21: return "SIGTTIN";
        case 22: return "SIGTTOU";
        case 23: return "SIGURG";
        case 24: return "SIGXCPU";
        case 25: return "SIGXFSZ";
        case 26: return "SIGVTALRM";
        case 27: return "SIGPROF";
        case 28: return "SIGWINCH";
        case 29: return "SIGIO";
        case 30: return "SIGPWR";
        case 31: return "SIGSYS";
        case 32: return "SIGRTMIN";
        default: return "NULL";
    }
}

static void print_64bit_syscall(pid_t pid, struct user_regs_struct* regs)
{
    static bool entering = true;
    
    unsigned long syscall_num = regs->orig_rax;

    if (syscall_num < MAX_SYSCALL_NUMBER && entering) {
        SyscallInfo syscall = syscalls_64[syscall_num];
        fprintf(stderr, "%s(", syscall.name);

        for (int i = 0; i < syscall.arg_count; i++) {
            unsigned long arg = 0;
            switch (i) {
                case 0: arg = regs->rdi; break;
                case 1: arg = regs->rsi; break;
                case 2: arg = regs->rdx; break;
                case 3: arg = regs->r10; break;
                case 4: arg = regs->r8; break;
                case 5: arg = regs->r9; break;
            }

            switch (syscall.arg_types[i]) {
                case INT:
                    fprintf(stderr, "%d", (int)arg);
                    break;
                case ULONG:
                    fprintf(stderr, "%ld", (unsigned long)arg);
                    break;
                case STR:
                    print_string(pid, (void *)arg);
                    break;
                case PTR:
                    print_ptr((void *)arg);
                    break;
                case FLAG_OPEN:
                    print_flag_open(arg);
                    break;
                case ARGV:
                    print_argv(pid, (char **)arg);
                    break;
                case ENVP:
                    fprintf(stderr, "%p /* %d vars */", (void *)arg, env_size);
                    break;
                case SIGNAL:
                    if ((int)arg <= SIGRTMAX)
                    {
                        fprintf(stderr, "%s", get_signal_name((unsigned int)arg));
                    }
                    else
                        fprintf(stderr, "%d", (int)arg);
                    break;
                default:
                    fprintf(stderr, "0x%lx", arg);
                    break;
            }

            if (i < syscall.arg_count - 1) {
                fprintf(stderr, ", ");
            }

        }
        entering = false;
        fprintf(stderr, ")");
        
    }
    else if (!entering)
    {
        if (syscalls_64[syscall_num].return_type == INT)
            fprintf(stderr, " = %d\n", (int)regs->rax);
        else
            fprintf(stderr, " = 0x%llx\n", regs->rax);
        entering = true;
    }

}

static void print_32bit_syscall(pid_t pid, struct user_regs_struct32* regs32)
{
    static bool entering = true;
    
    unsigned long syscall_num = regs32->orig_eax;

    if (syscall_num < MAX_SYSCALL_NUMBER && entering) {
        SyscallInfo syscall = syscalls_32[syscall_num];
        fprintf(stderr, "%s(", syscall.name);

        for (int i = 0; i < syscall.arg_count; i++) {
            unsigned long arg = 0;
            switch (i) {
                case 0: arg = regs32->ebx; break;
                case 1: arg = regs32->ecx; break;
                case 2: arg = regs32->edx; break;
                case 3: arg = regs32->esi; break;
                case 4: arg = regs32->edi; break;
                case 5: arg = regs32->ebp; break;
            }

            switch (syscall.arg_types[i]) {
                case INT:
                    fprintf(stderr, "%d", (int)arg);
                    break;
                case ULONG:
                    // fprintf(stderr, "SEGV on ULONG\n");
                    fprintf(stderr, "%ld", (unsigned long)arg);
                    break;
                case STR:
                    print_string(pid, (void *)arg);
                    break;
                case PTR:
                    print_ptr((void *)arg);
                    break;
                case FLAG_OPEN:
                    print_flag_open(arg);
                    break;
                case ARGV:
                    print_argv(pid, (char **)arg);
                    break;
                case ENVP:
                    fprintf(stderr, "%p /* %d vars */", (void *)arg, env_size);
                    break;
                case SIGNAL:
                    if ((int)arg <= SIGRTMAX)
                    {
                        fprintf(stderr, "%s", get_signal_name((unsigned int)arg));
                    }
                    else
                        fprintf(stderr, "%d", (int)arg);
                    break;
                default:
                    fprintf(stderr, "0x%lx", arg);
                    break;
            }

            if (i < syscall.arg_count - 1) {
                fprintf(stderr, ", ");
            }

        }
        entering = false;
        fprintf(stderr, ")");
        
    }
    else if (!entering)
    {
        if (syscalls_64[syscall_num].return_type == INT)
            fprintf(stderr, " = %d\n", (int)regs32->eax);
        else
            fprintf(stderr, " = %#x\n", regs32->eax);
        entering = true;
    }

}

int trace(int pid, const char *path, bool count_syscalls)
{
    int status;
    union {
        struct user_regs_struct regs64;
        struct user_regs_struct32 regs32;
    } regs;
    struct iovec iov;
    iov.iov_base = &regs;
    iov.iov_len = sizeof(regs);

	siginfo_t si;
    bool init = false;
    bool is_return = false;
    int i = 0;
    int signal = 0;
    int is_64bit = is_64bit_binary(path);
    
    if (is_64bit == -1)
    {
        fprintf(stderr, "Unable to determine binary architecture.\n");
        return -1;
    }

    while (1)
    {
		if (ptrace(PTRACE_SYSCALL, pid, NULL, signal) < 0)
        {
            break ;
        }
		if (waitpid(pid, &status, 0) < 0)
        {
            break ;
        }

        if (init && !count_syscalls &&\
         !ptrace(PTRACE_GETSIGINFO, pid, NULL, &si) && si.si_signo != SIGTRAP)
        {
            signal = si.si_signo;
            fprintf(stderr, "--- %s {si_signo=%d, si_code=%s, si_pid=%d, si_uid=%d, si_errno=%d} ---\n",\
            get_signal_name(si.si_signo), si.si_signo,\
            get_signal_name(si.si_code), pid, 1000, si.si_errno);
        }
        else
            signal = 0;

        /* this needs a vector such as iovec. */
        if (ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov) == -1)
        {
            break;
        }

        if (is_64bit)
        {
            if (strcmp(syscalls_64[regs.regs64.orig_rax].name, "execve") && !init)
                continue;
            
            init = true;

            if (count_syscalls)
            {
                count_64bit_syscall(&regs.regs64);
            }
            else
            {
                print_64bit_syscall(pid, &regs.regs64);
                if (is_return)
                {
                    is_return = false;
                }
                else
                    is_return = true;
            }
        }
        else
        {
            unsigned long syscall_num = regs.regs32.orig_eax;
            
            /**Validate syscall number to avoid invalid accesses**/
            if (syscall_num >= MAX_SYSCALL_NUMBER)
            {
                continue;
            }

            init = true;

            if (count_syscalls)
            {
                count_32bit_syscall(&regs.regs32);
            }
            else
            {
                print_32bit_syscall(pid, &regs.regs32);
                if (is_return)
                {
                    is_return = false;
                }
                else
                    is_return = true;

                i++;
                /*
                    horrible way to handle it, but it's the best one i thought... sorry.
                */
                if (i == 2)
                    fprintf(stderr, "ft_strace: [ Process PID=%d runs in 32 bit mode. ]\n", pid);
            }
        }
    }

    if (count_syscalls) {
        print_syscall_summary(is_64bit);
    }
    else if (WIFSIGNALED(status))
	{
		fprintf(stderr, "+++ killed by %s +++\n",\
        get_signal_name(WTERMSIG(status)));
		kill(getpid(), WTERMSIG(status));
	}
	else
    {
        if (is_return)
            fprintf(stderr, " = ?\n");
    	fprintf(stderr, "+++ exited with %d +++\n", WEXITSTATUS(status));
    }

    return status;
}
