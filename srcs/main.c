#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include <ft_strace.h>

#ifdef DEBUG
    static void print_syscall_list();
#else
    #define print_syscall_list(x, y) ((void)0)
#endif

Syscall syscalls_64[MAX_SYSCALL_NUMBER];
Syscall syscalls_32[MAX_SYSCALL_NUMBER];

#ifdef DEBUG
/*
    Print the list of syscalls with their number and name.
    Just for debug purposes.
*/
static void print_syscall_list()
{
    int i;
    bool first = true;

    printf("Syscalls 64 bits\n");
    for (i = 0; i < MAX_SYSCALL_NUMBER; i++)
    {
        if (syscalls_64[i].number == 0 && !first)
            break;

        first = false;

        printf("%d: %s\n", syscalls_64[i].number, syscalls_64[i].name);
    }

    first = true;
    printf("Syscalls 32 bits\n");
    for (i = 0; i < MAX_SYSCALL_NUMBER; i++)
    {
        if (syscalls_32[i].number == 0 && !first)
            break;

        first = false;
        printf("%d: %s\n", syscalls_32[i].number, syscalls_32[i].name);
    }
}
#endif

/*
    As ptrace just informs a number, we need the relation between the number and the name of the syscall.
    This function reads the unistd_64.h and unistd_32.h files to get the syscall number and name.
*/
void init_syscall_list()
{
    FILE *fp = fopen("/usr/include/x86_64-linux-gnu/asm/unistd_64.h", "r");
    char line[256];
    char syscall_name[MAX_SYSCALL_NAME];
    int syscall_number;
    int syscall_count = 0;

    if (fp)
    {
        while (fgets(line, sizeof(line), fp))
        {
            if (strncmp(line, "#define __NR_", 13) == 0)
            {
                sscanf(line, "#define __NR_%31s %d", syscall_name, &syscall_number);

                if (syscall_number < MAX_SYSCALL_NUMBER)
                {
                    syscalls_64[syscall_count].number = syscall_number;
                    strncpy(syscalls_64[syscall_count].name, syscall_name, MAX_SYSCALL_NAME);
                    // printf("%d: %s\n", syscalls_64[syscall_count].number, syscalls_64[syscall_count].name);
                    syscall_count++;
                }
            }
        }

        fclose(fp);
    }

    syscall_count = 0;
    fp = fopen("/usr/include/x86_64-linux-gnu/asm/unistd_32.h", "r");
    if (fp)
    {
        while (fgets(line, sizeof(line), fp))
        {
            if (strncmp(line, "#define __NR_", 13) == 0)
            {
                sscanf(line, "#define __NR_%31s %d", syscall_name, &syscall_number);

                if (syscall_number < MAX_SYSCALL_NUMBER)
                {
                    syscalls_32[syscall_count].number = syscall_number;
                    strncpy(syscalls_32[syscall_count].name, syscall_name, MAX_SYSCALL_NAME);
                    syscall_count++;
                }
            }
        }

        fclose(fp);
    }
}

void ignore_signals()
{
    sigset_t set;

    /*
        Initialize the signal set.
    */
    sigemptyset(&set);

	sigprocmask(SIG_SETMASK, &set, NULL);
    /*
        Add the signals to be ignored.
    */
    sigaddset(&set, SIGHUP);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGQUIT);
    sigaddset(&set, SIGPIPE);
    sigaddset(&set, SIGTERM);

    /*
        Add the signals to the mask.
    */
    sigprocmask(SIG_BLOCK, &set, NULL);
}

int main(int argc, char *argv[], char* env[])
{
    pid_t child;
    int status;

    /* No program to trace */
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s <command> [args]\n", argv[0]);
        return 1;
    }

    /*
        Init both structures with list of syscalls to be used later.
    */
    init_syscall_list(&syscalls_64, &syscalls_32);

    /* DEBUG */
    print_syscall_list(&syscalls_64, &syscalls_32);

    /*
        Fork where we will run the program that will be traced.
    */
    child = fork();
    if (child == 0)
    {
        // if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1)
        // {
        //     perror("ptrace(PTRACE_TRACEME)");
        //     return 1;
        // }
        /*
            Stop child until parent process it's attached properly.
        */
        raise(SIGSTOP);

        /* TODO: build path */
        execve(argv[1], &argv[1], env);
        perror("execvp");
        exit(1);
    }
    else if (child > 0)
    {

        if (ptrace(PTRACE_SEIZE, child, NULL, NULL) < 0)
            fprintf(stderr, "%s: ptrace: %s\n", "ft_strace", strerror(errno));
       
        if (ptrace(PTRACE_INTERRUPT, child, NULL, NULL) < 0)
            fprintf(stderr, "%s: ptrace: %s\n", "ft_strace", strerror(errno));

        waitpid(child, &status, 0);
        ignore_signals();
        trace(child, argv[1]);
        /* TODO: implement traces*/
        // TODO: return with proper status
        return WEXITSTATUS(status);
    }
    else
    {
        fprintf(stderr, "Fatal error. fork failed: %s\n", strerror(errno));
        return 1;
    }

    return 0;
}
