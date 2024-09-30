#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#define MAX_SYSCALL_NAME    32
#define MAX_SYSCALL_NUMBER  512

#ifdef DEBUG
    void print_syscall_list();
#else
    #define print_syscall_list(x, y) ((void)0)
#endif

typedef struct {
    int number;
    char name[MAX_SYSCALL_NAME];
} Syscall;

typedef enum {
    false = 0,
    true = 1
} bool;

Syscall syscalls_64[MAX_SYSCALL_NUMBER];
Syscall syscalls_32[MAX_SYSCALL_NUMBER];

#ifdef DEBUG
/*
    Print the list of syscalls with their number and name.
    Just for debug purposes.
*/
void print_syscall_list()
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

int main(int argc, char *argv[])
{
    pid_t child;

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

    /* TODO: Remove */
    print_syscall_list(&syscalls_64, &syscalls_32);
    (void)syscalls_64;
    (void)syscalls_32;
    return 0;
    /* TODO: Remove */

    /*
        Fork where we will run the program that will be traced.
    */
    child = fork();
    if (child == 0)
    {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1)
        {
            perror("ptrace(PTRACE_TRACEME)");
            return 1;
        }

        /* TODO: build path */
        execvp(argv[1], &argv[1]);
        perror("execvp");
        exit(1);
    }
    else if (child > 0)
    {
        /* TODO: implement traces*/
    }
    else
    {
        fprintf(stderr, "Fatal error. fork failed: %s\n", strerror(errno));
        return 1;
    }

    return 0;
}
