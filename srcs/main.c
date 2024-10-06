#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>

#include "ft_strace.h"

// SyscallInfo syscalls_64[MAX_SYSCALL_NUMBER];
// SyscallInfo syscalls_32[MAX_SYSCALL_NUMBER];
int env_size;

void ignore_signals(pid_t child)
{
    sigset_t set;
    int status;

    /*
        Initialize the signal set.
    */
    sigemptyset(&set);

	sigprocmask(SIG_SETMASK, &set, NULL);

    waitpid(child, &status, 0);

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

bool get_exe_path(const char* exec, char** env, char** buffer)
{
    if (exec == NULL || exec[0] == '\0')
    {
        return false;
    }

    if (strchr(exec, '/'))
    {
        struct stat sb;
        if (stat(exec, &sb) == 0 && sb.st_mode & S_IXUSR)
        {
            *buffer = strdup(exec);
            if (!buffer)
            {
                fprintf(stderr, "ft_strace: Fatal error: failed to allocate.\n");
                abort();
            }
            return true;
        }
        return false;
    }

    char* path_var = NULL;
    for (int i = 0; env[i] != NULL; i++)
    {
        if (strncmp(env[i], "PATH=", 5) == 0)
        {
            path_var = env[i] + 5;  // Skip the 'PATH=' part
            break;
        }
    }

    if (path_var == NULL)
    {
        return false;
    }

    char* path = strdup(path_var);
    if (!path)
    {
        fprintf(stderr, "ft_strace: Fatal error: failed to allocate.\n");
        abort();
    }
    
    char* dir = strtok(path, ":");
    while (dir != NULL)
    {
        size_t len = strlen(dir) + strlen(exec) + 2;
        *buffer = (char*)malloc(len);
        if (!buffer)
        {
            fprintf(stderr, "ft_strace: Fatal error: failed to allocate.\n");
            abort();
        }

        snprintf(*buffer, len, "%s/%s", dir, exec);

        struct stat sb;
        if (stat(*buffer, &sb) == 0 && sb.st_mode & S_IXUSR)
        {
            free(path);
            return true;
        }

        free(*buffer);
        *buffer = NULL;
        dir = strtok(NULL, ":");
    }

    free(path);
    return false;
}


int main(int argc, char *argv[], char* env[])
{
    pid_t child;
    int status;
    char* path;
    bool c_flag = false;


    if (argc > 1 && strcmp(argv[1], "-c") == 0)
    {
        c_flag = true;
        argv++;
        argc--;
    }

    /* No program to trace */
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s <command> [args]\n", argv[0]);
        return 1;
    }

    env_size = 0;
	while (env[env_size])
		env_size++;

    if (!get_exe_path(argv[1], env, &path))
    {
        fprintf(stderr, "ft_strace: Can't stat %s: no such file or directory\n", argv[1]);
        return 1;
    }

    if (c_flag)
    {
        init_syscall_stats();
    }


    /*
        Fork where we will run the program that will be traced.
    */
    child = fork();
    if (child == 0)
    {
        /*
            Stop child until parent process it's attached properly.
        */
        raise(SIGSTOP);

        execve(path, &argv[1], env);
        perror("execvp");
        exit(1);
    }
    else if (child > 0)
    {

        if (ptrace(PTRACE_SEIZE, child, NULL, NULL) < 0)
            fprintf(stderr, "%s: ptrace: %s\n", "ft_strace", strerror(errno));
       
        if (ptrace(PTRACE_INTERRUPT, child, NULL, NULL) < 0)
            fprintf(stderr, "%s: ptrace: %s\n", "ft_strace", strerror(errno));

        ignore_signals(child);
        status = trace(child, path, c_flag);
        free(path);
        return WEXITSTATUS(status);
    }
    else
    {
        fprintf(stderr, "ft_strace: fatal error. fork failed: %s\n", strerror(errno));
        free(path);
        return 1;
    }

    free(path);
    return 0;
}
