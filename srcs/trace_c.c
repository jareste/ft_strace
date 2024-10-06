#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include "ft_strace.h"

typedef struct {
    int count;
    int error_count;
    double total_time;
} SyscallStat;

SyscallStat syscall_stats_64[MAX_SYSCALL_NUMBER];
SyscallStat syscall_stats_32[MAX_SYSCALL_NUMBER];

void init_syscall_stats()
{
    memset(syscall_stats_64, 0, sizeof(syscall_stats_64));
    memset(syscall_stats_32, 0, sizeof(syscall_stats_32));
}

static double get_time_in_microseconds()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)(tv.tv_sec * 1000000 + tv.tv_usec);
}

void count_64bit_syscall(struct user_regs_struct* regs)
{
    static double start_time;
    unsigned long syscall_num = regs->orig_rax;

    if (syscall_num < MAX_SYSCALL_NUMBER)
    {
        SyscallStat *stat = &syscall_stats_64[syscall_num];

        if (start_time == 0)
        {
            start_time = get_time_in_microseconds();
            stat->count++;
        }
        else
        {
            double end_time = get_time_in_microseconds();
            stat->total_time += (end_time - start_time);
            start_time = 0;
            if ((long)regs->rax < 0)
            {
                stat->error_count++;
            }
        }
    }
}

void count_32bit_syscall(struct user_regs_struct32* regs32)
{
    static double start_time;
    unsigned long syscall_num = regs32->orig_eax;

    if (syscall_num < MAX_SYSCALL_NUMBER)
    {
        SyscallStat *stat = &syscall_stats_32[syscall_num];

        if (start_time == 0)
        {
            start_time = get_time_in_microseconds();
            stat->count++;
        }
        else
        {
            double end_time = get_time_in_microseconds();
            stat->total_time += (end_time - start_time);
            start_time = 0;
            if ((long)regs32->eax < 0)
            {
                stat->error_count++;
            }
        }
    }
}

void print_syscall_summary(int is_64bit)
{
    SyscallStat *stats = is_64bit ? syscall_stats_64 : syscall_stats_32;
    double total_time = 0;
    int total_calls = 0;
    int total_errors = 0;

    for (int i = 0; i < MAX_SYSCALL_NUMBER; i++)
    {
        total_time += stats[i].total_time;
        total_calls += stats[i].count;
        total_errors += stats[i].error_count;
    }

    fprintf(stderr, "%6s  %10s  %10s  %10s  %7s  %s\n", "% time", "seconds", "usecs/call", "calls", "errors", "syscall");

    for (int i = 0; i < MAX_SYSCALL_NUMBER; i++)
    {
        if (stats[i].count > 0)
        {
            double time = stats[i].total_time / 1000000.0;
            double percentage = (stats[i].total_time / total_time) * 100;
            double usecs_per_call = stats[i].total_time / stats[i].count;

            fprintf(stderr, "%6.2f  %10.6f  %10.2f  %10d  %7d  %s\n",
                    percentage, time, usecs_per_call, stats[i].count,
                    stats[i].error_count,
                    is_64bit ? syscalls_64[i].name : syscalls_32[i].name);
        }
    }

    fprintf(stderr, "------ ----------- ----------- --------- --------- ----------------\n");
    fprintf(stderr, "100.00    %10.6f             %9d %9d total\n", total_time / 1000000.0, total_calls, total_errors);
}


