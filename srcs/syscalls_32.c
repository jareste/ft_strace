#include "ft_strace.h"


SyscallInfo syscalls_32[MAX_SYSCALL_NUMBER] = {
[  0] = {"restart_syscall", 0, {0, 0, 0, 0, 0, 0}, LONG},
[  1] = {"exit", 1, {INT, 0, 0, 0, 0, 0}, 0},
[  2] = {"fork", 0, {0, 0, 0, 0, 0, 0}, INT},
[  3] = {"read", 3, {INT, PTR, INT, 0, 0, 0}, INT},
[  4] = {"write", 3, {INT, STR, INT, 0, 0, 0}, INT},
[  5] = {"open", 3, {STR, FLAG_OPEN, MODE, 0, 0, 0}, INT},
[  6] = {"close", 1, {INT, 0, 0, 0, 0, 0}, INT},
[  7] = {"waitpid", 3, {INT, PTR, INT, 0, 0, 0}, INT},
[  8] = {"creat", 2, {STR, MODE, 0, 0, 0, 0}, INT},
[  9] = {"link", 2, {STR, STR, 0, 0, 0, 0}, INT},
[ 10] = {"unlink", 1, {STR, 0, 0, 0, 0, 0}, INT},
[ 11] = {"execve", 3, {STR, ARGV, ENVP, 0, 0, 0}, INT},
[ 12] = {"chdir", 1, {STR, 0, 0, 0, 0, 0}, INT},
[ 13] = {"time", 1, {PTR, 0, 0, 0, 0, 0}, ULONG},
[ 14] = {"mknod", 3, {STR, MODE, DEV, 0, 0, 0}, INT},
[ 15] = {"chmod", 2, {STR, MODE, 0, 0, 0, 0}, INT},
[ 16] = {"lchown", 3, {STR, INT, INT, 0, 0, 0}, INT},
[ 17] = {"break", 0, {0, 0, 0, 0, 0, 0}, INT},
[ 18] = {"oldstat", 2, {STR, STRUCT_STAT, 0, 0, 0, 0}, INT},
[ 19] = {"lseek", 3, {INT, PTR, INT, 0, 0, 0}, PTR},
[ 20] = {"getpid", 0, {0, 0, 0, 0, 0, 0}, INT},
[ 21] = {"mount", 5, {STR, STR, STR, ULONG, PTR, 0}, INT},
[ 22] = {"umount", 1, {STR, 0, 0, 0, 0, 0}, INT},
[ 23] = {"setuid", 1, {INT, 0, 0, 0, 0, 0}, INT},
[ 24] = {"getuid", 0, {0, 0, 0, 0, 0, 0}, INT},
[ 25] = {"stime", 1, {TIME, 0, 0, 0, 0, 0}, INT},
[ 26] = {"ptrace", 4, {PTRACE, INT, PTR, PTR, 0, 0}, LONG},
[ 27] = {"alarm", 1, {ULONG, 0, 0, 0, 0, 0}, ULONG},
[ 28] = {"oldfstat", 2, {INT, STRUCT_STAT, 0, 0, 0, 0}, INT},
[ 29] = {"pause", 0, {0, 0, 0, 0, 0, 0}, INT},
[ 30] = {"utime", 2, {STR, PTR, 0, 0, 0, 0}, INT},
[ 31] = {"stty", 2, {0, 0, 0, 0, 0, 0}, 0},
[ 32] = {"gtty", 2, {0, 0, 0, 0, 0, 0}, 0},
[ 33] = {"access", 2, {0, 0, 0, 0, 0, 0}, 0},
[ 34] = {"nice", 1, {0, 0, 0, 0, 0, 0}, 0},
[ 35] = {"ftime", 0, {0, 0, 0, 0, 0, 0}, 0},
[ 36] = {"sync", 0, {0, 0, 0, 0, 0, 0}, 0},
[ 37] = {"kill", 2, {0, 0, 0, 0, 0, 0}, 0},
[ 38] = {"rename", 2, {0, 0, 0, 0, 0, 0}, 0},
[ 39] = {"mkdir", 2, {0, 0, 0, 0, 0, 0}, 0},
[ 40] = {"rmdir", 1, {0, 0, 0, 0, 0, 0}, 0},
[ 41] = {"dup", 1, {0, 0, 0, 0, 0, 0}, 0},
[ 42] = {"pipe", 1, {0, 0, 0, 0, 0, 0}, 0},
[ 43] = {"times", 1, {0, 0, 0, 0, 0, 0}, 0},
[ 44] = {"prof", 0, {0, 0, 0, 0, 0, 0}, 0},
[ 45] = {"brk", 1, {PTR, 0, 0, 0, 0, 0}, 0},
[ 46] = {"setgid", 1, {0, 0, 0, 0, 0, 0}, 0},
[ 47] = {"getgid", 0, {0, 0, 0, 0, 0, 0}, 0},
[ 48] = {"signal", 2, {0, 0, 0, 0, 0, 0}, 0},
[ 49] = {"geteuid", 0, {0, 0, 0, 0, 0, 0}, 0},
[ 50] = {"getegid", 0, {0, 0, 0, 0, 0, 0}, 0},
[ 51] = {"acct", 1, {0, 0, 0, 0, 0, 0}, 0},
[ 52] = {"umount", 2, {0, 0, 0, 0, 0, 0}, 0},
[ 53] = {"lock", 0, {0, 0, 0, 0, 0, 0}, 0},
[ 54] = {"ioctl", 3, {0, 0, 0, 0, 0, 0}, 0},
[ 55] = {"fcntl", 3, {0, 0, 0, 0, 0, 0}, 0},
[ 56] = {"mpx", 0, {0, 0, 0, 0, 0, 0}, 0},
[ 57] = {"setpgid", 2, {0, 0, 0, 0, 0, 0}, 0},
[ 58] = {"ulimit", 2, {0, 0, 0, 0, 0, 0}, 0},
[ 59] = {"oldolduname", 1, {0, 0, 0, 0, 0, 0}, 0},
[ 60] = {"umask", 1, {0, 0, 0, 0, 0, 0}, 0},
[ 61] = {"chroot", 1, {0, 0, 0, 0, 0, 0}, 0},
[ 62] = {"ustat", 2, {0, 0, 0, 0, 0, 0}, 0},
[ 63] = {"dup2", 2, {0, 0, 0, 0, 0, 0}, 0},
[ 64] = {"getppid", 0, {0, 0, 0, 0, 0, 0}, 0},
[ 65] = {"getpgrp", 0, {0, 0, 0, 0, 0, 0}, 0},
[ 66] = {"setsid", 0, {0, 0, 0, 0, 0, 0}, 0},
[ 67] = {"sigaction", 3, {SIGNAL, STRUCT_SIGACT, STRUCT_SIGACT, 0, 0, 0}, INT},
[ 68] = {"sgetmask", 0, {0, 0, 0, 0, 0, 0}, 0},
[ 69] = {"ssetmask", 1, {0, 0, 0, 0, 0, 0}, 0},
[ 70] = {"setreuid", 2, {0, 0, 0, 0, 0, 0}, 0},
[ 71] = {"setregid", 2, {0, 0, 0, 0, 0, 0}, 0},
[ 72] = {"sigsuspend", 3, {0, 0, 0, 0, 0, 0}, 0},
[ 73] = {"sigpending", 1, {0, 0, 0, 0, 0, 0}, 0},
[ 74] = {"sethostname", 2, {0, 0, 0, 0, 0, 0}, 0},
[ 75] = {"setrlimit", 2, {0, 0, 0, 0, 0, 0}, 0},
[ 76] = {"getrlimit", 2, {0, 0, 0, 0, 0, 0}, 0},
[ 77] = {"getrusage", 2, {0, 0, 0, 0, 0, 0}, 0},
[ 78] = {"gettimeofday", 2, {0, 0, 0, 0, 0, 0}, 0},
[ 79] = {"settimeofday", 2, {0, 0, 0, 0, 0, 0}, 0},
[ 80] = {"getgroups", 2, {0, 0, 0, 0, 0, 0}, 0},
[ 81] = {"setgroups", 2, {0, 0, 0, 0, 0, 0}, 0},
[ 82] = {"select", 1, {0, 0, 0, 0, 0, 0}, 0},
[ 83] = {"symlink", 2, {0, 0, 0, 0, 0, 0}, 0},
[ 84] = {"oldlstat",2, {0, 0, 0, 0, 0, 0}, 0},
[ 85] = {"readlink", 3, {0, 0, 0, 0, 0, 0}, 0},
[ 86] = {"uselib", 1, {0, 0, 0, 0, 0, 0}, 0},
[ 87] = {"swapon", 2, {0, 0, 0, 0, 0, 0}, 0},
[ 88] = {"reboot", 4, {0, 0, 0, 0, 0, 0}, 0},
[ 89] = {"readdir", 3, {0, 0, 0, 0, 0, 0}, 0},
[ 90] = {"mmap", 1, {0, 0, 0, 0, 0, 0}, 0},
[ 91] = {"munmap", 2, {0, 0, 0, 0, 0, 0}, 0},
[ 92] = {"truncate", 2, {0, 0, 0, 0, 0, 0}, 0},
[ 93] = {"ftruncate", 2, {0, 0, 0, 0, 0, 0}, 0},
[ 94] = {"fchmod", 2, {0, 0, 0, 0, 0, 0}, 0},
[ 95] = {"fchown", 3, {0, 0, 0, 0, 0, 0}, 0},
[ 96] = {"getpriority", 2, {0, 0, 0, 0, 0, 0}, 0},
[ 97] = {"setpriority", 3, {0, 0, 0, 0, 0, 0}, 0},
[ 98] = {"profil", 4, {0, 0, 0, 0, 0, 0}, 0},
[ 99] = {"statfs", 2, {0, 0, 0, 0, 0, 0}, 0},
[100] = {"fstatfs", 2, {0, 0, 0, 0, 0, 0}, 0},
[101] = {"ioperm", 3, {0, 0, 0, 0, 0, 0}, 0},
[102] = {"socketcall", 2, {0, 0, 0, 0, 0, 0}, 0},
[103] = {"syslog", 3, {0, 0, 0, 0, 0, 0}, 0},
[104] = {"setitimer", 3, {0, 0, 0, 0, 0, 0}, 0},
[105] = {"getitimer", 2, {0, 0, 0, 0, 0, 0}, 0},
[106] = {"stat", 2, {0, 0, 0, 0, 0, 0}, 0},
[107] = {"lstat", 2, {0, 0, 0, 0, 0, 0}, 0},
[108] = {"fstat", 2, {0, 0, 0, 0, 0, 0}, 0},
[109] = {"olduname", 1, {0, 0, 0, 0, 0, 0}, 0},
[110] = {"iopl", 1, {0, 0, 0, 0, 0, 0}, 0},
[111] = {"vhangup", 0, {0, 0, 0, 0, 0, 0}, 0},
[112] = {"idle", 0, {0, 0, 0, 0, 0, 0}, 0},
[113] = {"vm86old", 1, {0, 0, 0, 0, 0, 0}, 0},
[114] = {"wait4", 4, {INT, PTR, INT, 0, 0, 0}, 0},
[115] = {"swapoff", 1, {0, 0, 0, 0, 0, 0}, 0},
[116] = {"sysinfo", 1, {0, 0, 0, 0, 0, 0}, 0},
[117] = {"ipc", 6, {0, 0, 0, 0, 0, 0}, 0},
[118] = {"fsync", 1, {0, 0, 0, 0, 0, 0}, 0},
[119] = {"sigreturn", 0, {0, 0, 0, 0, 0, 0}, 0},
[120] = {"clone", 5, {0, 0, 0, 0, 0, 0}, 0},
[121] = {"setdomainname", 2, {0, 0, 0, 0, 0, 0}, 0},
[122] = {"uname", 1, {0, 0, 0, 0, 0, 0}, 0},
[123] = {"modify_ldt", 3, {0, 0, 0, 0, 0, 0}, 0},
[124] = {"adjtimex", 1, {0, 0, 0, 0, 0, 0}, 0},
[125] = {"mprotect", 3, {0, 0, 0, 0, 0, 0}, 0},
[126] = {"sigprocmask", 3, {0, 0, 0, 0, 0, 0}, 0},
[127] = {"create_module", 2, {0, 0, 0, 0, 0, 0}, 0},
[128] = {"init_module", 3, {0, 0, 0, 0, 0, 0}, 0},
[129] = {"delete_module", 2, {0, 0, 0, 0, 0, 0}, 0},
[130] = {"get_kernel_syms", 1, {0, 0, 0, 0, 0, 0}, 0},
[131] = {"quotactl", 4, {0, 0, 0, 0, 0, 0}, 0},
[132] = {"getpgid", 1, {0, 0, 0, 0, 0, 0}, 0},
[133] = {"fchdir", 1, {0, 0, 0, 0, 0, 0}, 0},
[134] = {"bdflush", 2, {0, 0, 0, 0, 0, 0}, 0},
[135] = {"sysfs", 3, {0, 0, 0, 0, 0, 0}, 0},
[136] = {"personality", 1, {0, 0, 0, 0, 0, 0}, 0},
[137] = {"afs_syscall", 5, {0, 0, 0, 0, 0, 0}, 0},
[138] = {"setfsuid", 1, {0, 0, 0, 0, 0, 0}, 0},
[139] = {"setfsgid", 1, {0, 0, 0, 0, 0, 0}, 0},
[140] = {"_llseek", 5, {0, 0, 0, 0, 0, 0}, 0},
[141] = {"getdents", 3, {0, 0, 0, 0, 0, 0}, 0},
[142] = {"_newselect", 5, {0, 0, 0, 0, 0, 0}, 0},
[143] = {"flock", 2, {0, 0, 0, 0, 0, 0}, 0},
[144] = {"msync", 3, {0, 0, 0, 0, 0, 0}, 0},
[145] = {"readv", 3, {0, 0, 0, 0, 0, 0}, 0},
[146] = {"writev", 3, {0, 0, 0, 0, 0, 0}, 0},
[147] = {"getsid", 1, {0, 0, 0, 0, 0, 0}, 0},
[148] = {"fdatasync", 1, {0, 0, 0, 0, 0, 0}, 0},
[149] = {"_sysctl", 1, {0, 0, 0, 0, 0, 0}, 0},
[150] = {"mlock", 2, {0, 0, 0, 0, 0, 0}, 0},
[151] = {"munlock", 2, {0, 0, 0, 0, 0, 0}, 0},
[152] = {"mlockall", 1, {0, 0, 0, 0, 0, 0}, 0},
[153] = {"munlockall", 0, {0, 0, 0, 0, 0, 0}, 0},
[154] = {"sched_setparam", 2, {0, 0, 0, 0, 0, 0}, 0},
[155] = {"sched_getparam", 2, {0, 0, 0, 0, 0, 0}, 0},
[156] = {"sched_setscheduler", 3, {0, 0, 0, 0, 0, 0}, 0},
[157] = {"sched_getscheduler", 1, {0, 0, 0, 0, 0, 0}, 0},
[158] = {"sched_yield", 0, {0, 0, 0, 0, 0, 0}, 0},
[159] = {"sched_get_priority_max", 1, {0, 0, 0, 0, 0, 0}, 0},
[160] = {"sched_get_priority_min", 1, {0, 0, 0, 0, 0, 0}, 0},
[161] = {"sched_rr_get_interval", 2, {0, 0, 0, 0, 0, 0}, 0},
[162] = {"nanosleep", 2, {0, 0, 0, 0, 0, 0}, 0},
[163] = {"mremap", 5, {0, 0, 0, 0, 0, 0}, 0},
[164] = {"setresuid", 3, {0, 0, 0, 0, 0, 0}, 0},
[165] = {"getresuid", 3, {0, 0, 0, 0, 0, 0}, 0},
[166] = {"vm86", 5, {0, 0, 0, 0, 0, 0}, 0},
[167] = {"query_module", 5, {0, 0, 0, 0, 0, 0}, 0},
[168] = {"poll", 3, {0, 0, 0, 0, 0, 0}, 0},
[169] = {"nfsservctl", 3, {0, 0, 0, 0, 0, 0}, 0},
[170] = {"setresgid", 3, {0, 0, 0, 0, 0, 0}, 0},
[171] = {"getresgid", 3, {0, 0, 0, 0, 0, 0}, 0},
[172] = {"prctl", 5, {0, 0, 0, 0, 0, 0}, 0},
[173] = {"rt_sigreturn", 0, {0, 0, 0, 0, 0, 0}, 0},
[174] = {"rt_sigaction", 4, {0, 0, 0, 0, 0, 0}, 0},
[175] = {"rt_sigprocmask", 4, {0, 0, 0, 0, 0, 0}, 0},
[176] = {"rt_sigpending", 2, {0, 0, 0, 0, 0, 0}, 0},
[177] = {"rt_sigtimedwait", 4, {0, 0, 0, 0, 0, 0}, 0},
[178] = {"rt_sigqueueinfo", 3, {0, 0, 0, 0, 0, 0}, 0},
[179] = {"rt_sigsuspend", 2, {0, 0, 0, 0, 0, 0}, 0},
[180] = {"pread64", 5, {INT, 0, 0, 0, 0, 0}, 0},
[181] = {"pwrite64", 5, {0, 0, 0, 0, 0, 0}, 0},
[182] = {"chown", 3, {0, 0, 0, 0, 0, 0}, 0},
[183] = {"getcwd", 2, {0, 0, 0, 0, 0, 0}, 0},
[184] = {"capget", 2, {0, 0, 0, 0, 0, 0}, 0},
[185] = {"capset", 2, {0, 0, 0, 0, 0, 0}, 0},
[186] = {"sigaltstack", 2, {0, 0, 0, 0, 0, 0}, 0},
[187] = {"sendfile", 4, {0, 0, 0, 0, 0, 0}, 0},
[188] = {"getpmsg", 5, {0, 0, 0, 0, 0, 0}, 0},
[189] = {"putpmsg", 5, {0, 0, 0, 0, 0, 0}, 0},
[190] = {"vfork", 0, {0, 0, 0, 0, 0, 0}, 0},
[191] = {"ugetrlimit", 2, {0, 0, 0, 0, 0, 0}, 0},
[192] = {"mmap2", 6, {0, 0, 0, 0, 0, 0}, 0},
[193] = {"truncate64", 3, {0, 0, 0, 0, 0, 0}, 0},
[194] = {"ftruncate64", 3, {0, 0, 0, 0, 0, 0}, 0},
[195] = {"stat64", 2, {0, 0, 0, 0, 0, 0}, 0},
[196] = {"lstat64", 2, {0, 0, 0, 0, 0, 0}, 0},
[197] = {"fstat64", 2, {INT, 0, 0, 0, 0, 0}, 0},
[198] = {"lchown32", 3, {0, 0, 0, 0, 0, 0}, 0},
[199] = {"getuid32", 0, {0, 0, 0, 0, 0, 0}, 0},
[200] = {"getgid32", 0, {0, 0, 0, 0, 0, 0}, 0},
[201] = {"geteuid32", 0, {0, 0, 0, 0, 0, 0}, 0},
[202] = {"getegid32", 0, {0, 0, 0, 0, 0, 0}, 0},
[203] = {"setreuid32", 2, {0, 0, 0, 0, 0, 0}, 0},
[204] = {"setregid32", 2, {0, 0, 0, 0, 0, 0}, 0},
[205] = {"getgroups32", 2, {0, 0, 0, 0, 0, 0}, 0},
[206] = {"setgroups32", 2, {0, 0, 0, 0, 0, 0}, 0},
[207] = {"fchown32", 3, {0, 0, 0, 0, 0, 0}, 0},
[208] = {"setresuid32", 3, {0, 0, 0, 0, 0, 0}, 0},
[209] = {"getresuid32", 3, {0, 0, 0, 0, 0, 0}, 0},
[210] = {"setresgid32", 3, {0, 0, 0, 0, 0, 0}, 0},
[211] = {"getresgid32", 3, {0, 0, 0, 0, 0, 0}, 0},
[212] = {"chown32", 3, {0, 0, 0, 0, 0, 0}, 0},
[213] = {"setuid32", 1, {0, 0, 0, 0, 0, 0}, 0},
[214] = {"setgid32", 1, {0, 0, 0, 0, 0, 0}, 0},
[215] = {"setfsuid32", 1, {0, 0, 0, 0, 0, 0}, 0},
[216] = {"setfsgid32", 1, {0, 0, 0, 0, 0, 0}, 0},
[217] = {"pivot_root", 2, {0, 0, 0, 0, 0, 0}, 0},
[218] = {"mincore", 3, {0, 0, 0, 0, 0, 0}, 0},
[219] = {"madvise", 3, {0, 0, 0, 0, 0, 0}, 0},
[220] = {"getdents64", 3, {0, 0, 0, 0, 0, 0}, 0},
[221] = {"fcntl64", 3, {0, 0, 0, 0, 0, 0}, 0},
[224] = {"gettid", 0, {0, 0, 0, 0, 0, 0}, 0},
[225] = {"readahead", 4, {0, 0, 0, 0, 0, 0}, 0},
[226] = {"setxattr", 5, {0, 0, 0, 0, 0, 0}, 0},
[227] = {"lsetxattr", 5, {0, 0, 0, 0, 0, 0}, 0},
[228] = {"fsetxattr", 5, {0, 0, 0, 0, 0, 0}, 0},
[229] = {"getxattr", 4, {0, 0, 0, 0, 0, 0}, 0},
[230] = {"lgetxattr", 4, {0, 0, 0, 0, 0, 0}, 0},
[231] = {"fgetxattr", 4, {0, 0, 0, 0, 0, 0}, 0},
[232] = {"listxattr", 3, {0, 0, 0, 0, 0, 0}, 0},
[233] = {"llistxattr", 3, {0, 0, 0, 0, 0, 0}, 0},
[234] = {"flistxattr", 3, {0, 0, 0, 0, 0, 0}, 0},
[235] = {"removexattr", 2, {0, 0, 0, 0, 0, 0}, 0},
[236] = {"lremovexattr", 2, {0, 0, 0, 0, 0, 0}, 0},
[237] = {"fremovexattr", 2, {0, 0, 0, 0, 0, 0}, 0},
[238] = {"tkill", 2, {0, 0, 0, 0, 0, 0}, 0},
[239] = {"sendfile64", 4, {0, 0, 0, 0, 0, 0}, 0},
[240] = {"futex", 6, {0, 0, 0, 0, 0, 0}, 0},
[241] = {"sched_setaffinity", 3, {0, 0, 0, 0, 0, 0}, 0},
[242] = {"sched_getaffinity", 3, {0, 0, 0, 0, 0, 0}, 0},
[243] = {"set_thread_area", 1, {0, 0, 0, 0, 0, 0}, 0},
[244] = {"get_thread_area", 1, {0, 0, 0, 0, 0, 0}, 0},
[245] = {"io_setup", 2, {0, 0, 0, 0, 0, 0}, 0},
[246] = {"io_destroy", 1, {0, 0, 0, 0, 0, 0}, 0},
[247] = {"io_getevents", 5, {0, 0, 0, 0, 0, 0}, 0},
[248] = {"io_submit", 3, {0, 0, 0, 0, 0, 0}, 0},
[249] = {"io_cancel", 3, {0, 0, 0, 0, 0, 0}, 0},
[250] = {"fadvise64", 5, {0, 0, 0, 0, 0, 0}, 0},
[252] = {"exit_group", 1, {INT, 0, 0, 0, 0, 0}, INT},
[253] = {"lookup_dcookie", 4, {0, 0, 0, 0, 0, 0}, 0},
[254] = {"epoll_create", 1, {0, 0, 0, 0, 0, 0}, 0},
[255] = {"epoll_ctl", 4, {0, 0, 0, 0, 0, 0}, 0},
[256] = {"epoll_wait", 4, {0, 0, 0, 0, 0, 0}, 0},
[257] = {"remap_file_pages", 5, {0, 0, 0, 0, 0, 0}, 0},
[258] = {"set_tid_address", 1, {0, 0, 0, 0, 0, 0}, 0},
[259] = {"timer_create", 3, {0, 0, 0, 0, 0, 0}, 0},
[260] = {"timer_settime", 4, {0, 0, 0, 0, 0, 0}, 0},
[261] = {"timer_gettime", 2, {0, 0, 0, 0, 0, 0}, 0},
[262] = {"timer_getoverrun", 1, {0, 0, 0, 0, 0, 0}, 0},
[263] = {"timer_delete", 1, {0, 0, 0, 0, 0, 0}, 0},
[264] = {"clock_settime", 2, {0, 0, 0, 0, 0, 0}, 0},
[265] = {"clock_gettime", 2, {0, 0, 0, 0, 0, 0}, 0},
[266] = {"clock_getres", 2, {0, 0, 0, 0, 0, 0}, 0},
[267] = {"clock_nanosleep", 4, {0, 0, 0, 0, 0, 0}, 0},
[268] = {"statfs64", 3, {0, 0, 0, 0, 0, 0}, 0},
[269] = {"fstatfs64", 3, {0, 0, 0, 0, 0, 0}, 0},
[270] = {"tgkill", 3, {0, 0, 0, 0, 0, 0}, 0},
[271] = {"utimes", 2, {0, 0, 0, 0, 0, 0}, 0},
[272] = {"fadvise64_64", 6, {0, 0, 0, 0, 0, 0}, 0},
[273] = {"vserver", 5, {0, 0, 0, 0, 0, 0}, 0},
[274] = {"mbind", 6, {0, 0, 0, 0, 0, 0}, 0},
[275] = {"get_mempolicy", 5, {0, 0, 0, 0, 0, 0}, 0},
[276] = {"set_mempolicy", 3, {0, 0, 0, 0, 0, 0}, 0},
[277] = {"mq_open", 4, {0, 0, 0, 0, 0, 0}, 0},
[278] = {"mq_unlink", 1, {0, 0, 0, 0, 0, 0}, 0},
[279] = {"mq_timedsend", 5, {0, 0, 0, 0, 0, 0}, 0},
[280] = {"mq_timedreceive", 5, {0, 0, 0, 0, 0, 0}, 0},
[281] = {"mq_notify", 2, {0, 0, 0, 0, 0, 0}, 0},
[282] = {"mq_getsetattr", 3, {0, 0, 0, 0, 0, 0}, 0},
[283] = {"kexec_load", 4, {0, 0, 0, 0, 0, 0}, 0},
[284] = {"waitid", 5, {0, 0, 0, 0, 0, 0}, 0},
[286] = {"add_key", 5, {0, 0, 0, 0, 0, 0}, 0},
[287] = {"request_key", 4, {0, 0, 0, 0, 0, 0}, 0},
[288] = {"keyctl", 5, {0, 0, 0, 0, 0, 0}, 0},
[289] = {"ioprio_set", 3, {0, 0, 0, 0, 0, 0}, 0},
[290] = {"ioprio_get", 2, {0, 0, 0, 0, 0, 0}, 0},
[291] = {"inotify_init", 0, {0, 0, 0, 0, 0, 0}, 0},
[292] = {"inotify_add_watch", 3, {0, 0, 0, 0, 0, 0}, 0},
[293] = {"inotify_rm_watch", 2, {0, 0, 0, 0, 0, 0}, 0},
[294] = {"migrate_pages", 4, {0, 0, 0, 0, 0, 0}, 0},
[295] = {"openat", 4, {INT, STR, FLAG_OPEN, MODE, 0, 0}, INT},
[296] = {"mkdirat", 3, {0, 0, 0, 0, 0, 0}, 0},
[297] = {"mknodat", 4, {0, 0, 0, 0, 0, 0}, 0},
[298] = {"fchownat", 5, {0, 0, 0, 0, 0, 0}, 0},
[299] = {"futimesat", 3, {0, 0, 0, 0, 0, 0}, 0},
[300] = {"fstatat64", 4, {0, 0, 0, 0, 0, 0}, 0},
[301] = {"unlinkat", 3, {0, 0, 0, 0, 0, 0}, 0},
[302] = {"renameat", 4, {0, 0, 0, 0, 0, 0}, 0},
[303] = {"linkat", 5, {0, 0, 0, 0, 0, 0}, 0},
[304] = {"symlinkat", 3, {0, 0, 0, 0, 0, 0}, 0},
[305] = {"readlinkat", 4, {0, 0, 0, 0, 0, 0}, 0},
[306] = {"fchmodat", 3, {0, 0, 0, 0, 0, 0}, 0},
[307] = {"faccessat", 3, {0, 0, 0, 0, 0, 0}, 0},
[308] = {"pselect", 6, {0, 0, 0, 0, 0, 0}, 0},
[309] = {"ppoll", 5, {0, 0, 0, 0, 0, 0}, 0},
[310] = {"unshare", 1, {0, 0, 0, 0, 0, 0}, 0},
[311] = {"set_robust_list", 2, {0, 0, 0, 0, 0, 0}, 0},
[312] = {"get_robust_list", 3, {0, 0, 0, 0, 0, 0}, 0},
[313] = {"splice", 6, {0, 0, 0, 0, 0, 0}, 0},
[314] = {"sync_file_range", 6, {0, 0, 0, 0, 0, 0}, 0},
[315] = {"tee", 4, {0, 0, 0, 0, 0, 0}, 0},
[316] = {"vmsplice", 4, {0, 0, 0, 0, 0, 0}, 0},
[317] = {"move_pages", 6, {0, 0, 0, 0, 0, 0}, 0},
[318] = {"getcpu", 3, {0, 0, 0, 0, 0, 0}, 0},
[319] = {"epoll_pwait", 6, {0, 0, 0, 0, 0, 0}, 0},
[320] = {"utimensat", 4, {0, 0, 0, 0, 0, 0}, 0},
[321] = {"signalfd", 3, {0, 0, 0, 0, 0, 0}, 0},
[322] = {"timerfd_create", 2, {0, 0, 0, 0, 0, 0}, 0},
[323] = {"eventfd", 1, {0, 0, 0, 0, 0, 0}, 0},
[324] = {"fallocate", 6, {0, 0, 0, 0, 0, 0}, 0},
[325] = {"timerfd_settime", 4, {0, 0, 0, 0, 0, 0}, 0},
[326] = {"timerfd_gettime", 2, {0, 0, 0, 0, 0, 0}, 0},
[327] = {"signalfd", 4, {0, 0, 0, 0, 0, 0}, 0},
[328] = {"eventfd", 2, {0, 0, 0, 0, 0, 0}, 0},
[329] = {"epoll_create", 1, {0, 0, 0, 0, 0, 0}, 0},
[330] = {"dup3", 3, {0, 0, 0, 0, 0, 0}, 0},
[331] = {"pipe2", 2, {0, 0, 0, 0, 0, 0}, 0},
[332] = {"inotify_init", 1, {0, 0, 0, 0, 0, 0}, 0},
[333] = {"preadv", 5, {0, 0, 0, 0, 0, 0}, 0},
[334] = {"pwritev", 5, {0, 0, 0, 0, 0, 0}, 0},
[335] = {"rt_tgsigqueueinfo", 4, {0, 0, 0, 0, 0, 0}, 0},
[336] = {"perf_event_open", 5, {0, 0, 0, 0, 0, 0}, 0},
[337] = {"recvmmsg", 5, {0, 0, 0, 0, 0, 0}, 0},
[338] = {"fanotify_init", 2, {0, 0, 0, 0, 0, 0}, 0},
[339] = {"fanotify_mark", 6, {0, 0, 0, 0, 0, 0}, 0},
[340] = {"prlimit64", 4, {0, 0, 0, 0, 0, 0}, 0},
[341] = {"name_to_handle_at", 5, {0, 0, 0, 0, 0, 0}, 0},
[342] = {"open_by_handle_at", 3, {0, 0, 0, 0, 0, 0}, 0},
[343] = {"clock_adjtime", 2, {0, 0, 0, 0, 0, 0}, 0},
[344] = {"syncfs", 1, {0, 0, 0, 0, 0, 0}, 0},
[345] = {"sendmmsg", 4, {0, 0, 0, 0, 0, 0}, 0},
[346] = {"setns", 2, {0, 0, 0, 0, 0, 0}, 0},
[347] = {"process_vm_readv", 6, {0, 0, 0, 0, 0, 0}, 0},
[348] = {"process_vm_writev", 6, {0, 0, 0, 0, 0, 0}, 0},
[349] = {"kcmp", 5, {0, 0, 0, 0, 0, 0}, 0},
[350] = {"finit_module", 3, {0, 0, 0, 0, 0, 0}, 0},
[351] = {"sched_setattr", 3, {0, 0, 0, 0, 0, 0}, 0},
[352] = {"sched_getattr", 4, {0, 0, 0, 0, 0, 0}, 0},
[353] = {"renameat2", 5, {0, 0, 0, 0, 0, 0}, 0},
[354] = {"seccomp", 3, {0, 0, 0, 0, 0, 0}, 0},
[355] = {"getrandom", 3, {0, 0, 0, 0, 0, 0}, 0},
[356] = {"memfd_create", 2, {0, 0, 0, 0, 0, 0}, 0},
[357] = {"bpf", 3, {0, 0, 0, 0, 0, 0}, 0},
[358] = {"execveat", 5, {0, 0, 0, 0, 0, 0}, 0},
[359] = {"socket", 3, {0, 0, 0, 0, 0, 0}, 0},
[360] = {"socketpair", 4, {0, 0, 0, 0, 0, 0}, 0},
[361] = {"bind", 3, {0, 0, 0, 0, 0, 0}, 0},
[362] = {"connect", 3, {0, 0, 0, 0, 0, 0}, 0},
[363] = {"listen", 2, {0, 0, 0, 0, 0, 0}, 0},
[364] = {"accept4", 4, {0, 0, 0, 0, 0, 0}, 0},
[365] = {"getsockopt", 5, {0, 0, 0, 0, 0, 0}, 0},
[366] = {"setsockopt", 5, {0, 0, 0, 0, 0, 0}, 0},
[367] = {"getsockname", 3, {0, 0, 0, 0, 0, 0}, 0},
[368] = {"getpeername", 3, {0, 0, 0, 0, 0, 0}, 0},
[369] = {"sendto", 6, {0, 0, 0, 0, 0, 0}, 0},
[370] = {"sendmsg", 3, {0, 0, 0, 0, 0, 0}, 0},
[371] = {"recvfrom", 6, {0, 0, 0, 0, 0, 0}, 0},
[372] = {"recvmsg", 3, {0, 0, 0, 0, 0, 0}, 0},
[373] = {"shutdown", 2, {0, 0, 0, 0, 0, 0}, 0},
[374] = {"userfaultfd", 1, {0, 0, 0, 0, 0, 0}, 0},
[375] = {"membarrier", 3, {0, 0, 0, 0, 0, 0}, 0},
[376] = {"mlock2", 3, {0, 0, 0, 0, 0, 0}, 0},
[377] = {"copy_file_range", 6, {0, 0, 0, 0, 0, 0}, 0},
[378] = {"preadv2", 6, {0, 0, 0, 0, 0, 0}, 0},
[379] = {"pwritev2", 6, {0, 0, 0, 0, 0, 0}, 0},
[380] = {"pkey_mprotect", 4, {0, 0, 0, 0, 0, 0}, 0},
[381] = {"pkey_alloc", 2, {0, 0, 0, 0, 0, 0}, 0},
[382] = {"pkey_free", 1, {0, 0, 0, 0, 0, 0}, 0},
[383] = {"statx", 5, {0, 0, 0, 0, 0, 0}, 0},
[384] = {"arch_prctl", 2, {0, 0, 0, 0, 0, 0}, 0},
[385] = {"io_pgetevents", 6, {0, 0, 0, 0, 0, 0}, 0},
[386] = {"rseq", 4, {0, 0, 0, 0, 0, 0}, 0},
[393] = {"semget", 3, {0, 0, 0, 0, 0, 0}, 0},
[394] = {"semctl", 4, {0, 0, 0, 0, 0, 0}, 0},
[395] = {"shmget", 3, {0, 0, 0, 0, 0, 0}, 0},
[396] = {"shmctl", 3, {0, 0, 0, 0, 0, 0}, 0},
[397] = {"shmat", 3, {0, 0, 0, 0, 0, 0}, 0},
[398] = {"shmdt", 1, {0, 0, 0, 0, 0, 0}, 0},
[399] = {"msgget", 2, {0, 0, 0, 0, 0, 0}, 0},
[400] = {"msgsnd", 4, {0, 0, 0, 0, 0, 0}, 0},
[401] = {"msgrcv", 5, {0, 0, 0, 0, 0, 0}, 0},
[402] = {"msgctl", 3, {0, 0, 0, 0, 0, 0}, 0}
};
