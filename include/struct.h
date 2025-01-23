#ifndef STRUCT_H
#define STRUCT_H

typedef struct opt {
    bool summary_only;
} t_opt;

typedef struct syscall {
    long id;
    char* name;
    ulong args[6];
    long code;
} t_syscall;

typedef struct t_strace {
    t_opt opt;
    byte code;
    char** target;
    t_syscall syscall;
} t_strace;

#define OPT_SIZE sizeof(t_opt)
#define SYSCALL_SIZE sizeof(t_syscall)
#define STRACE_SIZE sizeof(t_strace)

#endif
