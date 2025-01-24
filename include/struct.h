#ifndef STRUCT_H
#define STRUCT_H

typedef struct opt {
    bool summary_only;
} t_opt;

typedef struct syscall {
    long id;
    char* name;
    ubyte nargs;
    ubyte arg_types[6];
    ubyte ret_type;
    ulong args[6];
    ulong ret;
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

#define SYSCALL_INFO(name, nargs, ret_type, ...) \
    (t_syscall){0, name, nargs, {__VA_ARGS__}, ret_type, {0}, 0}

#endif
