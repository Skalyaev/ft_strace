#ifndef STRUCT_H
#define STRUCT_H

typedef struct opt {
    bool summary_only;
} t_opt;

typedef struct t_strace {
    t_opt opt;
    byte code;
    char** target;
} t_strace;

#define OPT_SIZE sizeof(t_opt)
#define STRACE_SIZE sizeof(t_strace)

#endif
