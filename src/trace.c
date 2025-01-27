#include "../include/header.h"

extern t_strace data;

static void print_value(const ubyte type, const ulong value) {

    switch(type) {
    case ADDR:
    case STR:
    case A_ADDR:
    case A_STR:
    case A_CHAR:
    case A_UCHAR:
    case A_SHORT:
    case A_USHORT:
    case A_INT:
    case A_UINT:
    case A_LONG:
    case A_ULONG:
    case A_FLOAT:
    case A_DOUBLE:
        // As PTRACE_PEEKDATA is not allowed for this project,
        // we only print the address.
        if(!value) printf("NULL");
        else printf("%p", (void*)value);
        break;
    case CHAR:
        printf("'%c'", (char)value);
        break;
    case UCHAR:
        printf("'%c'", (uchar)value);
        break;
    case SHORT:
        printf("%i", (short)value);
        break;
    case USHORT:
        printf("%u", (ushort)value);
        break;
    case INT:
        printf("%i", (int)value);
        break;
    case UINT:
        printf("%u", (uint)value);
        break;
    case LONG:
        printf("%li", (long)value);
        break;
    case ULONG:
        printf("%lu", value);
        break;
    case FLOAT:
        printf("%f", (float)value);
        break;
    case DOUBLE:
        printf("%f", (double)value);
        break;
    default:
        printf("?");
        break;
    }
}

static byte wait_for_syscall(const pid_t pid, t_timespec* const end) {

    if(ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1) {

        data.code = errno;
        perror("ptrace(SYSCALL)");
        return EXIT_FAILURE;
    }
    if(end && data.opt.summary_only
            && clock_gettime(CLOCK_MONOTONIC, end) == -1) {

        data.code = errno;
        perror("clock_gettime");
        return EXIT_FAILURE;
    }
    int status;
    if(dowait(pid, &status, 0) == EXIT_FAILURE)
        return EXIT_FAILURE;

    if(WIFEXITED(status)) {

        status = WEXITSTATUS(status);
        data.code = status;
        if(!data.opt.summary_only) {

            if(end) printf(" = ?\n");
            printf("+++ exited with %d +++\n", status);
        }
        return EXIT_FAILURE;
    }
    if(WIFSIGNALED(status)) {

        status = WTERMSIG(status);
        data.code = status;
        data.sigexit = YES;
        if(!data.opt.summary_only) {

            if(end) printf(" = ?\n");
            printf("+++ killed by %s +++\n", si_signo_to_str(status));
        }
        return EXIT_FAILURE;
    }
    if(!WIFSTOPPED(status)) return EXIT_FAILURE;

    int sig = WSTOPSIG(status);
    if(sig == (SIGTRAP | 0x80)) return EXIT_SUCCESS;

    siginfo_t info;
    if(ptrace(PTRACE_GETSIGINFO, pid, 0, &info) == -1) {

        data.code = errno;
        perror("ptrace(GETSIGINFO)");
        return EXIT_FAILURE;
    }
    if(!data.opt.summary_only) print_siginfo(&info);
    if(ptrace(PTRACE_SYSCALL, pid, 0, sig) == -1) {

        data.code = errno;
        perror("ptrace(SYSCALL)");
        return EXIT_FAILURE;
    }
    if(dowait(pid, &status, 0) == EXIT_FAILURE)
        return EXIT_FAILURE;

    if(WIFEXITED(status)) {

        status = WEXITSTATUS(status);
        data.code = status;

        if(!data.opt.summary_only)
            printf("+++ exited with %d +++\n", status);
        return EXIT_FAILURE;
    }
    if(WIFSIGNALED(status)) {

        status = WTERMSIG(status);
        data.code = status;
        data.sigexit = YES;

        if(!data.opt.summary_only)
            printf("+++ killed by %s +++\n", si_signo_to_str(status));
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

static byte end_timer(const t_syscall* const syscall,
                      const t_timespec* const start,
                      t_timespec* const end,
                      const long code) {

    if(!end->tv_sec && !end->tv_nsec &&
            clock_gettime(CLOCK_MONOTONIC, end) == -1) {

        data.code = errno;
        perror("clock_gettime");
        return EXIT_FAILURE;
    }
    const float seconds = (end->tv_sec - start->tv_sec)
                          + (end->tv_nsec - start->tv_nsec) / 1e9;

    return add_to_summary(data.syscall.id, syscall->name, code < 0, seconds);
}

void trace(const pid_t pid) {

    bool started = NO;
    t_timespec start = {0};
    t_timespec end = {0};

    t_syscall syscall = {0};
    long code = 0;
    do {
        if(wait_for_syscall(pid, NULL) != EXIT_SUCCESS) break;
        if(syscall_reg(pid) != EXIT_SUCCESS) break;

        syscall = syscall_info();
        if(!data.opt.summary_only) {

            printf("%s(", syscall.name);
            for(ubyte x = 0; x < syscall.nargs; x++) {

                if(x > 0) printf(", ");
                print_value(syscall.arg_types[x], data.syscall.args[x]);
            }
            printf(")");
            fflush(stdout);
        }
        else if(!started) {

            memset(&end, 0, TIMESPEC_SIZE);
            if(clock_gettime(CLOCK_MONOTONIC, &start) == -1) {

                data.code = errno;
                perror("clock_gettime");
                break;
            }
            started = YES;
        }
        if(wait_for_syscall(pid, &end) != EXIT_SUCCESS) break;
        if(syscall_reg(pid) != EXIT_SUCCESS) break;

        code = data.syscall.ret;
        if(!data.opt.summary_only) {

            printf(" = ");
            if (code >= -4095 && code <= -1){
                code *= -1;

                if(code == 512 || code == 516)
                    printf("? ERESTARTSYS (To be restarted if SA_RESTART is set)");
                else printf("-1 %s (%s)", errno_to_str(code), strerror(code));

            } else print_value(syscall.ret_type, data.syscall.ret);
            printf("\n");
        }
        else if(started) {

            started = NO;
            if(end_timer(&syscall, &start, &end, code) != EXIT_SUCCESS) break;
        }
    } while(YES);

    if(!strncmp(syscall.name, "exit", 4)) return;
    if(data.opt.summary_only && started) end_timer(&syscall, &start, &end, code);
}
