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

const char* sig_name(int sig) {
    switch(sig) {
    case SIGWINCH:
        return "SIGWINCH";
    case SIGINT:
        return "SIGINT";
    case SIGTERM:
        return "SIGTERM";
    // Add other signals as needed
    default:
        return "UNKNOWN";
    }
}

static byte wait_for_syscall(const pid_t pid, const bool ret) {
    int status;
    if(ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1) {
        data.code = errno;
        perror("ptrace(SYSCALL)");
        return EXIT_FAILURE;
    }
    if(waitpid(pid, &status, 0) == -1) {
        data.code = errno;
        perror("waitpid");
        return EXIT_FAILURE;
    }

    // Handle normal exit
    if(WIFEXITED(status)) {
        if(ret) printf(" = ?\n");
        printf("+++ exited with %d +++\n", WEXITSTATUS(status));
        return EXIT_FAILURE;
    }

    // Handle termination by signal
    if(WIFSIGNALED(status)) {
        if(ret) printf(" = ?\n");
        printf("+++ killed by %s +++\n", strsignal(WTERMSIG(status)));
        return EXIT_FAILURE;
    }

    // Handle stopped by signal
    if(WIFSTOPPED(status)) {
        int sig = WSTOPSIG(status);

        // Check if it's a syscall stop
        if(sig == (SIGTRAP | 0x80)) {
            return EXIT_SUCCESS;
        }

        // If it's a real signal, print it in strace format
        if(sig != SIGTRAP) {
            if(ret) printf(" = ? ERESTARTSYS (To be restarted if SA_RESTART is set)\n");
            printf("--- %s {si_signo=%s, si_code=SI_KERNEL} ---\n",
                   strsignal(sig), sig_name(sig));
            return EXIT_SUCCESS;
        }
    }

    return EXIT_SUCCESS;
}

void trace(const pid_t pid) {

    t_syscall syscall;
    int code;
    do {
        if(wait_for_syscall(pid, NO) != EXIT_SUCCESS) break;
        if(syscall_reg(pid) != EXIT_SUCCESS) break;

        syscall = syscall_info();
        printf("%s(", syscall.name);

        for(ubyte x = 0; x < syscall.nargs; x++) {

            if(x > 0) printf(", ");
            print_value(syscall.arg_types[x], data.syscall.args[x]);
        }
        printf(")");
        fflush(stdout);

        if(wait_for_syscall(pid, YES) != EXIT_SUCCESS) break;
        if(syscall_reg(pid) != EXIT_SUCCESS) break;

        printf(" = ");
        if((long)data.syscall.ret < 0) {

            code = -data.syscall.ret;
            printf("-1 %s (%s)", errno_to_str(code), strerror(code));
        } else print_value(syscall.ret_type, data.syscall.ret);

        printf("\n");
    } while(YES);
}
