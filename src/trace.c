#include "../include/header.h"

extern t_strace data;

void trace(const pid_t pid) {

    int status;
    do {
        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1) {

            data.code = errno;
            perror("ptrace(SYSCALL)");
            break;
        }
        if (waitpid(pid, &status, 0) == -1) {

            data.code = errno;
            perror("waitpid");
            break;
        }
        if (WIFEXITED(status)) {

            printf("+++ exited with %d +++\n", WEXITSTATUS(status));
            break;
        }
        if (WIFSIGNALED(status)) {

            printf("+++ killed by %s +++\n", strsignal(WTERMSIG(status)));
            break;
        }
        if (!WIFSTOPPED(status) || (WSTOPSIG(status) & 0x80) != 0x80) continue;

        if (syscall_info(pid) == EXIT_SUCCESS) {

            data.syscall.name = syscall_to_str(data.syscall.id);
            printf("%s(", data.syscall.name);

            for (ubyte x = 0; x < 6; x++) {

                if (x > 0) printf(", ");
                if (data.syscall.args[x] == 0) printf("NULL");
                else printf("0x%lx", data.syscall.args[x]);
            }
            printf(")");
            fflush(stdout);
        } else break;

        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1) {

            data.code = errno;
            perror("ptrace(SYSCALL)");
            break;
        }
        if (waitpid(pid, &status, 0) == -1) {

            data.code = errno;
            perror("waitpid");
            break;
        }
        if (syscall_info(pid) == EXIT_SUCCESS) {

            if (data.syscall.code < 0) {

                printf(" = -1 errno = %ld (%s)\n",
                       -data.syscall.code,
                       strerror(-data.syscall.code));
            } else {
                printf(" = %ld\n", data.syscall.code);
            }
        } else break;
    } while(YES);
}
