#include "../include/header.h"

t_strace data = {0};

static byte bye() {

    if(data.target) free(data.target);
    return data.code;
}

static void sigexit(const int sig) {

    static bool exiting = NO;
    if(exiting) return;
    exiting = YES;

    data.code = sig;
    exit(bye());
}

int main(int ac, char** av) {

    setlocale(LC_ALL, "");
    signal(SIGINT, sigexit);
    signal(SIGTERM, sigexit);
    signal(SIGQUIT, sigexit);

    getargs(ac, av);
    if(init() != EXIT_SUCCESS) return bye();

    const pid_t pid = fork();
    if(pid == -1) {

        data.code = errno;
        perror("fork");
        return bye();
    }
    if(!pid) {
        if(ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {

            data.code = errno;
            perror("ptrace(TRACEME)");
            return bye();
        }
        execvp(data.target[0], data.target);
        perror("execve");
    } else {
        int status;
        waitpid(pid, &status, 0);

        if (ptrace(PTRACE_SETOPTIONS, pid, 0,
                   PTRACE_O_TRACESYSGOOD) == -1) {

            data.code = errno;
            perror("ptrace(SETOPTIONS)");
            return bye();
        }
        trace(pid);
    }
    return bye();
}
