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
    getargs(ac, av);

    signal(SIGINT, sigexit);
    signal(SIGTERM, sigexit);
    signal(SIGQUIT, sigexit);

    const pid_t pid = fork();
    if(pid == -1) {

        data.code = errno;
        perror("fork");
        return bye();
    }
    if(!pid) {
        raise(SIGSTOP);
        execvp(data.target[0], data.target);
        perror("execvp");
    } else {
        int status;
        if(waitpid(pid, &status, WSTOPPED) == -1) {

            data.code = errno;
            perror("waitpid");
            return bye();
        }
        if(ptrace(PTRACE_SEIZE, pid, 0, PTRACE_O_TRACESYSGOOD) == -1) {

            data.code = errno;
            perror("ptrace(SEIZE)");
            return bye();
        }
        trace(pid);
    }
    return bye();
}
