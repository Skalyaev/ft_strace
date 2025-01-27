#include "../include/header.h"

t_strace data = {0};

static byte bye() {

    if(data.target) free(data.target);
    if(data.opt.summary_only) print_summary();
    if(data.sigexit) printf("%s\n", strsignal(data.code));
    return data.code;
}

static void sigexit(const int sig) {

    static bool exiting = NO;
    if(exiting) return;
    exiting = YES;

    data.code = sig;
    exit(bye());
}

byte dowait(const pid_t pid, int* const status, const int opts) {

    static sigset_t set = {0};
    if(sigemptyset(&set) == -1) {

        data.code = errno;
        perror("sigemptyset");
        return EXIT_FAILURE;
    }
    if(sigprocmask(SIG_SETMASK, &set, NULL) == -1) {

        data.code = errno;
        perror("sigprocmask");
        return EXIT_FAILURE;
    }
    if(waitpid(pid, status, opts) == -1) {

        data.code = errno;
        perror("waitpid");
        return EXIT_FAILURE;
    }
    static const int toblock[] = {

        SIGHUP, SIGINT, SIGQUIT, SIGPIPE, SIGTERM
    };
    for(ubyte x = 0; x < sizeof(toblock) / INT_SIZE; x++) {

        if(sigaddset(&set, toblock[x]) == 0) continue;

        data.code = errno;
        perror("sigaddset");
        return EXIT_FAILURE;
    }
    if(sigprocmask(SIG_BLOCK, &set, NULL) == -1) {

        data.code = errno;
        perror("sigprocmask");
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

int main(int ac, char** av) {

    setlocale(LC_ALL, "");
    getargs(ac, av);

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
        data.code = errno;

        free(data.target);
        exit(data.code);
    }
    signal(SIGINT, sigexit);
    signal(SIGTERM, sigexit);
    signal(SIGQUIT, sigexit);

    int status;
    if(dowait(pid, &status, WSTOPPED) == EXIT_FAILURE) return bye();

    if(WIFEXITED(status)) return bye();
    if(!WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP) return bye();

    if(ptrace(PTRACE_SEIZE, pid, 0, PTRACE_O_TRACESYSGOOD) == -1) {

        data.code = errno;
        perror("ptrace(SEIZE)");
        return bye();
    }
    trace(pid);
    return bye();
}
