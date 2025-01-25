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

static char* resolve(char* const target, const char* const self) {

    if(target[0] == '/') return target;

    char* const path = getenv("PATH");
    if(!path) {

        data.code = ENOENT;
        fprintf(stderr, "%s: Can't stat '%s': %s\n", self, target, strerror(data.code));
        exit(bye());
    }
    char* const paths = strdup(path);
    if(!paths) {

        data.code = errno;
        perror("strdup");
        exit(bye());
    }
    char* ptr = NULL;
    char* token = strtok_r(paths, ":", &ptr);
    while(token) {

        char* const fullpath = malloc(strlen(token) + strlen(target) + 2);
        if(!fullpath) {

            data.code = errno;
            perror("malloc");
            free(paths);
            exit(bye());
        }
        sprintf(fullpath, "%s/%s", token, target);
        if(access(fullpath, X_OK) == 0) {

            free(paths);
            return fullpath;
        }
        free(fullpath);
        token = strtok_r(NULL, ":", &ptr);
    }
    free(paths);
    data.code = ENOENT;
    fprintf(stderr, "%s: Can't stat '%s': %s\n", self, target, strerror(data.code));
    exit(bye());
}

int main(int ac, char** av, char** env) {

    setlocale(LC_ALL, "");
    getargs(ac, av);

    const pid_t pid = fork();
    if(pid == -1) {

        data.code = errno;
        perror("fork");
        return bye();
    }
    if(!pid) {
        data.target[0] = resolve(data.target[0], av[0]);
        raise(SIGSTOP);

        // We do not use execvp() because a bonus point
        // for this project is to manage PATH ourselves.
        execve(data.target[0], data.target, env);
        perror("execve");
        data.code = errno;

        free(data.target[0]);
        free(data.target);
        exit(data.code);
    }
    signal(SIGINT, sigexit);
    signal(SIGTERM, sigexit);
    signal(SIGQUIT, sigexit);

    int status;
    if(waitpid(pid, &status, WSTOPPED) == -1) {

        data.code = errno;
        perror("waitpid");
        return bye();
    }
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
