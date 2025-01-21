#include "../include/header.h"

t_strace data = {0};

static void sigexit(const int sig) {

    static bool exiting = NO;
    if(exiting) return;
    exiting = YES;

    data.code = sig;
    exit(bye());
}

int main(int ac, char** av, char** env) {

    signal(SIGINT, sigexit);
    signal(SIGTERM, sigexit);
    signal(SIGQUIT, sigexit);

    getargs(ac, av);
    if(init() != EXIT_SUCCESS) return bye();

    // WORK IN PROGRESS
    (void)env;
    return bye();
}
