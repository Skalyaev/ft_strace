#include "../include/header.h"

extern t_strace data;

void getargs(const int ac, char** const av) {

    const t_option options[] = {

        {"summary-only", no_argument, 0, 'c'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    const char* const optstring = "ch";

    int idx = 0;
    int opt;
    while((opt = getopt_long(ac, av, optstring, options, &idx)) != -1) {

        switch(opt) {
        case 'c':
            data.opt.summary_only = YES;
            break;
        case 'h':
            printf(USAGE, av[0]);
            exit(EXIT_SUCCESS);
        default:
            fprintf(stderr, "try '%s -h' for more information.\n", av[0]);
            exit(EXIT_FAILURE);
        }
    }
    const int size = ac - optind + 1;
    if(!size - 1) {

        fprintf(stderr, "%s: must have PROG [ARGS]\n", av[0]);
        fprintf(stderr, "try '%s -h' for more information.\n", av[0]);
        exit(EXIT_FAILURE);
    }
    data.target = malloc(PTR_SIZE * size);
    if(!data.target) {

        perror("malloc");
        exit(EXIT_FAILURE);
    }
    memset(data.target, 0, PTR_SIZE * size);
    for(int x = optind; x < ac; x++) data.target[x - optind] = av[x];
}
