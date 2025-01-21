#include "../include/header.h"

extern t_strace data;

static const char* usage() {

    return "\nUsage: %s [-ch] PROG [ARGS]\n"\
           "\n"\
           "Statistics:\n"\
           "  -c, --summary-only\n"\
           "                 count time, calls, and errors for each syscall\n"\
           "                 and report summary\n"\
           "\n"\
           "Miscellaneous:\n"\
           "  -h, --help     print help message\n\n";
}

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
            printf(usage(), av[0]);
            exit(EXIT_SUCCESS);
        default:
            fprintf(stderr, "try '%s -h' for more information.\n", av[0]);
            exit(EXIT_FAILURE);
        }
    }
    int size = ac - optind;
    if(!size) {

        fprintf(stderr, "%s: must have PROG [ARGS]\n", av[0]);
        fprintf(stderr, "try '%s -h' for more information.\n", av[0]);
        exit(EXIT_FAILURE);
    }
    size = (size + 1) * PTR_SIZE;

    data.target = malloc(size);
    if(!data.target) {

        perror("malloc");
        exit(EXIT_FAILURE);
    }
    memset(data.target, 0, size);
    for(int x = optind; x < ac; x++) data.target[x - optind] = av[x];
}
