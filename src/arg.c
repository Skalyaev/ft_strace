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

    int x;
    for(x = 1; x < ac; x++) {

        if(av[x][0] != '-') break;

        if(strcmp(av[x], "-c") == 0 || strcmp(av[x], "--summary-only") == 0){

            data.opt.summary_only = YES;
            continue;
        }
        else if(strcmp(av[x], "-h") == 0 || strcmp(av[x], "--help") == 0) {

            printf(usage(), av[0]);
            exit(EXIT_SUCCESS);
        }
        fprintf(stderr, "%s: invalid option -- '%s'\n", av[0], av[x]);
        fprintf(stderr, "try '%s -h' for more information.\n", av[0]);
        exit(EXIT_FAILURE);
    }
    const int size = ac - x;
    if(!size) {

        fprintf(stderr, "%s: must have PROG [ARGS]\n", av[0]);
        fprintf(stderr, "try '%s -h' for more information.\n", av[0]);
        exit(EXIT_FAILURE);
    }
    data.target = malloc(size * PTR_SIZE);
    if(!data.target) {

        perror("malloc");
        exit(EXIT_FAILURE);
    }
    memset(data.target, 0, size * PTR_SIZE);
    for(int y = 0; y < size; y++) data.target[y] = av[x + y];
}
