#include "../../include/header.h"

extern t_strace data;

byte add_to_summary(const long id, const char* const name,
                    const bool failed, const double seconds) {

    t_summary** ptr = &data.summary;
    while(*ptr) {

        if((*ptr)->id == id) {

            (*ptr)->calls++;
            if(failed) (*ptr)->errors++;

            (*ptr)->seconds += seconds;
            (*ptr)->avg = (*ptr)->seconds / (*ptr)->calls;
            return EXIT_SUCCESS;
        }
        ptr = &(*ptr)->next;
    }
    *ptr = malloc(SUMMARY_SIZE);
    if(!*ptr) {

        data.code = errno;
        perror("malloc");
        return EXIT_FAILURE;
    }
    memset(*ptr, 0, SUMMARY_SIZE);

    (*ptr)->id = id;
    (*ptr)->name = strdup(name);
    if(!(*ptr)->name) {

        data.code = errno;
        perror("strdup");

        free(*ptr);
        *ptr = NULL;
        return EXIT_FAILURE;
    }
    (*ptr)->calls = 1;
    if(failed) (*ptr)->errors = 1;

    (*ptr)->seconds = seconds;
    (*ptr)->avg = seconds;
    return EXIT_SUCCESS;
}

void free_summary() {

    t_summary* old = NULL;
    while(data.summary) {

        old = data.summary;
        data.summary = data.summary->next;
        free(old->name);
        free(old);
    }
}

void print_summary() {

    if(!data.summary) return;
    size_t calls = 0;
    size_t errors = 0;
    double seconds = 0;
    size_t avg = 0;

    printf("% time     seconds  usecs/call     calls    errors syscall\n");
    printf("------ ----------- ----------- --------- --------- ----------------\n");
    for(t_summary* ptr = data.summary; ptr; ptr = ptr->next) {

        printf("%.2f %11.6f %11.6f %9lu %9lu %s\n",
               ptr->percent, ptr->seconds, ptr->avg,
               ptr->calls, ptr->errors, ptr->name);

        calls += ptr->calls;
        errors += ptr->errors;
        seconds += ptr->seconds;
        avg += ptr->avg;
    }
    printf("------ ----------- ----------- --------- --------- ----------------\n");
    printf("100.00 %11.6f %11lu %9lu %9lu total\n",
           seconds, avg / calls, calls, errors);

    return free_summary();
}
