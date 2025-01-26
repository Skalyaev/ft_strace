#include "../include/header.h"

extern t_strace data;

byte add_to_summary(const long id, const char* const name,
                    const bool failed, const float seconds) {

    t_summary** ptr = &data.summary;
    while(*ptr) {

        if((*ptr)->id == id) {

            (*ptr)->calls++;
            if(failed) (*ptr)->errors++;

            (*ptr)->seconds += seconds;
            (*ptr)->avg = (*ptr)->seconds * 1e6 / (*ptr)->calls;
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
    (*ptr)->avg = seconds * 1e6;
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

static void fill_percent() {

    float total = 0;
    for(t_summary* ptr = data.summary; ptr; ptr = ptr->next)
        total += ptr->seconds;

    for(t_summary* ptr = data.summary; ptr; ptr = ptr->next)
        ptr->percent = (ptr->seconds / total) * 100;
}
static void order_summary() {

    t_summary* x = data.summary;
    t_summary* y = NULL;

    t_summary* max = NULL;
    t_summary swap = {0};
    while(x) {

        max = x;
        for(y = x->next; y; y = y->next)
            if(y->seconds > max->seconds) max = y;

        if(x != max) {

            swap = *x;
            *x = *max;
            *max = swap;

            max->next = x->next;
            max->prev = x->prev;

            x->next = swap.next;
            x->prev = swap.prev;
        }
        x = x->next;
    }
}
void print_summary() {

    if(!data.summary) return;
    fill_percent();
    order_summary();

    size_t calls = 0;
    size_t errors = 0;
    float seconds = 0;
    size_t avg = 0;
    size_t count = 0;

    printf("%% time     seconds  usecs/call     calls    errors syscall\n");
    printf("------ ----------- ----------- --------- --------- ----------------\n");
    for(t_summary* ptr = data.summary; ptr; ptr = ptr->next) {

        printf("%6.2f", ptr->percent);
        printf(" %11.6f", ptr->seconds);
        printf(" %11lu", ptr->avg);
        printf(" %9lu", ptr->calls);

        if(ptr->errors) printf(" %9lu", ptr->errors);
        else printf("          ");
        printf(" %s\n", ptr->name);

        calls += ptr->calls;
        errors += ptr->errors;
        seconds += ptr->seconds;
        avg += ptr->avg;
        count++;
    }
    printf("------ ----------- ----------- --------- --------- ----------------\n");
    printf("100,00 %11.6f %11lu %9lu %9lu total\n",
           seconds, avg / count, calls, errors);

    return free_summary();
}
