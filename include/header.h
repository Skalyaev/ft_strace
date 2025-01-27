#ifndef HEADER_H
#define HEADER_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <locale.h>
#include <signal.h>
#include <getopt.h>
#include <time.h>
#include <math.h>
#include <errno.h>

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <linux/elf.h>

#include "define.h"
#include "struct.h"

void getargs(const int ac, char** const av);
void trace(const pid_t pid);
byte dowait(const pid_t pid, int* const status, const int opts);

byte syscall_reg(const pid_t pid);
t_syscall syscall_info();

#ifdef __x86_64__
t_syscall syscall64_info();

#elif defined(__i386__)
t_syscall syscall32_info();

#else
#error "Architecture not supported"
#endif

char* errno_to_str(const int code);
char* si_signo_to_str(const int code);
void print_siginfo(const siginfo_t* info);

byte add_to_summary(const long id, const char* const name,
                    const bool failed, const float seconds);
void free_summary();
void print_summary();

#endif
