#ifndef HEADER_H
#define HEADER_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <locale.h>
#include <signal.h>
#include <getopt.h>
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

byte syscall_reg(const pid_t pid);
t_syscall syscall_info();
const char* errno_to_str(const int code);

#ifdef __x86_64__
t_syscall syscall64_info();
#elif defined(__i386__)
t_syscall syscall32_info();
#else
#error "Architecture not supported"
#endif

#endif
