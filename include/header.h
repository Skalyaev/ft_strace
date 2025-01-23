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
byte syscall_info(const pid_t pid);
char* syscall_to_str(const long id);

#endif
