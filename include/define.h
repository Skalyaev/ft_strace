#ifndef DEFINE_H
#define DEFINE_H

#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1

#define USAGE "\nUsage: %s [-ch] PROG [ARGS]\n"\
"\n"\
"Statistics:\n"\
"  -c, --summary-only\n"\
"                 count time, calls, and errors for each syscall\n"\
"                 and report summary\n"\
"\n"\
"Miscellaneous:\n"\
"  -h, --help     print help message\n"\
"\n"

#define YES 1
#define NO 0

typedef char byte;
typedef unsigned char ubyte;
typedef unsigned char bool;
typedef unsigned short ushort;
typedef unsigned int uint;

typedef struct option t_option;

#define PTR_SIZE sizeof(void*)

#endif
