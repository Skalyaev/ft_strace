#ifndef DEFINE_H
#define DEFINE_H

#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1

#define YES 1
#define NO 0

#define VOID 0
#define ADDR 1
#define STR 2
#define CHAR 3
#define UCHAR 4
#define SHORT 5
#define USHORT 6
#define INT 7
#define UINT 8
#define LONG 9
#define ULONG 10
#define FLOAT 11
#define DOUBLE 12
#define A_ADDR 21
#define A_STR 22
#define A_CHAR 23
#define A_UCHAR 24
#define A_SHORT 25
#define A_USHORT 26
#define A_INT 27
#define A_UINT 28
#define A_LONG 29
#define A_ULONG 30
#define A_FLOAT 31
#define A_DOUBLE 32

typedef char byte;
typedef unsigned char ubyte;
typedef unsigned char bool;
typedef unsigned char uchar;
typedef unsigned short ushort;
typedef unsigned int uint;
typedef unsigned long ulong;

typedef struct option t_option;
typedef struct iovec t_iovec;
typedef struct user_regs_struct t_user_regs;

#define PTR_SIZE sizeof(void*)
#define OPTION_SIZE sizeof(t_option)
#define IOVEC_SIZE sizeof(t_iovec)
#define USER_REGS_SIZE sizeof(t_user_regs)

#endif
