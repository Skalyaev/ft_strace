#ifndef DEFINE_H
#define DEFINE_H

#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1

#define YES 1
#define NO 0

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
