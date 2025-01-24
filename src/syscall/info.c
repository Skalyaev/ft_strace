#include "../../include/header.h"

t_syscall syscall_info() {

#ifdef __x86_64__
    return syscall64_info();

#elif defined(__i386__)
    return syscall32_info();
#else
#error "Architecture not supported"
#endif
}
