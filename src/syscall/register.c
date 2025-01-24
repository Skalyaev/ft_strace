#include "../../include/header.h"

extern t_strace data;

byte syscall_reg(const pid_t pid) {

    t_user_regs regs;
    t_iovec iov;

    iov.iov_base = &regs;
    iov.iov_len = USER_REGS_SIZE;

    if(ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) == -1) {

        data.code = errno;
        perror("ptrace(GETREGSET)");
        return EXIT_FAILURE;
    }
#ifdef __x86_64__
    data.syscall.id = regs.orig_rax;
    data.syscall.args[0] = regs.rdi;
    data.syscall.args[1] = regs.rsi;
    data.syscall.args[2] = regs.rdx;
    data.syscall.args[3] = regs.r10;
    data.syscall.args[4] = regs.r8;
    data.syscall.args[5] = regs.r9;
    data.syscall.ret = regs.rax;

#elif defined(__i386__)
    data.syscall.id = regs.orig_eax;
    data.syscall.args[0] = regs.ebx;
    data.syscall.args[1] = regs.ecx;
    data.syscall.args[2] = regs.edx;
    data.syscall.args[3] = regs.esi;
    data.syscall.args[4] = regs.edi;
    data.syscall.args[5] = regs.ebp;
    data.syscall.ret = regs.eax;
#else
#error "Architecture not supported"
#endif
    return EXIT_SUCCESS;
}
