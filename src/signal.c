#include "../include/header.h"

char* si_signo_to_str(const int code) {

    switch(code) {
    case SIGHUP:
        return "SIGHUP";
    case SIGINT:
        return "SIGINT";
    case SIGQUIT:
        return "SIGQUIT";
    case SIGILL:
        return "SIGILL";
    case SIGTRAP:
        return "SIGTRAP";
    case SIGABRT:
        return "SIGABRT";
    case SIGBUS:
        return "SIGBUS";
    case SIGFPE:
        return "SIGFPE";
    case SIGKILL:
        return "SIGKILL";
    case SIGUSR1:
        return "SIGUSR1";
    case SIGSEGV:
        return "SIGSEGV";
    case SIGUSR2:
        return "SIGUSR2";
    case SIGPIPE:
        return "SIGPIPE";
    case SIGALRM:
        return "SIGALRM";
    case SIGTERM:
        return "SIGTERM";
    case SIGSTKFLT:
        return "SIGSTKFLT";
    case SIGCHLD:
        return "SIGCHLD";
    case SIGCONT:
        return "SIGCONT";
    case SIGSTOP:
        return "SIGSTOP";
    case SIGTSTP:
        return "SIGTSTP";
    case SIGTTIN:
        return "SIGTTIN";
    case SIGTTOU:
        return "SIGTTOU";
    case SIGURG:
        return "SIGURG";
    case SIGXCPU:
        return "SIGXCPU";
    case SIGXFSZ:
        return "SIGXFSZ";
    case SIGVTALRM:
        return "SIGVTALRM";
    case SIGPROF:
        return "SIGPROF";
    case SIGWINCH:
        return "SIGWINCH";
    case SIGIO:
        return "SIGIO";
    case SIGPWR:
        return "SIGPWR";
    case SIGSYS:
        return "SIGSYS";
    default:
        break;
    }
    static char unknown[1024] = {0};
    sprintf(unknown, "UNKNOWN_%d", code);
    return unknown;
}

static char* si_code_to_str(const int code) {

    switch(code) {
    case SI_USER:
        return "SI_USER";
    case SI_KERNEL:
        return "SI_KERNEL";
    case SI_QUEUE:
        return "SI_QUEUE";
    case SI_TIMER:
        return "SI_TIMER";
    case SI_MESGQ:
        return "SI_MESGQ";
    case SI_ASYNCIO:
        return "SI_ASYNCIO";
    case SI_SIGIO:
        return "SI_SIGIO";
    case SI_TKILL:
        return "SI_TKILL";
    case SI_DETHREAD:
        return "SI_DETHREAD";
    case SI_ASYNCNL:
        return "SI_ASYNCNL";
    default:
        break;
    }
    static char unknown[1024] = {0};
    sprintf(unknown, "UNKNOWN_%d", code);
    return unknown;
}

static char* sighill_si_code_to_str(const int code) {

    switch(code) {
    case ILL_ILLOPC:
        return "ILL_ILLOPC";
    case ILL_ILLOPN:
        return "ILL_ILLOPN";
    case ILL_ILLADR:
        return "ILL_ILLADR";
    case ILL_ILLTRP:
        return "ILL_ILLTRP";
    case ILL_PRVOPC:
        return "ILL_PRVOPC";
    case ILL_PRVREG:
        return "ILL_PRVREG";
    case ILL_COPROC:
        return "ILL_COPROC";
    case ILL_BADSTK:
        return "ILL_BADSTK";
    case ILL_BADIADDR:
        return "ILL_BADIADDR";
    default:
        break;
    }
    static char unknown[1024] = {0};
    sprintf(unknown, "UNKNOWN_%d", code);
    return unknown;
}

static char* sigfpe_si_code_to_str(const int code) {

    switch(code) {
    case FPE_INTDIV:
        return "FPE_INTDIV";
    case FPE_INTOVF:
        return "FPE_INTOVF";
    case FPE_FLTDIV:
        return "FPE_FLTDIV";
    case FPE_FLTOVF:
        return "FPE_FLTOVF";
    case FPE_FLTUND:
        return "FPE_FLTUND";
    case FPE_FLTRES:
        return "FPE_FLTRES";
    case FPE_FLTINV:
        return "FPE_FLTINV";
    case FPE_FLTSUB:
        return "FPE_FLTSUB";
    case FPE_FLTUNK:
        return "FPE_FLTUNK";
    case FPE_CONDTRAP:
        return "FPE_CONDTRAP";
    default:
        break;
    }
    static char unknown[1024] = {0};
    sprintf(unknown, "UNKNOWN_%d", code);
    return unknown;
}

static char* sigsegv_si_code_to_str(const int code) {

    switch(code) {
    case SEGV_MAPERR:
        return "SEGV_MAPERR";
    case SEGV_ACCERR:
        return "SEGV_ACCERR";
    case SEGV_BNDERR:
        return "SEGV_BNDERR";
#ifdef __ia64__
    case __SEGV_PSTKOVF:
        return "__SEGV_PSTKOVF";
#else
    case SEGV_PKUERR:
        return "SEGV_PKUERR";
#endif
    case SEGV_ACCADI:
        return "SEGV_ACCADI";
    case SEGV_ADIDERR:
        return "SEGV_ADIDERR";
    case SEGV_ADIPERR:
        return "SEGV_ADIPERR";
    case SEGV_MTEAERR:
        return "SEGV_MTEAERR";
    case SEGV_MTESERR:
        return "SEGV_MTESERR";
    default:
        break;
    }
    static char unknown[1024] = {0};
    sprintf(unknown, "UNKNOWN_%d", code);
    return unknown;
}

static char* sigbus_si_code_to_str(const int code) {

    switch(code) {
    case BUS_ADRALN:
        return "BUS_ADRALN";
    case BUS_ADRERR:
        return "BUS_ADRERR";
    case BUS_OBJERR:
        return "BUS_OBJERR";
    case BUS_MCEERR_AR:
        return "BUS_MCEERR_AR";
    case BUS_MCEERR_AO:
        return "BUS_MCEERR_AO";
    default:
        break;
    }
    static char unknown[1024] = {0};
    sprintf(unknown, "UNKNOWN_%d", code);
    return unknown;
}

static char* sigchld_si_code_to_str(const int code) {

    switch(code) {
    case CLD_EXITED:
        return "CLD_EXITED";
    case CLD_KILLED:
        return "CLD_KILLED";
    case CLD_DUMPED:
        return "CLD_DUMPED";
    case CLD_TRAPPED:
        return "CLD_TRAPPED";
    case CLD_STOPPED:
        return "CLD_STOPPED";
    case CLD_CONTINUED:
        return "CLD_CONTINUED";
    default:
        break;
    }
    static char unknown[1024] = {0};
    sprintf(unknown, "UNKNOWN_%d", code);
    return unknown;
}

static char* sigpoll_si_code_to_str(const int code) {

    switch(code) {
    case POLL_IN:
        return "POLL_IN";
    case POLL_OUT:
        return "POLL_OUT";
    case POLL_MSG:
        return "POLL_MSG";
    case POLL_ERR:
        return "POLL_ERR";
    case POLL_PRI:
        return "POLL_PRI";
    case POLL_HUP:
        return "POLL_HUP";
    default:
        break;
    }
    static char unknown[1024] = {0};
    sprintf(unknown, "UNKNOWN_%d", code);
    return unknown;
}

#define _KILL_STRUCT 1
#define _TIMER_STRUCT 2
#define _RT_STRUCT 3
#define _SIGCHLD_STRUCT 4
#define _SIGFAULT_STRUCT 5
#define _SIGPOLL_STRUCT 6
#define _SIGSYS_STRUCT 7

void print_siginfo(const siginfo_t* info) {

    char* si_signo = si_signo_to_str(info->si_signo);
    printf("--- %s {si_signo=%s", si_signo, si_signo);

    char* si_code = NULL;
    ubyte si_field = 0;
    switch(info->si_signo) {

    case SIGILL:
        si_code = sighill_si_code_to_str(info->si_code);
        si_field = _SIGFAULT_STRUCT;
        break;
    case SIGFPE:
        si_code = sigfpe_si_code_to_str(info->si_code);
        si_field = _SIGFAULT_STRUCT;
        break;
    case SIGSEGV:
        si_code = sigsegv_si_code_to_str(info->si_code);
        si_field = _SIGFAULT_STRUCT;
        break;
    case SIGBUS:
        si_code = sigbus_si_code_to_str(info->si_code);
        si_field = _SIGFAULT_STRUCT;
        break;
    case SIGCHLD:
        si_code = sigchld_si_code_to_str(info->si_code);
        si_field = _SIGCHLD_STRUCT;
        break;
    case SIGPOLL:
        si_code = sigpoll_si_code_to_str(info->si_code);
        si_field = _SIGPOLL_STRUCT;
        break;
    default:
        si_code = si_code_to_str(info->si_code);
        switch(info->si_code) {

        case SI_ASYNCNL:
            si_field = _RT_STRUCT;
            break;
        case SI_DETHREAD:
            si_field = _KILL_STRUCT;
            break;
        case SI_TKILL:
            si_field = _KILL_STRUCT;
            break;
        case SI_SIGIO:
            si_field = _SIGPOLL_STRUCT;
            break;
        case SI_ASYNCIO:
            si_field = _SIGPOLL_STRUCT;
            break;
        case SI_MESGQ:
            si_field = _RT_STRUCT;
            break;
        case SI_TIMER:
            si_field = _TIMER_STRUCT;
            break;
        case SI_QUEUE:
            si_field = _RT_STRUCT;
            break;
        case SI_USER:
            si_field = _KILL_STRUCT;
            break;
        case SI_KERNEL:
        default:
            break;
        }
        break;
    }
    printf(", si_code=%s", si_code);
    if(info->si_errno) printf(", si_errno=%d", info->si_errno);
    switch(si_field) {

    case _KILL_STRUCT:
        printf(", si_pid=%d, si_uid=%d", info->si_pid, info->si_uid);
        break;

    case _TIMER_STRUCT:
        printf(", si_tid=%d, si_overrun=%d, si_sigval={sival_int=%d, sival_ptr=%p}",
               info->_sifields._timer.si_tid, info->si_overrun,
               info->si_value.sival_int, info->si_value.sival_ptr);
        break;

    case _RT_STRUCT:
        printf(", si_pid=%d, si_uid=%d, si_sigval={sival_int=%d, sival_ptr=%p}",
               info->si_pid, info->si_uid,
               info->si_value.sival_int, info->si_value.sival_ptr);
        break;

    case _SIGCHLD_STRUCT:
        printf(", si_pid=%d, si_uid=%d, si_status=%d, si_utime=%lu, si_stime=%lu",
               info->si_pid, info->si_uid, info->si_status,
               info->si_utime, info->si_stime);
        break;

    case _SIGFAULT_STRUCT:
        printf(", si_addr=%p", info->si_addr);
        break;

    case _SIGPOLL_STRUCT:
        printf(", si_band=%ld, si_fd=%d", info->si_band, info->si_fd);
        break;

    default:
        break;
    }
    printf("} ---\n");
}
