#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <linux/elf.h>  // Pour NT_PRSTATUS
#include <asm/unistd.h>

// Structure pour stocker les informations de l'appel système
struct syscall_info {
    long syscall_number;
    unsigned long args[6];
    long return_value;
};

// Fonction pour convertir le numéro d'appel système en nom
const char* syscall_name(long syscall_nr) {
    switch (syscall_nr) {
    case __NR_read:
        return "read";
    case __NR_write:
        return "write";
    case __NR_open:
        return "open";
    case __NR_close:
        return "close";
    case __NR_stat:
        return "stat";
    case __NR_fstat:
        return "fstat";
    case __NR_lstat:
        return "lstat";
    case __NR_poll:
        return "poll";
    case __NR_lseek:
        return "lseek";
    case __NR_mmap:
        return "mmap";
    case __NR_mprotect:
        return "mprotect";
    case __NR_munmap:
        return "munmap";
    case __NR_brk:
        return "brk";
    case __NR_rt_sigaction:
        return "rt_sigaction";
    case __NR_rt_sigprocmask:
        return "rt_sigprocmask";
    case __NR_rt_sigreturn:
        return "rt_sigreturn";
    case __NR_ioctl:
        return "ioctl";
    case __NR_pread64:
        return "pread64";
    case __NR_pwrite64:
        return "pwrite64";
    case __NR_readv:
        return "readv";
    case __NR_writev:
        return "writev";
    case __NR_access:
        return "access";
    case __NR_pipe:
        return "pipe";
    case __NR_select:
        return "select";
    case __NR_sched_yield:
        return "sched_yield";
    case __NR_mremap:
        return "mremap";
    case __NR_msync:
        return "msync";
    case __NR_mincore:
        return "mincore";
    case __NR_madvise:
        return "madvise";
    case __NR_dup:
        return "dup";
    case __NR_dup2:
        return "dup2";
    case __NR_pause:
        return "pause";
    case __NR_nanosleep:
        return "nanosleep";
    case __NR_getitimer:
        return "getitimer";
    case __NR_alarm:
        return "alarm";
    case __NR_setitimer:
        return "setitimer";
    case __NR_getpid:
        return "getpid";
    case __NR_exit:
        return "exit";
    // Ajoutez d'autres appels système selon vos besoins
    default:
        return "unknown";
    }
}

// Fonction pour obtenir les registres
static int get_syscall_info(pid_t pid, struct syscall_info *info) {
    struct iovec iov;
    struct user_regs_struct regs;

    iov.iov_base = &regs;
    iov.iov_len = sizeof(regs);

    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) == -1) {
        perror("ptrace(GETREGSET)");
        return -1;
    }

    // Récupérer les informations des registres selon l'architecture
#ifdef __x86_64__
    info->syscall_number = regs.orig_rax;
    info->args[0] = regs.rdi;
    info->args[1] = regs.rsi;
    info->args[2] = regs.rdx;
    info->args[3] = regs.r10;
    info->args[4] = regs.r8;
    info->args[5] = regs.r9;
    info->return_value = regs.rax;
#else
#error "Architecture non supportée"
#endif

    return 0;
}

// Fonction principale de trace
static void trace_process(pid_t child_pid) {
    int status;
    struct syscall_info info;
    //siginfo_t sig_info;

    // Configurer les options de trace
    if (ptrace(PTRACE_SETOPTIONS, child_pid, 0,
               PTRACE_O_TRACESYSGOOD) == -1) {
        perror("ptrace(SETOPTIONS)");
        return;
    }

    while (1) {
        // Attendre le prochain appel système
        if (ptrace(PTRACE_SYSCALL, child_pid, 0, 0) == -1) {
            perror("ptrace(SYSCALL)");
            break;
        }

        if (waitpid(child_pid, &status, 0) == -1) {
            perror("waitpid");
            break;
        }

        if (WIFEXITED(status)) {
            printf("+++ exited with %d +++\n", WEXITSTATUS(status));
            break;
        }

        // Obtenir les informations de l'appel système
        if (get_syscall_info(child_pid, &info) == 0) {
            // Afficher l'appel système et ses arguments
            const char* name = syscall_name(info.syscall_number);
            printf("%s(", name);
            for (int i = 0; i < 6; i++) {
                if (i > 0) printf(", ");
                printf("0x%lx", info.args[i]);
            }
            printf(")");
            fflush(stdout);
        }

        // Attendre la fin de l'appel système
        if (ptrace(PTRACE_SYSCALL, child_pid, 0, 0) == -1) {
            perror("ptrace(SYSCALL)");
            break;
        }

        if (waitpid(child_pid, &status, 0) == -1) {
            perror("waitpid");
            break;
        }

        // Afficher la valeur de retour
        if (get_syscall_info(child_pid, &info) == 0) {
            printf(" = %ld\n", info.return_value);
        }
    }
}

int main2(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s command [args...]\n", argv[0]);
        exit(1);
    }

    pid_t child_pid = fork();
    if (child_pid == -1) {
        perror("fork");
        exit(1);
    }

    if (child_pid == 0) {
        // Processus fils
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {
            perror("ptrace(TRACEME)");
            exit(1);
        }
        execvp(argv[1], &argv[1]);
        perror("execvp");
        exit(1);
    } else {
        // Processus parent
        trace_process(child_pid);
    }

    return 0;
}
