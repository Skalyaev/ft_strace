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
#include <asm/unistd.h>

// Structure pour stocker les informations de l'appel système
struct syscall_info {
    long syscall_number;
    unsigned long args[6];
    long return_value;
};

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
    siginfo_t sig_info;

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
            printf("%s(", syscall_name(info.syscall_number));
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

int main(int argc, char *argv[]) {
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
