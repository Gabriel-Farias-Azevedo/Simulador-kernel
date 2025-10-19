#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <time.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>

#define NUM_PROCS 5
#define MAX_PC 20
#define TIMESLICE_SEC 1
#define IC_PERIOD_US 500000  // 500 ms
#define _GNU_SOURCE

// Estados dos processos
typedef enum {READY, RUNNING, BLOCKED, FINISHED} State;

// Estrutura do processo de aplicação
typedef struct {
    pid_t pid;
    int pc;
    State state;
    int waitingDevice; // 0 = nenhum, 1 = D1, 2 = D2
    char waitingOp;    // 'R', 'W', 'X' se estiver bloqueado por syscall
    int D1_access;
    int D2_access;
} Process;

// Estrutura de mensagem de syscall
typedef struct {
    pid_t pid;
    int device;
    char op;
} SyscallMsg;

Process processes[NUM_PROCS];

int proc_index_by_pid(pid_t pid) {
    for (int i = 0; i < NUM_PROCS; i++) {
        if (processes[i].pid == pid) {
            return i;
        }
    }
    return -1;
}

// Filas para D1 e D2
int queue_D1[NUM_PROCS];
int qd1_head = 0;
int qd1_tail = 0;
int qd1_len = 0;

int queue_D2[NUM_PROCS];
int qd2_head = 0;
int qd2_tail = 0;
int qd2_len = 0;

// Inserção nas filas de bloqueio
void enqueue_D1(int idx) {
    if (qd1_len < NUM_PROCS) {
        queue_D1[qd1_tail] = idx;
        qd1_tail = (qd1_tail + 1) % NUM_PROCS;
        qd1_len++;
    }
}

void enqueue_D2(int idx) {
    if (qd2_len < NUM_PROCS) {
        queue_D2[qd2_tail] = idx;
        qd2_tail = (qd2_tail + 1) % NUM_PROCS;
        qd2_len++;
    }
}

// Remoção das filas de bloqueio
int dequeue_D1() {
    if (qd1_len == 0) {
        return -1;
    }
    int v = queue_D1[qd1_head];
    qd1_head = (qd1_head + 1) % NUM_PROCS;
    qd1_len--;
    return v;
}

int dequeue_D2() {
    if (qd2_len == 0) {
        return -1;
    }
    int v = queue_D2[qd2_head];
    qd2_head = (qd2_head + 1) % NUM_PROCS;
    qd2_len--;
    return v;
}

int pipefd[2];

// Flags de controle de sinais
volatile sig_atomic_t flag_irq0 = 0;
volatile sig_atomic_t flag_irq1 = 0;
volatile sig_atomic_t flag_irq2 = 0;
volatile sig_atomic_t flag_syscall = 0;
volatile sig_atomic_t flag_sigint = 0;
volatile sig_atomic_t flag_child_exit = 0;

// Índice do processo em execução
int current_running = -1;

// Escrita segura em tratadores de sinal
void safe_printf(const char *s) {
    write(STDOUT_FILENO, s, strlen(s));
}

// Tratadores de sinais
void handler_irq0(int signo) { flag_irq0 = 1; }
void handler_irq1(int signo) { flag_irq1 = 1; }
void handler_irq2(int signo) { flag_irq2 = 1; }
void handler_sigchld(int signo) { flag_child_exit = 1; }
void handler_sigint(int signo) { flag_sigint = 1; }
void handler_syscall(int signo) { flag_syscall = 1; }

// Criação dos 5 processos de aplicação
void spawn_app_processes() {
    for (int i = 0; i < NUM_PROCS; i++) {
        pid_t pid = fork();

        if (pid < 0) {
            perror("Erro ao criar processo de aplicação");
            exit(1);
        } 
        
        else if (pid == 0) {
            close(pipefd[0]); 
            srand(time(NULL) ^ (getpid() << 8));
            int pc = 0;

            while (pc < MAX_PC) {
                sleep(1);
                int d = rand() % 100 + 1;

                if (d <= 15) { 
                    int device = (d % 2) ? 1 : 2;
                    char op;
                    int mod3 = d % 3;

                    if (mod3 == 1) op = 'R';
                    else if (mod3 == 2) op = 'W';
                    else op = 'X';

                    char buf[128];
                    int n = snprintf(buf, sizeof(buf), "APID %d fazendo syscall %c em D%d\n", getpid(), op, device);
                    write(STDOUT_FILENO, buf, n);

                    SyscallMsg msg;
                    msg.pid = getpid();
                    msg.device = device;
                    msg.op = op;

                    write(pipefd[1], &msg, sizeof(msg));
                    kill(getppid(), SIGUSR1);
                    pause();
                }
                pc++;
            }

            close(pipefd[1]);
            _exit(0);
        } 
        
        else {
            processes[i].pid = pid;
            processes[i].pc = 0;
            processes[i].state = READY;
            processes[i].waitingDevice = 0;
            processes[i].waitingOp = 0;
            processes[i].D1_access = 0;
            processes[i].D2_access = 0;
        }
    }
}

// Criação do processo InterControllerSim (gera interrupções)
void spawn_intercontroller(pid_t parent_pid) {
    pid_t pid = fork();

    if (pid < 0) { 
        perror("Erro ao criar InterControllerSim");
        exit(1);
    }

    if (pid == 0) {
        srand(time(NULL) ^ (getpid() << 8));

        while (1) {
            usleep(IC_PERIOD_US);

            kill(parent_pid, SIGALRM); // IRQ0 (Time slice)

            if ((rand() % 100) < 10) { // IRQ1 (D1)
                kill(parent_pid, SIGUSR2);
            }

            if ((rand() % 100) < 5) { // IRQ2 (D2)
                kill(parent_pid, SIGRTMIN);
            }
        }
        _exit(0);
    }
}

// Busca processos prontos
int find_first_ready() {
    for (int i = 0; i < NUM_PROCS; i++) {
        if (processes[i].state == READY) {
            return i;
        }
    }
    return -1;
}

// Para o processo atual
void stop_current_running() {
    if (current_running >= 0 && current_running < NUM_PROCS) {
        pid_t p = processes[current_running].pid;

        if (processes[current_running].state == RUNNING) {
            kill(p, SIGSTOP);
            processes[current_running].state = READY;
        }

        current_running = -1;
    }
}

// Inicia um processo
void start_process_idx(int idx) {
    if (idx < 0) return;

    if (processes[idx].state == READY) {
        pid_t p = processes[idx].pid;
        processes[idx].state = RUNNING;
        kill(p, SIGCONT);
        current_running = idx;
    }
}

// Desbloqueia processo bloqueado
void unblock_process_idx(int idx) {
    if (idx < 0) return;

    if (processes[idx].state == BLOCKED) {
        processes[idx].state = READY;
        processes[idx].waitingDevice = 0;
        processes[idx].waitingOp = 0;
        kill(processes[idx].pid, SIGCONT);
    }
}

// Exibe o estado de todos os processos (Ctrl+C)
void print_status() {
    char buf[512];
    int n;

    safe_printf("\n========== ESTADO ATUAL ==========\n");

    for (int i = 0; i < NUM_PROCS; i++) {
        Process *pr = &processes[i];
        const char *st;

        switch (pr->state) {
            case READY: st = "READY"; break;
            case RUNNING: st = "RUNNING"; break;
            case BLOCKED: st = "BLOCKED"; break;
            case FINISHED: st = "FINISHED"; break;
            default: st = "?"; break;
        }

        if (pr->state == BLOCKED) {
            n = snprintf(buf, sizeof(buf),
                "A%d (pid %d): PC=%d ESTADO=%s (aguardando D%d op=%c) D1=%d D2=%d\n",
                i+1, pr->pid, pr->pc, st, pr->waitingDevice, pr->waitingOp, pr->D1_access, pr->D2_access);
        } 
        else {
            n = snprintf(buf, sizeof(buf),
                "A%d (pid %d): PC=%d ESTADO=%s D1=%d D2=%d\n",
                i+1, pr->pid, pr->pc, st, pr->D1_access, pr->D2_access);
        }

        write(STDOUT_FILENO, buf, n);
    }

    safe_printf("Filas: ");

    if (qd1_len == 0) safe_printf("D1=[] ");
    else {
        write(STDOUT_FILENO, "D1=[", 4);
        for (int i = 0; i < qd1_len; i++) {
            int v = queue_D1[(qd1_head + i) % NUM_PROCS];
            char tmp[32];
            int m = snprintf(tmp, sizeof(tmp), "A%d%s", v+1, (i+1 == qd1_len) ? "" : ",");
            write(STDOUT_FILENO, tmp, m);
        }
        write(STDOUT_FILENO, "] ", 2);
    }

    if (qd2_len == 0) safe_printf("D2=[]\n");
    else {
        write(STDOUT_FILENO, "D2=[", 4);
        for (int i = 0; i < qd2_len; i++) {
            int v = queue_D2[(qd2_head + i) % NUM_PROCS];
            char tmp[32];
            int m = snprintf(tmp, sizeof(tmp), "A%d%s", v+1, (i+1 == qd2_len) ? "" : ",");
            write(STDOUT_FILENO, tmp, m);
        }
        write(STDOUT_FILENO, "]\n", 2);
    }

    safe_printf("====================================\n");
}

int main() {
    if (pipe(pipefd) == -1) {
        perror("pipe");
        exit(1);
    }

    int flags = fcntl(pipefd[0], F_GETFL, 0);
    fcntl(pipefd[0], F_SETFL, flags | O_NONBLOCK);

    struct sigaction sa;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    sa.sa_handler = handler_irq0;
    sigaction(SIGALRM, &sa, NULL);

    sa.sa_handler = handler_irq1;
    sigaction(SIGUSR2, &sa, NULL);

    sa.sa_handler = handler_irq2;
    sigaction(SIGRTMIN, &sa, NULL);

    sa.sa_handler = handler_syscall;
    sigaction(SIGUSR1, &sa, NULL);

    sa.sa_handler = handler_sigchld;
    sigaction(SIGCHLD, &sa, NULL);

    sa.sa_handler = handler_sigint;
    sigaction(SIGINT, &sa, NULL);

    spawn_app_processes();
    spawn_intercontroller(getpid());

    int first = find_first_ready();
    if (first >= 0) {
        start_process_idx(first);
    }

    while (1) {
        pause();

        if (flag_child_exit) {
            flag_child_exit = 0;
            int status;
            pid_t w;

            while ((w = waitpid(-1, &status, WNOHANG)) > 0) {
                int idx = proc_index_by_pid(w);

                if (idx >= 0) {
                    processes[idx].state = FINISHED;
                    processes[idx].pc = MAX_PC;
                    if (current_running == idx) current_running = -1;

                    char buf[128];
                    int n = snprintf(buf, sizeof(buf),
                        "APID %d finalizado (A%d)\n", w, idx+1);
                    write(STDOUT_FILENO, buf, n);
                }
            }
        }

        if (flag_syscall) {
            flag_syscall = 0;
            SyscallMsg msg;
            ssize_t r;

            while ((r = read(pipefd[0], &msg, sizeof(msg))) == sizeof(msg)) {
                int idx = proc_index_by_pid(msg.pid);
                if (idx < 0) continue;

                kill(msg.pid, SIGSTOP);
                processes[idx].state = BLOCKED;
                processes[idx].waitingDevice = msg.device;
                processes[idx].waitingOp = msg.op;

                if (msg.device == 1) processes[idx].D1_access++;
                else if (msg.device == 2) processes[idx].D2_access++;

                if (msg.device == 1) enqueue_D1(idx);
                else enqueue_D2(idx);

                char buf[128];
                int n = snprintf(buf, sizeof(buf),
                    "Kernel: syscall de A%d (pid %d) adicionada na fila D%d op=%c\n",
                    idx+1, msg.pid, msg.device, msg.op);
                write(STDOUT_FILENO, buf, n);

                if (current_running == idx) current_running = -1;
            }
        }

        if (flag_irq1) {
            flag_irq1 = 0;
            int idx = dequeue_D1();

            if (idx >= 0) {
                char buf[128];
                int n = snprintf(buf, sizeof(buf),
                    "Kernel: IRQ1 -> D1 concluído, desbloqueando A%d (pid %d)\n",
                    idx+1, processes[idx].pid);
                write(STDOUT_FILENO, buf, n);
                unblock_process_idx(idx);
            }
        }

        if (flag_irq2) {
            flag_irq2 = 0;
            int idx = dequeue_D2();

            if (idx >= 0) {
                char buf[128];
                int n = snprintf(buf, sizeof(buf),
                    "Kernel: IRQ2 -> D2 concluído, desbloqueando A%d (pid %d)\n",
                    idx+1, processes[idx].pid);
                write(STDOUT_FILENO, buf, n);
                unblock_process_idx(idx);
            }
        }

        if (flag_irq0) {
            flag_irq0 = 0;

            if (current_running >= 0 && processes[current_running].state == RUNNING) {
                pid_t p = processes[current_running].pid;
                kill(p, SIGSTOP);
                processes[current_running].state = READY;

                char buf[128];
                int n = snprintf(buf, sizeof(buf),
                    "Kernel: IRQ0 -> preempção de A%d (pid %d)\n",
                    current_running+1, p);
                write(STDOUT_FILENO, buf, n);
            }

            int next = find_first_ready();
            if (next >= 0) start_process_idx(next);
        }

        if (flag_sigint) {
            flag_sigint = 0;
            print_status();
        }

        if (current_running >= 0 && processes[current_running].state == RUNNING) {
            if (processes[current_running].pc < MAX_PC){
            processes[current_running].pc++;
            }

            if (processes[current_running].pc >= MAX_PC) {
                processes[current_running].state = FINISHED;
                char buf[128];
                int n = snprintf(buf, sizeof(buf),
                    "Kernel: A%d (pid %d) finalizado\n",
                    current_running + 1,
                    processes[current_running].pid);
                write(STDOUT_FILENO, buf, n);

                current_running = -1;
    }
        }
    }

    return 0;
}
