#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <time.h>

#define NUM_PROCS 5
#define MAX 20  // Interações maximas
#define TIMESLICE 1  // tempo em segundos 

typedef enum {READY, RUNNING, BLOCKED, FINISHED} State;
typedef struct {
    int pid;
    int pc;
    State state;
    char waitingDevice;
    char waitingOp;
    int D1_access;
    int D2_access;
} Process;

Process processes[NUM_PROCS];
int current = 0;

void sigcont_handler(int signo) {
    // não faz nada, apenas para acordar do SIGSTOP
}

void create_processes() {
    for(int i=0; i<NUM_PROCS; i++) {
        int pid = fork();
        
        if(pid < 0) {
            perror("fork");
            exit(1);
        } 
        
        else if(pid == 0) {
            srand(time(NULL) ^ getpid());
            int pc = 0;
            
            while(pc < MAX) {
                sleep(1);
                int d = rand()%100 + 1;

                if(d <= 15) { // chance de syscall
                    char device = (d % 2) ? 'D1' : 'D2';
                    char op;
                    int mod3 = d % 3;
                    if(mod3 == 1) op = 'R';
                    else if(mod3 == 2) op = 'W';
                    else op = 'X';
                    printf("Process %d making syscall %c on %c\n", getpid(), op, device);
                    kill(getppid(), SIGUSR1);  // syscall
                    pause(); // aguarda SIGCONT
                }
                pc++;
            }
            exit(0);

        } else {
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

void kernel_handler(int signo) {
    // Placeholder: poderia tratar IRQ0/IRQ1/IRQ2 aqui
    // por exemplo, alternar processos, desbloquear filas etc.
}

int main() {
    signal(SIGUSR1, sigcont_handler); // sinal de syscall
    create_processes();

    // InterControllerSim fork
    int pid_ic = fork();
    
    if(pid_ic == 0) {
        srand(time(NULL) ^ getpid());
        
        while(1) {
            sleep(0.5);
            // IRQ0
            kill(getppid(), SIGALRM);
            // IRQ1
            if(rand()%10 < 1) kill(getppid(), SIGUSR2);
            // IRQ2
            if(rand()%20 < 1) kill(getppid(), SIGCHLD);
        }
        exit(0);
    }

    // KernelSim loop
    signal(SIGALRM, kernel_handler); // time slice
    signal(SIGUSR2, kernel_handler); // D1
    signal(SIGCHLD, kernel_handler); // D2

    while(1) {
        // Escalonamento Round-Robin
        for(int i=0; i<NUM_PROCS; i++) {
            if(processes[i].state == READY) {
                processes[i].state = RUNNING;
                kill(processes[i].pid, SIGCONT);
                sleep(TIMESLICE);
                kill(processes[i].pid, SIGSTOP);
                processes[i].state = READY;
            }
        }
    }

    return 0;
}
