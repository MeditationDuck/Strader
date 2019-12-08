#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>

unsigned long long int break_address;
unsigned long long int original_text;

void p_wait(pid_t pid){
    int status;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status)) {
      printf("program exited normally\n");
      exit(0);
    } else if (WIFSIGNALED(status)) {
      printf("terminated by signal %d\n", WTERMSIG(status));
    } else if (WIFSTOPPED(status)) {
      printf("stopped by signal %d\n", WSTOPSIG(status));
    }
}
void set_break(pid_t pid, unsigned long long int address){
    original_text = ptrace(PTRACE_PEEKTEXT, pid, address, 0);
    if(original_text == -1){
        printf("error at peektext\n");
    }
    if(-1 == ptrace(PTRACE_POKETEXT, pid, address, ((original_text & 0xFFFFFFFFFFFFFF00) | 0xCC))){
        printf("error at poketext\n");

    }
    printf("set breakpoint  :%016llx  :%016llx\n", address, original_text);

}
void run_target(const char* target){
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    execl(target, target, NULL);
    fprintf(stderr, "failed at executing target.");
}
void p_setbreakpoint(int pid){
    char str_address[17];
    /*
    unsigned long long int break_address;
    unsigned long long int original_text;
    */

    printf("set breakpoint\n");
    printf("put the address of you want to break\n");
    fgets(str_address, 17, stdin);
    break_address = (unsigned long long int)strtol(str_address, NULL, 16);
    printf("%016llx\n", break_address);
    set_break(pid, break_address);
}
void p_removebreakpoint(pid_t pid){
    struct user_regs_struct regs;
    unsigned long long int b_text;

    ptrace(PTRACE_GETREGS, pid, 0, &regs);
    b_text = ptrace(PTRACE_PEEKTEXT, pid, break_address, 0);
    if(b_text == -1){
        printf("faied.\n");
        exit(1);
    }printf("breaked text is :%016llx\n", b_text);
    
    printf("now rip is: %016llx\n",regs.rip);
    regs.rip -= 1;
    ptrace(PTRACE_SETREGS, pid, 0, &regs);
    ptrace(PTRACE_POKETEXT, pid, break_address, original_text);
    b_text = ptrace(PTRACE_PEEKTEXT, pid, break_address, 0);
    if(b_text == -1){
        printf("faied.\n");
        exit(1);
    }printf("restored :%016llx\n", b_text);

}
void p_continue(int pid){   
    ptrace(PTRACE_CONT, pid, 0, 0);
    printf("----------------------------------------------------\n");
    p_wait(pid);
}
void p_step(int pid){   
    ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
    p_wait(pid);
}
struct user_regs_struct p_getregs(int pid){
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, 0, &regs);
    return regs;
}
void p_showregs(int pid){
    struct user_regs_struct regs;
    regs = p_getregs(pid);
    printf("rax: 0x%llx\n", regs.rax);
    printf("rdx: 0x%llx\n", regs.rdx);
    printf("rcx: 0x%llx\n", regs.rcx);
    printf("rbx: 0x%llx\n", regs.rbx);
    printf("rsi: 0x%llx\n", regs.rsi);
    printf("rdi: 0x%llx\n", regs.rdi);
    printf("rsp: 0x%llx\n", regs.rsp);
    printf("rbp: 0x%llx\n", regs.rbp);
    printf("r8 : 0x%llx\n", regs.r8);
    printf("r9 : 0x%llx\n", regs.r9);
    printf("r10: 0x%llx\n", regs.r10);
    printf("r11: 0x%llx\n", regs.r11);
    printf("r12: 0x%llx\n", regs.r12);
    printf("r13: 0x%llx\n", regs.r13);
    printf("r14: 0x%llx\n", regs.r14);
    printf("r15: 0x%llx\n", regs.r15);
    printf("flag:0x%llx\n", regs.fs);
    printf("\n");
    printf("rip: 0x%llx\n", regs.rip);
}
void print_help(){
    printf("b set breakpoint.\n");
    printf("s step.\n");
    printf("q quit.\n");
    printf("if you set breakpoint i create log.txt so if you want to delete breakpoint log , you can delete the textfile\n");
    printf("when the target process stop at breakpoint you have to execute \"rb\", delete breakpoint.\n");
    return;
}
void continueing(int pid){
    struct user_regs_struct regs;
    unsigned long long int text;

    regs = p_getregs(pid);

    text = ptrace(PTRACE_PEEKTEXT, pid, regs.rip -1 , 0);
    if( 0xCC == ((text & 0x00000000000000FF))){
        p_removebreakpoint(pid);
        p_step(pid);
        set_break(pid, (regs.rip-1 ));
        p_continue(pid);
    }else{
        p_continue(pid);
    }
}
void run_debugger(int pid){   
    int status;
    //unsigned long long int original_text = 0;
    printf("run_debugger.\n");
    printf("press \"h\" to help.\n");

    printf("I`m tracer and child process id is %d \n", pid);
    p_wait(pid);

    while(1){
        char str[17];
        //unsigned long long int address;
        //unsigned long long int original_text;
        
        p_showregs(pid);
        printf(">");
        fgets(str, 20, stdin);
        if(!strcmp(str,"b\n")){
            p_setbreakpoint(pid);
        }
        else if(!strcmp(str, "c\n")){
            continueing(pid);
        }
        else if(!strcmp(str, "r\n")){
            p_showregs(pid);
        }
        else if(!strcmp(str, "rb\n")){
            if(original_text != 0){
                printf("remove breakpoint\n");
                p_removebreakpoint(pid);
            }
        }
        
        else if(!strcmp(str, "s\n")){
            p_step(pid);
        }
        else if(!strcmp(str, "q\n")){
            ptrace(PTRACE_KILL,pid, 0, 0);
            break;
        }
        else if(!strcmp(str, "h\n")){
            print_help();
        }
        else{
            printf("unexpected.\n");  
        }  
    }
}
int main(int argc, char** argv){
    pid_t child_pid;
    if (argc < 2){
        printf("argument error");
        fprintf(stderr, "Usage :$ %s <target> <addr>\n", argv[0]);
        exit(1);
    }
    child_pid = fork();
    if (child_pid == 0){
        run_target(argv[1]);
    }
    else if (child_pid > 0){
        run_debugger(child_pid);
    }
    else {
        fprintf(stderr, "error at forking target");
        exit(1);
    }
    return 0;
}
