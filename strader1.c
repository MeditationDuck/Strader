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

# define  SUCCESSFUL 1;
# define FAILURE 0;




typedef unsigned long long int data_t;
typedef struct nodetag{
    data_t address;
    data_t text;
    struct nodetag *next;
}node_t;

node_t *list = NULL;

node_t *nodeNew(data_t dt, data_t dt2, node_t *nxt){
    node_t * ndPtr;
    ndPtr = malloc(sizeof(node_t));
    if(ndPtr == NULL){
        return NULL;
    }else{
        ndPtr -> address = dt;
        ndPtr -> text = dt2;
        return ndPtr;
    }
}

int nodeAppend(node_t**ndPtrPtr, data_t address, data_t text){
    node_t * ndPtr;
    ndPtr = nodeNew(address, text, NULL);
    if(ndPtr == NULL) return FAILURE;
    while(*ndPtrPtr != NULL){
        ndPtrPtr = &((*ndPtrPtr) -> next);
    }
    *ndPtrPtr = ndPtr;
    return SUCCESSFUL;
}

int listPrint(node_t *ndPtr){
    while(ndPtr != NULL) {
        printf("address :%016llx\ntext :%016llx\n", ndPtr -> address, ndPtr->text);
        ndPtr = ndPtr -> next;
    }
}
int node_findtext(node_t *ndPtr, data_t address){
    int cnt;
    cnt = 0;
    while(ndPtr!= NULL){
        
        if(address == ndPtr ->address){
            return ndPtr -> text;
        }
        ndPtr = ndPtr -> next;
        cnt++;        
    }
    return FAILURE;
}
int node_findcnt(node_t *ndPtr, data_t address){
    int cnt;
    cnt = 0;
    while(ndPtr!= NULL){
        
        if(address == ndPtr ->address){
            return cnt;
        }
        ndPtr = ndPtr -> next;
        cnt++;        
    }
    return FAILURE;
}
int nodeDelete(node_t **ndPtrPtr, int n){
    node_t * ndPtr;
    while (n>0 && *ndPtrPtr != NULL){
        ndPtrPtr = &((*ndPtrPtr)->next);
        n--;
    }
    if(*ndPtrPtr != NULL) {
        ndPtr = (*ndPtrPtr) -> next;
        free(*ndPtrPtr);
        *ndPtrPtr = ndPtr;
        return SUCCESSFUL;
    }else{
        return FAILURE;
    }

}


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
    unsigned long long int original_text;
    original_text = ptrace(PTRACE_PEEKTEXT, pid, address, 0);
    if(original_text == -1){
        printf("error at peektext\n");
        return;
    }
    if(-1 == ptrace(PTRACE_POKETEXT, pid, address, ((original_text & 0xFFFFFFFFFFFFFF00) | 0xCC))){
        printf("error at poketext\n");

    }
    printf("set breakpoint  :%016llx  :%016llx\n", address, original_text);
    nodeAppend(&list, address, original_text);
}
void run_target(const char* target){
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    execl(target, target, NULL);
    fprintf(stderr, "failed at executing target.");
}
void p_setbreakpoint(int pid){
    char str_address[17];
    
    unsigned long long int break_address;
    

    printf("set breakpoint\n");
    printf("put the address of you want to break\n");
    fgets(str_address, 17, stdin);
    break_address = (unsigned long long int)strtol(str_address, NULL, 16);
    printf("%016llx\n", break_address);
    set_break(pid, break_address);
}
unsigned long long int p_removebreakpoint(pid_t pid){
    struct user_regs_struct regs;
    unsigned long long int b_text;
    unsigned long long int text;
    unsigned long long int address;

    ptrace(PTRACE_GETREGS, pid, 0, &regs);
    address = regs.rip;
    printf("breakaddress is :%016llx\n", address);
    text = node_findtext(list, address - 1);
    if(0 == text){
        printf("Last break was Unexpected.\n");
        return -1;
    }
    printf("find breakpoint\n");

    b_text = ptrace(PTRACE_PEEKTEXT, pid, address-1, 0);
    if(b_text == -1){
        printf("faied.\n");
        exit(1);
    }printf("breaked text is :%016llx\n", b_text);
    
    printf("now rip is: %016llx\n",address);
    regs.rip -= 1;
    ptrace(PTRACE_SETREGS, pid, 0, &regs);
    ptrace(PTRACE_POKETEXT, pid, address - 1, text);
    b_text = ptrace(PTRACE_PEEKTEXT, pid, address -1, 0);
    if(b_text == -1){
        printf("faied.\n");
        exit(1);
    }printf("restored :%016llx\n", b_text);
    if(0 == nodeDelete(&list, node_findcnt(list, address-1))){
        printf("falure at removing breakpoint from list.\n");
    }
    return address -1;
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
    printf("\n\n");
    printf("rip: 0x%llx\n", regs.rip);
    printf("\n");
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
    
    
}
void print_help(){
    printf("b set breakpoint.\n");
    printf("s step.\n");
    printf("q quit.\n");
    printf("if you set breakpoint i create log.txt so if you want to delete breakpoint log , you can delete the textfile\n");
    printf("when the target process stop at breakpoint you have to execute \"rb\", delete breakpoint.\n");
    return;
}
void showmemory(pid_t pid){
    char str_address[17];
    unsigned long long int address;
    char str_count[4];
    int count; 
    printf("put address you want to see inside :");
    fgets(str_address, 17, stdin);
    address = (unsigned long long int)strtol(str_address, NULL, 16);
    fgets(str_count, 4, stdin);
    printf("how many repeat per 8byte :");
    count = (int)strtol(str_count, NULL, 10);
    printf("%016llx\n", address);
    for(int i=0;i<count;i++){
        printf("%016lx\n", ptrace(PTRACE_PEEKTEXT, pid, address + 8*i, 0));
    }printf("\n");
}
void stepping(int pid){
    struct user_regs_struct regs;
    unsigned long long int text;
    unsigned long long int address;

    regs = p_getregs(pid);

    text = ptrace(PTRACE_PEEKTEXT, pid, regs.rip -1 , 0);
    if( 0xCC == ((text & 0x00000000000000FF))){
        address = p_removebreakpoint(pid);
        p_step(pid);
        set_break(pid, address);
        p_step(pid);     
    }else{
        p_step(pid);
    }
}
void set_condition(pid_t pid){
    // this function is not yet complete;
    struct user_regs_struct before_regs;
    before_regs = p_getregs(pid);
    char str_cnt[4];
    int cont;

    printf("            1 :rax\n\
            2 :rbx\n\
            3 :rcx\n\
            4 :rdx\n\
            5 :rsi\n\
            6 :rdi\n\
            7 :rsp\n\
            8 :rbp\n\
            9 :r8\n\
            10:r9\n\
            11:r10\n\
            12:r11\n\
            13:r12\n\
            14:r13\n\
            15:r14\n\
            16:r15\n\
            17:flag\n");
    printf("choose register you want to check :");
    fgets(str_cnt, 20, stdin);
    cont = (int)strtol(str_cnt, NULL, 10);
    if(cont == 1){
        struct user_regs_struct regs;
        while(regs.rax != before_regs.rax){
            regs = p_getregs(pid);
            p_step(pid);
        }
    }
    
}
void continueing(int pid){
    struct user_regs_struct regs;
    unsigned long long int text;
    unsigned long long int address;

    regs = p_getregs(pid);

    text = ptrace(PTRACE_PEEKTEXT, pid, regs.rip -1 , 0);
    if( 0xCC == ((text & 0x00000000000000FF))){
        address = p_removebreakpoint(pid);
        p_step(pid);
        set_break(pid, address);
        p_continue(pid);
    }else{
        p_continue(pid);
    }
}
void change_regs_color(){

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
            p_removebreakpoint(pid);            
        }        
        else if(!strcmp(str, "sb\n")){
            listPrint(list);
        }
        else if(!strcmp(str, "s\n")){
            stepping(pid);
        }
        else if(!strcmp(str, "q\n")){
            ptrace(PTRACE_KILL,pid, 0, 0);
            break;
        }
        else if(!strcmp(str, "m\n")){
            showmemory(pid);
        }
        else if(!strcmp(str, "h\n")){
            print_help();
        }
        else if(!strcmp(str, "sc\n")){
            //set_condition(pid);
            change_regs_color();
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