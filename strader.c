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

# define SUCCESSFUL 1
# define FAILURE 0

#define KNRM  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KMAG  "\x1B[35m"
#define KCYN  "\x1B[36m"
#define KWHT  "\x1B[37m"




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


void p_wait(pid_t pid)
{
    int status;
    waitpid(pid, &status, WUNTRACED);
    if (WIFEXITED(status)) {
      printf("program exited normally\n");
      exit(0);
    } else if (WIFSIGNALED(status)) {
      printf("terminated by signal %d\n", WTERMSIG(status));
    } else if (WIFSTOPPED(status)) {
      printf("stopped by signal %d\n", WSTOPSIG(status));
    }
}

void set_break(pid_t pid, unsigned long long int address)
{
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

void run_target(const char* target)
{
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    execl(target, target, NULL);
    fprintf(stderr, "failed at executing target.");
}

void p_setbreakpoint(int pid)
{
    char str_address[17];
    
    unsigned long long int break_address;
    

    printf("set breakpoint\n");
    printf("put the address of you want to break\n");
    fgets(str_address, 17, stdin);
    break_address = (unsigned long long int)strtol(str_address, NULL, 16);
    printf("%016llx\n", break_address);
    set_break(pid, break_address);
}

unsigned long long int p_removebreakpoint(pid_t pid)
{
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
    ptrace(PTRACE_POKETEXT, pid, address - 1, ((b_text & 0xFFFFFFFFFFFFFF00) |(text & 0x00000000000000FF)));
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

void p_continue(int pid)
{   
    ptrace(PTRACE_CONT, pid, 0, 0);
    printf("----------------------------------------------------\n");
    p_wait(pid);
}

void p_step(int pid)
{   
    ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
    p_wait(pid);
}

struct user_regs_struct p_getregs(int pid)
{
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, 0, &regs);
    return regs;
}

void p_showregs(int pid)
{
    struct user_regs_struct regs;
    regs = p_getregs(pid);
    //printf("\n");
    printf("rip: 0x%llx\n", regs.rip);
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

void print_help()
{
    printf(">b to set breakpoint.\n");
    printf(">s to step.\n");
    printf(">q to quit.\n");
    return;
}

void showmemory(int pid)
{
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

void stepping(int pid)
{
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

void setregs(int pid)
{
    // this function still not complete;
    struct user_regs_struct regs;
    regs = p_getregs(pid);
    char str_cnt[2];
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
    printf("choose the register you want to change :");
    fgets(str_cnt, 10, stdin);
    cont = (int)strtol(str_cnt, NULL, 10);

    if(cont == 1){
        char str_value[17];
        unsigned long long int value;
        printf("\nnow 0x%llx\n", regs.rax);
        printf("type the value :");
        fgets(str_value, 17, stdin);
        value = (unsigned long long int)strtol(str_value, NULL, 16);
        regs.rax = value;
    }
    if(cont == 2){
        char str_value[17];
        unsigned long long int value;
        printf("\nnow 0x%llx\n", regs.rbx);
        printf("type the value :");
        fgets(str_value, 17, stdin);
        value = (unsigned long long int)strtol(str_value, NULL, 16);
        regs.rbx = value;
    }
    if(cont == 3){
        char str_value[17];
        unsigned long long int value;
        printf("\nnow 0x%llx\n", regs.rcx);
        printf("type the value :");
        fgets(str_value, 17, stdin);
        value = (unsigned long long int)strtol(str_value, NULL, 16);
        regs.rcx = value;
    }
    if(cont == 4){
        char str_value[17];
        unsigned long long int value;
        printf("\nnow 0x%llx\n", regs.rdx);
        printf("type the value :");
        fgets(str_value, 17, stdin);
        value = (unsigned long long int)strtol(str_value, NULL, 16);
        regs.rdx = value;
    }
    if(cont == 5){
        char str_value[17];
        unsigned long long int value;
        printf("\nnow 0x%llx\n", regs.rsi);
        printf("type the value :");
        fgets(str_value, 17, stdin);
        value = (unsigned long long int)strtol(str_value, NULL, 16);
        regs.rsi = value;
    }
    if(cont == 6){
        char str_value[17];
        unsigned long long int value;
        printf("\nnow 0x%llx\n", regs.rdi);
        printf("type the value :");
        fgets(str_value, 17, stdin);
        value = (unsigned long long int)strtol(str_value, NULL, 16);
        regs.rdi = value;
    }
    if(cont == 7){
        char str_value[17];
        unsigned long long int value;
        printf("\nnow 0x%llx\n", regs.rsp);
        printf("type the value :");
        fgets(str_value, 17, stdin);
        value = (unsigned long long int)strtol(str_value, NULL, 16);
        regs.rsp = value;
    }
    if(cont == 8){
        char str_value[17];
        unsigned long long int value;
        printf("\nnow 0x%llx\n", regs.rbp);
        printf("type the value :");
        fgets(str_value, 17, stdin);
        value = (unsigned long long int)strtol(str_value, NULL, 16);
        regs.rbp = value;
    }
    if(cont == 9){
        char str_value[17];
        unsigned long long int value;
        printf("\nnow 0x%llx\n", regs.r8);
        printf("type the value :");
        fgets(str_value, 17, stdin);
        value = (unsigned long long int)strtol(str_value, NULL, 16);
        regs.r8 = value;
    }
    if(cont == 10){
        char str_value[17];
        unsigned long long int value;
        printf("\nnow 0x%llx\n", regs.r9);
        printf("type the value :");
        fgets(str_value, 17, stdin);
        value = (unsigned long long int)strtol(str_value, NULL, 16);
        regs.r9 = value;
    }
    if(cont == 11){
        char str_value[17];
        unsigned long long int value;
        printf("\nnow 0x%llx\n", regs.r10);
        printf("type the value :");
        fgets(str_value, 17, stdin);
        value = (unsigned long long int)strtol(str_value, NULL, 16);
        regs.r10 = value;
    }
    if(cont == 12){
        char str_value[17];
        unsigned long long int value;
        printf("\nnow 0x%llx\n", regs.r11);
        printf("type the value :");
        fgets(str_value, 17, stdin);
        value = (unsigned long long int)strtol(str_value, NULL, 16);
        regs.r11 = value;
    }
    if(cont == 13){
        char str_value[17];
        unsigned long long int value;
        printf("\nnow 0x%llx\n", regs.r12);
        printf("type the value :");
        fgets(str_value, 17, stdin);
        value = (unsigned long long int)strtol(str_value, NULL, 16);
        regs.r12 = value;
    }
    if(cont == 14){
        char str_value[17];
        unsigned long long int value;
        printf("\nnow 0x%llx\n", regs.r13);
        printf("type the value :");
        fgets(str_value, 17, stdin);
        value = (unsigned long long int)strtol(str_value, NULL, 16);
        regs.r13 = value;
    }
    if(cont == 15){
        char str_value[17];
        unsigned long long int value;
        printf("\nnow 0x%llx\n", regs.r14);
        printf("type the value :");
        fgets(str_value, 17, stdin);
        value = (unsigned long long int)strtol(str_value, NULL, 16);
        regs.r14 = value;
    }
    if(cont == 16){
        char str_value[17];
        unsigned long long int value;
        printf("\nnow 0x%llx\n", regs.r15);
        printf("type the value :");
        fgets(str_value, 17, stdin);
        value = (unsigned long long int)strtol(str_value, NULL, 16);
        regs.r15 = value;
    }
    if(cont == 17){
        char str_value[17];
        unsigned long long int value;
        printf("\nnow 0x%llx\n", regs.fs);
        printf("type the value :");
        fgets(str_value, 17, stdin);
        value = (unsigned long long int)strtol(str_value, NULL, 16);
        regs.fs = value;
    }
    ptrace(PTRACE_SETREGS, pid,NULL, &regs);
    
}

void continueing(int pid)
{
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

void change_regs_color(int pid)
{
    struct user_regs_struct regs1;
    struct user_regs_struct regs2;
    char biger[7] = KCYN;
    char leser[7] = KMAG;
    char def[7] = KNRM;
    regs1 = p_getregs(pid);
    char str[10];
    int cyc;
    printf("please type time you want to repeat(ms): ");
    fgets(str, 10, stdin);
    cyc = atoi(str);
    while(1){
        long long int inlong;
        p_step(pid);
        
        regs2 = p_getregs(pid);

        inlong = regs2.rip - regs1.rip;

        if(inlong > 0){
            printf("%srip: %016llx\t%s", leser ,regs2.rip, KNRM);   
        }else if(inlong < 0){
            printf("%srip: %016llx\t%s", biger ,regs2.rip, KNRM);   
        }
        else{
            printf("rip: %016llx\t", regs2.rip);
        }

        inlong = regs2.rip - regs1.rip;
        /*
        if(inlong > 1000){
            printf("%lld maybe rip was jumped to anyware.\n", inlong);
        }else if(inlong < 0){
            printf("\t%lld instruction pointer was moved to behind.\n", inlong);
        } else {
            printf("\t%lld byte  the size of instruction.\n", inlong);
        }
        */
        if(regs1.rax == regs2.rax){
            printf("rax: %016llx\n", regs2.rax);
           
        }else{
            printf("%srax: %016llx\n%s", biger ,regs2.rax, KNRM);
            
        }
          
        if(regs1.rdx != regs2.rdx){
            printf("%srdx: %016llx\n%s", biger ,regs2.rdx, KNRM);   
        }else{
            printf("rdx: %016llx\n", regs2.rdx);
        }


        if(regs1.rcx != regs2.rcx){
            printf("%srcx: %016llx\n%s", biger ,regs2.rcx, KNRM);   
        }else{
            printf("rcx: %016llx\n", regs2.rcx);
        }

        if(regs1.rbx != regs2.rbx){
            printf("%srbx: %016llx\n%s", biger ,regs2.rbx, KNRM);   
        }else{
            printf("rbx: %016llx\n", regs2.rbx);
        }
 
        if(regs1.rsi != regs2.rsi){
            printf("%srsi: %016llx\n%s", biger ,regs2.rsi, KNRM);   
        }else{
            printf("rsi: %016llx\n", regs2.rsi);
        }

        if(regs1.rdi != regs2.rdi){
            printf("%srdi: %016llx\n%s", biger ,regs2.rdi, KNRM);   
        }else{
            printf("rdi: %016llx\n", regs2.rdi);
        }

        if(regs1.rsp != regs2.rsp){
            printf("%srsp: %016llx\n%s", biger ,regs2.rsp, KNRM);   
        }else{
            printf("rsp: %016llx\n", regs2.rsp);
        }

        if(regs1.rbp != regs2.rbp){
            printf("%srbp: %016llx\n%s", biger ,regs2.rbp, KNRM);   
        }else{
            printf("rbp: %016llx\n", regs2.rbp);
        }

        if(regs1.r8 != regs2.r8){
            printf("%sr8 : %016llx\n%s", biger ,regs2.r8, KNRM);   
        }else{
            printf("r8 : %016llx\n", regs2.r8);
        }

        if(regs1.r9 != regs2.r9){
            printf("%sr9 : %016llx\n%s", biger ,regs2.r9, KNRM);   
        }else{
            printf("r9 : %016llx\n", regs2.r9);
        }

        if(regs1.r10 != regs2.r10){
            printf("%sr10: %016llx\n%s", biger ,regs2.r10, KNRM);   
        }else{
            printf("r10: %016llx\n", regs2.r10);
        }

        if(regs1.r11 != regs2.r11){
            printf("%sr11: %016llx\n%s", biger ,regs2.r11, KNRM);   
        }else{
            printf("r11: %016llx\n", regs2.r11);
        }

        if(regs1.r12 != regs2.r12){
            printf("%sr12: %016llx\n%s", biger ,regs2.r12, KNRM);   
        }else{
            printf("r12: %016llx\n", regs2.r12);
        }
 
        if(regs1.fs != regs2.fs){
            printf("%sfs : %016llx\n%s", biger ,regs2.fs, KNRM);   
        }else{
            printf("fs : %016llx\n", regs2.fs);
        }

        if(regs2.rbp != 0){
            printf("stack size (bytes):%lld\n", regs2.rbp - regs2.rsp);
        }

        regs1 = regs2;
        usleep(cyc * 1000);
    
        system("clear");
    }
    
}

void showrip(int pid)
{
    struct user_regs_struct regs;
    regs = p_getregs(pid);
    printf("rip: 0x%llx\n", regs.rip); 

}

void run_debugger(int pid, int attach)
{   
    int status;
    
    
    //unsigned long long int original_text = 0;
    printf("run_debugger.\n");
    printf("press \"h\" to help.\n");

    printf("I`m tracer and child process id is %d \n", pid);
    p_wait(pid);

    while(1){
        char str[20];
        
        //showrip(pid);
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
        else if(!strcmp(str, "sr\n")){
            setregs(pid);
        }
        else if(!strcmp(str, "d\n")){            
            p_removebreakpoint(pid);            
        }        
        else if(!strcmp(str, "ib\n")){
            listPrint(list);
        }
        else if(!strcmp(str, "s\n")){
            stepping(pid);
        }
        else if(!strcmp(str, "q\n")){
            if(attach == 1){
                ptrace(PTRACE_DETACH, pid, NULL, NULL);
            }
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
            change_regs_color(pid);
        }
        else{
            printf("unexpected.\n");  
        }  
    }
}

int main(int argc, char** argv){
    pid_t child_pid;
    printf("\
.▄▄ · ▄▄▄▄▄▄▄▄   ▄▄▄· ·▄▄▄▄  ▄▄▄ .▄▄▄  \n\
▐█ ▀. •██  ▀▄ █·▐█ ▀█ ██▪ ██ ▀▄.▀·▀▄ █·\n\
▄▀▀▀█▄ ▐█.▪▐▀▀▄ ▄█▀▀█ ▐█· ▐█▌▐▀▀▪▄▐▀▀▄ \n\
▐█▄▪▐█ ▐█▌·▐█•█▌▐█ ▪▐▌██. ██ ▐█▄▄▌▐█•█▌\n\
 ▀▀▀▀  ▀▀▀ .▀  ▀ ▀  ▀ ▀▀▀▀▀•  ▀▀▀ .▀  ▀\n\
");
    if (argc < 2){
        char strpid[32];
        int intpid;

        printf("If you want to debug aleady exist process, Please type the process id.\n");
        printf("type \"q\" to quit.\n");
        fgets(strpid ,sizeof(strpid) , stdin);
        if(!strcmp(strpid, "q\n")){
            exit(1);
            run_debugger(intpid, 1);
        }
        long ret;
        intpid = atoi(strpid);
        ret = ptrace(PTRACE_ATTACH, intpid, NULL, NULL);
        if(ret < 0){
            perror("failed to attach");
            exit(1);
        }
        run_debugger(intpid, 1);

        printf("argument error");
        fprintf(stderr, "Usage :$ %s <target>\n", argv[0]);
        exit(1);
    }
    child_pid = fork();
    if (child_pid == 0){
        run_target(argv[1]);
    }
    else if (child_pid > 0){
        run_debugger(child_pid, 0);
    }
    else {
        fprintf(stderr, "error at forking target");
        exit(1);
    }
    return 0;
}
