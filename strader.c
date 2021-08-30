
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

#include "breakpoint_list.h"

//レジスタの値の色を変更するためのマクロ
#define KNRM  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KMAG  "\x1B[35m"
#define KCYN  "\x1B[36m"
#define KWHT  "\x1B[37m"


//子プロセスの動作が完了し停止するまで待つ
void p_wait(pid_t pid)
{
    //このデバッガが子プロセスに対して操作（命令）をした際に，
    //子プロセスが停止するまでこのデバッガ（親プロセス）の動作を停止させる
    int status;
    waitpid(pid, &status, WUNTRACED);
    //子プロセスが停止した際statusに子プロセスが停止した原因が入る．
    if (WIFEXITED(status)) {
      printf("program exited normally\n");
      exit(0);
    } else if (WIFSIGNALED(status)) {
      printf("terminated by signal %d\n", WTERMSIG(status));
    } else if (WIFSTOPPED(status)) {
      printf("stopped by signal %d\n", WSTOPSIG(status));
    }
    return;
}

//ブレークポイントを設置する．
//ブレークポイントはそのアドレスとそのアドレスから上に８バイト分のメモリ内容を保存します．
void set_break(pid_t pid, unsigned long long int address)
{     
    unsigned long long int original_text;
    //もとの命令（メモリ内容）を変数に保存します
    original_text = ptrace(PTRACE_PEEKTEXT, pid, address, 0);
    if(original_text == -1){
        printf("error at peektext\n");
        return;
    }
    //ブレークポイントをつけた命令を書き込みます．
    //マスクを使って，もとの上位７バイトの命令と下位１バイトの0xCCを保存します．
    //もちろん場所（アドレス）は命令を取ってきた場所と同じ場所です．
    if(-1 == ptrace(PTRACE_POKETEXT, pid, address, ((original_text & 0xFFFFFFFFFFFFFF00) | 0xCC))){
        printf("error at poketext\n");
        return;
    }
    //ブレークポイントを設定する前のメモリ内容８バイトを表示
    printf("set breakpoint  :%016llx  :%016llx\n", address, original_text);
    //設定したブレークポイントをリンクドリストに保存
    nodeAppend(&list, address, original_text);

    return;
}

//子プロセス上で与えられた文字列のプログラムを実行
void run_target(const char* target)
{
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    //コマンドライン引数であったプログラム名を起動
    //うまく行った場合exec系関数は何も返さないつまり帰った場合すべてエラー
    execl(target, target, NULL);
    
    fprintf(stderr, "failed at executing target.");
    exit(1);
}

//アドレスの値の入力の受け入れてそれをもとにブレークポイントを設定する関数を呼び出す
void p_setbreakpoint(int pid)
{   
    char str_address[17];
    
    unsigned long long int break_address;

    printf("ブレークポイントを設定します．\n");
    printf("ブレークポイントを設定したいアドレスを入力．\n");
    //アドレスの文字列を受け入れ，文字列であるから方を変換して，
    fgets(str_address, 17, stdin);
    break_address = (unsigned long long int)strtol(str_address, NULL, 16);
    printf("%016llx\n", break_address);
    // そのアドレスをもとにブレークポイントを設置
    set_break(pid, break_address);

    return;
}

void removebreakpoint(int pid)
{
    char str_address[17];
    
    unsigned long long int break_address;
    unsigned long long int text;
    unsigned long long int b_text;

    printf("ブレークポイントを削除します．\n");
    printf("ブレークポイントを削除したいアドレスを入力．\n");
    //アドレスの文字列を受け入れ，文字列であるから方を変換して，
    fgets(str_address, 17, stdin);
    break_address = (unsigned long long int)strtol(str_address, NULL, 16);
    printf("%016llx\n", break_address);
    // そのアドレスをもとにブレークポイントを設置
    //set_break(pid, break_address);
    text = node_findtext(list, break_address);
    if(0 == text){
        //リスト上にあるアドレスと指定されたアドレスが一致しなかった場合
        printf("指定されたアドレスにブレークポイントは存在しません.\n");
        return ;
    }
    printf("リスト上にブレークポイントを発見しました\n");

    b_text = ptrace(PTRACE_PEEKTEXT, pid, break_address, 0);
    if(b_text == -1){
        printf("メモリ内容の保存に失敗\n");
        exit(1);
    }
    printf("ブレークが行われる命令から８バイトのメモリ内容 :%016llx\n", b_text);
    printf("ブレークポイントのrip: %016llx\n",break_address);

    ptrace(PTRACE_POKETEXT, pid, break_address, ((b_text & 0xFFFFFFFFFFFFFF00) |(text & 0x00000000000000FF)));

    //上の操作が行われたかの確認
    b_text = ptrace(PTRACE_PEEKTEXT, pid, break_address -1, 0);
    if(b_text == -1){
        printf("メモリ内容の保存に失敗\n");
        exit(1);
    }
    printf("ブレークポイントが削除された命令内容 :%016llx\n", b_text);
    //ブレークポイントリストからブレークポイントを削除することを試みる．
    if(0 == nodeDelete(&list, node_findcnt(list, break_address))){
        printf("ブレークポイントリストからブレークポイントを削除できませんでした．\n");
    }
    return ;
}



//子プロセスが停止した際にその原因がブレークポイントであるかの確認をしそうだったときのみ
//ブレークポイントの0xCC命令をもとの命令に戻しまたブレークポイントのリストからも削除する
unsigned long long int p_removebreakpoint(pid_t pid)
{

    struct user_regs_struct regs;
    unsigned long long int b_text;
    unsigned long long int text;
    unsigned long long int address;

    //レジスタの値を保存しripの値を見るそのアドレスが
    ptrace(PTRACE_GETREGS, pid, 0, &regs);
    address = regs.rip;
    printf("ブレークしたアドレス :%016llx\n", address);

    //ブレークポイントのリスト上にさっき停止したアドレスと一致するものがあるかの確認
    //つまり子プロセスの停止原因がデバッガが設定したブレークポイントであるかの確認
    // -1 しているのはaddressが0xCCを指すようにするため
    //停止した原因がブレークポイントつまり１バイト命令の0xCCだったときその命令が実行された直後に
    //プログラムは停止するから-1することでaddressは0xCCを指す
    //逆にそうでなかった場合命令長も異なるため0xCCでないものつまりブレークポイント以外のものであることがわかる
    text = node_findtext(list, address - 1);

    if(0 == text){
        //リスト上にある命令停止したアドレスが一致しなかった場合
        printf("デバッガが設定したブレークポイントによる停止ではありませんでした.\n");
        return -1;
    }
    //リスト上の過去に設定したブレークポイントのアドレスと
    //今回停止したアドレスに一致するものがあった場合
    printf("リスト上にブレークポイントを発見しました\n");

    //現在の停止したメモリ内容８バイトを保存
    b_text = ptrace(PTRACE_PEEKTEXT, pid, address-1, 0);
    if(b_text == -1){
        printf("メモリ内容の保存に失敗\n");
        exit(1);
    }
    printf("ブレークが行われた命令から８バイトのメモリ内容 :%016llx\n", b_text);
    printf("現在のrip: %016llx\n",address);

    //また同じ命令を行うためにripの値を一つ戻してあげる
    //ブレークポイントの命令長はccの1バイトである
    regs.rip -= 1;

    //レジスタを設定
    ptrace(PTRACE_SETREGS, pid, 0, &regs);

    //ブレークが行われたメモリ内容からブレークポイントのリストをもとに0xCCをなくし，もともとのメモリ内容に戻す．
    //マスクを使って下位１バイトのみが変更されるようにしている
    ptrace(PTRACE_POKETEXT, pid, address - 1, ((b_text & 0xFFFFFFFFFFFFFF00) |(text & 0x00000000000000FF)));

    //上の操作が行われたかの確認
    b_text = ptrace(PTRACE_PEEKTEXT, pid, address -1, 0);
    if(b_text == -1){
        printf("メモリ内容の保存に失敗\n");
        exit(1);
    }
    printf("ブレークポイントが削除された命令内容 :%016llx\n", b_text);
    //ブレークポイントリストからブレークポイントを削除することを試みる．
    if(0 == nodeDelete(&list, node_findcnt(list, address-1))){
        printf("ブレークポイントリストからブレークポイントを削除できませんでした．\n");
    }
    //ブレークポイントが設定されていたアドレスを返す．
    return address -1;
}

//動作を再開するだけ
void p_continue(int pid)
{   
    ptrace(PTRACE_CONT, pid, 0, 0);
    printf("----------------------------------------------------\n");
    p_wait(pid);
    return;
}

// ステップをするだけ
void p_step(int pid)
{   
    ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
    p_wait(pid);
    return;
}

//レジスタの値を構造体に保存しそれを返す．
struct user_regs_struct p_getregs(int pid)
{
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, 0, &regs);
    return regs;
}
// レジスタの値を表示
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
    
    return;
}

// ヘルプ（使い方）を表示
void print_help()
{
    
    printf(">s ステップ実行\n");
    printf(">c 停止したプロセスの動作再開\n");
    printf(">b ブレークポイントの設置\n");
    printf(">d ブレークポイントの削除\n");
    printf(">ib 設置したブレークポイントの表示\n");
    printf(">m メモリの内容の表示\n");
    printf(">r レジスタの値の表示\n");
    printf(">sr レジスタの値の書き換え\n");
    printf(">sc ステップ実行を一定時間繰り返し変更があったレジスタの色を変更する\n");
    printf(">h 使い方の表示\n");
    printf(">q 終了\n");
    return;
}

//メモリの内容を表示
void showmemory(int pid)
{
    char str_address[17];
    unsigned long long int address;
    char str_count[4];
    int count; 
    printf("表示したいメモリのアドレスを入力 :");
    fgets(str_address, 17, stdin);
    address = (unsigned long long int)strtol(str_address, NULL, 16);
    printf("８バイトずつ表示しますが何回繰り返しますか？ :");
    fgets(str_count, 4, stdin);
    
    count = (int)strtol(str_count, NULL, 10);
    printf("%016llx\n", address);
    // 繰り返す回数リピート
    for(int i=0;i<count;i++){
        //８バイトずつ表示されるためi*8をすることで重複したメモリ内容を表示することを避けながら
        //指定されたアドレス付近のメモリ内容を表示
        printf("%016lx\n", ptrace(PTRACE_PEEKTEXT, pid, address + 8*i, 0));
    }printf("\n");
    return;
}

//ブレークポイントを監視しながらステップ実行
void stepping(int pid)
{
    struct user_regs_struct regs;
    unsigned long long int text;
    unsigned long long int address;

    //レジスタの値を取得
    regs = p_getregs(pid);
    
    //停止した原因がブレークポイントであったかどうかの確認
    text = ptrace(PTRACE_PEEKTEXT, pid, regs.rip -1 , 0);
    if( 0xCC == ((text & 0x00000000000000FF))){
        //そうであった場合
        //ブレークポイントを一旦削除
        //この関数はブレークポイントが設定されていたアドレスを返すから
        //そのアドレスと同じ場所に再度ブレークポイントを設定すると
        //ブレークポイントが設定された状態を保てる
        address = p_removebreakpoint(pid);

        //命令を一つ進める
        //ここではブレークポイントがあった場所のもともとの命令を実行する
        p_step(pid);
        //同じ場所にブレークポイントを設置
        //このときすでにaddress上にある命令は実行済み
        //つまり子プロセスに繰り返しの処理などによって同じ命令が繰り返される
        //ことがない限りブレークはしない
        set_break(pid, address);
            
    }else{
        //停止した原因がブレークポイントでない場合そのままステップ
        p_step(pid);
    }
    return;
}

//レジスタの値を変更する
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
    printf("変更したいレジスタの番号を選択してください :");
    //入力を受け入れる
    fgets(str_cnt, 10, stdin);
    //受け入れた値の型を文字列から整数に
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
    
    return;
}

// ブレークポイントの監視をしながら停止したプロセスの動作の再開
void continueing(int pid)
{

    // マスクをして停止したアドレスが0xCCつまりブレークポイントであった場合は，
    // そのブレークポイントを一旦もとの命令に戻し，ステップ実行によって命令を一つ進める．こうすることによってもとのプログラムの通りに動作する
    // そして，また同じ場所にブレークポイントを設置する．
    // こうすることによってブレークする以前のブレークポイントがあった状態を保とうとしている．
    struct user_regs_struct regs;
    unsigned long long int text;
    unsigned long long int address;
    //レジスタを一旦構造体として保存
    regs = p_getregs(pid);
    //現在のブレークする一つ前のメモリの状態８バイトを保存

    text = ptrace(PTRACE_PEEKTEXT, pid, regs.rip -1 , 0);
    
    if( 0xCC == ((text & 0x00000000000000FF))){
        //プログラムが停止した原因がブレークポイントであった場合の処理
        //ブレークポイントをもとの命令に戻す
        address = p_removebreakpoint(pid);
        //ステップ実行をして命令を一つ進める．
        p_step(pid);
        // ブレークポイントを再度設定する
        set_break(pid, address);
        // 動作を再開
        p_continue(pid);
    }else{
        //プログラムが停止した原因がデバッガが設定したブレークポイント出なかった場合の処理
        //動作を再開
        p_continue(pid);
    }
    return;
}

//１ミリ秒あたりの命令実行回数を制限し，
//毎回ステップ実行を行うことによって直前のレジスタと今のレジスタの値の違いを調べる．
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
    printf("1ミリ秒あたりの命令実行回数を入力: ");
    fgets(str, 10, stdin);
    cyc = atoi(str);
    while(1){
        long long int inlong;
        // ステップ実行
        p_step(pid);
        
        //レジスタの値を取ってくる
        regs2 = p_getregs(pid);

        inlong = regs2.rip - regs1.rip;

        if(inlong > 0){
            printf("%srip: %016llx\n%s", leser ,regs2.rip, KNRM);   
        }else if(inlong < 0){
            printf("%srip: %016llx\n%s", biger ,regs2.rip, KNRM);   
        }
        else{
            printf("rip: %016llx\n", regs2.rip);
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
    return;
    
}

//ripのレジスタの値のみを表示
void showrip(int pid)
{   
    //レジスタの値を構造体に保存しripの値を表示
    struct user_regs_struct regs;
    regs = p_getregs(pid);
    printf("rip: 0x%llx\n", regs.rip); 
    return;

}

//デバッガ本体の処理
void run_debugger(int pid, int attach)
{   
    
    printf("デバッガが起動しました.\n");
    printf("\"h\" と入力することで使い方を表示します．\n");

    printf("子プロセスのプロセスIDは  %d \n", pid);
    p_wait(pid);
            // 以下でデバッガの操作を行うキー入力に対する処理
            // 
    while(1){
        char str[20];
        
        showrip(pid);
        printf(">");
        fgets(str, 20, stdin);
        if(!strcmp(str,"b\n")){
            // ブレークポイントの設置
            p_setbreakpoint(pid);
        }
        else if(!strcmp(str, "c\n")){
            // 停止したプロセスの動作の再開
            continueing(pid);
        }
        else if(!strcmp(str, "r\n")){
            // レジスタの値を表示
            p_showregs(pid);
        }
        else if(!strcmp(str, "sr\n")){
            // レジスタの値を設定
            setregs(pid);
        }
        else if(!strcmp(str, "d\n")){
            // ブレークポイントを消去            
            removebreakpoint(pid);            
        }        
        else if(!strcmp(str, "ib\n")){
            // 設定されたブレークポイントを表示
            listPrint(list);
        }
        else if(!strcmp(str, "s\n")){
            // ステップ処理
            stepping(pid);
        }
        else if(!strcmp(str, "q\n")){
            // 子プロセスをデタッチし，そして子プロセスを終了させ，親プロセスも終了
            if(attach == 1){
                ptrace(PTRACE_DETACH, pid, NULL, NULL);
            }
            ptrace(PTRACE_KILL,pid, 0, 0);
            break;
        }
        else if(!strcmp(str, "m\n")){
            // メモリの内容を表示
            showmemory(pid);
        }
        else if(!strcmp(str, "h\n")){
            // ヘルプを表示
            print_help();
        }
        else if(!strcmp(str, "sc\n")){
            // ステップ実行を繰り返し変更があったレジスタの色を変更する．モード
            change_regs_color(pid);
        }
        else{
            // それ以外のキー入力があったときの処理
            printf("unexpected.\n");  
        }  
    }
    return;
}

