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


#include "strader.h"


//子プロセスを生成し，親プロセスではデバッガを子プロセスではデバッグ対象になる
int main(int argc, char** argv){
    pid_t child_pid;
    printf("\
.▄▄ · ▄▄▄▄▄▄▄▄   ▄▄▄· ·▄▄▄▄  ▄▄▄ .▄▄▄  \n\
▐█ ▀. •██  ▀▄ █·▐█ ▀█ ██▪ ██ ▀▄.▀·▀▄ █·\n\
▄▀▀▀█▄ ▐█.▪▐▀▀▄ ▄█▀▀█ ▐█· ▐█▌▐▀▀▪▄▐▀▀▄ \n\
▐█▄▪▐█ ▐█▌·▐█•█▌▐█ ▪▐▌██. ██ ▐█▄▄▌▐█•█▌\n\
 ▀▀▀▀  ▀▀▀ .▀  ▀ ▀  ▀ ▀▀▀▀▀•  ▀▀▀ .▀  ▀\n\
");
    // コマンドライン引数がなかったときの処理
    if (argc < 2){
        char strpid[32];
        int intpid;
        // ここから始まる

        printf("すでに動作しているプロセスをデバッグするときはプロセスIDを入力.\n");
        printf("type \"q\" to quit.\n > ");
        fgets(strpid ,sizeof(strpid) , stdin);
        if(!strcmp(strpid, "q\n")){
            exit(1);
            // コマンドライン引数がなかった場合の処理でq 意外であった場合は文字列はプロセスIDとして
            // 認識しそのプロセスIDのすでに動作しているプロセスのアタッチを試みる
            run_debugger(intpid, 1);
        }
        // 与えられたプロセスIDのプロセスのアタッチを試みる
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
    //コマンドライン引数があったときの処理
    //子プロセスを生成
    child_pid = fork();
    if (child_pid == 0){
        //子プロセスではコマンドライン引数のプログラムを実行
        run_target(argv[1]);
    }
    else if (child_pid > 0){
        // 親プロセスではデバッガを実行
        run_debugger(child_pid, 0);
    }
    else {
        fprintf(stderr, "error at forking target");
        exit(1);
    }
    return 0;
}
