
// #ifndef BREAKPOINT_LIST_H
// #define BREAKPOINT_LIST_H

#include <stdio.h>
#include <stdlib.h>


# define SUCCESSFUL 1
# define FAILURE 0

typedef unsigned long long int data_t;

//構造体の作成
typedef struct nodetag{

    //ブレークポイントのアドレス
    data_t address;

    //ブレークポイントを設定する命令内容
    data_t text;

    //次の構造体へのアドレス
    struct nodetag *next;
}node_t;


// ブレークポイントをヒープ領域に保存するためのリンクドリスト


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
// リストの中身を表示
int listPrint(node_t *ndPtr){
    //一番最後の構造体では次の構造体へのポインタにNULLが設定されているため
    //NULLが出るまで繰り返す
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

// #endif