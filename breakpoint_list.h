#include <stddef.h>

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

node_t *list = NULL;

node_t *nodeNew(data_t dt, data_t dt2, node_t *nxt);

int nodeAppend(node_t**ndPtrPtr, data_t address, data_t text);

int listPrint(node_t *ndPtr);

int node_findtext(node_t *ndPtr, data_t address);

int node_findcnt(node_t *ndPtr, data_t address);

int nodeDelete(node_t **ndPtrPtr, int n);