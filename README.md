# Strader

シンプルでわかりやすいデバッガを作ることで自分みたいなライトユーザーや初心者にも使いやすいはず！！
This is a debugger it is simple and it is tracer or debugger, so I named "Strader".
I made this to learn what is happening in debugger and executable file and process.
It was hard to make Strader because there are few way to verify debugger works correctly.


## 使い方 How to use Strader

./strader ＜デバッグ対象/Debug target＞

実行中のプロセスもデバッグ可能 Strader can debug running process
./strader   実行の後 Firstly run only Strader, then type processID  
プロセスIDを入力

＞b ブレークポイントの設置  setting breakpoint 
＞ｓ ステップ実行  step into execution
＞ｃ  停止したプロセスの動作再開   Continue, It means restart the process.  
＞d ブレークポイントの削除  delete breakpoint
＞ib 設置したブレークポイントの表示  show breakpoint what I had set
＞ｍ メモリの内容の表示  show content in memory
＞r  レジスタの値の表示  show register values
＞sr  レジスタの値の書き換え  rewrite register value.
＞sc  ステップ実行を一定時間繰り返し変更があったレジスタの色を変更する  Repeat the step into execution and show register values every execution then if register values was changed, change values color.  
＞h   使い方の表示  show how to use Strader
＞q デバッグの終了 quit debugging
  
scではレジスタの値が変わっていることがわかるが、
値が変わったときに色が変わるようにしている。

## コンパイル Complile
make 
