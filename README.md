# Strader

シンプルでわかりやすいデバッガを作ることで自分みたいなライトユーザーや初心者にも使いやすいはず！！


## 使い方

./strader ＜デバッグ対象＞

実行中のプロセスもデバッグ可能
./strader
＜対象プロセスid＞



＞b ブレークポイントの設置
＞ｓ ステップ実行
＞ｃ  コンテニュー
＞d ブレークポイントの削除
＞ib 設置したブレークポイントの表示
＞ｍ メモリの内容の表示
＞r  レジスタの値の表示
＞sr  レジスタの書き換え
＞sc  任意の時間おきにステップ実行をするレジスタの値がどのように変化していっているのかがわかる。
＞h   使い方の表示


scではレジスタの値が変わっていることがわかるが、
値が変わったときに色が変わるようにしている。
