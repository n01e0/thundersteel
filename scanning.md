# How to port scan.
Client is scanner.
Server is target.

## SYN scan
ポートが空いている場合は

1. Client: send SYN packet
1. Server: send SYN|ACK packet
1. Client: send ACK packet (実際のポートスキャンではここまで行う必要はない)

3way handshakeによりコネクションを確立する(できる)

空いていない場合

1. Client: send SYN packet
1. Server: send RST|ACK packet

サーバにより、RSTパケットが送り返されて終了する。

**これでポートの状態がわかる。**

## FIN scan
1. Client: send FIN packet
1. Server: send RST packet

コネクション張ってないのにFINパケットだけ送る。

意味わからんけど、これに大して[RFC793](https://tools.ietf.org/html/rfc793)に厳密に準拠した実装を行っているTCPサーバは

**ポートが閉じている場合、RSTパケットを返信する。**

## NULL scan
TCPのコントロールフラグを何も立てずに送信する。FINスキャンと同じ挙動。

## X-mas scan
1. Client: send FIN|URG|PSH packet
1. Server: send RST packet

FIN|URG|PSHのフラグ立ったパケットを送信する。FINスキャンと同じ挙動。
