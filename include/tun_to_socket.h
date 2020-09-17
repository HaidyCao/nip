//
// Created by Haidy on 2020/6/18.
//

#ifndef NETWORK_TUN_TO_SOCKET_H
#define NETWORK_TUN_TO_SOCKET_H

#include "ip_proto.h"
#include "tcp.h"
#include "socks/lib/c_sparse_array.h"
#include "socks/lib/c_linked_list.h"
#include "tcp_window.h"
#include "buf.h"

struct tun_to_socket;
typedef struct tun_to_socket TunToSocket;

struct tts_socket;
typedef struct tts_socket Socket;

typedef int (*tts_func_accept)(TunToSocket *tts, Socket *socket);

typedef int (*tts_func_close)(TunToSocket *tts, Socket *socket);

typedef int (*tts_func_output)(TunToSocket *tts, Socket *socket, char *buf, size_t len);

typedef int (*tts_func_err)(TunToSocket *tts, Socket *socket, int err, void *arg);

struct tts_socket {
    uint32_t id;
    TunToSocket *tts;

    uint32_t last_client_seq;   // last client seq
    uint32_t expect_ack;        // ack

    uint32_t src;
    uint32_t dest;

    uint16_t src_port;
    uint16_t dest_port;

    short status;
    tts_func_output func_read;
    tts_func_close func_close;
    tts_func_err func_err;

    TCP_WINDOW *window_send;            // tcp window for send data
    TCP_WINDOW *window_recv;            // tcp window for receive data
    uint32_t client_window_left_size;   // the size of client window left

    void *arg;

    struct packet_buf *out_buf;         // the buffer of ready send to tun
    int close;                          // tts_close called
};

struct tun_to_socket {
    size_t mtu;                         // default 1400

    CSparseArray *socket_array;         // socket map
    CLinkedList *buf_pool;

    void *arg;                          // arg

    tts_func_accept func_accept;
    tts_func_output func_output;

};

TunToSocket *tun_to_socket_init();

int tts_tcp_input(TunToSocket *tts, IP_PROTO *ip, TCP_PROTO *tcp);

int tts_tcp_write(Socket *socket, const char *buf, size_t len);

int tts_tcp_send(Socket *socket);

/**
 * close socket
 *
 * @param socket socket
 * @return close result
 */
int tts_close(Socket *socket);

#endif //NETWORK_TUN_TO_SOCKET_H
