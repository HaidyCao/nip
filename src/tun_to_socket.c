//
// Created by Haidy on 2020/6/18.
//

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "log.h"
#include "tun_to_socket.h"
#include "tcp_status.h"
#include "checksum.h"
#include "nip_err.h"
#include "buf.h"
#include "utils.h"
#include "list.h"

// Maximum Segment Lifetime
#define TCP_MSL 120
#define TCP_2MSL (2 * TCP_MSL)

#define SOCKET_OUT_BUFFER_MAX 102400

struct time_wait {
    Socket *socket;
    time_t t;
};

static uint16_t ip_identification = 0;
static LinkList *time_wait_list = NULL;
static bool write_out_enable = false;

static int64_t gen_socket_key(uint32_t src, uint16_t src_port);

static void Socket_free(TunToSocket *tts, Socket *socket);

static void time_wait_list_init() {
    if (time_wait_list != NULL) {
        return;
    }

    time_wait_list = LinkList_new();
}

static void remove_expire_socket() {
    struct timespec ts;
    clock_gettime(CLOCK_BOOTTIME, &ts);
    time_t now = ts.tv_sec;

    time_wait_list_init();

    while (true) {
        struct time_wait *v = LinkList_header(time_wait_list);

        if (v == NULL || now - v->t < TCP_2MSL) {
            break;
        }
        LinkList_remove_header(time_wait_list);
        Socket_free(v->socket->tts, v->socket);
    }
}

static bool is_socket_in_wait_list(uint32_t src_ip, uint16_t src_port) {
    void *it = LinkList_iterator(time_wait_list);
    time_wait_list_init();

    while (it) {
        struct time_wait *v = LinkList_value(it);
        if (v->socket->src == src_ip && v->socket->src_port == src_port) {
            return true;
        }

        it = LinkList_next(it);
    }
    return false;
}

static void socket_time_wait(Socket *socket) {
    // remove from tss
    NIP_LOGD("put socket to wait list");
    int64_t key = gen_socket_key(socket->src, socket->src_port);
    CSparseArray_remove(socket->tts->socket_array, key);

    remove_expire_socket();

    struct timespec ts;
    clock_gettime(CLOCK_BOOTTIME, &ts);

    time_wait_list_init();

    struct time_wait *end = malloc(sizeof(struct time_wait));
    end->socket = socket;
    end->t = ts.tv_sec;

    LinkList_add(time_wait_list, end);
}

static uint16_t get_ip_identification() {
    return ip_identification++;
}

static void hexDump(char *buf, int len, int addr) {
    int i, j, k;
    char binstr[80];

    for (i = 0; i < len; i++) {
        if (0 == (i % 16)) {
            sprintf(binstr, "%08x -", i + addr);
            sprintf(binstr, "%s %02x", binstr, (unsigned char) buf[i]);
        } else if (15 == (i % 16)) {
            sprintf(binstr, "%s %02x", binstr, (unsigned char) buf[i]);
            sprintf(binstr, "%s  ", binstr);
            for (j = i - 15; j <= i; j++) {
                sprintf(binstr, "%s%c", binstr, ('!' < buf[j] && buf[j] <= '~') ? buf[j] : '.');
            }
            __android_log_print(ANDROID_LOG_DEBUG, "hex", "%s\n", binstr);
        } else {
            sprintf(binstr, "%s %02x", binstr, (unsigned char) buf[i]);
        }
    }
    if (0 != (i % 16)) {
        k = 16 - (i % 16);
        for (j = 0; j < k; j++) {
            sprintf(binstr, "%s   ", binstr);
        }
        sprintf(binstr, "%s  ", binstr);
        k = 16 - k;
        for (j = i - k; j < i; j++) {
            sprintf(binstr, "%s%c", binstr, ('!' < buf[j] && buf[j] <= '~') ? buf[j] : '.');
        }
        __android_log_print(ANDROID_LOG_DEBUG, "hex", "%s\n", binstr);
    }
}

static uint32_t socket_id = 1;

static int handle_tcp_FIN_WAIT_1(TCP_PROTO *tcp, Socket *socket);

static int handle_tcp_FIN_WAIT_2(IP_PROTO *ip, TCP_PROTO *tcp, Socket *socket);

static Socket *Socket_new() {
    Socket *socket = calloc(1, sizeof(Socket));
    socket->id = socket_id;
    socket_id++;
    return socket;
}

static void Socket_free(TunToSocket *tts, Socket *socket) {
    if (socket == NULL) {
        return;
    }

    if (socket->func_close) {
        socket->func_close(tts, socket);
    }

    TCP_WINDOW_free(socket->window_send);
    TCP_WINDOW_free(socket->window_recv);

    PacketBuf_free(tts->buf_pool, socket->out_buf);
    free(socket);
}

static uint32_t random_seq() {
    return ((uint16_t) random()) / 2;
}

static int64_t gen_socket_key(uint32_t src, uint16_t src_port) {
    uint64_t ret = src_port;
    ret = ret << ((uint32_t) 32) & (0xFFFFFFFF00000000);
    ret = ret | (src & 0x00000000FFFFFFFF);
    return (int64_t) ret;
}

TunToSocket *tun_to_socket_init() {
    NIP_LOGD("init");
    TunToSocket *tts = calloc(1, sizeof(TunToSocket));
    tts->mtu = 1400;

    tts->socket_array = CSparseArray_new();
    tts->buf_pool = c_linked_list_new();

    return tts;
}

static int tcp_handshake1(TunToSocket *tts, IP_PROTO *ip, TCP_PROTO *tcp) {
    PacketBuf *buf = PacketBuf_new(tts->buf_pool, tts->mtu);
    buf->len = IP_TOTAL_LEN(ip->header);
    buf->index = 0;
    memcpy(buf->data, ip->data, buf->len);
    hexDump(ip->data, IP_TOTAL_LEN(ip->header), 0);

    IP_PROTO ip_resp;
    ip_resp.header = buf->data;
    ip_resp.data = buf->data;

    TCP_PROTO tcp_resp;
    tcp_init_with_data(&tcp_resp, &ip_resp);

    ip_resp.header->src = ip->header->dest;
    ip_resp.header->dest = ip->header->src;
    tcp_resp.header->src_port = tcp->header->dest_port;
    tcp_resp.header->dest_port = tcp->header->src_port;

    tcp_resp.header->ACK = 1;
    uint32_t seq = random_seq();
    tcp_resp.header->seq = htonl(seq);

    tcp_resp.header->ack = htonl(ntohl(tcp->header->seq) + 1);

    // create socket and save to tts handshake map
    Socket *socket = Socket_new();
    socket->tts = tts;
    socket->expect_ack = htonl(seq + 1);

    socket->src = ip->header->src;
    socket->dest = ip->header->dest;
    socket->src_port = tcp->header->src_port;
    socket->dest_port = tcp->header->dest_port;
    socket->status = TCP_STATUS_SYN_RECV;

    tcp_parse_options(tcp);

    uint32_t tcp_win_size = tcp_window_size(tcp);
    socket->window_send = TCP_WINDOW_new_with_size(tcp_win_size);
    socket->window_recv = TCP_WINDOW_new();
    socket->client_window_left_size = tcp_window_size(tcp);

    tcp_clear_options(&tcp_resp);
    if (tcp->SACK) {
        tcp_add_sack_option(&tcp_resp);
    }

    ip_resp.header->identifier = htons(get_ip_identification());
    ip_resp.header->R = 0;
    ip_resp.header->DF = 1;
    ip_resp.header->MF = 0;
    ip_resp.header->ttl = 0xff;

    uint16_t offset = 0;
    SET_IP_OFFSET((&ip_resp), offset);

    ip_resp.header->total_len = htons(IP_HEADER_LEN(ip->header) + TCP_HEADER_LEN(tcp_resp.header));
    tcp_resp.header->window_size = htons(TCP_WINDOW_DEFAULT_SIZE);
    tcp_checksum(&ip_resp, &tcp_resp);

    int result = -1;
    if (tts->func_output != NULL) {
        int64_t key = gen_socket_key(socket->src, socket->src_port);
        NIP_LOGE("key = %ju", key);
        CSparseArray_put(tts->socket_array, key, socket);
        hexDump(ip_resp.data, IP_TOTAL_LEN(ip_resp.header), 0);

        result = tts->func_output(tts, socket, ip_resp.data, IP_TOTAL_LEN(ip_resp.header));
    }
    PacketBuf_free(tts->buf_pool, buf);

    return result;
}

/**
 * finish tcp handshake
 *
 * @param tts TunToSocket
 * @param tcp TCP_PROTO
 * @param socket Socket
 * @return -1 failure else success
 */
static int tcp_handshake_end(TunToSocket *tts, TCP_PROTO *tcp, Socket *socket) {
    int result = NIP_ERR_NOT_IMPL;
    if (tts->func_accept != NULL) {
        result = tts->func_accept(tts, socket);
    }
    if (result == NIP_OK) {
        NIP_LOGE("seq = %d", ntohs(tcp->header->seq));
        socket->last_client_seq = tcp->header->seq;
        socket->status = TCP_STATUS_ESTABLISHED;
    }
    return result;
}

static void
init_tcp_ip_response_by_socket(IP_PROTO *ip, TCP_PROTO *tcp, Socket *socket, uint32_t ack) {
    ip_init_from_empty_data(ip);
    ip->header->src = socket->dest;
    ip->header->dest = socket->src;

    tcp_init_with_data(tcp, ip);
    tcp->header->src_port = socket->dest_port;
    tcp->header->dest_port = socket->src_port;
    tcp->header->seq = socket->expect_ack;
    tcp->header->ack = ack;
    tcp->header->header_len = TCP_HEADER_DEFAULT_LEN / 4;
    tcp->header->rsv_1 = 0;
    tcp->header->rsv_2 = 0;
    tcp->header->URG = 0;
    tcp->header->ACK = 1;
    tcp->header->PSH = 0;
    tcp->header->RST = 0;
    tcp->header->SYN = 0;
    tcp->header->FIN = 0;
    tcp->header->window_size = TCP_WINDOW_DEFAULT_SIZE;
    tcp->header->checksum = 0;
    tcp->header->urgent_pointer = 0;
}

static int
tcp_send_ACK_without_data(TunToSocket *tts, Socket *socket, uint32_t ack, uint8_t window_scale) {
    int result = NIP_ERR_NOT_IMPL;
    PacketBuf *buf = PacketBuf_new(tts->buf_pool, tts->mtu);
    IP_PROTO ip;
    ip.data = buf->data;

    TCP_PROTO tcp;
    init_tcp_ip_response_by_socket(&ip, &tcp, socket, ack);

    if (window_scale > 0) {
        tcp_add_window_scale_option(&tcp, window_scale);
    }
    tcp_checksum(&ip, &tcp);

    if (tts->func_output != NULL) {
        result = tts->func_output(tts, socket, ip.data, IP_TOTAL_LEN(ip.header));
    }

    PacketBuf_free(tts->buf_pool, buf);
    return result;
}

static int handle_tcp_ACK(TunToSocket *tts, IP_PROTO *ip, TCP_PROTO *tcp, Socket *socket) {
    NIP_LOGD("");
    int result = NIP_ERR_NOT_IMPL;

    if (socket->window_send->send_not_ack_count > 0) {
        NIP_LOGD("nip expect ack = %d", ntohl(socket->expect_ack));
        TCP_WINDOW *window = socket->window_send;
        uint32_t expect_ack = ntohl(socket->expect_ack);
        uint32_t ack = ntohl(tcp->header->ack);

        if (expect_ack == ack) {
            // update socket send window
            if (window->send_not_ack_count == window->data_len) {
                NIP_LOGD("%zu data is ack, reset window", window->send_not_ack_count);
                window->data_len = 0;
                window->data_index = 0;
                window->send_not_ack_count = 0;
            } else {
                window->data_len -= window->send_not_ack_count;
                window->data_index += window->send_not_ack_count;
                window->send_not_ack_count = 0;
            }
        } else /*if (expect_ack > ack)*/ {
            int32_t received_len = window->data_len - (expect_ack - ack);
            NIP_LOGD("received count = %d", received_len);
            if (received_len < 0) {
                return NIP_ERR_BAD_DATA;
            } else if (received_len > 0) {
                window->data_index += received_len;
                window->data_len -= received_len;
                window->send_not_ack_count -= received_len;

                if (window->data_index > (window->window_size > 2)) {
                    memcpy(window->window, window->window + window->data_index, window->data_len);
                }
            }
        }

        result = NIP_OK;
    }

    // read data from client
    size_t header_len = IP_HEADER_LEN(ip->header) + TCP_HEADER_LEN(tcp->header);
    size_t tcp_date_len = IP_TOTAL_LEN(ip->header) - header_len;
    if (tcp_date_len != 0) {
        uint32_t last_seq = ntohl(socket->last_client_seq);
        uint32_t seq = ntohl(tcp->header->seq);
        if (last_seq > seq) {
            NIP_LOGD("seq = %u is received", seq);
            result = tcp_send_ACK_without_data(tts, socket, socket->last_client_seq,
                                               tcp->window_scale);
        } else if (socket->window_recv->data_len + tcp_date_len >=
                   socket->window_recv->window_size) {
            // send ACK for window full
            if (socket->window_recv->data_len + tcp_date_len == socket->window_recv->window_size) {
                char *data = ip->data + header_len;
                memcpy(socket->window_recv->window + socket->window_recv->data_len, data,
                       tcp_date_len);

                if (socket->func_read != NULL) {
                    result = socket->func_read(tts, socket, socket->window_recv->window,
                                               socket->window_recv->window_size);
                }
            } else {
                if (socket->func_read != NULL) {
                    // send data of recv window
                    result = socket->func_read(tts, socket, socket->window_recv->window,
                                               socket->window_recv->data_len);

                    if (result != NIP_OK) {
                        return result;
                    }

                    // send data of current packet to client
                    char *data = ip->data + header_len;
                    result = socket->func_read(tts, socket, data, tcp_date_len);
                }
            }

            if (result != NIP_OK) {
                return result;
            }

            // send ACK for window freed
            socket->window_recv->data_len = 0;
            result = tcp_send_ACK_without_data(tts, socket, tcp->header->seq, tcp->window_scale);
        } else if (tcp->header->PSH) {
            // ip packet not full, should ACK
            TCP_WINDOW *window = socket->window_recv;
            char *data = ip->data + header_len;
            memcpy(window->window + window->data_index + window->data_len, data, tcp_date_len);
            window->data_len += tcp_date_len;

            if (socket->func_read != NULL) {
                result = socket->func_read(tts, socket, window->window + window->data_index,
                                           window->data_len);
            }

            if (result != NIP_OK) {
                return result;
            }

            NIP_LOGE("seq = %u", seq);
            window->data_len = 0;
            window->data_index = 0;
            // update seq add data length
            seq = htonl(seq + tcp_date_len);
            socket->last_client_seq = seq;
            result = tcp_send_ACK_without_data(tts, socket, seq, tcp->window_scale);
        } else {
            // put data to window and wait next packet
            char *data = ip->data + header_len;
            TCP_WINDOW *window = socket->window_recv;
            memcpy(window->window + window->data_index + window->data_len, data, tcp_date_len);
            window->data_len += tcp_date_len;
            NIP_LOGD("put data(%zu) to window: window length = %zu", tcp_date_len,
                     window->data_len);
            result = NIP_OK;
        }
    } else {
        socket->last_client_seq = tcp->header->seq;
    }

    if (result == -1) {
        return result;
    }

    // record last seq
    socket->client_window_left_size = tcp_window_size(tcp);

    // try send data to client
    return tts_tcp_send(socket);
}

static int handle_tcp_FIN(TunToSocket *tts, TCP_PROTO *tcp, Socket *socket) {
    NIP_LOGD("FIN");
    int result = NIP_ERR_NOT_IMPL;
    PacketBuf *buf = PacketBuf_new(tts->buf_pool, tts->mtu);
    socket->last_client_seq = tcp->header->seq;

    // init response data
    IP_PROTO ip_resp;
    ip_resp.data = buf->data;
    ip_resp.header = buf->data;

    TCP_PROTO tcp_resp;

    // update ack + 1
    int ack = htonl(ntohl(tcp->header->seq) + 1);
    init_tcp_ip_response_by_socket(&ip_resp, &tcp_resp, socket, ack);
    socket->expect_ack = ack;
    tcp_checksum(&ip_resp, &tcp_resp);

    if (tts->func_output != NULL) {
        NIP_LOGD("send response (ACK = 1) to client");
        result = tts->func_output(tts, socket, ip_resp.data, IP_TOTAL_LEN(ip_resp.header));
    }

    if (result == NIP_OK) {
        socket->status = TCP_STATUS_CLOSE_WAIT;
    }

    // check whether out buffer is empty, if it is set FIN = 1 and send to tun
    if (socket->out_buf == NULL || socket->out_buf->len == 0) {
        tcp_resp.header->ACK = 1;
        tcp_resp.header->FIN = 1;

        tcp_checksum(&ip_resp, &tcp_resp);

        if (tts->func_output != NULL) {
            NIP_LOGD("send response (ACK = 1, FIN = 1) to client");
            result = tts->func_output(tts, socket, ip_resp.data, IP_TOTAL_LEN(ip_resp.header));
        }

        if (result == NIP_OK) {
            socket->status = TCP_STATUS_LAST_ACK;
            socket->expect_ack = htonl(ntohl(tcp_resp.header->seq) + 1);
        }
    } else {
        // send last data
    }

    PacketBuf_free(tts->buf_pool, buf);
    return result;
}

static int handle_tcp_CLOSE_WAIT(TunToSocket *tts, IP_PROTO *ip, TCP_PROTO *tcp, Socket *socket) {
    int result = NIP_ERR_NOT_IMPL;

    PacketBuf *buf = PacketBuf_new(tts->buf_pool, tts->mtu);
    buf->len = IP_TOTAL_LEN(ip->header);
    buf->index = 0;
    memcpy(buf->data, ip->data, buf->len);

    IP_PROTO ip_resp;
    ip_resp.header = buf->data;
    ip->data = buf->data;

    TCP_PROTO tcp_resp;
    tcp_resp.header = (TCP_PROTO_HEADER *) buf->data + IP_HEADER_LEN(ip->header);
    tcp_resp.data = buf->data;

    ip_resp.header->src = ip->header->dest;
    ip_resp.header->dest = ip->header->src;
    tcp_resp.header->src_port = tcp->header->dest_port;
    tcp_resp.header->dest_port = tcp->header->src_port;

    tcp_resp.header->seq = tcp->header->ack;
    tcp_resp.header->ack = tcp->header->seq;

    size_t header_len = IP_HEADER_LEN(ip->header) + TCP_HEADER_LEN(tcp->header);
    buf->len = header_len;

    nip_out_buffer_to_window(socket, socket->window_send->window_size);
    if (TCO_WINDOW_not_send_data(socket->window_send) == 0
        && (socket->out_buf == NULL || socket->out_buf->len == 0)) {
        // send FIN = 1 to client, let them known we have not data anymore, just close socket
        tcp_resp.header->ACK = 1;
        tcp_resp.header->FIN = 1;

        ip_resp.header->total_len = htonl(buf->len);
        tcp_checksum(&ip_resp, &tcp_resp);

        if (tts->func_output != NULL) {
            result = tts->func_output(tts, socket, buf->data, buf->len);
        }

        if (result == NIP_OK) {
            // start wait last ACK from client
            socket->status = TCP_STATUS_LAST_ACK;
            socket->expect_ack = htonl(ntohl(tcp->header->ack) + 1);
        }
    } else {
        // send left data
        result = tts_tcp_send(socket);
    }

    PacketBuf_free(tts->buf_pool, buf);
    return result;
}

int tts_tcp_input(TunToSocket *tts, IP_PROTO *ip, TCP_PROTO *tcp) {
    if (tts == NULL) {
        NIP_LOGE("ip is NULL");
        return -1;
    }

    if (ip == NULL) {
        NIP_LOGE("buf is NULL");
        return -1;
    }

    if (tcp == NULL) {
        TCP_PROTO tcpProto;
        tcpProto.header = (TCP_PROTO_HEADER *) ip->data + IP_HEADER_LEN(ip->header);
        tcpProto.data = ip->data;

        return tts_tcp_input(tts, ip, &tcpProto);
    }

    NIP_LOGD("SYN = %d, ACK = %d, PSH = %d, FIN = %d", tcp->header->SYN, tcp->header->ACK,
             tcp->header->PSH, tcp->header->FIN);
    if (tcp->header->SYN == 1) {
        // check time wait list first
        remove_expire_socket();
        if (is_socket_in_wait_list(ip->header->src, tcp->header->src_port)) {
            NIP_LOGE("new handshake is in wait list");
            return -1;
        }

        if (tcp_handshake1(tts, ip, tcp) == -1) {
            NIP_LOGE("tcp_handshake1 failed");
            return -1;
        }
        return 0;
    } else if (tcp->header->ACK == 1) {
        write_out_enable = true;
        int64_t key = gen_socket_key(ip->header->src, tcp->header->src_port);
        Socket *socket = CSparseArray_get(tts->socket_array, key);

        if (socket) {
            if (socket->close) {
                NIP_LOGW("tcp closed");
                return NIP_ERR_CLOSED;
            }

            int result = NIP_ERR_NOT_IMPL;
            if (socket->status == TCP_STATUS_SYN_RECV) {
                result = tcp_handshake_end(tts, tcp, socket);
                if (result != NIP_OK) {
                    CSparseArray_remove(tts->socket_array, key);
                }
            } else if (socket->status == TCP_STATUS_ESTABLISHED) {
                if (tcp->header->FIN) {
                    result = handle_tcp_FIN(tts, tcp, socket);
                } else if (tcp->header->ACK) {
                    result = handle_tcp_ACK(tts, ip, tcp, socket);
                }
            } else if (socket->status == TCP_STATUS_CLOSE_WAIT) {
                result = handle_tcp_CLOSE_WAIT(tts, ip, tcp, socket);
            } else if (socket->status == TCP_STATUS_LAST_ACK) {
                NIP_LOGD("TCP LAST ACK");
                result = NIP_OK;
                CSparseArray_remove(tts->socket_array, key);
                Socket_free(tts, socket);
                socket = NULL;
            } else if (socket->status == TCP_STATUS_FIN_WAIT_1) {
                NIP_LOGD("wait for client close");
                result = handle_tcp_FIN_WAIT_1(tcp, socket);
            } else if (socket->status == TCP_STATUS_FIN_WAIT_2) {
                result = handle_tcp_FIN_WAIT_2(ip, tcp, socket);
            }

            if (result != NIP_OK) {
                NIP_LOGE("error = %d, str = %s", result, nip_error(result));
                if (socket->func_err != NULL) {
                    socket->func_err(tts, socket, result, tts->arg);
                }
                return result;
            }

            return result;
        } else {
            NIP_LOGE("find socket failed: key = %ju", key);
        }
    }

    return -1;
}

int tts_tcp_write(Socket *socket, const char *buf, size_t len) {
    int result;
    // put data to sending window
    TCP_WINDOW *window = socket->window_send;
    uint32_t window_left_size = window->window_size - window->data_len - window->data_index;

    if (len < window_left_size) {
        memcpy(window->window + window->data_index + window->data_len, buf, len);
        window->data_len += len;
        result = len;
    } else {
        memcpy(window->window + window->data_index + window->data_len, buf, window_left_size);
        window->data_len = window->window_size;

        // put data to out buffer
        size_t data_left = len - window_left_size;
        const char *data = buf + window_left_size;

        size_t buffer_size = 0;
        PacketBuf *buffer;
        if (socket->out_buf == NULL) {
            buffer = PacketBuf_new(socket->tts->buf_pool, socket->tts->mtu);
            socket->out_buf = buffer;
        } else {
            buffer = socket->out_buf;
            buffer_size = buffer->len;
            while (buffer->next != NULL) {
                buffer_size += buffer->next->len;
                buffer = buffer->next;
            }
        }

        while (data_left > 0 && buffer_size < SOCKET_OUT_BUFFER_MAX) {
            size_t cap = buffer->cap - buffer->index - buffer->len;
            if (data_left > cap) {
                memcpy(buffer->data + buffer->index + buffer->len, data, cap);
                data_left -= cap;
                data += cap;
                buffer->len += cap;

                buffer->next = PacketBuf_new(socket->tts->buf_pool, socket->tts->mtu);
                buffer = buffer->next;

                buffer_size += cap;
                continue;
            }

            memcpy(buffer->data + buffer->index + buffer->len, data, data_left);
            break;
        }

        result = buffer_size;
    }

    if (write_out_enable) {
        int send_result = tts_tcp_send(socket);
        if (send_result != NIP_OK) {
            NIP_LOGE("tcp_send error: %s", nip_error(send_result));
            return send_result;
        }
        write_out_enable = false;
    }

    return result;
}

/**
 * try send window data to client
 *
 * @param socket socket
 * @return result
 */
int tts_tcp_send(Socket *socket) {
    TCP_WINDOW *window = socket->window_send;
    nip_out_buffer_to_window(socket, window->window_size);

    if (window->data_len == 0) {
        if (socket->close) {
            return tts_close(socket);
        }
        return NIP_OK;
    }

    int result = NIP_ERR_NOT_IMPL;
    TunToSocket *tts = socket->tts;
    PacketBuf *buf = PacketBuf_new(tts->buf_pool, tts->mtu);
    IP_PROTO ip;
    ip.data = buf->data;
    ip.header = buf->data;

    TCP_PROTO tcp;
    init_tcp_ip_response_by_socket(&ip, &tcp, socket, socket->last_client_seq);

    int64_t left = socket->client_window_left_size;
    uint16_t header_len = IP_HEADER_LEN(ip.header) + TCP_HEADER_LEN(tcp.header);
    uint16_t packet_data_cap = buf->cap - header_len;

    size_t window_data_len = window->data_len - window->send_not_ack_count;
    size_t window_data_index = window->data_index + window->send_not_ack_count;

    uint32_t seq = socket->expect_ack;
    uint16_t packet_data_len = 0;   // the data length of a packet send to client
    if (left > 0 && window_data_len > 0) {
        while (left > 0 && window_data_len > 0) {
            if (socket->out_buf != NULL && socket->out_buf->len > 0) {
                size_t window_left_size =
                        window->window_size - window->data_index - window->data_len;
                if (window_left_size > 0) {
                    size_t c = nip_out_buffer_to_window(socket, window_left_size);
                    window_data_len += c;
                }
            }
            // packet_data_len = MIN(packet_data_cap, left, window_data_len)
            packet_data_len = left < packet_data_cap ? left : packet_data_cap;
            packet_data_len =
                    packet_data_len > window_data_len ? window_data_len : packet_data_len;

            memcpy(buf->data + header_len, window->window + window_data_index, packet_data_len);

            // update ip total length
            uint16_t packet_len = header_len + packet_data_len;
            ip.header->total_len = htons(packet_len);

            // update tcp seq
            tcp.header->seq = seq;
            tcp.header->ack = socket->last_client_seq;
            if (packet_data_len < packet_data_cap) {
                tcp.header->PSH = 1;
            }

            tcp_checksum(&ip, &tcp);

            if (tts->func_output != NULL) {
                NIP_LOGD("write %d to tun", packet_len);
                result = tts->func_output(tts, socket, buf->data, packet_len);
            }

            if (result != NIP_OK) {
                break;
            }

            seq = htonl(ntohl(seq) + packet_data_len);
            left -= packet_data_len;
            window_data_len -= packet_data_len;
            window_data_index += packet_data_len;
            window->send_not_ack_count += packet_data_len;
        }
    } else {
        result = NIP_OK;
    }

    if (result == NIP_OK) {
        socket->expect_ack = seq;

        // if socket status is CLOSE_WAIT, send FIN
        if (socket->status == TCP_STATUS_CLOSE_WAIT) {
            ip_init_from_empty_data(&ip);
            tcp_init_with_data(&tcp, &ip);
            init_tcp_ip_response_by_socket(&ip, &tcp, socket, socket->last_client_seq);

            tcp.header->ACK = 1;
            tcp.header->FIN = 1;

            tcp_checksum(&ip, &tcp);

            if (tts->func_output != NULL) {
                result = tts->func_output(tts, socket, ip.data, IP_TOTAL_LEN(ip.header));
            }

            if (result == NIP_OK) {
                socket->status = TCP_STATUS_LAST_ACK;
                socket->expect_ack = htonl(ntohl(socket->expect_ack) + 1);
            }
        }
    }

    PacketBuf_free(tts->buf_pool, buf);

    return result;
}

int tts_close(Socket *socket) {
    NIP_LOGD("close socket");
    int result = NIP_ERR_NOT_IMPL;
    socket->close = 1;
    if (socket->close) {
        return NIP_OK;
    }

    // check socket out buffer, if not empty send all data to client first
    if (TCO_WINDOW_not_send_data(socket->window_send) > 0
        || (socket->out_buf != NULL && socket->out_buf->len > 0)) {
        NIP_LOGD("send left data to client before close");
        return tts_tcp_send(socket);
    }

    TunToSocket *tts = socket->tts;
    PacketBuf *buf = PacketBuf_new(tts->buf_pool, tts->mtu);
    IP_PROTO ip;
    ip.data = buf->data;
    ip.header = buf->data;

    TCP_PROTO tcp;
    init_tcp_ip_response_by_socket(&ip, &tcp, socket, socket->last_client_seq);

    // set FIN = 1
    tcp.header->FIN = 1;
    tcp_checksum(&ip, &tcp);

    if (tts->func_output != NULL) {
        result = tts->func_output(tts, socket, ip.data, IP_TOTAL_LEN(ip.header));
    }

    if (result == NIP_OK) {
        socket->status = TCP_STATUS_FIN_WAIT_1;
        socket->expect_ack = htonl(ntohl(tcp.header->seq) + 1);
    }

    return result;
}

static int handle_tcp_FIN_WAIT_1(TCP_PROTO *tcp, Socket *socket) {
    int result;

    if (tcp->header->ack == socket->expect_ack) {
        result = NIP_OK;
        socket->status = TCP_STATUS_FIN_WAIT_2;
        NIP_LOGD("socket new status FIN_WAIT_2");
    } else if (htonl(ntohl(tcp->header->ack) + 1) == socket->expect_ack) {
        // the last ACK send form client when socket status is ESTABLISHED
        result = NIP_OK;

        // clear socket window
        socket->window_send->data_len = 0;
        socket->window_send->data_index = 0;
        socket->window_send->send_not_ack_count = 0;
    } else {
        result = NIP_ERR_BAD_DATA;
    }

    return result;
}

static int handle_tcp_FIN_WAIT_2(IP_PROTO *ip, TCP_PROTO *tcp, Socket *socket) {
    NIP_LOGD("FIN_WAIT_2");
    int result = NIP_ERR_NOT_IMPL;
    // if FIN is 0, call handle_tcp_ACK
    if (tcp->header->FIN == 0) {
        return handle_tcp_ACK(socket->tts, ip, tcp, socket);
    }

    NIP_LOGD("send last ACK");
    TunToSocket *tts = socket->tts;
    PacketBuf *buf = PacketBuf_new(tts->buf_pool, tts->mtu);
    IP_PROTO ip_resp;
    ip_resp.data = buf->data;
    ip_resp.header = buf->data;

    TCP_PROTO tcp_resp;
    init_tcp_ip_response_by_socket(&ip_resp, &tcp_resp, socket, htonl(ntohl(tcp->header->seq) + 1));

    tcp_checksum(&ip_resp, &tcp_resp);

    if (tts->func_output != NULL) {
        result = tts->func_output(tts, socket, ip_resp.data, IP_TOTAL_LEN(ip_resp.header));
    }

    if (result == NIP_OK) {
        socket->status = TCP_STATUS_TIME_WAIT;
        NIP_LOGD("socket new status TIME_WAIT");
        socket_time_wait(socket);
    }

    return result;
}
