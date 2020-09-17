//
// Created by Haidy on 2020/6/16.
//

#ifndef NETWORK_TCP_H
#define NETWORK_TCP_H

#include <stdint.h>
#include "ip_proto.h"

typedef struct {
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t seq;
    uint32_t ack;
    unsigned char rsv_1: 4;
    unsigned short header_len: 4;
    unsigned short FIN: 1;
    unsigned short SYN: 1;
    unsigned short RST: 1;
    unsigned short PSH: 1;
    unsigned short ACK: 1;
    unsigned short URG: 1;
    unsigned short rsv_2: 2;
    unsigned int window_size:16;
    uint16_t checksum;
    uint16_t urgent_pointer;
} TCP_PROTO_HEADER;

#define TCP_HEADER_DEFAULT_LEN 20

#define TCP_HEADER_LEN(header) ((header->header_len == 0) ? 20 : (header->header_len * 4))
#define TCP_DATA_LEN(ip_header, tcp_header) (IP_DATA_LEN(ip_header) - TCP_HEADER_LEN(tcp_header))

typedef struct {
    TCP_PROTO_HEADER *header;
    uint32_t options_length;
    uint16_t max_segment;
    uint8_t window_scale;
    uint8_t SACK;
    uint32_t ts_value;
    uint32_t ts_echo_reply;

    uint32_t offset;
    char *data;
} TCP_PROTO;

void tcp_init_with_data(TCP_PROTO *tcp, IP_PROTO *ip);

void tcp_parse_options(TCP_PROTO *tcp);

uint32_t tcp_window_size(TCP_PROTO *tcp);

void tcp_clear_options(TCP_PROTO *tcp);

void tcp_add_sack_option(TCP_PROTO *tcp);

void tcp_add_window_scale_option(TCP_PROTO *tcp, uint8_t shift);

#endif //NETWORK_TCP_H
