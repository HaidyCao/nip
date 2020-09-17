//
// Created by Haidy on 2020/6/16.
//

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "tcp.h"
#include "config.h"
#include "log.h"
#include "tcp_status.h"
#include "ip_proto.h"
#include "tcp_window.h"
#include "checksum.h"

#define MAX(x, y) (x > y) ? (x) : (y)
#define MIN(x, y) (x > y) ? (y) : (x)

#define TCP_END_OF_OPTION_LIST_OPTION 0
#define TCP_NO_OPERATION_OPTION 1
#define TCP_MAX_SEGMENT_OPTION 2
#define TCP_WINDOW_SCALE_OPTION 3
#define TCP_SACK_OPTION 4

#define TCP_TIME_STAMP_OPTION 8

void tcp_init_with_data(TCP_PROTO *tcp, IP_PROTO *ip) {
    tcp->offset = IP_HEADER_LEN(ip->header);
    tcp->header = (TCP_PROTO_HEADER *) (ip->data + tcp->offset);
    tcp->options_length = 0;
    tcp->data = ip->data;

    tcp->SACK = 0;
    tcp->ts_echo_reply = 0;
    tcp->ts_value = 0;
    tcp->max_segment = 0;
    tcp->window_scale = 0;
}

void tcp_parse_options(TCP_PROTO *tcp) {
    uint16_t header_len = TCP_HEADER_LEN(tcp->header);
    if (header_len > TCP_HEADER_DEFAULT_LEN) {
        tcp->options_length = header_len - TCP_HEADER_DEFAULT_LEN;
        char *option_data = (char *) tcp->header + TCP_HEADER_DEFAULT_LEN;

        int left = header_len - TCP_HEADER_DEFAULT_LEN;
        uint8_t kind_len = 0;
        for (; left > 0; left -= kind_len) {
            uint8_t kind = option_data[0];

            if (kind == TCP_END_OF_OPTION_LIST_OPTION) {
                break;
            } else if (kind == TCP_NO_OPERATION_OPTION) {
                kind_len = 1;
                option_data += kind_len;
                continue;
            } else if (kind == TCP_MAX_SEGMENT_OPTION) {
                tcp->max_segment = ntohs(nip_read_short(option_data, 2));
            } else if (kind == TCP_WINDOW_SCALE_OPTION) {
                tcp->window_scale = option_data[2];
            } else if (kind == TCP_SACK_OPTION) {
                tcp->SACK = 1;
            } else if (kind == TCP_TIME_STAMP_OPTION) {
                tcp->ts_value = nip_read_int32(option_data, 2);
                tcp->ts_echo_reply = nip_read_int32(option_data, 2 + 4);
            }

            kind_len = option_data[1];
            option_data += kind_len;
        }
    }
}

uint32_t tcp_window_size(TCP_PROTO *tcp) {
    uint8_t shift_cnt = tcp->window_scale;
    if (shift_cnt > 14) {
        return TCP_WINDOW_DEFAULT_SIZE;
    }

    uint32_t window_size = ntohs(tcp->header->window_size);
    return window_size << shift_cnt;
}

void tcp_clear_options(TCP_PROTO *tcp) {
    tcp->header->header_len = 5;
    tcp->options_length = 0;

    tcp->SACK = 0;
    tcp->ts_echo_reply = 0;
    tcp->ts_value = 0;
    tcp->max_segment = 0;
    tcp->window_scale = 0;
}

static void resize_tcp_header_len(TCP_PROTO *tcp, char *padding) {
    if (tcp->options_length + TCP_HEADER_DEFAULT_LEN > TCP_HEADER_LEN(tcp->header)) {
        tcp->header->header_len += 1;

        uint32_t padding_len =
                TCP_HEADER_LEN(tcp->header) - TCP_HEADER_DEFAULT_LEN - tcp->options_length;
        bzero(padding, padding_len);
    }
}

void tcp_add_sack_option(TCP_PROTO *tcp) {
    char *options = (char *) (tcp->data + tcp->offset + TCP_HEADER_DEFAULT_LEN +
                              tcp->options_length);
    options[0] = TCP_SACK_OPTION;
    options[1] = 2; // length
    tcp->options_length += 2;

    resize_tcp_header_len(tcp, options + 2);
}

void tcp_add_window_scale_option(TCP_PROTO *tcp, uint8_t shift) {
    char *options = (char *) (tcp->data + tcp->offset + TCP_HEADER_DEFAULT_LEN +
                              tcp->options_length);
    options[0] = TCP_WINDOW_SCALE_OPTION;
    options[1] = 3;
    options[2] = shift;

    tcp->options_length += 3;
    resize_tcp_header_len(tcp, options + 2);
}