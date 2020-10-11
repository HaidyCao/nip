//
// Created by Haidy on 2020/10/11.
//

#ifndef NETWORK_NIP_PROTO_H
#define NETWORK_NIP_PROTO_H

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

typedef struct {
    unsigned short src_port;
    unsigned short dest_port;

    unsigned short udp_length;
    unsigned short udp_checksum;
} UDP_PROTO_HEADER;

#define UDP_HEADER_LENGTH 8

#define UDP_TOTAL_LENGTH(header) ntohs(header->udp_length)

#define UDP_SET_TOTAL_LENGTH(header, length) 

#define UDP_DATA_LENGTH(header) UDP_TOTAL_LENGTH(header) - UDP_HEADER_LENGTH

#endif //NETWORK_NIP_PROTO_H
