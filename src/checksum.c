//
// Created by Haidy on 2020/6/18.
//

#include "checksum.h"

#define IP_HEADER_SRC_IP_OFFSET 12

unsigned short nip_read_short(const char *data, int offset) {
    uint16_t a = data[offset];
    a = a << (uint) 8;
    a &= (uint16_t) 0xFF00;

    uint16_t b = data[offset + 1];
    b &= (uint16_t) 0x00FF;

    return a | b;
}

uint32_t nip_read_int32(const char *data, int offset) {
    uint32_t a = ((uint32_t) data[offset]) << (uint32_t) 24;
    a &= (uint32_t) 0xFF000000;

    uint32_t b = ((uint32_t) data[offset + 1]) << (uint32_t) 16;
    b &= (uint32_t) 0x00FF0000;

    uint32_t c = ((uint32_t) data[offset + 2]) << (uint) 8;
    c &= (uint32_t) 0xFF00;

    uint32_t d = ((uint32_t) data[offset + 3]) & (uint32_t) 0xFF;

    return a | b | c | d;
}

static long get_sum(const char *buf, int offset, int len) {
    long sum = 0;
    while (len > 1) {
        uint16_t s = nip_read_short(buf, offset);
        sum += s;
        offset += 2;
        len -= 2;
    }
    if (len > 0) {
        uint16_t s = buf[offset];
        s = s << (uint) 8;
        sum += s;
    }
    return sum;
}

static short checksum(long sum, char *buf, int offset, int len) {
    sum += get_sum(buf, offset, len);
    while (((uint32_t) sum >> (uint) 16) > 0) {
        long a = (uint16_t) sum & (uint16_t) 0xFFFF;
        long b = (uint32_t) sum >> (uint) 16;
        sum = a + b;
    }
    uint16_t c = sum;
    return (short) ~c;
}

void ip_checksum(IP_PROTO *ip) {
    ip->header->checksum = 0;
    short sum = checksum(0, ip->data, 0, IP_HEADER_LEN(ip->header));
    ip->header->checksum = htons(sum);
}

bool tcp_checksum(IP_PROTO *ip, TCP_PROTO *tcp) {
    if (ip == NULL) {
        return false;
    }

    if (tcp == NULL) {
        TCP_PROTO tcpProto;
        unsigned char ip_header_len = IP_HEADER_LEN(ip->header);
        tcpProto.header = (TCP_PROTO_HEADER *) ip->data + ip_header_len;
        tcpProto.data = ip->data;

        return tcp_checksum(ip, &tcpProto);
    }

    ip_checksum(ip);
    int ip_data_len = IP_DATA_LEN(ip->header);
    if (ip_data_len <= 0) {
        return false;
    }

    long sum = get_sum(ip->data, IP_HEADER_SRC_IP_OFFSET, 8);
    sum += ip->header->protocol & (uint8_t) 0xFF;
    sum += ip_data_len;

    uint16_t old_sum = tcp->header->checksum;
    tcp->header->checksum = 0;
    short new_sum = checksum(sum, ip->data, IP_HEADER_LEN(ip->header), ip_data_len);
    tcp->header->checksum = htons(new_sum);
    return old_sum == tcp->header->checksum;
}